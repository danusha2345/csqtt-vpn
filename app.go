package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wdtt-vpn/core"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Settings — конфигурация, которой обменивается фронтенд с бэкендом.
type Settings struct {
	Server    string `json:"server"`
	Password  string `json:"password"`
	VKLinks   string `json:"vkLinks"`
	Workers   int    `json:"workers"`
	SystemVPN bool   `json:"systemVPN"`
	Excludes  string `json:"excludes"`
	ObfsMode  string `json:"obfsMode"`
}

// App — бэкенд Wails.
type App struct {
	ctx context.Context

	mu        sync.Mutex
	mgr       *core.Manager
	cancel    context.CancelFunc
	connected bool
	done      chan struct{} // закрывается, когда горутина Connect завершилась
}

// stopTimeout — сколько ждём завершения горутины Connect при отключении. Она
// прерывается по отмене контекста между этапами системной маршрутизации; запас
// нужен на случай зависшего netsh/powershell.
const stopTimeout = 20 * time.Second

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.trafficLoop()
}

func (a *App) emitLog(line string) { runtime.EventsEmit(a.ctx, "log", line) }
func (a *App) emitStatus(s string) { runtime.EventsEmit(a.ctx, "status", s) }

func configPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "wdtt", "config.json")
}

// LoadSettings читает сохранённые настройки.
func (a *App) LoadSettings() Settings {
	s := Settings{Workers: 12, ObfsMode: "audio"}
	if data, err := os.ReadFile(configPath()); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	if s.Workers <= 0 {
		s.Workers = 12
	}
	if s.ObfsMode != "video" {
		s.ObfsMode = "audio"
	}
	return s
}

// SaveSettings сохраняет настройки (вызывается фронтендом при изменении).
func (a *App) SaveSettings(s Settings) {
	p := configPath()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if data, err := json.MarshalIndent(s, "", "  "); err == nil {
		_ = os.WriteFile(p, data, 0o600)
	}
}

func binDir() string {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	if _, err := os.Stat(filepath.Join(dir, "bin", "wdtt-client.exe")); err == nil {
		return filepath.Join(dir, "bin")
	}
	return dir
}

// Connect запускает туннель. Возвращает "" при успешном старте или текст ошибки.
func (a *App) Connect(s Settings) string {
	a.SaveSettings(s)
	a.mu.Lock()
	if a.connected {
		a.mu.Unlock()
		return "уже подключено"
	}
	ctx, cancel := context.WithCancel(context.Background())
	mgr := core.NewManager(binDir(), filepath.Join(os.TempDir(), "wdtt"), a.emitLog, nil)
	mgr.SetOnDown(func() { a.onTunnelDown(mgr) })
	done := make(chan struct{})
	a.mgr, a.cancel, a.connected, a.done = mgr, cancel, true, done
	a.mu.Unlock()

	a.emitStatus("connecting")
	go func() {
		defer close(done)
		err := mgr.Connect(ctx, core.Config{
			Server: s.Server, Password: s.Password, VKLinks: s.VKLinks,
			Workers: s.Workers, SystemVPN: s.SystemVPN, Excludes: s.Excludes, ObfsMode: s.ObfsMode,
		})
		// Пользователь мог отключиться, пока шло подключение: процессы уже
		// убиты, статус "disconnected" отправлен — не перетирать его.
		a.mu.Lock()
		current := a.mgr == mgr
		a.mu.Unlock()
		if !current {
			return
		}
		if err != nil {
			a.emitLog("Ошибка: " + err.Error())
			a.stop(false) // ждать саму себя нельзя — отсюда без ожидания
			return
		}
		// Статус по фактическому режиму: при ошибке системной маршрутизации
		// core откатывается в SOCKS5 — не показывать "весь трафик защищён".
		if s.SystemVPN && mgr.SysActive() {
			a.emitStatus("connected-vpn")
		} else {
			a.emitStatus("connected-socks")
		}
	}()
	return ""
}

// Disconnect останавливает туннель и откатывает маршруты. Снятие маршрутов
// занимает секунды — на это время фронту уходит статус "disconnecting".
func (a *App) Disconnect() { a.stop(true) }

// stop гасит туннель. При wait=true сначала дожидается завершения горутины
// Connect и только потом откатывает: иначе она продолжает поднимать tun2socks,
// DNS-прокси, NRPT-правило и split-маршруты уже ПОСЛЕ отката, и система остаётся
// без сети и без DNS при статусе «Отключено». Из самой горутины вызывается с
// wait=false — ждать саму себя было бы взаимной блокировкой.
func (a *App) stop(wait bool) {
	a.mu.Lock()
	mgr, cancel, done := a.mgr, a.cancel, a.done
	a.mgr, a.cancel, a.done, a.connected = nil, nil, nil, false
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if mgr != nil {
		a.emitStatus("disconnecting")
		if wait && done != nil {
			select {
			case <-done:
			case <-time.After(stopTimeout):
				a.emitLog("⚠ подключение не остановилось за " + stopTimeout.String() +
					" — снимаю маршруты принудительно")
			}
		}
		mgr.Disconnect()
	}
	a.emitStatus("disconnected")
}

// beforeClose гасит VPN перед закрытием окна. Без этого остаются процессы,
// split-маршруты и NRPT-правило, а оно живёт в реестре и переживает перезагрузку:
// Windows продолжает резолвить всё через 10.7.0.2, которого больше нет, и DNS
// перестаёт работать во всей системе.
func (a *App) beforeClose(ctx context.Context) bool {
	if a.IsConnected() {
		a.Disconnect()
	}
	return false
}

func (a *App) IsConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected
}

// onTunnelDown вызывается ядром, когда туннель выключился сам (fail-safe после
// серии падений wireproxy). Ядро уже сняло маршруты и процессы — здесь лишь
// синхронизируем состояние и возвращаем кнопку GUI в «Подключить».
func (a *App) onTunnelDown(mgr *core.Manager) {
	a.mu.Lock()
	if a.mgr != mgr { // пользователь уже отключился/переподключился — не вмешиваемся
		a.mu.Unlock()
		return
	}
	a.mgr, a.cancel, a.done, a.connected = nil, nil, nil, false
	a.mu.Unlock()
	a.emitStatus("disconnected")
}

// Diagnose выполняет сетевую диагностику и выводит её в журнал.
func (a *App) Diagnose() {
	go func() {
		a.emitLog("════════ ДИАГНОСТИКА (скопируй и пришли) ════════")
		a.emitLog(core.Diagnostics())
		a.emitLog("════════ КОНЕЦ ДИАГНОСТИКИ ════════")
	}()
}

// CheckVPN возвращает имена активных «чужих» VPN-интерфейсов (tun/tap/wg/…),
// кроме нашего, — частая причина «не работает». Фронт предупреждает пользователя.
func (a *App) CheckVPN() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var found []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		n := strings.ToLower(iface.Name)
		if strings.Contains(n, "wdtt") {
			continue // наш собственный TUN
		}
		for _, p := range []string{"tun", "tap", "wg", "ppp", "nordlynx", "proton", "utun", "ipsec", "wireguard"} {
			if strings.HasPrefix(n, p) || strings.Contains(n, p) {
				found = append(found, iface.Name)
				break
			}
		}
	}
	return found
}

func profilesDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "wdtt", "profiles")
}

// ListProfiles возвращает имена сохранённых профилей.
func (a *App) ListProfiles() []string {
	entries, err := os.ReadDir(profilesDir())
	if err != nil {
		return []string{}
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return names
}

// SaveProfile сохраняет настройки под именем профиля.
func (a *App) SaveProfile(name string, s Settings) error {
	name = sanitizeProfileName(name)
	if name == "" {
		return fmt.Errorf("пустое имя профиля")
	}
	if err := os.MkdirAll(profilesDir(), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(profilesDir(), name+".json"), data, 0o600)
}

// LoadProfile загружает настройки профиля по имени.
func (a *App) LoadProfile(name string) Settings {
	s := Settings{Workers: 12}
	data, err := os.ReadFile(filepath.Join(profilesDir(), sanitizeProfileName(name)+".json"))
	if err == nil {
		_ = json.Unmarshal(data, &s)
	}
	if s.Workers <= 0 {
		s.Workers = 12
	}
	return s
}

// DeleteProfile удаляет профиль.
func (a *App) DeleteProfile(name string) error {
	return os.Remove(filepath.Join(profilesDir(), sanitizeProfileName(name)+".json"))
}

// sanitizeProfileName убирает разделители путей из имени профиля.
func sanitizeProfileName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.NewReplacer("/", "_", "\\", "_", "..", "_", ":", "_").Replace(name)
	return name
}

// trafficLoop раз в 1.5с шлёт фронтенду скорость и накопленный объём за сессию.
func (a *App) trafficLoop() {
	var lastD, lastU, baseD, baseU int64
	var lastT time.Time
	haveBase := false
	tk := time.NewTicker(1500 * time.Millisecond)
	defer tk.Stop()
	for range tk.C {
		a.mu.Lock()
		mgr, conn := a.mgr, a.connected
		a.mu.Unlock()
		if mgr == nil || !conn {
			haveBase = false
			lastT = time.Time{}
			continue
		}
		d, u, ok := mgr.Stats()
		if !ok {
			continue
		}
		if !haveBase {
			baseD, baseU, haveBase = d, u, true
		}
		now := time.Now()
		var downRate, upRate int64
		if !lastT.IsZero() {
			if dt := now.Sub(lastT).Seconds(); dt > 0 {
				downRate = int64(float64(d-lastD) / dt)
				upRate = int64(float64(u-lastU) / dt)
				if downRate < 0 {
					downRate = 0
				}
				if upRate < 0 {
					upRate = 0
				}
			}
		}
		lastD, lastU, lastT = d, u, now
		runtime.EventsEmit(a.ctx, "traffic", map[string]int64{
			"downRate": downRate, "upRate": upRate,
			"downTotal": d - baseD, "upTotal": u - baseU,
		})
	}
}
