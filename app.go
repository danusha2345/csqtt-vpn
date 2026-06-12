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
}

// App — бэкенд Wails.
type App struct {
	ctx context.Context

	mu        sync.Mutex
	mgr       *core.Manager
	cancel    context.CancelFunc
	connected bool
}

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
	s := Settings{Workers: 12}
	if data, err := os.ReadFile(configPath()); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	if s.Workers <= 0 {
		s.Workers = 12
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
	a.mgr, a.cancel, a.connected = mgr, cancel, true
	a.mu.Unlock()

	a.emitStatus("connecting")
	go func() {
		err := mgr.Connect(ctx, core.Config{
			Server: s.Server, Password: s.Password, VKLinks: s.VKLinks,
			Workers: s.Workers, SystemVPN: s.SystemVPN, Excludes: s.Excludes,
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
			a.Disconnect()
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
func (a *App) Disconnect() {
	a.mu.Lock()
	mgr, cancel := a.mgr, a.cancel
	a.mgr, a.cancel, a.connected = nil, nil, false
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if mgr != nil {
		a.emitStatus("disconnecting")
		mgr.Disconnect()
	}
	a.emitStatus("disconnected")
}

func (a *App) IsConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected
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
