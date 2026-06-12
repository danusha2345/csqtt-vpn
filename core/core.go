// Package core — ядро управления WDTT Windows-клиентом (Этап 1: SOCKS5-режим).
//
// Архитектура Этапа 1 (без системного TUN, поэтому без проблемы split-tunnel):
//
//	приложение --SOCKS5 127.0.0.1:1080--> wireproxy.exe (userspace WireGuard)
//	                                            | Endpoint 127.0.0.1:9000
//	                                            v
//	                                      wdtt-client.exe (наш go_client)
//	                                            | VK TURN
//	                                            v
//	                                      wdtt-server (VPS)
//
// wdtt-client идёт к VK TURN напрямую через физический интерфейс — петли нет,
// пока не включён системный TUN (это Этап 2: tun2socks + split).
package core

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	innerListen  = "127.0.0.1:9000" // wdtt-client слушает локально
	socksBind    = "127.0.0.1:1080" // wireproxy отдаёт SOCKS5 приложениям
	configWait   = 70 * time.Second // сколько ждём wg-turn.conf от сервера
	handshakeMax = 8 * time.Second  // сколько ждём WG-handshake в логах wireproxy
)

// Config — параметры подключения (заполняет пользователь / GUI).
type Config struct {
	Server    string // host:port WDTT-сервера
	Password  string // пароль туннеля
	VKLinks   string // VK-ссылки/хеши через запятую или с новых строк
	Workers   int    // число воркеров (по умолчанию 12)
	SystemVPN bool   // системный VPN (весь трафик через TUN), иначе только SOCKS5
	Excludes  string // домены/IP/подсети, которые идут МИМО VPN (по строкам/запятым)
}

// CaptchaFunc вызывается, когда go_client просит решить капчу через WebView
// (mode|redirectURI|sessionToken). Возврат — токен решения (Этап 4). На Этапе 1
// можно передать nil — авто-решатель Go v2 внутри go_client работает сам.
type CaptchaFunc func(mode, redirectURI, sessionToken string) string

// Manager управляет жизненным циклом процессов одного подключения.
type Manager struct {
	binDir string
	runDir string

	mu        sync.Mutex
	client    *exec.Cmd
	wireproxy *exec.Cmd
	clientIn  *os.File // stdin go_client для CAPTCHA_RESULT
	onLog     func(string)
	onCaptcha CaptchaFunc

	// системный VPN (Windows): tun2socks + маршруты
	tun2socks *exec.Cmd
	physGW    string
	physIf    string
	routes    map[string]bool // добавленные маршруты (для отката)
	sysActive bool
	dns       *dnsProxy // DNS-перехват для обхода по доменам
}

// NewManager: binDir — папка с wdtt-client.exe/wireproxy.exe; runDir — рабочая
// папка для wg-turn.conf/wireproxy.conf (например, %TEMP%\wdtt).
func NewManager(binDir, runDir string, onLog func(string), onCaptcha CaptchaFunc) *Manager {
	if onLog == nil {
		onLog = func(string) {}
	}
	return &Manager{binDir: binDir, runDir: runDir, onLog: onLog, onCaptcha: onCaptcha}
}

func (m *Manager) exe(name string) string { return filepath.Join(m.binDir, name) }

func (m *Manager) log(format string, a ...any) { m.onLog(fmt.Sprintf(format, a...)) }

// parseVKLinks нормализует ввод (строки/запятые) в "a,b,c".
func parseVKLinks(raw string) string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		for _, p := range strings.Split(line, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return strings.Join(out, ",")
}

func (m *Manager) preflight(cfg Config, vk string) error {
	for _, b := range []string{"wdtt-client.exe", "wireproxy.exe"} {
		if _, err := os.Stat(m.exe(b)); err != nil {
			return fmt.Errorf("не найден %s: %w", b, err)
		}
	}
	if !strings.Contains(cfg.Server, ":") {
		return fmt.Errorf("адрес сервера должен быть host:port")
	}
	if strings.TrimSpace(cfg.Password) == "" {
		return fmt.Errorf("не указан пароль туннеля")
	}
	if vk == "" {
		return fmt.Errorf("не указана ни одна VK-ссылка")
	}
	return nil
}

// Connect запускает цепочку и блокируется до подъёма SOCKS5 (или ошибки).
// ctx отменяет ожидание конфига/handshake.
func (m *Manager) Connect(ctx context.Context, cfg Config) error {
	vk := parseVKLinks(cfg.VKLinks)
	if err := m.preflight(cfg, vk); err != nil {
		return err
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = 12
	}

	if err := os.MkdirAll(m.runDir, 0o755); err != nil {
		return fmt.Errorf("runDir: %w", err)
	}
	m.cleanupStale() // убрать осиротевшие процессы/маршруты прошлой сессии
	wgConf := filepath.Join(m.runDir, "wg-turn.conf")
	wpConf := filepath.Join(m.runDir, "wireproxy.conf")
	_ = os.Remove(wgConf)

	m.log("• Запускаю wdtt-client (go_client)…")
	client := exec.Command(m.exe("wdtt-client.exe"),
		"-peer", cfg.Server,
		"-vk", vk,
		"-password", cfg.Password,
		"-listen", innerListen,
		"-n", fmt.Sprintf("%d", workers),
		"-device-id", "windows-wireproxy",
		"-captcha-mode", "auto",
	)
	client.Dir = m.runDir
	hideConsole(client)
	stdout, err := client.StdoutPipe()
	if err != nil {
		return err
	}
	// go_client пишет логи стандартным log → stderr; без этого теряются все его
	// логи и строки с turn:IP для динамического bypass.
	client.Stderr = client.Stdout
	stdin, err := client.StdinPipe()
	if err != nil {
		return err
	}
	if err := client.Start(); err != nil {
		return fmt.Errorf("старт wdtt-client: %w", err)
	}
	m.mu.Lock()
	m.client = client
	if f, ok := stdin.(*os.File); ok {
		m.clientIn = f
	}
	m.mu.Unlock()
	go m.readClient(stdout)

	m.log("• Жду WireGuard-конфиг от сервера (до %s)…", configWait)
	if err := m.waitFile(ctx, wgConf, client, configWait); err != nil {
		m.stopClient()
		return err
	}
	m.log("  ✓ конфиг получен")

	if err := buildWireproxyConf(wgConf, wpConf); err != nil {
		m.stopClient()
		return fmt.Errorf("конвертация конфига: %w", err)
	}

	m.log("• Запускаю wireproxy (userspace WireGuard)…")
	wp := exec.Command(m.exe("wireproxy.exe"), "-c", wpConf)
	wp.Dir = m.runDir
	hideConsole(wp)
	wpOut, err := wp.StdoutPipe()
	if err != nil {
		m.stopClient()
		return err
	}
	wp.Stderr = wp.Stdout
	if err := wp.Start(); err != nil {
		m.stopClient()
		return fmt.Errorf("старт wireproxy: %w", err)
	}
	m.mu.Lock()
	m.wireproxy = wp
	m.mu.Unlock()

	got := m.waitHandshake(ctx, wpOut)
	if got {
		m.log("  ✓ WireGuard handshake получен")
	} else {
		m.log("  ⚠ handshake пока не подтверждён — проверь позже")
	}

	if cfg.SystemVPN {
		host := cfg.Server
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		if err := m.startSystemRouting(ctx, host, parseVKLinks(cfg.Excludes)); err != nil {
			m.log("Ошибка системного VPN: %v — откатываю, остаюсь в SOCKS5", err)
			m.stopSystemRouting()
			// туннель/SOCKS5 продолжают работать
		}
		return nil
	}

	m.log("✅ Подключено. SOCKS5: %s", socksBind)
	m.log("   Проверка: curl --socks5 %s https://api.ipify.org", socksBind)
	return nil
}

// clientTS — префикс времени стандартного log-пакета go_client
// ("2006/01/02 15:04:05.000000 "); в журнале GUI он только шумит и ломает
// дедупликацию повторов на фронтенде.
var clientTS = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)? `)

// readClient читает stdout+stderr go_client: пишет логи и обрабатывает CAPTCHA_SOLVE.
func (m *Manager) readClient(stdout interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := clientTS.ReplaceAllString(sc.Text(), "")
		if strings.HasPrefix(line, "CAPTCHA_SOLVE|") {
			parts := strings.Split(strings.TrimPrefix(line, "CAPTCHA_SOLVE|"), "|")
			if m.onCaptcha != nil && len(parts) >= 3 {
				token := m.onCaptcha(parts[0], parts[1], parts[2])
				if token != "" {
					m.SendCaptchaResult(token)
				}
			}
			continue
		}
		// Динамический bypass: адреса TURN-серверов из логов go_client выводим
		// мимо TUN (иначе при системном VPN — петля). Строки вида "turn:IP:port".
		if ip := extractTurnIP(line); ip != "" {
			m.excludeHost(ip)
		}
		m.log("[client] %s", line)
	}
}

// extractTurnIP вытаскивает IPv4 из строки лога с "turn:IP:port" / "turns:IP:port".
func extractTurnIP(line string) string {
	for _, marker := range []string{"turn:", "turns:"} {
		if i := strings.Index(line, marker); i >= 0 {
			rest := line[i+len(marker):]
			rest = strings.TrimLeftFunc(rest, func(r rune) bool { return r == '/' })
			if end := strings.IndexAny(rest, ":?\" ]"); end >= 0 {
				rest = rest[:end] // иначе IP стоит в конце строки — берём её целиком
			}
			if net.ParseIP(rest) != nil {
				return rest
			}
		}
	}
	return ""
}

// SendCaptchaResult отправляет решённый токен капчи в go_client (Этап 4).
func (m *Manager) SendCaptchaResult(token string) {
	m.mu.Lock()
	in := m.clientIn
	m.mu.Unlock()
	if in != nil {
		_, _ = in.Write([]byte("CAPTCHA_RESULT|" + token + "\n"))
	}
}

func (m *Manager) waitFile(ctx context.Context, path string, client *exec.Cmd, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return fmt.Errorf("wdtt-client завершился до выдачи конфига")
		case <-tick.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("не дождался конфига за %s", timeout)
			}
		}
	}
}

func (m *Manager) waitHandshake(ctx context.Context, out interface{ Read([]byte) (int, error) }) bool {
	type res struct{ ok bool }
	ch := make(chan res, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			line := sc.Text()
			if wpInteresting(line) {
				m.log("[wireproxy] %s", line)
			}
			if strings.Contains(line, "Received handshake response") {
				ch <- res{true}
				// продолжаем читать, чтобы не блокировать процесс
				for sc.Scan() {
					if wpInteresting(sc.Text()) {
						m.log("[wireproxy] %s", sc.Text())
					}
				}
				return
			}
		}
		ch <- res{false}
	}()
	select {
	case r := <-ch:
		return r.ok
	case <-time.After(handshakeMax):
		return false
	case <-ctx.Done():
		return false
	}
}

// Disconnect откатывает маршруты системного VPN и останавливает все процессы.
func (m *Manager) Disconnect() {
	m.stopSystemRouting() // откат маршрутов + tun2socks (no-op, если не было)
	m.mu.Lock()
	wp, cl := m.wireproxy, m.client
	m.wireproxy, m.client, m.clientIn = nil, nil, nil
	m.mu.Unlock()
	if wp != nil && wp.Process != nil {
		_ = wp.Process.Kill()
	}
	if cl != nil && cl.Process != nil {
		_ = cl.Process.Kill()
	}
	m.log("✅ Отключено")
}

func (m *Manager) stopClient() {
	m.mu.Lock()
	cl := m.client
	m.client, m.clientIn = nil, nil
	m.mu.Unlock()
	if cl != nil && cl.Process != nil {
		_ = cl.Process.Kill()
	}
}

// Running сообщает, поднят ли wireproxy.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.wireproxy != nil
}

// SysActive сообщает, активен ли системный VPN (TUN-маршруты подняты). Может
// быть false при успешном Connect, если системная маршрутизация не поднялась
// и клиент остался в SOCKS5-режиме.
func (m *Manager) SysActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sysActive
}

// wpInteresting отсеивает шумные DEBUG-строки wireproxy (worker started,
// keepalive, UAPI) — оставляет INFO/ERROR и факт получения handshake.
func wpInteresting(line string) bool {
	if !strings.Contains(line, "DEBUG:") {
		return true
	}
	return strings.Contains(line, "Received handshake response")
}

// buildWireproxyConf конвертирует wg-turn.conf (от сервера) в формат wireproxy
// с секцией [Socks5] (как делает Linux-клиент _build_wireproxy_conf).
func buildWireproxyConf(wgConf, wpConf string) error {
	raw, err := os.ReadFile(wgConf)
	if err != nil {
		return err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		ls := strings.TrimSpace(line)
		switch {
		case ls == "":
			continue
		case strings.HasPrefix(strings.ToLower(ls), "dns"):
			continue // wireproxy не любит DNS=, как и wg-quick
		case strings.HasPrefix(ls, "Address"):
			out = append(out, strings.SplitN(line, "/", 2)[0]) // без /32
		default:
			out = append(out, line)
		}
	}
	out = append(out, "", "[Socks5]", "BindAddress = "+socksBind, "")
	return os.WriteFile(wpConf, []byte(strings.Join(out, "\n")), 0o600)
}
