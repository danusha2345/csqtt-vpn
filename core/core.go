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
	"io"
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
	ObfsMode  string // audio (PT=111) или video (PT=96)
}

func normalizeObfsMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "video") {
		return "video"
	}
	return "audio"
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
	clientIn  *os.File        // stdin go_client для CAPTCHA_RESULT
	turnIPs   map[string]bool // TURN-IP из логов клиента — для bypass при старте маршрутизации
	onLog     func(string)
	onCaptcha CaptchaFunc
	onDown    func() // вызывается, когда туннель выключился сам (fail-safe)

	// shuttingDown=true означает намеренную остановку (Disconnect или fail-safe):
	// супервайзер wireproxy в этом случае НЕ перезапускает процесс.
	shuttingDown bool

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

// SetOnDown регистрирует колбэк, который ядро вызывает, когда туннель выключился
// сам (fail-safe после серии падений wireproxy) — чтобы GUI вернул кнопку в
// «Подключить» и не показывал ложное «подключено».
func (m *Manager) SetOnDown(f func()) {
	m.mu.Lock()
	m.onDown = f
	m.mu.Unlock()
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
		"-obfs", normalizeObfsMode(cfg.ObfsMode),
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
	clientExit := m.watchExit("wdtt-client", client)

	m.log("• Жду WireGuard-конфиг от сервера (до %s)…", configWait)
	if err := m.waitFile(ctx, wgConf, clientExit, configWait); err != nil {
		m.stopClient()
		return err
	}
	m.log("  ✓ конфиг получен")

	if err := buildWireproxyConf(wgConf, wpConf); err != nil {
		m.stopClient()
		return fmt.Errorf("конвертация конфига: %w", err)
	}

	m.log("• Запускаю wireproxy (userspace WireGuard)…")
	wpOut, wpExit, err := m.startWireproxy(wpConf)
	if err != nil {
		m.stopClient()
		return fmt.Errorf("старт wireproxy: %w", err)
	}

	got := m.waitHandshake(ctx, wpOut)
	if got {
		m.log("  ✓ WireGuard handshake получен")
	} else {
		m.log("  ⚠ handshake пока не подтверждён — проверь позже")
	}

	// SOCKS5 обязан слушать ДО объявления успеха и до системной маршрутизации —
	// иначе весь трафик уйдёт в мёртвый прокси (refused-спам, нет интернета).
	if err := m.waitSocks(ctx, socksBind, wpExit, 6*time.Second); err != nil {
		m.stopWireproxy()
		m.stopClient()
		return fmt.Errorf("SOCKS5-прокси: %w", err)
	}

	// SOCKS5 поднят — берём wireproxy под наблюдение: торрент-вал коннектов или
	// OOM роняет его (exit status 2), а tun2socks без живого SOCKS5 превращает
	// сеть в «чёрную дыру». Супервайзер перезапускает его на том же порту.
	go m.superviseWireproxy(wpConf, wpExit)

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

// wgPrivate маскирует приватный ключ WG в журнале — пользователи шлют логи
// при проблемах, ключ туда попадать не должен.
var wgPrivate = regexp.MustCompile(`(PrivateKey\s*=\s*)\S+`)

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
		// Запоминаем всегда: они приходят ДО старта маршрутизации, когда
		// excludeHost ещё no-op, — startSystemRouting добавит их повторно.
		if ip := extractTurnIP(line); ip != "" {
			m.mu.Lock()
			if m.turnIPs == nil {
				m.turnIPs = map[string]bool{}
			}
			m.turnIPs[ip] = true
			m.mu.Unlock()
			m.excludeHost(ip)
		}
		m.log("[client] %s", wgPrivate.ReplaceAllString(line, "${1}•••"))
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

// watchExit ждёт завершения процесса (единственный вызов cmd.Wait) и сообщает
// о неожиданной смерти в журнал — иначе упавший wireproxy/tun2socks умирает
// молча и причину не найти. Намеренная остановка отличается тем, что процесс
// сперва вычёркивается из полей Manager и только потом убивается.
// Возвращает канал, закрываемый по завершении процесса.
func (m *Manager) watchExit(name string, cmd *exec.Cmd) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		err := cmd.Wait()
		close(ch)
		m.mu.Lock()
		tracked := m.client == cmd || m.wireproxy == cmd || m.tun2socks == cmd
		m.mu.Unlock()
		if tracked {
			msg := "код 0"
			if err != nil {
				msg = err.Error()
			}
			m.log("⚠ %s неожиданно завершился (%s)", name, msg)
		}
	}()
	return ch
}

// startWireproxy запускает один процесс wireproxy и возвращает его объединённый
// stdout+stderr и канал завершения. Чтение логов выбирает вызывающий: первый старт
// ждёт handshake (waitHandshake), перезапуск из супервайзера просто читает
// (readWireproxy). Намеренную остановку не начинает запуск (shuttingDown).
func (m *Manager) startWireproxy(wpConf string) (io.ReadCloser, <-chan struct{}, error) {
	wp := exec.Command(m.exe("wireproxy.exe"), "-c", wpConf)
	wp.Dir = m.runDir
	hideConsole(wp)
	out, err := wp.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	wp.Stderr = wp.Stdout
	if err := wp.Start(); err != nil {
		return nil, nil, err
	}
	// Проверку «не остановлены ли» и запись m.wireproxy делаем под одним замком:
	// иначе Disconnect, прочитавший старое m.wireproxy, не убьёт только что
	// запущенный процесс — останется сирота.
	m.mu.Lock()
	if m.shuttingDown {
		m.mu.Unlock()
		_ = wp.Process.Kill()
		go func() { _ = wp.Wait() }()
		return nil, nil, fmt.Errorf("идёт остановка")
	}
	m.wireproxy = wp
	m.mu.Unlock()
	return out, m.watchExit("wireproxy", wp), nil
}

// readWireproxy читает логи wireproxy до конца процесса. Используется для
// перезапущенных инстансов: гарантирует, что причина падения (паника/ERROR,
// exit status 2) попадёт в журнал, а не потеряется молча.
func (m *Manager) readWireproxy(out io.Reader) {
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := sc.Text(); wpInteresting(line) {
			m.log("[wireproxy] %s", line)
		}
	}
}

// superviseWireproxy перезапускает wireproxy, если он упал НЕ по нашей команде
// (паника под валом BitTorrent-коннектов, OOM — типичный exit status 2). SOCKS5
// поднимается на том же 127.0.0.1:1080, поэтому tun2socks и маршруты
// восстанавливаются сами — трогать их не нужно. Если падения идут подряд, делаем
// fail-safe: гасим VPN и возвращаем прямой интернет, чтобы не оставить сеть
// «чёрной дырой» (весь трафик в мёртвый прокси).
func (m *Manager) superviseWireproxy(wpConf string, exit <-chan struct{}) {
	const (
		maxRestarts = 5
		stableAfter = 60 * time.Second // прожил дольше — следующее падение это новый инцидент
	)
	fails := 0
	startedAt := time.Now()
	for {
		<-exit
		if m.isShuttingDown() {
			return // Disconnect/fail-safe — это намеренная остановка
		}
		if time.Since(startedAt) > stableAfter {
			fails = 0
		}
		fails++
		if fails > maxRestarts {
			m.log("⛔ wireproxy падает подряд (%d раз) — выключаю VPN и возвращаю прямой интернет", fails-1)
			m.failSafe()
			return
		}
		backoff := time.Duration(fails) * time.Second
		m.log("↻ wireproxy упал — перезапуск %d/%d через %s…", fails, maxRestarts, backoff)
		time.Sleep(backoff)
		out, newExit, err := m.startWireproxy(wpConf)
		if err != nil {
			if m.isShuttingDown() {
				return
			}
			m.log("  ⚠ не удалось перезапустить wireproxy: %v", err)
			m.failSafe()
			return
		}
		go m.readWireproxy(out)
		if err := m.waitSocks(context.Background(), socksBind, newExit, 10*time.Second); err == nil {
			m.log("  ✓ wireproxy восстановлен, SOCKS5 снова доступен")
		} else {
			m.log("  ⚠ SOCKS5 пока не отвечает после перезапуска: %v", err)
		}
		exit = newExit
		startedAt = time.Now()
	}
}

// failSafe выключает туннель, когда wireproxy не удаётся удержать: снимает
// tun2socks и системные маршруты (возврат прямого интернета), гасит процессы и
// сообщает GUI через onDown. Идемпотентна — повторный вход сразу выходит.
func (m *Manager) failSafe() {
	m.mu.Lock()
	if m.shuttingDown {
		m.mu.Unlock()
		return
	}
	m.shuttingDown = true
	sys := m.sysActive
	onDown := m.onDown
	m.mu.Unlock()

	if sys {
		m.log("• Снимаю tun2socks и системные маршруты (fail-safe)…")
		m.stopSystemRouting()
	}
	m.stopWireproxy()
	m.stopClient()
	m.log("⛔ VPN остановлен. Прямой интернет восстановлен. Нажмите «Подключить» для повторной попытки.")
	if onDown != nil {
		onDown()
	}
}

func (m *Manager) isShuttingDown() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.shuttingDown
}

func (m *Manager) waitFile(ctx context.Context, path string, exited <-chan struct{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			return fmt.Errorf("wdtt-client завершился до выдачи конфига")
		case <-tick.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("не дождался конфига за %s", timeout)
			}
		}
	}
}

// waitSocks ждёт, когда SOCKS5-порт wireproxy начнёт принимать соединения.
func (m *Manager) waitSocks(ctx context.Context, addr string, exited <-chan struct{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			return fmt.Errorf("wireproxy завершился, SOCKS5 %s не поднялся", addr)
		case <-time.After(300 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s не отвечает за %s", addr, timeout)
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
	m.mu.Lock()
	m.shuttingDown = true // запретить супервайзеру перезапуск во время остановки
	m.mu.Unlock()
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

func (m *Manager) stopWireproxy() {
	m.mu.Lock()
	wp := m.wireproxy
	m.wireproxy = nil
	m.mu.Unlock()
	if wp != nil && wp.Process != nil {
		_ = wp.Process.Kill()
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
