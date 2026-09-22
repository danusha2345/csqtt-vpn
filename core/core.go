// Package core manages the desktop CSQTT client process and platform routing.
package core

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
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
	innerListen = "127.0.0.1:19000"
	configWait  = 90 * time.Second
	// clientStopWait — сколько ждём штатного выхода ядра по STOP. В «Авто ВК» за
	// это время ядро само завершает звонок; после — kill.
	clientStopWait = 10 * time.Second
)

type Config struct {
	Server        string
	Password      string
	VKLinks       string
	Workers       int
	SystemVPN     bool
	Excludes      string
	ObfsMode      string
	TurnTransport string
	DeviceID      string
	VKHashMode    string // manual | auto_api | auto_js
	VKToken       string
}

type CaptchaFunc func(mode, redirectURI, sessionToken string) string

type tunnelConfig struct {
	IP  string
	DNS string
}

type bridgeController interface {
	Close() error
}

type Manager struct {
	binDir string
	runDir string

	mu            sync.Mutex
	routeMu       sync.Mutex
	client        *exec.Cmd
	clientIn      io.WriteCloser
	bridge        bridgeController
	routes        map[string]bool
	turnIPs       map[string]bool
	tunUDS        string
	physGW        string
	physIf        string
	sysActive     bool
	dns           *dnsProxy
	shuttingDown  bool
	cleanupRoutes []string
	cleanupPhysIf string
	hashMode      string
	vkCalls       vkCallState
	onLog         func(string)
	onCaptcha     CaptchaFunc
	onDown        func()

	configCh chan tunnelConfig
	readyCh  chan struct{}
	exitCh   chan struct{}
}

func NewManager(binDir, runDir string, onLog func(string), onCaptcha CaptchaFunc) *Manager {
	if onLog == nil {
		onLog = func(string) {}
	}
	return &Manager{
		binDir: binDir, runDir: runDir, onLog: onLog, onCaptcha: onCaptcha,
		routes: map[string]bool{}, turnIPs: map[string]bool{},
		configCh: make(chan tunnelConfig, 1), readyCh: make(chan struct{}, 1),
	}
}

func (m *Manager) SetOnDown(f func()) {
	m.mu.Lock()
	m.onDown = f
	m.mu.Unlock()
}

func (m *Manager) exe(name string) string         { return filepath.Join(m.binDir, name) }
func (m *Manager) log(format string, args ...any) { m.onLog(fmt.Sprintf(format, args...)) }

func normalizeObfsMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "video") {
		return "video"
	}
	return "audio"
}

func normalizeTurnTransport(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "tcp_tls") || strings.EqualFold(strings.TrimSpace(mode), "tcp") {
		return "tcp_tls"
	}
	return "udp"
}

func normalizeWorkers(value int) int {
	if value <= 0 {
		return 18
	}
	if value > 126 {
		value = 126
	}
	value -= value % 9
	if value < 9 {
		return 9
	}
	return value
}

func parseVKLinks(raw string) string {
	var values []string
	for _, line := range strings.Split(raw, "\n") {
		for _, value := range strings.Split(line, ",") {
			if value = strings.TrimSpace(value); value != "" {
				values = append(values, value)
			}
		}
	}
	return strings.Join(values, ",")
}

func resolveHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return host
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if net.ParseIP(ip).To4() != nil {
			return ip
		}
	}
	return ""
}

func (m *Manager) preflight(cfg Config, mode, token, hashes string) error {
	if _, err := os.Stat(m.exe(platformClientName())); err != nil {
		return fmt.Errorf("не найден %s: %w", platformClientName(), err)
	}
	if !isElevated() {
		return fmt.Errorf("CSQTT system VPN требует повышенных прав (Administrator/root)")
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(cfg.Server)); err != nil {
		return fmt.Errorf("адрес сервера должен быть host:port: %w", err)
	}
	if strings.TrimSpace(cfg.Password) == "" {
		return fmt.Errorf("не указан пароль туннеля")
	}
	if mode == VKHashManual && hashes == "" {
		return fmt.Errorf("не указан ни один VK hash/link")
	}
	if mode != VKHashManual && token == "" {
		return fmt.Errorf("не указан VK-токен для автоматического режима")
	}
	if strings.TrimSpace(cfg.DeviceID) == "" {
		return fmt.Errorf("не создан локальный device ID")
	}
	return nil
}

func (m *Manager) Connect(ctx context.Context, cfg Config) error {
	mode := NormalizeVKHashMode(cfg.VKHashMode)
	token := ExtractVKToken(cfg.VKToken)
	hashes := parseVKLinks(cfg.VKLinks)
	if mode != VKHashManual {
		hashes = ""
	}
	if err := m.preflight(cfg, mode, token, hashes); err != nil {
		return err
	}
	if err := os.MkdirAll(m.runDir, 0o700); err != nil {
		return fmt.Errorf("runDir: %w", err)
	}
	started := time.Now()
	m.cleanupStale(ctx)
	m.log("[STARTUP] cleanup: %s", time.Since(started))
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.platformPreflight(); err != nil {
		return err
	}
	m.mu.Lock()
	m.shuttingDown = false
	m.exitCh = make(chan struct{})
	m.configCh = make(chan tunnelConfig, 1)
	m.readyCh = make(chan struct{}, 1)
	m.turnIPs = map[string]bool{}
	m.hashMode = mode
	m.mu.Unlock()

	authMode := "vkcalls"
	redistribute := false
	switch mode {
	case VKHashAutoAPI:
		created, err := m.startVKCalls(ctx, token, cfg.Workers)
		if err != nil {
			return err
		}
		hashes = strings.Join(created, ",")
		redistribute = len(created) < vkCallCountForWorkers(cfg.Workers)
	case VKHashAutoJS:
		authMode = VKHashAutoJS
		m.log("• «Авто ВК»: ядро создаёт звонок через аккаунт VK…")
	}

	args := []string{
		"--peer", strings.TrimSpace(cfg.Server), "--credentials-stdin",
		"--workers", fmt.Sprint(normalizeWorkers(cfg.Workers)),
		"--device-id", strings.TrimSpace(cfg.DeviceID), "--vk-hash-mode", mode,
		"--vk-auth-mode", authMode, "--captcha-mode", "auto",
		"--obfs", normalizeObfsMode(cfg.ObfsMode), "--turn-transport", normalizeTurnTransport(cfg.TurnTransport),
	}
	if redistribute {
		args = append(args, "--allow-hash-redistribution")
	}
	args = append(args, m.platformClientArgs()...)
	// Без контекста: отмена подключения идёт через Disconnect, который сначала
	// просит ядро выйти по STOP (и завершить звонки), а убивает только по таймауту.
	cmd := exec.Command(m.exe(platformClientName()), args...)
	cmd.Dir = m.runDir
	cmd.Env = append(os.Environ(), "CSQTT_EVENTS=1")
	hideConsole(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("старт csqtt-client: %w", err)
	}
	credentials, err := json.Marshal(map[string]string{"password": cfg.Password, "vk": hashes})
	if err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("кодирование credentials: %w", err)
	}
	input := fmt.Sprintf("CSQTT_CREDENTIALS|%s\n", credentials)
	if mode == VKHashAutoJS {
		bootstrap, _ := json.Marshal(map[string]string{"token": token})
		input += "VK_JS_BOOTSTRAP:" + base64.StdEncoding.EncodeToString(bootstrap) + "\n"
	}
	if _, err := io.WriteString(stdin, input); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("передача credentials в csqtt-client: %w", err)
	}
	attachJob(cmd)
	m.mu.Lock()
	m.client, m.clientIn = cmd, stdin
	exitCh := m.exitCh
	m.mu.Unlock()
	m.log("• CSQTT Rust client запущен; жду TUNCONF…")
	go m.readClient(stdout)
	go m.waitClient(cmd, exitCh)

	var assigned tunnelConfig
	select {
	case assigned = <-m.configCh:
		m.log("[STARTUP] first CONFIG: %s", time.Since(started))
	case <-exitCh:
		return fmt.Errorf("csqtt-client завершился до TUNCONF")
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(configWait):
		return fmt.Errorf("сервер не выдал TUNCONF за %s", configWait)
	}
	host, _, _ := net.SplitHostPort(strings.TrimSpace(cfg.Server))
	setupCtx, stopSetup := context.WithCancel(ctx)
	defer stopSetup()
	go func() {
		select {
		case <-exitCh:
			stopSetup()
		case <-setupCtx.Done():
		}
	}()
	if err := m.startSystemRouting(setupCtx, host, cfg.Excludes, assigned); err != nil {
		m.Disconnect()
		return err
	}
	m.log("[STARTUP] routing ready: %s", time.Since(started))
	m.failSafeOnExit(exitCh)
	m.log("✅ CSQTT system VPN активен: %s, DNS %s", assigned.IP, assigned.DNS)
	return nil
}

type eventEnvelope struct {
	Config string `json:"config"`
}

var relayIP = regexp.MustCompile(`\brelay\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3}):`)

func (m *Manager) readClient(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "__CSQTT_EVENT__|") {
			m.handleEvent(line)
			continue
		}
		if match := relayIP.FindStringSubmatch(line); len(match) == 2 {
			m.mu.Lock()
			m.turnIPs[match[1]] = true
			m.mu.Unlock()
			m.excludeHost(match[1])
		}
		if strings.HasPrefix(line, "CAPTCHA_SOLVE|") && m.onCaptcha != nil {
			parts := strings.Split(strings.TrimPrefix(line, "CAPTCHA_SOLVE|"), "|")
			if len(parts) >= 3 {
				m.SendCaptchaResult(m.onCaptcha(parts[0], parts[1], parts[2]))
			}
			continue
		}
		m.log("[client] %s", line)
	}
}

func (m *Manager) handleEvent(line string) {
	parts := strings.SplitN(line, "|", 3)
	if len(parts) != 3 {
		return
	}
	switch parts[1] {
	case "CONFIG":
		var payload eventEnvelope
		if json.Unmarshal([]byte(parts[2]), &payload) == nil {
			if cfg, ok := parseTunnelConfig(payload.Config); ok {
				select {
				case m.configCh <- cfg:
				default:
				}
			}
		}
	case "READY":
		select {
		case m.readyCh <- struct{}{}:
		default:
		}
	case "STATS":
	case "CALL_UNAVAILABLE":
		m.log("⚠ Звонок VK завершён или недоступен — переподключитесь (в режимах «Авто» будут созданы новые звонки)")
	default:
		m.log("[event] %s", parts[1])
	}
}

func parseTunnelConfig(value string) (tunnelConfig, bool) {
	value = strings.TrimPrefix(value, "TUNCONF:")
	parts := strings.SplitN(value, ":", 3)
	if len(parts) < 2 || net.ParseIP(parts[0]).To4() == nil {
		return tunnelConfig{}, false
	}
	for _, candidate := range strings.Split(parts[1], ",") {
		dns := strings.TrimSpace(candidate)
		if net.ParseIP(dns).To4() != nil {
			return tunnelConfig{IP: parts[0], DNS: dns}, true
		}
	}
	return tunnelConfig{}, false
}

func (m *Manager) waitClient(cmd *exec.Cmd, exit chan struct{}) {
	err := cmd.Wait()
	close(exit)
	m.mu.Lock()
	intentional := m.shuttingDown || m.client != cmd
	if m.client == cmd {
		m.client, m.clientIn = nil, nil
	}
	m.mu.Unlock()
	if !intentional {
		m.log("⛔ csqtt-client завершился: %v", err)
	}
}

func (m *Manager) failSafeOnExit(exit <-chan struct{}) {
	go func() {
		<-exit
		m.mu.Lock()
		intentional, callback := m.shuttingDown, m.onDown
		m.mu.Unlock()
		if intentional {
			return
		}
		m.stopSystemRouting()
		_ = m.finishVKCalls(true)
		if callback != nil {
			callback()
		}
	}()
}

func (m *Manager) SendCaptchaResult(token string) {
	if token == "" {
		return
	}
	m.mu.Lock()
	writer := m.clientIn
	m.mu.Unlock()
	if writer != nil {
		_, _ = fmt.Fprintf(writer, "CAPTCHA_RESULT|%s\n", token)
	}
}

func (m *Manager) Disconnect() {
	m.mu.Lock()
	m.shuttingDown = true
	cmd, input, exit, mode := m.client, m.clientIn, m.exitCh, m.hashMode
	m.client, m.clientIn = nil, nil
	m.mu.Unlock()
	m.stopSystemRouting()
	m.stopClient(cmd, input, exit, mode, clientStopWait)
	if err := m.finishVKCalls(true); err != nil {
		m.log("⚠ Часть звонков VK не завершена, повторю при следующем подключении: %v", err)
	}
}

// stopClient просит ядро выйти штатно (в «Авто ВК» — ещё и завершить звонок) и
// убивает процесс, только если он не уложился в wait.
func (m *Manager) stopClient(cmd *exec.Cmd, input io.WriteCloser, exit <-chan struct{}, mode string, wait time.Duration) {
	if input != nil {
		command := "STOP\n"
		if mode == VKHashAutoJS {
			command = "FINISH_VK_CALLS\n" + command
		}
		_, _ = io.WriteString(input, command)
		_ = input.Close()
	}
	if cmd == nil || cmd.Process == nil {
		return
	}
	select {
	case <-exit:
	case <-time.After(wait):
		m.log("⚠ csqtt-client не завершился за %s — останавливаю принудительно", wait)
	}
	_ = cmd.Process.Kill()
}

// RecoverStale снимает то, что мог оставить аварийно завершённый прошлый запуск:
// NRPT-правило (живёт в реестре и переживает перезагрузку), IPv6 leak guard,
// процессы ядра и незавершённые звонки «Авто API».
func (m *Manager) RecoverStale(ctx context.Context) {
	if isElevated() {
		m.cleanupStale(ctx)
	}
	if err := m.finishVKCalls(false); err != nil {
		m.log("⚠ Звонки VK прошлого запуска не завершены: %v", err)
	}
}

func (m *Manager) Running() bool   { m.mu.Lock(); defer m.mu.Unlock(); return m.client != nil }
func (m *Manager) SysActive() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.sysActive }
