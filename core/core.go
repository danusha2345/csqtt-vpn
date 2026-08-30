// Package core manages the desktop CSQTT client process and platform routing.
package core

import (
	"bufio"
	"context"
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

	mu           sync.Mutex
	routeMu      sync.Mutex
	client       *exec.Cmd
	clientIn     io.WriteCloser
	bridge       bridgeController
	routes       map[string]bool
	turnIPs      map[string]bool
	tunUDS       string
	physGW       string
	physIf       string
	sysActive    bool
	dns          *dnsProxy
	shuttingDown bool
	onLog        func(string)
	onCaptcha    CaptchaFunc
	onDown       func()

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

func (m *Manager) preflight(cfg Config, hashes string) error {
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
	if hashes == "" {
		return fmt.Errorf("не указан ни один VK hash/link")
	}
	if strings.TrimSpace(cfg.DeviceID) == "" {
		return fmt.Errorf("не создан локальный device ID")
	}
	return nil
}

func (m *Manager) Connect(ctx context.Context, cfg Config) error {
	hashes := parseVKLinks(cfg.VKLinks)
	if err := m.preflight(cfg, hashes); err != nil {
		return err
	}
	if err := os.MkdirAll(m.runDir, 0o700); err != nil {
		return fmt.Errorf("runDir: %w", err)
	}
	m.cleanupStale()
	if err := m.platformPreflight(); err != nil {
		return err
	}
	m.mu.Lock()
	m.shuttingDown = false
	m.exitCh = make(chan struct{})
	m.configCh = make(chan tunnelConfig, 1)
	m.readyCh = make(chan struct{}, 1)
	m.turnIPs = map[string]bool{}
	m.mu.Unlock()

	args := []string{
		"--peer", strings.TrimSpace(cfg.Server), "--credentials-stdin",
		"--workers", fmt.Sprint(normalizeWorkers(cfg.Workers)),
		"--device-id", strings.TrimSpace(cfg.DeviceID), "--vk-hash-mode", "manual",
		"--vk-auth-mode", "vkcalls", "--captcha-mode", "auto",
		"--obfs", normalizeObfsMode(cfg.ObfsMode), "--turn-transport", normalizeTurnTransport(cfg.TurnTransport),
	}
	args = append(args, m.platformClientArgs()...)
	cmd := exec.CommandContext(ctx, m.exe(platformClientName()), args...)
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
	if _, err := fmt.Fprintf(stdin, "CSQTT_CREDENTIALS|%s\n", credentials); err != nil {
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
	case <-exitCh:
		return fmt.Errorf("csqtt-client завершился до TUNCONF")
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(configWait):
		return fmt.Errorf("сервер не выдал TUNCONF за %s", configWait)
	}
	host, _, _ := net.SplitHostPort(strings.TrimSpace(cfg.Server))
	if err := m.startSystemRouting(ctx, host, cfg.Excludes, assigned); err != nil {
		m.Disconnect()
		return err
	}
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
	cmd, input := m.client, m.clientIn
	m.client, m.clientIn = nil, nil
	m.mu.Unlock()
	m.stopSystemRouting()
	if input != nil {
		_ = input.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func (m *Manager) Running() bool   { m.mu.Lock(); defer m.mu.Unlock(); return m.client != nil }
func (m *Manager) SysActive() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.sysActive }
