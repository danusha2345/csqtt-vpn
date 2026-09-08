//go:build windows

package core

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	tunName         = "CSQTT"
	tunMTU          = 1300
	nrptDisplayName = "CSQTT DNS"
	nrptComment     = "CSQTT_MANAGED"
	commandTimeout  = 15 * time.Second
)

var bypassCIDRs = []string{
	"87.240.0.0/16", "93.186.224.0/19", "95.142.192.0/20", "95.213.0.0/18",
	"94.100.176.0/20", "217.20.144.0/20", "217.69.128.0/20", "185.6.244.0/22",
}

func platformClientName() string { return "csqtt-client.exe" }

func (m *Manager) platformClientArgs() []string { return []string{"--listen", innerListen} }

func (m *Manager) platformPreflight() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("путь CSQTT-VPN.exe: %w", err)
	}
	dll := filepath.Join(filepath.Dir(executable), "wintun.dll")
	if info, statErr := os.Stat(dll); statErr != nil || info.IsDir() {
		return fmt.Errorf("не найден wintun.dll рядом с CSQTT-VPN.exe: %s", dll)
	}
	if err := validateWintunDLL(dll); err != nil {
		return err
	}
	address, err := net.ResolveUDPAddr("udp", innerListen)
	if err != nil {
		return err
	}
	probe, err := net.ListenUDP("udp", address)
	if err != nil {
		return fmt.Errorf("локальный UDP dispatcher %s занят: %w", innerListen, err)
	}
	return probe.Close()
}

func validateWintunDLL(path string) error {
	handle, err := windows.LoadLibrary(path)
	if err != nil {
		return fmt.Errorf("wintun.dll не загружается: %w", err)
	}
	defer windows.FreeLibrary(handle)
	if _, err := windows.GetProcAddress(handle, "WintunCreateAdapter"); err != nil {
		return fmt.Errorf("wintun.dll несовместим: нет WintunCreateAdapter: %w", err)
	}
	return nil
}

type packetBridge struct {
	device  tun.Device
	conn    *net.UDPConn
	closing atomic.Bool
	onError func(error)
	wg      sync.WaitGroup
}

func newPacketBridge(remote string, onError func(error)) (*packetBridge, error) {
	endpoint, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, endpoint)
	if err != nil {
		return nil, err
	}
	device, err := tun.CreateTUN(tunName, tunMTU)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	bridge := &packetBridge{device: device, conn: conn, onError: onError}
	bridge.wg.Add(2)
	go bridge.tunToUDP()
	go bridge.udpToTUN()
	return bridge, nil
}

func (b *packetBridge) fail(err error) {
	if err != nil && !b.closing.Load() && b.onError != nil {
		go b.onError(err)
	}
}

func (b *packetBridge) tunToUDP() {
	defer b.wg.Done()
	batch := b.device.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	for !b.closing.Load() {
		n, err := b.device.Read(bufs, sizes, 0)
		if err != nil {
			b.fail(err)
			return
		}
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 || sizes[i] > len(bufs[i]) {
				continue
			}
			if _, err := b.conn.Write(bufs[i][:sizes[i]]); err != nil {
				b.fail(err)
				return
			}
		}
	}
}

func (b *packetBridge) udpToTUN() {
	defer b.wg.Done()
	buf := make([]byte, 65535)
	for !b.closing.Load() {
		n, err := b.conn.Read(buf)
		if err != nil {
			b.fail(err)
			return
		}
		if n > 0 {
			packet := [][]byte{buf[:n]}
			if _, err := b.device.Write(packet, 0); err != nil {
				b.fail(err)
				return
			}
		}
	}
}

func (b *packetBridge) Close() error {
	if b.closing.Swap(true) {
		return nil
	}
	_ = b.conn.Close()
	err := b.device.Close()
	b.wg.Wait()
	return err
}

func runHidden(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	decoded := decodeCommandOutput(out)
	if ctx.Err() == context.DeadlineExceeded {
		return decoded, fmt.Errorf("%s: timeout после %s", name, commandTimeout)
	}
	return decoded, err
}

type packetBridgeResult struct {
	bridge *packetBridge
	err    error
}

func createPacketBridge(
	ctx context.Context,
	remote string,
	timeout time.Duration,
	onError func(error),
) (*packetBridge, error) {
	result := make(chan packetBridgeResult, 1)
	go func() {
		bridge, err := newPacketBridge(remote, onError)
		result <- packetBridgeResult{bridge: bridge, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case completed := <-result:
		return completed.bridge, completed.err
	case <-ctx.Done():
		go closeLatePacketBridge(result)
		return nil, ctx.Err()
	case <-timer.C:
		go closeLatePacketBridge(result)
		return nil, fmt.Errorf("создание адаптера Wintun не завершилось за %s", timeout)
	}
}

func closeLatePacketBridge(result <-chan packetBridgeResult) {
	completed := <-result
	if completed.bridge != nil {
		_ = completed.bridge.Close()
	}
}

func installManagedNRPT(nameServer string) error {
	ps := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -eq '%s' -or $_.Comment -eq '%s' } |
  ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop }
$rule = Add-DnsClientNrptRule -Namespace '.' -NameServers '%s' -DisplayName '%s' -Comment '%s' -PassThru -ErrorAction Stop
if ($null -eq $rule -or $rule.NameServers -notcontains '%s') { throw 'NRPT verification failed' }
Clear-DnsClientCache -ErrorAction SilentlyContinue
`, nrptDisplayName, nrptComment, nameServer, nrptDisplayName, nrptComment, nameServer)
	out, err := runHidden("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	if err != nil {
		return fmt.Errorf("NRPT %s: %w: %s", nameServer, err, strings.TrimSpace(out))
	}
	return nil
}

func removeManagedNRPT() {
	ps := fmt.Sprintf(`Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq '%s' -or $_.Comment -eq '%s' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }; Clear-DnsClientCache -ErrorAction SilentlyContinue`, nrptDisplayName, nrptComment)
	_, _ = runHidden("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
}

func physDefault() (gw, ifIndex string, err error) {
	ps := `$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric | Select-Object -First 1; "$($r.NextHop) $($r.InterfaceIndex)"`
	out, e := runHidden("powershell", "-NoProfile", "-Command", ps)
	if e != nil {
		return "", "", fmt.Errorf("Get-NetRoute: %v: %s", e, out)
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 {
		return "", "", fmt.Errorf("не разобран физический default route: %q", out)
	}
	return fields[0], fields[1], nil
}

func physDNS(ifIndex string) string {
	ps := fmt.Sprintf(`(Get-DnsClientServerAddress -InterfaceIndex %s -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Select-Object -First 1`, ifIndex)
	out, _ := runHidden("powershell", "-NoProfile", "-Command", ps)
	return strings.TrimSpace(out)
}

func cidrToRoute(cidr string) (string, string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return "", "", fmt.Errorf("invalid IPv4 CIDR %q", cidr)
	}
	mask := net.IP(network.Mask).String()
	return network.IP.String(), mask, nil
}

func (m *Manager) setBypassRoute(network, mask, gw string) error {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	key := network + " mask " + mask
	m.mu.Lock()
	if m.shuttingDown || m.routes[key] {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	out, err := runHidden("route", "add", network, "mask", mask, gw, "metric", "1")
	if err != nil {
		if routeAlreadyExists(out) {
			return nil
		}
		return fmt.Errorf("route add: %w: %s", err, strings.TrimSpace(out))
	}
	m.mu.Lock()
	m.routes[key] = true
	m.mu.Unlock()
	return nil
}

func (m *Manager) cleanupStale() {
	target := strings.ReplaceAll(m.exe(platformClientName()), "'", "''")
	ps := fmt.Sprintf(`$target = '%s'; Get-CimInstance Win32_Process -Filter "Name='csqtt-client.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -eq $target } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`, target)
	_, _ = runHidden("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	removeManagedNRPT()
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		ps := fmt.Sprintf(`Get-NetRoute -DestinationPrefix '%s' -InterfaceAlias '%s' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue`, prefix, tunName)
		_, _ = runHidden("powershell", "-NoProfile", "-Command", ps)
	}
}

func (m *Manager) startSystemRouting(ctx context.Context, serverHost, excludesCSV string, assigned tunnelConfig) error {
	m.log("• Определяю физический маршрут Windows…")
	gw, ifIndex, err := physDefault()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.physGW, m.physIf, m.routes = gw, ifIndex, map[string]bool{}
	m.mu.Unlock()
	m.log("✓ Физический шлюз определён")
	serverIP := resolveHost(serverHost)
	if serverIP == "" {
		return fmt.Errorf("не разрешён адрес сервера %s", serverHost)
	}
	if err := m.setBypassRoute(serverIP, "255.255.255.255", gw); err != nil {
		return fmt.Errorf("bypass-route сервера %s: %w", serverIP, err)
	}
	m.log("• Добавляю bypass-маршруты сервера и TURN…")
	for _, cidr := range bypassCIDRs {
		network, mask, parseErr := cidrToRoute(cidr)
		if parseErr == nil {
			if err := m.setBypassRoute(network, mask, gw); err != nil {
				return fmt.Errorf("bypass-route %s: %w", cidr, err)
			}
		}
	}
	m.mu.Lock()
	turn := make([]string, 0, len(m.turnIPs))
	for ip := range m.turnIPs {
		turn = append(turn, ip)
	}
	m.mu.Unlock()
	for _, ip := range turn {
		if err := m.addBypassHost(ip); err != nil {
			return fmt.Errorf("bypass-route TURN relay %s: %w", ip, err)
		}
	}
	m.log("✓ Bypass-маршруты добавлены")

	var domains []string
	for _, raw := range strings.FieldsFunc(excludesCSV, func(r rune) bool { return r == ',' || r == '\n' }) {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			if network, mask, e := cidrToRoute(value); e == nil {
				if err := m.setBypassRoute(network, mask, gw); err != nil {
					return fmt.Errorf("bypass-route %s: %w", value, err)
				}
			}
		} else if net.ParseIP(value) != nil {
			if err := m.addBypassHost(value); err != nil {
				return fmt.Errorf("bypass-route %s: %w", value, err)
			}
		} else {
			domains = append(domains, expandBypassDomain(value)...)
		}
	}

	m.log("• Создаю адаптер Wintun %s…", tunName)
	bridge, err := createPacketBridge(
		ctx,
		innerListen,
		15*time.Second,
		func(cause error) { m.bridgeFailed(cause) },
	)
	if err != nil {
		return fmt.Errorf("Wintun raw bridge: %w", err)
	}
	m.mu.Lock()
	m.bridge = bridge
	m.mu.Unlock()
	if err := m.waitAdapter(ctx, tunName, 12*time.Second); err != nil {
		return err
	}
	m.log("✓ Адаптер Wintun %s создан", tunName)
	idxOut, _ := runHidden("powershell", "-NoProfile", "-Command", fmt.Sprintf("(Get-NetAdapter -Name '%s').ifIndex", tunName))
	tunIndex := strings.TrimSpace(idxOut)
	if tunIndex == "" {
		return fmt.Errorf("не определён ifIndex адаптера %s", tunName)
	}
	if out, e := runHidden("netsh", "interface", "ipv4", "set", "address", "name="+tunName, "static", assigned.IP, "255.255.255.0"); e != nil {
		return fmt.Errorf("IP адаптера: %v: %s", e, out)
	}
	_, _ = runHidden("netsh", "interface", "ipv4", "set", "interface", tunName, "metric=1")
	time.Sleep(500 * time.Millisecond)

	// Активируем split routes до DNS-proxy/NRPT. Поэтому его публичный UDP
	// upstream уже идёт внутри CSQTT, а не напрямую через ТСПУ клиента.
	m.routeMu.Lock()
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		ps := fmt.Sprintf(`New-NetRoute -DestinationPrefix '%s' -InterfaceIndex %s -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null`, prefix, tunIndex)
		if out, e := runHidden("powershell", "-NoProfile", "-NonInteractive", "-Command", ps); e != nil {
			m.routeMu.Unlock()
			return fmt.Errorf("split route %s: %v: %s", prefix, e, out)
		}
	}
	if err := installIPv6Guard(func(prefix string) error {
		ps := fmt.Sprintf(`$ErrorActionPreference = 'Stop'; New-NetRoute -DestinationPrefix '%s' -InterfaceIndex %s -NextHop '::' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null`, prefix, tunIndex)
		if out, err := runHidden("powershell", "-NoProfile", "-NonInteractive", "-Command", ps); err != nil {
			return fmt.Errorf("IPv6 leak guard %s: %w: %s", prefix, err, out)
		}
		return nil
	}); err != nil {
		m.routeMu.Unlock()
		return err
	}
	m.routeMu.Unlock()
	m.log("✓ Системные маршруты направлены в CSQTT")

	bypassUpstream := physDNS(ifIndex)
	if bypassUpstream != "" {
		bypassUpstream += ":53"
	}
	if err := m.startDNS(assigned.IP+":53", domains, bypassUpstream, assigned.DNS); err != nil {
		return err
	}
	if out, e := runHidden("netsh", "interface", "ipv4", "set", "dnsservers", "name="+tunName, "static", assigned.IP, "primary"); e != nil {
		return fmt.Errorf("DNS адаптера: %v: %s", e, out)
	}
	if err := installManagedNRPT(assigned.IP); err != nil {
		return err
	}
	m.mu.Lock()
	m.sysActive = true
	m.mu.Unlock()
	return nil
}

func (m *Manager) bridgeFailed(err error) {
	m.mu.Lock()
	intentional, callback, cmd := m.shuttingDown, m.onDown, m.client
	if !intentional {
		m.shuttingDown = true
	}
	m.mu.Unlock()
	if intentional {
		return
	}
	m.log("⛔ Wintun bridge завершился: %v", err)
	m.stopSystemRouting()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if callback != nil {
		callback()
	}
}

func (m *Manager) waitAdapter(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := runHidden("powershell", "-NoProfile", "-Command", fmt.Sprintf("if (Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue) { 'ok' }", name))
		if strings.Contains(out, "ok") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return fmt.Errorf("адаптер %s не появился", name)
}

func (m *Manager) excludeHost(ip string) {
	if err := m.addBypassHost(ip); err != nil {
		m.log("⚠ bypass %s не добавлен: %v", ip, err)
	}
}

func (m *Manager) addBypassHost(ip string) error {
	m.mu.Lock()
	gw := m.physGW
	already := m.routes[ip+" mask 255.255.255.255"]
	m.mu.Unlock()
	if gw == "" || ip == "" || already {
		return nil
	}
	if err := m.setBypassRoute(ip, "255.255.255.255", gw); err != nil {
		return err
	}
	m.log("  + bypass %s", ip)
	return nil
}

func (m *Manager) stopSystemRouting() {
	removeManagedNRPT()
	m.stopDNS()
	m.routeMu.Lock()
	m.mu.Lock()
	for route := range m.routes {
		m.cleanupRoutes = append(m.cleanupRoutes, route)
	}
	if m.physIf != "" {
		m.cleanupPhysIf = m.physIf
	}
	bridge, routes := m.bridge, m.routes
	m.bridge, m.routes, m.sysActive = nil, map[string]bool{}, false
	m.physGW, m.physIf = "", ""
	m.mu.Unlock()
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		ps := fmt.Sprintf(`Get-NetRoute -DestinationPrefix '%s' -InterfaceAlias '%s' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue`, prefix, tunName)
		_, _ = runHidden("powershell", "-NoProfile", "-Command", ps)
	}
	for route := range routes {
		parts := strings.SplitN(route, " mask ", 2)
		if len(parts) == 2 {
			_, _ = runHidden("route", "delete", parts[0], "mask", parts[1])
		}
	}
	m.routeMu.Unlock()
	if bridge != nil {
		_ = bridge.Close()
	}
}

func (m *Manager) Stats() (down, up int64, ok bool) {
	m.mu.Lock()
	active := m.sysActive
	m.mu.Unlock()
	if !active {
		return 0, 0, false
	}
	out, err := runHidden("powershell", "-NoProfile", "-Command", fmt.Sprintf(`$s = Get-NetAdapterStatistics -Name '%s' -ErrorAction SilentlyContinue; "$($s.ReceivedBytes) $($s.SentBytes)"`, tunName))
	if err != nil {
		return 0, 0, false
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 {
		return 0, 0, false
	}
	down, err1 := strconv.ParseInt(fields[0], 10, 64)
	up, err2 := strconv.ParseInt(fields[1], 10, 64)
	return down, up, err1 == nil && err2 == nil
}
