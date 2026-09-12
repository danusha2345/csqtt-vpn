//go:build windows

package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
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
	traffic trafficCounters
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
			b.traffic.up.Add(int64(sizes[i]))
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
			written, err := b.device.Write(packet, 0)
			if err != nil {
				b.fail(err)
				return
			}
			if written == 1 {
				b.traffic.down.Add(int64(n))
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
	return runHiddenContext(context.Background(), name, args...)
}

func runHiddenContext(parent context.Context, name string, args ...string) (string, error) {
	return runCommandContext(parent, commandTimeout, name, args...)
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

func installManagedNRPT(ctx context.Context, nameServer string) error {
	ps := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -eq '%s' -or $_.Comment -eq '%s' } |
  ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction Stop }
$rule = Add-DnsClientNrptRule -Namespace '.' -NameServers '%s' -DisplayName '%s' -Comment '%s' -PassThru -ErrorAction Stop
if ($null -eq $rule -or $rule.NameServers -notcontains '%s') { throw 'NRPT verification failed' }
Clear-DnsClientCache -ErrorAction SilentlyContinue
`, nrptDisplayName, nrptComment, nameServer, nrptDisplayName, nrptComment, nameServer)
	out, err := runHiddenContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	if err != nil {
		return fmt.Errorf("NRPT %s: %w: %s", nameServer, err, strings.TrimSpace(out))
	}
	return nil
}

func cidrToRoute(cidr string) (string, string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return "", "", fmt.Errorf("invalid IPv4 CIDR %q", cidr)
	}
	mask := net.IP(network.Mask).String()
	return network.IP.String(), mask, nil
}

func (m *Manager) setBypassRoute(ctx context.Context, network, mask, gw string) error {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	key := network + " mask " + mask
	m.mu.Lock()
	if m.shuttingDown || m.routes[key] {
		m.mu.Unlock()
		return nil
	}
	index := m.physIf
	m.mu.Unlock()
	prefix, err := nativeRoutePrefix(network, mask)
	if err != nil {
		return err
	}
	gateway, err := netip.ParseAddr(gw)
	if err != nil {
		return err
	}
	created, err := nativeAddRoute(ctx, index, prefix, gateway)
	if created {
		m.mu.Lock()
		m.routes[key] = true
		m.mu.Unlock()
	}
	if err != nil {
		return fmt.Errorf("route add: %w", err)
	}
	return nil
}

func (m *Manager) cleanupStale(ctx context.Context) {
	_, _ = runHiddenContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		windowsCleanupScript(m.exe(platformClientName()), tunName, nrptDisplayName, nrptComment))
}

func (m *Manager) startSystemRouting(ctx context.Context, serverHost, excludesCSV string, assigned tunnelConfig) error {
	m.log("• Определяю физический маршрут Windows…")
	gw, ifIndex, err := physDefault(ctx)
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
	if err := m.setBypassRoute(ctx, serverIP, "255.255.255.255", gw); err != nil {
		return fmt.Errorf("bypass-route сервера %s: %w", serverIP, err)
	}
	m.log("• Добавляю bypass-маршруты сервера и TURN…")
	for _, cidr := range bypassCIDRs {
		network, mask, parseErr := cidrToRoute(cidr)
		if parseErr == nil {
			if err := m.setBypassRoute(ctx, network, mask, gw); err != nil {
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
		if err := m.addBypassHost(ctx, ip); err != nil {
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
				if err := m.setBypassRoute(ctx, network, mask, gw); err != nil {
					return fmt.Errorf("bypass-route %s: %w", value, err)
				}
			}
		} else if net.ParseIP(value) != nil {
			if err := m.addBypassHost(ctx, value); err != nil {
				return fmt.Errorf("bypass-route %s: %w", value, err)
			}
		} else {
			domains = append(domains, expandBypassDomain(value)...)
			for _, cidr := range providerBypassCIDRs(value) {
				if network, mask, e := cidrToRoute(cidr); e == nil {
					if err := m.setBypassRoute(ctx, network, mask, gw); err != nil {
						return fmt.Errorf("bypass-route %s: %w", cidr, err)
					}
				}
			}
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
	tunIndex, err := m.waitAdapter(ctx, tunName, 12*time.Second)
	if err != nil {
		return err
	}
	m.log("✓ Адаптер Wintun %s создан", tunName)
	if out, e := runHiddenContext(ctx, "netsh", "interface", "ipv4", "set", "address", "name="+tunName, "static", assigned.IP, "255.255.255.0"); e != nil {
		return fmt.Errorf("IP адаптера: %v: %s", e, out)
	}
	_, _ = runHiddenContext(ctx, "netsh", "interface", "ipv4", "set", "interface", tunName, "metric=1")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(500 * time.Millisecond):
	}

	// Активируем split routes до DNS-proxy/NRPT. Поэтому его публичный UDP
	// upstream уже идёт внутри CSQTT, а не напрямую через ТСПУ клиента.
	m.routeMu.Lock()
	script, err := windowsSplitScript(tunIndex)
	if err != nil {
		m.routeMu.Unlock()
		return err
	}
	if out, err := runHiddenContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script); err != nil {
		m.routeMu.Unlock()
		return fmt.Errorf("split routes / IPv6 guard: %w: %s", err, out)
	}
	m.routeMu.Unlock()
	m.log("✓ Системные маршруты направлены в CSQTT")

	bypassUpstream := physDNS(ctx, ifIndex)
	if bypassUpstream != "" {
		bypassUpstream += ":53"
	}
	if err := m.startDNS(assigned.IP+":53", domains, bypassUpstream, assigned.DNS); err != nil {
		return err
	}
	if out, e := runHiddenContext(ctx, "netsh", "interface", "ipv4", "set", "dnsservers", "name="+tunName, "static", assigned.IP, "primary"); e != nil {
		return fmt.Errorf("DNS адаптера: %v: %s", e, out)
	}
	if err := installManagedNRPT(ctx, assigned.IP); err != nil {
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

func (m *Manager) waitAdapter(ctx context.Context, name string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		iface, err := net.InterfaceByName(name)
		if err == nil && iface.Index > 0 {
			return strconv.Itoa(iface.Index), nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("адаптер %s: %w", name, ctx.Err())
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func (m *Manager) excludeHost(ip string) {
	if err := m.addBypassHost(context.Background(), ip); err != nil {
		m.log("⚠ bypass %s не добавлен: %v", ip, err)
	}
}

func (m *Manager) addBypassHost(ctx context.Context, ip string) error {
	m.mu.Lock()
	gw := m.physGW
	already := m.routes[ip+" mask 255.255.255.255"]
	m.mu.Unlock()
	if gw == "" || ip == "" || already {
		return nil
	}
	if err := m.setBypassRoute(ctx, ip, "255.255.255.255", gw); err != nil {
		return err
	}
	m.log("  + bypass %s", ip)
	return nil
}

func (m *Manager) stopSystemRouting() {
	if out, err := runHidden("powershell", "-NoProfile", "-NonInteractive", "-Command", windowsCleanupScript("", tunName, nrptDisplayName, nrptComment)); err != nil {
		m.log("⚠ Очистка NRPT/маршрутов не подтверждена (%v): %s — будет повторена при следующем запуске", err, strings.TrimSpace(out))
	}
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
	physIndex, gateway := m.physIf, m.physGW
	m.bridge, m.routes, m.sysActive = nil, map[string]bool{}, false
	m.physGW, m.physIf = "", ""
	m.mu.Unlock()
	for route := range routes {
		parts := strings.SplitN(route, " mask ", 2)
		if len(parts) == 2 {
			prefix, e := nativeRoutePrefix(parts[0], parts[1])
			luid, le := nativeLUID(physIndex)
			hop, he := netip.ParseAddr(gateway)
			if e == nil && le == nil && he == nil {
				_ = luid.DeleteRoute(prefix, hop)
			}
		}
	}
	m.routeMu.Unlock()
	if bridge != nil {
		_ = bridge.Close()
	}
}

func (m *Manager) Stats() (down, up int64, ok bool) {
	m.mu.Lock()
	bridge, isBridge := m.bridge.(*packetBridge)
	active := m.sysActive
	m.mu.Unlock()
	if !active || !isBridge || bridge == nil {
		return 0, 0, false
	}
	down, up = bridge.traffic.snapshot()
	return down, up, true
}
