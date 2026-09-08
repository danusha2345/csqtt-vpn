//go:build linux

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	linuxTunName = "csqtt0"
	linuxTunMTU  = 1300
)

var linuxBypassCIDRs = []string{
	"87.240.0.0/16", "93.186.224.0/19", "95.142.192.0/20", "95.213.0.0/18",
	"94.100.176.0/20", "217.20.144.0/20", "217.69.128.0/20", "185.6.244.0/22",
}

type linuxTun struct{ file *os.File }

func (t *linuxTun) Close() error { return t.file.Close() }

func platformClientName() string { return "csqtt-client" }

func (m *Manager) platformPreflight() error { return nil }

func (m *Manager) platformClientArgs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunUDS = fmt.Sprintf("csqtt-tun-%d-%d", os.Getpid(), time.Now().UnixNano())
	return []string{"--tun-uds", m.tunUDS}
}

func runIP(args ...string) (string, error) {
	out, err := exec.Command("ip", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

type linuxDefaultRoute struct {
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

func linuxPhysicalDefault() (linuxDefaultRoute, error) {
	out, err := runIP("-j", "-4", "route", "show", "default")
	if err != nil {
		return linuxDefaultRoute{}, fmt.Errorf("ip route show default: %w: %s", err, out)
	}
	return parseLinuxDefaultRoute([]byte(out))
}

func parseLinuxDefaultRoute(data []byte) (linuxDefaultRoute, error) {
	var routes []linuxDefaultRoute
	if err := json.Unmarshal(data, &routes); err != nil || len(routes) == 0 || routes[0].Dev == "" {
		return linuxDefaultRoute{}, fmt.Errorf("не разобран физический default route: %q", string(data))
	}
	return routes[0], nil
}

func createLinuxTUN() (*os.File, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	request, err := unix.NewIfreq(linuxTunName)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, request); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("TUNSETIFF %s: %w", linuxTunName, err)
	}
	return file, nil
}

func sendLinuxTUN(ctx context.Context, name string, file *os.File) error {
	address := &net.UnixAddr{Name: "\x00" + name, Net: "unix"}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialUnix("unix", nil, address)
		if err == nil {
			defer conn.Close()
			_, _, err = conn.WriteMsgUnix([]byte{0}, unix.UnixRights(int(file.Fd())), nil)
			if err != nil {
				return fmt.Errorf("SCM_RIGHTS: %w", err)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("тайм-аут подключения к abstract UDS %q", name)
}

func linuxPhysicalDNS(device string) string {
	out, err := exec.Command("resolvectl", "dns", device).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, field := range strings.Fields(string(out)) {
		value := strings.Trim(field, "[]")
		if ip := net.ParseIP(strings.TrimSuffix(value, ":53")); ip != nil && ip.To4() != nil {
			return ip.String() + ":53"
		}
	}
	return ""
}

func (m *Manager) addLinuxBypass(cidr string) error {
	m.mu.Lock()
	gw, device := m.physGW, m.physIf
	if m.routes[cidr] {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	args := []string{"-4", "route", "add", cidr}
	if gw != "" {
		args = append(args, "via", gw)
	}
	args = append(args, "dev", device)
	out, err := runIP(args...)
	if err != nil {
		if strings.Contains(strings.ToLower(out), "file exists") {
			return nil
		}
		return fmt.Errorf("ip route add %s: %w: %s", cidr, err, out)
	}
	m.mu.Lock()
	m.routes[cidr] = true
	m.mu.Unlock()
	return nil
}

func (m *Manager) startSystemRouting(ctx context.Context, serverHost, excludesCSV string, assigned tunnelConfig) error {
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("для Linux-клиента нужен iproute2: %w", err)
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return fmt.Errorf("для защищённой настройки DNS нужен systemd-resolved/resolvectl: %w", err)
	}
	physical, err := linuxPhysicalDefault()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.physGW, m.physIf, m.routes = physical.Gateway, physical.Dev, map[string]bool{}
	tunUDS := m.tunUDS
	m.mu.Unlock()
	serverIP := resolveHost(serverHost)
	if serverIP == "" {
		return fmt.Errorf("не разрешён адрес сервера %s", serverHost)
	}
	if err := m.addLinuxBypass(serverIP + "/32"); err != nil {
		return fmt.Errorf("bypass-route сервера: %w", err)
	}
	for _, cidr := range linuxBypassCIDRs {
		if err := m.addLinuxBypass(cidr); err != nil {
			return fmt.Errorf("bypass-route %s: %w", cidr, err)
		}
	}
	m.mu.Lock()
	relayIPs := make([]string, 0, len(m.turnIPs))
	for ip := range m.turnIPs {
		relayIPs = append(relayIPs, ip)
	}
	m.mu.Unlock()
	for _, ip := range relayIPs {
		if err := m.addLinuxBypass(ip + "/32"); err != nil {
			return fmt.Errorf("bypass-route TURN relay %s: %w", ip, err)
		}
	}

	var domains []string
	for _, raw := range strings.FieldsFunc(excludesCSV, func(r rune) bool { return r == ',' || r == '\n' }) {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			if _, _, parseErr := net.ParseCIDR(value); parseErr == nil {
				if err := m.addLinuxBypass(value); err != nil {
					return err
				}
			}
		} else if net.ParseIP(value) != nil {
			if err := m.addLinuxBypass(value + "/32"); err != nil {
				return err
			}
		} else {
			domains = append(domains, expandBypassDomain(value)...)
			for _, cidr := range providerBypassCIDRs(value) {
				if err := m.addLinuxBypass(cidr); err != nil {
					return err
				}
			}
		}
	}

	file, err := createLinuxTUN()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.bridge = &linuxTun{file: file}
	m.mu.Unlock()
	if out, err := runIP("link", "set", "dev", linuxTunName, "mtu", strconv.Itoa(linuxTunMTU), "up"); err != nil {
		return fmt.Errorf("ip link set %s: %w: %s", linuxTunName, err, out)
	}
	if out, err := runIP("addr", "replace", assigned.IP+"/32", "dev", linuxTunName); err != nil {
		return fmt.Errorf("ip addr: %w: %s", err, out)
	}
	if err := sendLinuxTUN(ctx, tunUDS, file); err != nil {
		return err
	}
	bypassDNS := linuxPhysicalDNS(physical.Dev)
	if err := m.startDNS(assigned.IP+":53", domains, bypassDNS, assigned.DNS); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"dns", linuxTunName, assigned.IP},
		{"domain", linuxTunName, "~."},
		{"default-route", linuxTunName, "yes"},
	} {
		if out, err := exec.Command("resolvectl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("resolvectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if out, err := runIP("-4", "route", "replace", prefix, "dev", linuxTunName, "metric", "1"); err != nil {
			return fmt.Errorf("split route %s: %w: %s", prefix, err, out)
		}
	}
	for _, prefix := range []string{"::/1", "8000::/1"} {
		if out, err := runIP("-6", "route", "replace", "unreachable", prefix, "metric", "1"); err != nil {
			return fmt.Errorf("IPv6 leak guard %s: %w: %s", prefix, err, out)
		}
	}
	m.mu.Lock()
	m.sysActive = true
	m.mu.Unlock()
	return nil
}

func (m *Manager) excludeHost(ip string) {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
		if err := m.addLinuxBypass(parsed.String() + "/32"); err == nil {
			m.log("  + bypass %s", parsed.String())
		}
	}
}

func (m *Manager) cleanupStale() {
	_, _ = exec.Command("resolvectl", "revert", linuxTunName).CombinedOutput()
	_, _ = runIP("link", "delete", linuxTunName)
	for _, prefix := range []string{"::/1", "8000::/1"} {
		_, _ = runIP("-6", "route", "delete", "unreachable", prefix, "metric", "1")
	}
}

func (m *Manager) stopSystemRouting() {
	m.stopDNS()
	_, _ = exec.Command("resolvectl", "revert", linuxTunName).CombinedOutput()
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_, _ = runIP("-4", "route", "delete", prefix, "dev", linuxTunName)
	}
	for _, prefix := range []string{"::/1", "8000::/1"} {
		_, _ = runIP("-6", "route", "delete", "unreachable", prefix, "metric", "1")
	}
	m.mu.Lock()
	bridge, routes, gw, device := m.bridge, m.routes, m.physGW, m.physIf
	m.bridge, m.routes, m.sysActive = nil, map[string]bool{}, false
	m.physGW, m.physIf, m.tunUDS = "", "", ""
	m.mu.Unlock()
	if bridge != nil {
		_ = bridge.Close()
	}
	_, _ = runIP("link", "delete", linuxTunName)
	for cidr := range routes {
		args := []string{"-4", "route", "delete", cidr}
		if gw != "" {
			args = append(args, "via", gw)
		}
		if device != "" {
			args = append(args, "dev", device)
		}
		_, _ = runIP(args...)
	}
}

func readLinuxCounter(name string) (int64, error) {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", linuxTunName, "statistics", name))
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func (m *Manager) Stats() (down, up int64, ok bool) {
	m.mu.Lock()
	active := m.sysActive
	m.mu.Unlock()
	if !active {
		return 0, 0, false
	}
	down, errDown := readLinuxCounter("rx_bytes")
	up, errUp := readLinuxCounter("tx_bytes")
	return down, up, errors.Join(errDown, errUp) == nil
}
