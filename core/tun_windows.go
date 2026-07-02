//go:build windows

package core

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Параметры виртуального TUN-адаптера (Wintun).
const (
	tunName = "wdtt"
	tunAddr = "10.7.0.2"
	tunMask = "255.255.255.0"
	tunGW   = "10.7.0.1" // виртуальный шлюз в подсети TUN (tun2socks отвечает на него)
	tunDNS  = "1.1.1.1"
)

// bypassCIDRs — подсети VK/Mail.ru/OK и Yandex-DNS, к которым ходит wdtt-client.
// Их трафик ДОЛЖЕН идти мимо TUN (через физический шлюз), иначе петля.
var bypassCIDRs = []string{
	"87.240.0.0/16",   // VK
	"93.186.224.0/19", // VK
	"95.142.192.0/20", // VK
	"95.213.0.0/18",   // Mail.ru
	"94.100.176.0/20", // Mail.ru / OK
	"217.20.144.0/20", // Mail.ru
	"217.69.128.0/20", // Mail.ru
	"185.6.244.0/22",  // VK
	"77.88.8.0/24",    // Yandex DNS (резолвер wdtt-client: 77.88.8.8/77.88.8.1)
}

// cleanupStale убирает осиротевшие остатки прошлой сессии (процессы и
// split-default маршруты), чтобы новый запуск был чистым.
func (m *Manager) cleanupStale() {
	for _, p := range []string{"tun2socks.exe", "wireproxy.exe", "wdtt-client.exe"} {
		_, _ = runHidden("taskkill", "/F", "/IM", p)
	}
	_, _ = runHidden("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_, _ = runHidden("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
	// страховка: вернуть IPv6 на всех адаптерах (если прошлая сессия крашнула с
	// отключённым IPv6)
	_, _ = runHidden("powershell", "-NoProfile", "-Command",
		"Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue")
}

func runHidden(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// physDefault возвращает шлюз и ifIndex текущего (физического) дефолтного маршрута.
func physDefault() (gw, ifIndex string, err error) {
	ps := `$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ` +
		`Sort-Object RouteMetric | Select-Object -First 1; "$($r.NextHop) $($r.InterfaceIndex)"`
	out, e := runHidden("powershell", "-NoProfile", "-Command", ps)
	if e != nil {
		return "", "", fmt.Errorf("Get-NetRoute: %v: %s", e, out)
	}
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) < 2 || f[0] == "" {
		return "", "", fmt.Errorf("не разобрал дефолтный маршрут: %q", out)
	}
	return f[0], f[1], nil
}

// physDNS возвращает первый IPv4 DNS-сервер физического интерфейса (провайдерский
// резолвер). Пусто, если определить не удалось — тогда обход резолвится через
// dnsBypassFallback.
func physDNS(ifIndex string) string {
	ps := fmt.Sprintf(
		`(Get-DnsClientServerAddress -InterfaceIndex %s -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses`,
		ifIndex)
	out, err := runHidden("powershell", "-NoProfile", "-Command", ps)
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(out) {
		f = strings.TrimSpace(f)
		if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
			return f
		}
	}
	return ""
}

// cidrToRoute разбивает CIDR на сеть и маску в формате route.exe.
func cidrToRoute(cidr string) (network, mask string, err error) {
	_, ipnet, e := net.ParseCIDR(cidr)
	if e != nil {
		return "", "", e
	}
	m := ipnet.Mask
	if len(m) != 4 {
		return "", "", fmt.Errorf("только IPv4: %s", cidr)
	}
	return ipnet.IP.String(), fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3]), nil
}

// startSystemRouting поднимает системный VPN: исключения мимо TUN + tun2socks +
// split-default через TUN. serverHost — host из -peer (IP или домен).
func (m *Manager) startSystemRouting(ctx context.Context, serverHost, excludesCSV string) error {
	gw, ifIndex, err := physDefault()
	if err != nil {
		return fmt.Errorf("физический шлюз: %w", err)
	}
	m.log("• Физический шлюз: %s (if %s)", gw, ifIndex)

	m.mu.Lock()
	m.physGW, m.physIf = gw, ifIndex
	if m.routes == nil {
		m.routes = map[string]bool{}
	}
	m.mu.Unlock()

	// Провайдерский DNS физ. интерфейса — через него резолвим bypass-домены, чтобы
	// CDN отдавал узлы, близкие к сети пользователя (публичный DNS даёт чужую
	// геолокацию → медленный CDN). Публичный резолвер выводим мимо туннеля (/32);
	// приватный (роутер 192.168.x) и так доступен по connected-маршруту.
	bypassDNS := physDNS(ifIndex)
	if bypassDNS != "" {
		m.log("• Провайдерский DNS для обхода: %s", bypassDNS)
		if ip := net.ParseIP(bypassDNS); ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			m.excludeHost(bypassDNS)
		}
	}

	// 1) Исключения для трафика wdtt-client (сервер + VK/DNS подсети) — мимо TUN.
	if ip := resolveHost(serverHost); ip != "" {
		m.excludeHost(ip)
	}
	// TURN-адреса из логов клиента, замеченные до этого момента (тогда
	// excludeHost был no-op — физический шлюз ещё не был известен).
	m.mu.Lock()
	turn := make([]string, 0, len(m.turnIPs))
	for ip := range m.turnIPs {
		turn = append(turn, ip)
	}
	m.mu.Unlock()
	for _, ip := range turn {
		m.excludeHost(ip)
	}
	for _, cidr := range bypassCIDRs {
		netw, mask, e := cidrToRoute(cidr)
		if e != nil {
			continue
		}
		if out, e := runHidden("route", "add", netw, "mask", mask, gw, "metric", "1"); e != nil {
			m.log("  ⚠ route add %s: %v %s", cidr, e, strings.TrimSpace(out))
		} else {
			m.mu.Lock()
			m.routes[netw+" mask "+mask] = true
			m.mu.Unlock()
		}
	}

	// 1b) Пользовательские исключения. IP/подсети — сразу route мимо TUN; домены —
	// в DNS-перехват (резолв на лету при запросе, ловит даже CDN/динамические IP).
	var domains []string
	for _, ex := range strings.Split(excludesCSV, ",") {
		ex = strings.TrimSpace(ex)
		if ex == "" {
			continue
		}
		switch {
		case strings.Contains(ex, "/"): // CIDR
			netw, mask, e := cidrToRoute(ex)
			if e != nil {
				m.log("  ⚠ исключение %q: %v", ex, e)
				continue
			}
			if out, e := runHidden("route", "add", netw, "mask", mask, gw, "metric", "1"); e == nil {
				m.mu.Lock()
				m.routes[netw+" mask "+mask] = true
				m.mu.Unlock()
				m.log("  + исключение %s", ex)
			} else {
				m.log("  ⚠ route add %s: %v %s", ex, e, strings.TrimSpace(out))
			}
		case net.ParseIP(ex) != nil: // IP
			m.excludeHost(ex)
		default: // домен → обход: резолв СЕЙЧАС (route на текущие IP, работает даже
			// при DoH в браузере) + DNS-перехват для динамики/CDN.
			domains = append(domains, ex)
			if ips, e := net.LookupHost(ex); e == nil {
				n := 0
				for _, ip := range ips {
					if p := net.ParseIP(ip); p != nil && p.To4() != nil {
						m.excludeHost(ip)
						n++
					}
				}
				m.log("  домен %s → %d IPv4 в обход (резолв при старте)", ex, n)
			} else {
				m.log("  ⚠ домен %s не разрешён сейчас: %v (сработает DNS-перехват)", ex, e)
			}
		}
	}

	// 2) tun2socks: системный TUN → SOCKS5.
	m.log("• Запускаю tun2socks (Wintun)…")
	ts := exec.Command(m.exe("tun2socks.exe"),
		"-device", "tun://"+tunName,
		"-proxy", "socks5://"+socksBind,
		"-mtu", "1280",
		"-loglevel", "warn",
	)
	ts.Dir = m.runDir
	hideConsole(ts)
	tsOut, _ := ts.StdoutPipe()
	ts.Stderr = ts.Stdout
	if err := ts.Start(); err != nil {
		return fmt.Errorf("старт tun2socks: %w", err)
	}
	m.mu.Lock()
	m.tun2socks = ts
	m.mu.Unlock()
	m.watchExit("tun2socks", ts)
	go func() {
		// Построчно + сводка по refused-спаму: при мёртвом SOCKS5 tun2socks
		// сыплет тысячи одинаковых warn — они топили журнал и вешали GUI.
		sc := bufio.NewScanner(tsOut)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		var refused int
		var lastFlush time.Time
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.Contains(line, "unreachable"): // не спамить IPv6/мусором
			case strings.Contains(line, socksBind+": connectex"):
				refused++
				if time.Since(lastFlush) > 5*time.Second {
					m.log("⚠ [tun2socks] SOCKS5 %s недоступен — отклонено соединений: %d", socksBind, refused)
					refused = 0
					lastFlush = time.Now()
				}
			default:
				m.log("[tun2socks] %s", line)
			}
		}
		if refused > 0 {
			m.log("⚠ [tun2socks] SOCKS5 %s недоступен — отклонено соединений: %d", socksBind, refused)
		}
	}()

	// 3) Ждём появления адаптера и настраиваем IP/маршруты.
	if err := m.waitAdapter(ctx, tunName, 12*time.Second); err != nil {
		return err
	}
	idxOut, _ := runHidden("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("(Get-NetAdapter -Name '%s').ifIndex", tunName))
	tunIdx := strings.TrimSpace(idxOut)
	m.log("• Настраиваю TUN-адаптер %s (if %s)…", tunName, tunIdx)

	if out, e := runHidden("netsh", "interface", "ipv4", "set", "address",
		"name="+tunName, "static", tunAddr, tunMask); e != nil {
		return fmt.Errorf("netsh set address: %v %s", e, out)
	}
	// Низкая метрика интерфейса TUN — иначе split-default проигрывает физическому
	// (Windows маршрутизирует по сумме «route metric + interface metric»).
	_, _ = runHidden("netsh", "interface", "ipv4", "set", "interface", tunName, "metric=1")
	time.Sleep(800 * time.Millisecond) // дать IP 10.7.0.2 примениться ДО bind DNS и маршрутов

	// DNS-перехват на адресе TUN. КРИТИЧНО: вешаем DNS адаптера на наш прокси
	// (10.7.0.2) ТОЛЬКО если он реально поднялся; иначе fallback на 1.1.1.1
	// (резолв через туннель), чтобы отказ прокси не убивал весь DNS → интернет.
	dnsServer := tunAddr
	bypassUpstream := ""
	if bypassDNS != "" {
		bypassUpstream = bypassDNS + ":53"
	}
	if err := m.startDNS(tunAddr+":53", domains, bypassUpstream); err != nil {
		m.log("  ⚠ DNS-перехват не поднялся (%v): обход по доменам недоступен, DNS через туннель (1.1.1.1)", err)
		dnsServer = dnsVPNUpstreamIP
	}
	_, _ = runHidden("netsh", "interface", "ipv4", "set", "dnsservers",
		"name="+tunName, "static", dnsServer, "primary")

	// 4) split-default через TUN (0.0.0.0/1 + 128.0.0.0/1) с явной привязкой к
	// интерфейсу TUN (IF idx) и низкой метрикой. Основной дефолт не трогаем.
	for _, half := range [][2]string{{"0.0.0.0", "128.0.0.0"}, {"128.0.0.0", "128.0.0.0"}} {
		args := []string{"add", half[0], "mask", half[1], tunGW, "metric", "1"}
		if tunIdx != "" {
			args = append(args, "if", tunIdx)
		}
		out, e := runHidden("route", args...)
		m.log("  route %s mask %s → %s", half[0], half[1], statusOf(e, out))
		if e == nil {
			m.mu.Lock()
			m.routes[half[0]+" mask "+half[1]] = true
			m.mu.Unlock()
		}
	}

	// 5) IPv6: двойная защита от утечки (у WG только IPv4).
	//   (a) blackhole — весь IPv6 заворачиваем в TUN; tun2socks не сможет его
	//       проксировать → IPv6-соединения сразу падают, приложения уходят на IPv4.
	//   (b) пытаемся отключить IPv6 на физ. адаптере (если сработает — чище).
	if tunIdx != "" {
		for _, p := range []string{"::/1", "8000::/1"} {
			out, e := runHidden("netsh", "interface", "ipv6", "add", "route",
				p, "interface="+tunIdx, "metric=1")
			m.log("  ipv6 blackhole %s → %s", p, statusOf(e, out))
		}
	}
	// Отключаем IPv6 на ВСЕХ адаптерах (по индексу не срабатывало — IPv6 оставался
	// активным на физическом, AAAA утекал через IPv6-DNS мимо нашего прокси).
	out6, e6 := runHidden("powershell", "-NoProfile", "-Command",
		"Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue")
	m.log("  IPv6 отключён на всех адаптерах → %s", statusOf(e6, out6))

	m.mu.Lock()
	m.sysActive = true
	m.mu.Unlock()
	m.log("✅ Системный VPN активен — весь трафик через туннель")
	return nil
}

// waitAdapter ждёт появления Wintun-адаптера с заданным именем.
func (m *Manager) waitAdapter(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		out, _ := runHidden("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`if (Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue) { 'ok' }`, name))
		if strings.Contains(out, "ok") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(400 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("TUN-адаптер %s не появился за %s", name, timeout)
		}
	}
}

// excludeHost добавляет /32-исключение через физический шлюз (мимо TUN).
// Вызывается также динамически из readClient для адресов TURN.
func (m *Manager) excludeHost(ip string) {
	m.mu.Lock()
	gw := m.physGW
	key := ip + " mask 255.255.255.255"
	already := m.routes != nil && m.routes[key]
	active := m.sysActive || gw != ""
	m.mu.Unlock()
	if ip == "" || gw == "" || already || !active {
		return
	}
	if out, e := runHidden("route", "add", ip, "mask", "255.255.255.255", gw, "metric", "1"); e == nil {
		m.mu.Lock()
		if m.routes == nil {
			m.routes = map[string]bool{}
		}
		m.routes[key] = true
		m.mu.Unlock()
		m.log("  + bypass %s", ip)
	} else {
		_ = out
	}
}

// stopSystemRouting откатывает все добавленные маршруты и гасит tun2socks.
func (m *Manager) stopSystemRouting() {
	m.stopDNS()
	m.mu.Lock()
	ts := m.tun2socks
	routes := m.routes
	m.tun2socks = nil
	m.routes = map[string]bool{}
	m.sysActive = false
	m.physGW, m.physIf = "", ""
	m.mu.Unlock()

	// вернуть IPv6 на всех адаптерах
	_, _ = runHidden("powershell", "-NoProfile", "-Command",
		"Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue")

	for r := range routes {
		parts := strings.SplitN(r, " mask ", 2)
		if len(parts) == 2 {
			_, _ = runHidden("route", "delete", parts[0], "mask", parts[1])
		} else {
			_, _ = runHidden("route", "delete", parts[0])
		}
	}
	// Безусловно снимаем split-default (на случай рассинхрона m.routes) — гарантия,
	// что основной дефолтный маршрут вернётся в работу.
	_, _ = runHidden("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	_, _ = runHidden("route", "delete", "128.0.0.0", "mask", "128.0.0.0")
	if ts != nil && ts.Process != nil {
		_ = ts.Process.Kill()
	}
}

// Stats возвращает счётчики байт TUN-адаптера (down, up) и ok=true в системном
// VPN-режиме. Эмпирически на Wintun: ReceivedBytes = входящий пользователю трафик
// (download), SentBytes = исходящий (upload).
func (m *Manager) Stats() (down, up int64, ok bool) {
	m.mu.Lock()
	active := m.sysActive
	m.mu.Unlock()
	if !active {
		return 0, 0, false
	}
	out, err := runHidden("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`$s = Get-NetAdapterStatistics -Name '%s' -ErrorAction SilentlyContinue; "$($s.ReceivedBytes) $($s.SentBytes)"`, tunName))
	if err != nil {
		return 0, 0, false
	}
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) < 2 {
		return 0, 0, false
	}
	d, e1 := strconv.ParseInt(f[0], 10, 64)
	u, e2 := strconv.ParseInt(f[1], 10, 64)
	if e1 != nil || e2 != nil {
		return 0, 0, false
	}
	return d, u, true
}

func statusOf(err error, out string) string {
	if err == nil {
		return "OK"
	}
	return fmt.Sprintf("ошибка: %v %s", err, strings.TrimSpace(out))
}

func resolveHost(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	ips, err := net.LookupHost(host)
	if err == nil && len(ips) > 0 {
		return ips[0]
	}
	return ""
}
