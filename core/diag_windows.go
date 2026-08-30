//go:build windows

package core

import "strings"

// Diagnostics собирает сетевую диагностику (маршруты, DNS, ping) для отправки
// разработчику. Безопасно для запуска при активном VPN.
func Diagnostics() string {
	cmds := [][]string{
		{"ipconfig", "/all"},
		{"route", "print", "-4"},
		{"powershell", "-NoProfile", "-Command", "Get-NetAdapter -Name 'CSQTT' -ErrorAction SilentlyContinue | Format-List Name,Status,ifIndex,LinkSpeed"},
		{"powershell", "-NoProfile", "-Command", "Get-NetIPAddress -InterfaceAlias 'CSQTT' -ErrorAction SilentlyContinue | Format-Table -AutoSize"},
		{"powershell", "-NoProfile", "-Command", "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Format-List Namespace,NameServers,DisplayName,Comment"},
		{"powershell", "-NoProfile", "-Command", "Resolve-DnsName ya.ru -Type A -DnsOnly -ErrorAction Continue | Format-Table -AutoSize"},
		{"nslookup", "-timeout=3", "ya.ru"},
		{"ping", "-n", "2", "1.1.1.1"},
		{"ping", "-n", "2", "77.88.55.242"},
		{"curl.exe", "-4", "--connect-timeout", "5", "--max-time", "12", "--silent", "--show-error", "--output", "NUL", "--write-out", "http=%{http_code} remote=%{remote_ip} dns=%{time_namelookup}s connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s", "https://example.com/"},
	}
	var b strings.Builder
	for _, c := range cmds {
		out, _ := runHidden(c[0], c[1:]...)
		b.WriteString("\n$ " + strings.Join(c, " ") + "\n")
		b.WriteString(strings.TrimSpace(out))
		b.WriteString("\n")
	}
	return b.String()
}
