//go:build linux

package core

import (
	"os/exec"
	"strings"
)

func Diagnostics() string {
	commands := [][]string{
		{"ip", "-brief", "address"},
		{"ip", "-4", "route", "show"},
		{"ip", "-6", "route", "show"},
		{"resolvectl", "status", linuxTunName},
		{"resolvectl", "query", "ya.ru"},
		{"ping", "-c", "2", "-W", "2", "1.1.1.1"},
		{"ping", "-c", "2", "-W", "2", "77.88.55.242"},
		{"curl", "-4", "--connect-timeout", "5", "--max-time", "12", "--silent", "--show-error", "--output", "/dev/null", "--write-out", "http=%{http_code} remote=%{remote_ip} dns=%{time_namelookup}s connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s", "https://example.com/"},
	}
	var report strings.Builder
	for _, command := range commands {
		output, _ := exec.Command(command[0], command[1:]...).CombinedOutput()
		report.WriteString("\n$ " + strings.Join(command, " ") + "\n")
		report.WriteString(strings.TrimSpace(string(output)))
		report.WriteString("\n")
	}
	return report.String()
}
