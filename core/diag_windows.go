//go:build windows

package core

import "strings"

// Diagnostics собирает сетевую диагностику (маршруты, DNS, ping) для отправки
// разработчику. Безопасно для запуска при активном VPN.
func Diagnostics() string {
	cmds := [][]string{
		{"ipconfig", "/all"},
		{"route", "print", "-4"},
		{"nslookup", "-timeout=3", "ya.ru"},             // через системный DNS (наш прокси 10.7.0.2)
		{"nslookup", "-timeout=3", "ya.ru", "10.7.0.2"}, // напрямую к прокси
		{"ping", "-n", "2", "10.7.0.2"},                 // TUN-адаптер жив?
		{"ping", "-n", "2", "1.1.1.1"},                  // через туннель
		{"ping", "-n", "2", "77.88.55.242"},             // Yandex (bypass)
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
