//go:build windows

package core

import "golang.org/x/sys/windows"

// isElevated сообщает, запущен ли процесс с правами администратора. Системный VPN
// без них невозможен: route/netsh/Add-DnsClientNrptRule отвечают «требуется
// повышение прав», маршрутизация не поднимается.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
