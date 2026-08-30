//go:build !windows && !linux

package core

import (
	"context"
	"fmt"
)

// Заглушки для не-Windows (нужны для сборки/vet на Linux). Системный VPN
// реализован только под Windows (tun_windows.go).
func (m *Manager) startSystemRouting(ctx context.Context, serverHost, excludesCSV string, assigned tunnelConfig) error {
	return fmt.Errorf("системный VPN поддерживается только на Windows")
}

func (m *Manager) stopSystemRouting() {}

func (m *Manager) excludeHost(ip string) {}

func (m *Manager) cleanupStale() {}

func (m *Manager) Stats() (down, up int64, ok bool) { return 0, 0, false }

func platformClientName() string { return "csqtt-client" }

func (m *Manager) platformPreflight() error { return nil }

func (m *Manager) platformClientArgs() []string { return []string{"--listen", innerListen} }
