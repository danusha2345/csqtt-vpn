package core

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Сервер назначает адреса из /24 и использует .1 как внутренний шлюз.
// Первый ответ подтверждает, что конкретный сервер разрешает ICMP.
func (m *Manager) watchGateway(ctx context.Context, exit <-chan struct{}, local string) {
	if runtime.GOOS != "windows" || m.OnLinkLost == nil {
		return
	}
	ip, err := netip.ParseAddr(local)
	if err != nil || !ip.Is4() {
		return
	}
	octets := ip.As4()
	octets[3] = 1
	gateway := netip.AddrFrom4(octets).String()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	if gatewayLost(ctx, exit, ticker.C, m.GatewayPreviouslyConfirmed == gateway, func() bool {
		return gatewayReplies(ctx, local, gateway)
	}) {
		m.OnLinkLost(gateway)
	}
}

func gatewayReplies(ctx context.Context, local, gateway string) bool {
	ping := filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE")
	out, err := runCommandContext(ctx, 4*time.Second, ping, "-4", "-n", "1", "-w", "2000", "-S", local, gateway)
	return err == nil && strings.Contains(strings.ToUpper(out), "TTL=")
}

func gatewayLost(ctx context.Context, exit <-chan struct{}, ticks <-chan time.Time, confirmed bool, probe func() bool) bool {
	state := gatewayHealth{confirmed: confirmed}
	for {
		reply := probe()
		select {
		case <-ctx.Done():
			return false
		case <-exit:
			return false
		default:
		}
		if state.lost(reply) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-exit:
			return false
		case <-ticks:
		}
	}
}

type gatewayHealth struct {
	confirmed bool
	misses    int
}

func (s *gatewayHealth) lost(reply bool) bool {
	if reply {
		s.confirmed = true
		s.misses = 0
	} else if s.confirmed {
		s.misses++
	}
	return s.misses >= 3
}
