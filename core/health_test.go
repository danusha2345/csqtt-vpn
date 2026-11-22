package core

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLossRequiresPreviouslyResponsiveGateway(t *testing.T) {
	var h gatewayHealth
	for i := 0; i < 6; i++ {
		if h.lost(false) {
			t.Fatal("сервер без ICMP вызвал переподключение")
		}
	}
	for i, reply := range []bool{true, false, false, true, false, false, false} {
		if got := h.lost(reply); got != (i == 6) {
			t.Fatalf("шаг %d, lost=%t", i, got)
		}
	}
}

func TestVerificationRequestIsPrivate(t *testing.T) {
	var log []string
	called := false
	m := NewManager("", "", func(line string) { log = append(log, line) }, func(mode, uri, token string) string {
		called = mode == "manual" && uri == "https://id.vk.com/captcha?session_token=private" && token == "private"
		return ""
	})
	const input = "CAPTCHA_SOLVE|manual|https://id.vk.com/captcha?session_token=private|private\n"
	m.readClient(strings.NewReader(input))
	if !called {
		t.Fatal("запрос ручной проверки не доставлен")
	}
	m.onCaptcha = nil
	m.readClient(strings.NewReader(input + "[КАПЧА] открыт ручной WebView\n[КАПЧА] URL: https://id.vk.com/?session_token=private\n"))
	if len(log) != 0 {
		t.Fatal("в журнал попали данные проверки или ложное сообщение об окне")
	}
}

func TestGatewayMonitor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cancel   bool
		exit     bool
		wantLoss bool
	}{
		{"процесс жив", false, false, true}, {"отмена пользователем", true, false, false}, {"процесс завершился", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exit := make(chan struct{})
			ticks := make(chan time.Time, 3)
			for i := 0; i < 3; i++ {
				ticks <- time.Time{}
			}
			attempt := 0
			lost := gatewayLost(ctx, exit, ticks, false, func() bool {
				attempt++
				if attempt == 4 {
					if tc.cancel {
						cancel()
					}
					if tc.exit {
						close(exit)
					}
				}
				return attempt == 1
			})
			if lost != tc.wantLoss || attempt != 4 {
				t.Fatalf("lost=%t, attempts=%d", lost, attempt)
			}
		})
	}
}

func TestWindowsEchoReply(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows ping.exe")
	}
	if !gatewayReplies(context.Background(), "127.0.0.1", "127.0.0.1") {
		t.Fatal("не распознан ответ локального IPv4")
	}
}
