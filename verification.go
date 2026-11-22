package main

import (
	"net/url"
	"strings"
	"time"

	"csqtt-vpn/core"
	"github.com/pkg/browser"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type verificationRequest struct {
	url     string
	expires time.Time
}

func allowedVerificationURL(raw string) bool {
	u, err := url.Parse(raw)
	if strings.ContainsAny(raw, "\x00\r\n") || err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, domain := range []string{"vk.com", "vk.ru", "ok.ru", "okcdn.ru"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func (a *App) requestVerification(m *core.Manager, raw string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mgr != m || !a.connected {
		return
	}
	if !allowedVerificationURL(raw) {
		a.emitLog("Проверку VK открыть нельзя: недопустимый адрес.")
		return
	}
	req := verificationRequest{raw, time.Now().Add(time.Minute)}
	a.challenge = req
	runtime.EventsEmit(a.ctx, "verification", true)
	time.AfterFunc(time.Until(req.expires), func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.mgr == m && a.challenge == req {
			a.challenge = verificationRequest{}
			runtime.EventsEmit(a.ctx, "verification", false)
		}
	})
}

func (a *App) clearVerification(m *core.Manager) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mgr == m && a.challenge.url != "" {
		a.challenge = verificationRequest{}
		runtime.EventsEmit(a.ctx, "verification", false)
	}
}

func (a *App) OpenVerification() string {
	a.mu.Lock()
	req := a.challenge
	a.mu.Unlock()
	if req.url == "" || !time.Now().Before(req.expires) {
		return "Запрос проверки уже завершён."
	}
	if err := browser.OpenURL(req.url); err != nil {
		return "Не удалось открыть браузер для проверки VK."
	}
	return ""
}
