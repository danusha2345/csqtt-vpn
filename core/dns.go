package core

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNS-перехват для надёжного обхода по доменам (включая CDN/динамические IP).
//
// Прокси слушает на адресе TUN-адаптера (DNS приложений идут к нему). Для доменов
// из списка обхода резолвит через Yandex-DNS (77.88.8.8 — он в bypassCIDRs, т.е.
// запрос идёт МИМО VPN), и на каждый отданный A-адрес ставит /32-маршрут мимо
// туннеля ДО того, как приложение подключится. Остальное резолвится через VPN.
const (
	dnsBypassUpstream = "77.88.8.8:53" // Yandex (в bypassCIDRs → мимо VPN)
	dnsVPNUpstream    = "1.1.1.1:53"   // через туннель
	dnsVPNUpstreamIP  = "1.1.1.1"      // для netsh dnsservers (fallback)
)

type dnsProxy struct {
	mgr      *Manager
	excludes []string // суффиксы доменов для обхода
	udp      *dns.Server
	tcp      *dns.Server
	mu       sync.Mutex
}

// startDNS поднимает DNS-прокси на listenAddr (например "10.7.0.2:53").
// Бинд СИНХРОННЫЙ с ретраями — IP TUN-адаптера может ещё применяться
// (EADDRNOTAVAIL). Возвращает ошибку, если поднять не удалось, чтобы вызывающий
// код не вешал DNS адаптера на мёртвый прокси.
func (m *Manager) startDNS(listenAddr string, domains []string) error {
	p := &dnsProxy{mgr: m, excludes: normalizeDomains(domains)}
	h := dns.HandlerFunc(p.handle)

	var pc net.PacketConn
	var l net.Listener
	var err error
	for i := 0; i < 12; i++ { // до ~3.6с ждём готовности IP/освобождения порта
		pc, err = net.ListenPacket("udp", listenAddr)
		if err == nil {
			l, err = net.Listen("tcp", listenAddr)
			if err == nil {
				break
			}
			_ = pc.Close()
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("bind %s: %w", listenAddr, err)
	}

	p.udp = &dns.Server{PacketConn: pc, Handler: h}
	p.tcp = &dns.Server{Listener: l, Handler: h}

	m.mu.Lock()
	m.dns = p
	m.mu.Unlock()

	go func() {
		if e := p.udp.ActivateAndServe(); e != nil {
			m.log("[DNS] udp: %v", e)
		}
	}()
	go func() {
		if e := p.tcp.ActivateAndServe(); e != nil {
			m.log("[DNS] tcp: %v", e)
		}
	}()
	m.log("• DNS-перехват на %s (обход доменов: %d)", listenAddr, len(p.excludes))
	return nil
}

func (m *Manager) stopDNS() {
	m.mu.Lock()
	p := m.dns
	m.dns = nil
	m.mu.Unlock()
	if p != nil {
		if p.udp != nil {
			_ = p.udp.Shutdown()
		}
		if p.tcp != nil {
			_ = p.tcp.Shutdown()
		}
	}
}

func (p *dnsProxy) handle(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}
	// IPv6 у нас не маршрутизируется (туннель только IPv4, AAAA → blackhole).
	// Отдаём пустой ответ на AAAA-запросы, чтобы приложения по happy-eyeballs не
	// висли на IPv6, а сразу шли по IPv4. Без этого сайты с AAAA «не открываются».
	if r.Question[0].Qtype == dns.TypeAAAA {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return
	}
	name := strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
	bypass := p.match(name)
	upstream := dnsVPNUpstream
	if bypass {
		upstream = dnsBypassUpstream
	}

	resp, err := dns.Exchange(r, upstream)
	if err != nil || resp == nil {
		dns.HandleFailed(w, r)
		return
	}

	if bypass {
		// каждый отданный IP — мимо VPN (route /32 через физ. шлюз)
		for _, ans := range resp.Answer {
			switch a := ans.(type) {
			case *dns.A:
				p.mgr.excludeHost(a.A.String())
			case *dns.AAAA:
				// IPv6 у нас blackhole'нут; обход IPv6 не поддерживаем
			}
		}
	}
	_ = w.WriteMsg(resp)
}

func (p *dnsProxy) match(name string) bool {
	for _, d := range p.excludes {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// normalizeDomains оставляет только доменные имена (IP/CIDR обходятся через route
// напрямую, не через DNS).
func normalizeDomains(in []string) []string {
	var out []string
	for _, d := range in {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" || strings.Contains(d, "/") || net.ParseIP(d) != nil {
			continue
		}
		out = append(out, strings.TrimSuffix(d, "."))
	}
	return out
}
