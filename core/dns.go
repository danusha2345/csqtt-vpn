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
	dnsBypassFallback = "77.88.8.8:53" // Yandex (в bypassCIDRs → мимо VPN), если физ. DNS неизвестен
	dnsVPNUpstream    = "1.1.1.1:53"   // через туннель
	dnsCacheMin       = 10 * time.Second
	dnsCacheMax       = 300 * time.Second
)

type dnsCacheEntry struct {
	msg    *dns.Msg
	expiry time.Time
}

type dnsProxy struct {
	mgr      *Manager
	excludes []string // суффиксы доменов для обхода
	bypassUp string   // upstream для bypass-доменов (физ./провайдерский DNS — правильная геолокация CDN)
	udp      *dns.Server
	tcp      *dns.Server
	mu       sync.Mutex

	cacheMu sync.Mutex
	cache   map[string]dnsCacheEntry // ключ: qname|qtype — режет латентность повторных резолвов
}

// startDNS поднимает DNS-прокси на listenAddr (например "10.7.0.2:53").
// Бинд СИНХРОННЫЙ с ретраями — IP TUN-адаптера может ещё применяться
// (EADDRNOTAVAIL). Возвращает ошибку, если поднять не удалось, чтобы вызывающий
// код не вешал DNS адаптера на мёртвый прокси.
func (m *Manager) startDNS(listenAddr string, domains []string, bypassUpstream string) error {
	p := &dnsProxy{
		mgr:      m,
		excludes: normalizeDomains(domains),
		bypassUp: bypassUpstream,
		cache:    map[string]dnsCacheEntry{},
	}
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
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	bypass := p.match(name)

	// Кэш: повторный резолв того же имени не ходит к upstream — режет латентность
	// открытия страниц (на странице десятки поддоменов). route для bypass уже стоит
	// с первого ответа, поэтому cache-hit безопасен.
	key := name + "|" + dns.TypeToString[q.Qtype]
	if cached := p.cacheGet(key); cached != nil {
		cached.SetReply(r)
		_ = w.WriteMsg(cached)
		return
	}

	upstream := dnsVPNUpstream
	if bypass {
		upstream = p.bypassUp // физ./провайдерский DNS → CDN отдаёт близкие узлы
		if upstream == "" {
			upstream = dnsBypassFallback
		}
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
	p.cachePut(key, resp)
	_ = w.WriteMsg(resp)
}

// cacheGet возвращает копию закэшированного ответа (или nil, если нет/протух).
func (p *dnsProxy) cacheGet(key string) *dns.Msg {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	e, ok := p.cache[key]
	if !ok {
		return nil
	}
	if time.Now().After(e.expiry) {
		delete(p.cache, key)
		return nil
	}
	return e.msg.Copy()
}

// cachePut кэширует успешный непустой ответ на min(TTL ответа), зажатый в
// [dnsCacheMin, dnsCacheMax]. Ошибки и пустые ответы не кэшируем.
func (p *dnsProxy) cachePut(key string, resp *dns.Msg) {
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		return
	}
	ttl := dnsCacheMax
	for _, ans := range resp.Answer {
		if t := time.Duration(ans.Header().Ttl) * time.Second; t < ttl {
			ttl = t
		}
	}
	if ttl < dnsCacheMin {
		ttl = dnsCacheMin
	}
	p.cacheMu.Lock()
	if p.cache == nil {
		p.cache = map[string]dnsCacheEntry{}
	}
	p.cache[key] = dnsCacheEntry{msg: resp.Copy(), expiry: time.Now().Add(ttl)}
	p.cacheMu.Unlock()
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
	seen := make(map[string]bool)
	for _, d := range in {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" || strings.Contains(d, "/") || net.ParseIP(d) != nil {
			continue
		}
		for _, expanded := range expandBypassDomain(strings.TrimSuffix(d, ".")) {
			if !seen[expanded] {
				seen[expanded] = true
				out = append(out, expanded)
			}
		}
	}
	return out
}

// expandBypassDomain добавляет домены ресурсов, без которых исключённый сайт
// всё равно получается разделён между прямым выходом и VPN. Для Яндекса это
// особенно важно: ya.ru загружает JS/captcha/телеметрию с yandex.ru,
// yandex.net и yastatic.net; разные внешние IP приводят к captcha или пустой
// странице. Общего безопасного способа угадать cross-domain ресурсы нет,
// поэтому расширяем только известное семейство.
func expandBypassDomain(domain string) []string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	for _, root := range []string{"ya.ru", "yandex.ru", "yandex.com"} {
		if domain == root || strings.HasSuffix(domain, "."+root) {
			out := []string{domain}
			for _, related := range []string{
				"ya.ru",
				"yandex.ru",
				"yandex.com",
				"yandex.net",
				"yastatic.net",
				"yastatic.com",
				"yandex.st",
			} {
				if related != domain {
					out = append(out, related)
				}
			}
			return out
		}
	}
	return []string{domain}
}
