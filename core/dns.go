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
	dnsCacheEntries   = 1024
	dnsCacheMax       = 300 * time.Second
)

// yandexBypassCIDRs — агрегированные IPv4-префиксы AS13238 (YANDEX),
// наблюдавшиеся RIPE RIS 14 июля 2026 года. Когда пользователь исключает
// ya.ru/yandex.*, эти сети маршрутизируются напрямую целиком: в отличие от
// разовых /32 из DNS это не ломается при смене A-записи, TTL или browser DoH.
var yandexBypassCIDRs = []string{
	"5.45.192.0/18",
	"5.255.192.0/18",
	"37.9.64.0/18",
	"37.140.128.0/18",
	"77.88.0.0/18",
	"84.252.160.0/19",
	"87.250.224.0/19",
	"92.255.112.0/20",
	"93.158.128.0/18",
	"95.108.128.0/17",
	"141.8.128.0/18",
	"178.154.128.0/18",
	"185.32.187.0/24",
	"213.180.192.0/19",
}

type dnsCacheEntry struct {
	msg    *dns.Msg
	expiry time.Time
}

type dnsProxy struct {
	mgr      *Manager
	vpnUp    string
	excludes []string // суффиксы доменов для обхода
	bypassUp string   // upstream для bypass-доменов (физ./провайдерский DNS — правильная геолокация CDN)
	udp      *dns.Server
	tcp      *dns.Server
	mu       sync.Mutex

	cacheMu sync.Mutex
	cache   map[string]dnsCacheEntry // ключ: qname|qtype — режет латентность повторных резолвов
}

// startDNS поднимает DNS-прокси на listenAddr внутри CSQTT TUN.
// Бинд СИНХРОННЫЙ с ретраями — IP TUN-адаптера может ещё применяться
// (EADDRNOTAVAIL). Возвращает ошибку, если поднять не удалось, чтобы вызывающий
// код не вешал DNS адаптера на мёртвый прокси.
func (m *Manager) startDNS(listenAddr string, domains []string, bypassUpstream, vpnDNS string) error {
	if ip := net.ParseIP(vpnDNS); ip == nil || ip.To4() == nil {
		return fmt.Errorf("некорректный DNS сервера: %q", vpnDNS)
	}
	p := &dnsProxy{
		mgr:      m,
		vpnUp:    net.JoinHostPort(vpnDNS, "53"),
		excludes: normalizeDomains(domains),
		bypassUp: bypassUpstream,
		cache:    map[string]dnsCacheEntry{},
	}
	// Upstream исключённых доменов сам должен идти мимо туннеля, иначе CDN
	// геолоцирует их по серверу CSQTT. Адреса LAN и так маршрутизируются напрямую.
	if len(p.excludes) > 0 {
		upstream := bypassUpstream
		if upstream == "" {
			upstream = dnsBypassFallback
		}
		if host, _, err := net.SplitHostPort(upstream); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() {
				m.excludeHost(ip.String())
			}
		}
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

	// Shutdown must not race ActivateAndServe's startup flag on a fast cancel.
	start := func(server *dns.Server) error {
		ready := make(chan error, 1)
		var once sync.Once
		signal := func(err error) { once.Do(func() { ready <- err }) }
		server.NotifyStartedFunc = func() { signal(nil) }
		go func() {
			err := server.ActivateAndServe()
			signal(err)
			if err != nil {
				m.log("[DNS] serve: %v", err)
			}
		}()
		return <-ready
	}
	if err := start(p.udp); err != nil {
		_ = pc.Close()
		_ = l.Close()
		return err
	}
	if err := start(p.tcp); err != nil {
		_ = p.udp.Shutdown()
		_ = l.Close()
		return err
	}
	m.mu.Lock()
	m.dns = p
	m.mu.Unlock()
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
	key := fmt.Sprintf("%s|%d|%d", name, q.Qtype, q.Qclass)
	cacheable := len(r.Question) == 1 && q.Qclass == dns.ClassINET && r.IsEdns0() == nil && !r.CheckingDisabled
	if cached := p.cacheGet(key); cacheable && cached != nil {
		cached.SetReply(r)
		_ = w.WriteMsg(cached)
		return
	}

	upstream := p.vpnUp
	if bypass {
		upstream = p.bypassUp // физ./провайдерский DNS → CDN отдаёт близкие узлы
		if upstream == "" {
			upstream = dnsBypassFallback
		}
	}

	resp, err := exchangeDNS(r, upstream)
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
	if cacheable {
		p.cachePut(key, resp)
	}
	_ = w.WriteMsg(resp)
}

// An upstream UDP answer may be truncated, including when the caller used TCP.
// Complete it before caching or returning it to the application.
func exchangeDNS(request *dns.Msg, upstream string) (*dns.Msg, error) {
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	response, _, err := client.Exchange(request, upstream)
	if err == nil && response != nil && response.Truncated {
		client.Net = "tcp"
		response, _, err = client.Exchange(request, upstream)
	}
	return response, err
}

// cacheGet возвращает копию закэшированного ответа (или nil, если нет/протух).
func (p *dnsProxy) cacheGet(key string) *dns.Msg {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	e, ok := p.cache[key]
	if !ok {
		return nil
	}
	remaining := time.Until(e.expiry)
	if remaining < time.Second {
		delete(p.cache, key)
		return nil
	}
	answer := e.msg.Copy()
	for _, section := range [][]dns.RR{answer.Answer, answer.Ns, answer.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > uint32(remaining/time.Second) {
				rr.Header().Ttl = uint32(remaining / time.Second)
			}
		}
	}
	return answer
}

// Cache lifetime never exceeds upstream TTL. Arbitrary eviction keeps the
// number of entries bounded with constant work per insertion.
func (p *dnsProxy) cachePut(key string, resp *dns.Msg) {
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 || resp.IsEdns0() != nil {
		return
	}
	ttl := dnsCacheMax
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, ans := range section {
			if ans.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if t := time.Duration(ans.Header().Ttl) * time.Second; t < ttl {
				ttl = t
			}
		}
	}
	if ttl <= 0 {
		return
	}
	p.cacheMu.Lock()
	if p.cache == nil {
		p.cache = map[string]dnsCacheEntry{}
	}
	if _, exists := p.cache[key]; !exists && len(p.cache) >= dnsCacheEntries {
		for oldest := range p.cache {
			delete(p.cache, oldest)
			break
		}
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

// providerBypassCIDRs возвращает устойчивый сетевой профиль для известных
// доменов. DNS-прокси всё равно добавляет динамические /32 для внешних CDN, но
// основной сайт больше не зависит от того, какой IP успел разрешиться первым.
func providerBypassCIDRs(domain string) []string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	for _, root := range []string{"ya.ru", "yandex.ru", "yandex.com"} {
		if domain == root || strings.HasSuffix(domain, "."+root) {
			return yandexBypassCIDRs
		}
	}
	return nil
}
