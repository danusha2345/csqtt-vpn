package core

import (
	"github.com/miekg/dns"
	"net"
	"reflect"
	"testing"
)

func TestServerDNSIsUsedAndInvalidAddressRejected(t *testing.T) {
	m := NewManager("", "", nil, nil)
	if err := m.startDNS("127.0.0.1:0", nil, "", "192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	defer m.stopDNS()
	if m.dns.vpnUp != "192.168.1.1:53" {
		t.Fatalf("server DNS ignored: %s", m.dns.vpnUp)
	}
	if err := m.startDNS("127.0.0.1:0", nil, "", "not-an-ip"); err == nil {
		t.Fatal("invalid server DNS accepted")
	}
}

func TestDNSRetriesTruncatedUDPOverTCP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		answer := new(dns.Msg)
		answer.SetReply(r)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			answer.Truncated = true
		} else {
			answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.42")}}
		}
		_ = w.WriteMsg(answer)
	})
	readyUDP, readyTCP := make(chan struct{}), make(chan struct{})
	u := &dns.Server{PacketConn: udp, Handler: handler, NotifyStartedFunc: func() { close(readyUDP) }}
	v := &dns.Server{Listener: tcp, Handler: handler, NotifyStartedFunc: func() { close(readyTCP) }}
	go u.ActivateAndServe()
	go v.ActivateAndServe()
	<-readyUDP
	<-readyTCP
	defer u.Shutdown()
	defer v.Shutdown()
	request := new(dns.Msg)
	request.SetQuestion("large.example.", dns.TypeA)
	answer, err := exchangeDNS(request, tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if answer.Truncated || len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).A.String() != "192.0.2.42" {
		t.Fatalf("incomplete DNS answer: %v", answer)
	}
}

func TestNormalizeDomainsExpandsYandexFamily(t *testing.T) {
	got := normalizeDomains([]string{"ya.ru", "YA.RU.", "example.com"})
	want := []string{
		"ya.ru",
		"yandex.ru",
		"yandex.com",
		"yandex.net",
		"yastatic.net",
		"yastatic.com",
		"yandex.st",
		"example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeDomains() = %#v, want %#v", got, want)
	}
}

func TestDNSProxyMatchExpandedYandexDomain(t *testing.T) {
	p := &dnsProxy{excludes: normalizeDomains([]string{"ya.ru"})}
	for _, domain := range []string{"ya.ru", "www.ya.ru", "mc.yandex.ru", "cdn.yandex.net", "yastatic.net"} {
		if !p.match(domain) {
			t.Errorf("expanded ya.ru bypass does not match %q", domain)
		}
	}
	if p.match("example.com") {
		t.Error("expanded ya.ru bypass unexpectedly matches example.com")
	}
}

func TestProviderBypassCIDRsForYandex(t *testing.T) {
	for _, domain := range []string{"ya.ru", "www.ya.ru", "yandex.ru", "maps.yandex.com"} {
		cidrs := providerBypassCIDRs(domain)
		if len(cidrs) == 0 {
			t.Fatalf("providerBypassCIDRs(%q) returned no routes", domain)
		}
		for _, cidr := range cidrs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				t.Errorf("providerBypassCIDRs(%q) contains invalid CIDR %q: %v", domain, cidr, err)
			}
		}
	}
	if got := providerBypassCIDRs("example.com"); got != nil {
		t.Fatalf("providerBypassCIDRs(example.com) = %#v, want nil", got)
	}
}
