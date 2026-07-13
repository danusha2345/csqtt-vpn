package core

import (
	"reflect"
	"testing"
)

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
