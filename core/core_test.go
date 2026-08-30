package core

import "testing"

func TestNormalizeSettings(t *testing.T) {
	if got := normalizeObfsMode("VIDEO"); got != "video" {
		t.Fatalf("obfs=%q", got)
	}
	if got := normalizeTurnTransport("tcp"); got != "tcp_tls" {
		t.Fatalf("transport=%q", got)
	}
	if got := normalizeWorkers(128); got != 126 {
		t.Fatalf("workers=%d", got)
	}
	if got := parseVKLinks(" a, b\nc "); got != "a,b,c" {
		t.Fatalf("hashes=%q", got)
	}
}

func TestParseTunnelConfig(t *testing.T) {
	cfg, ok := parseTunnelConfig("TUNCONF:10.66.67.2:1.1.1.1")
	if !ok || cfg.IP != "10.66.67.2" || cfg.DNS != "1.1.1.1" {
		t.Fatalf("cfg=%+v ok=%v", cfg, ok)
	}
	if _, ok := parseTunnelConfig("TUNCONF:bad:1.1.1.1"); ok {
		t.Fatal("invalid config accepted")
	}
}
