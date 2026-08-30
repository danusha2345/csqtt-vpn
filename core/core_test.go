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
	multiple, ok := parseTunnelConfig("TUNCONF:10.66.67.3:1.1.1.1,8.8.8.8:19000")
	if !ok || multiple.IP != "10.66.67.3" || multiple.DNS != "1.1.1.1" {
		t.Fatalf("multiple DNS config=%+v ok=%v", multiple, ok)
	}
	if _, ok := parseTunnelConfig("TUNCONF:10.66.67.3:bad,also-bad:19000"); ok {
		t.Fatal("invalid DNS list accepted")
	}
}

func TestDecodeCommandOutputRepairsWindowsOEM866(t *testing.T) {
	encoded := []byte{0x8f, 0xe0, 0xa8, 0xa2, 0xa5, 0xe2}
	if got := decodeCommandOutput(encoded); got != "Привет" {
		t.Fatalf("decoded=%q", got)
	}
	if got := decodeCommandOutput([]byte("UTF-8 ✓")); got != "UTF-8 ✓" {
		t.Fatalf("utf8=%q", got)
	}
}

func TestRouteAlreadyExistsAcceptsEnglishAndRussianWindows(t *testing.T) {
	for _, output := range []string{
		"The object already exists.",
		"Объект уже существует.",
		"Маршрут уже существует.",
	} {
		if !routeAlreadyExists(output) {
			t.Fatalf("not recognized: %q", output)
		}
	}
	if routeAlreadyExists("Access is denied") {
		t.Fatal("unrelated route error accepted")
	}
}
