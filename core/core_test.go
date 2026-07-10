package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeObfsMode(t *testing.T) {
	for input, want := range map[string]string{
		"video": "video", " VIDEO ": "video", "audio": "audio", "": "audio", "other": "audio",
	} {
		if got := normalizeObfsMode(input); got != want {
			t.Errorf("normalizeObfsMode(%q)=%q want %q", input, got, want)
		}
	}
}

func TestParseVKLinks(t *testing.T) {
	if got := parseVKLinks("one, two\nthree"); got != "one,two,three" {
		t.Fatalf("parseVKLinks = %q", got)
	}
}

func TestExtractTurnIPAtEndOfLine(t *testing.T) {
	if got := extractTurnIP("relay turn:87.240.1.2"); got != "87.240.1.2" {
		t.Fatalf("extractTurnIP = %q", got)
	}
}

func TestBuildWireproxyConf(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "wg.conf")
	out := filepath.Join(dir, "wireproxy.conf")
	raw := "[Interface]\nPrivateKey = secret\nAddress = 10.66.66.2/32\nDNS = 1.1.1.1\n\n[Peer]\nEndpoint = 127.0.0.1:9000\n"
	if err := os.WriteFile(in, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := buildWireproxyConf(in, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if strings.Contains(got, "DNS =") || !strings.Contains(got, "Address = 10.66.66.2\n") || !strings.Contains(got, "[Socks5]") {
		t.Fatalf("wireproxy config:\n%s", got)
	}
}
