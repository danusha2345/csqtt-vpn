package core

import "testing"

func TestCustomTurnBypass(t *testing.T) {
	ips, err := customTurnBypassIPs("203.0.113.1:3478;203.0.113.2\n203.0.113.1")
	if err != nil || len(ips) != 2 || !ips["203.0.113.1"] || !ips["203.0.113.2"] {
		t.Fatalf("%v %v", ips, err)
	}
	for _, invalid := range []string{"hostname:3478", "[::1]:3478", "203.0.113.1:65536", "203.0.113.1:abc"} {
		if _, err := customTurnBypassIPs(invalid); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
}
