package main

import "testing"

func TestSanitizeProfileName(t *testing.T) {
	if got := sanitizeProfileName(" ../server:main "); got != "__server_main" {
		t.Fatalf("sanitizeProfileName = %q", got)
	}
}
