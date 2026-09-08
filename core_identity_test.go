package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledCoreIdentityWithoutExecutingBinary(t *testing.T) {
	for _, name := range []string{"csqtt-client", "csqtt-client.exe"} {
		if got := bundledCoreIdentity(filepath.Join("bin", name)); !strings.HasPrefix(got, "2.1.11 ") {
			t.Fatalf("%s: %s", name, got)
		}
	}
	file := filepath.Join(t.TempDir(), "csqtt-client.exe")
	if err := os.WriteFile(file, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := bundledCoreIdentity(file); strings.HasPrefix(got, "2.1.11 ") {
		t.Fatal("tampered binary reported as verified")
	}
}
