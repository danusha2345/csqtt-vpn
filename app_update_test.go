package main

import (
	"strings"
	"testing"
)

func TestConnectBlockedDuringUpdateCloseOrPendingStop(t *testing.T) {
	for _, state := range []string{"updating", "closing", "pending"} {
		t.Run(state, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("APPDATA", t.TempDir())
			a := NewApp()
			a.updating = state == "updating"
			a.closing = state == "closing"
			if state == "pending" {
				a.done = make(chan struct{})
			}
			message := a.Connect(Settings{})
			if message == "" || a.mgr != nil || a.connected {
				t.Fatalf("started during %s: %s", state, message)
			}
			if state == "pending" && !strings.Contains(message, "завершается") {
				t.Fatal(message)
			}
		})
	}
}
func TestDesktopVersionFromReleaseConfig(t *testing.T) {
	if desktopVersion() == "" {
		t.Fatal("missing embedded version")
	}
}
