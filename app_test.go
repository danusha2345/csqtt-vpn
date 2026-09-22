package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSanitizeProfileName(t *testing.T) {
	if got := sanitizeProfileName(" ../server:main "); got != "__server_main" {
		t.Fatalf("sanitizeProfileName = %q", got)
	}
}

func TestLoadOrCreateDeviceIDIsStableAndPrivate(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	first, err := loadOrCreateDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || first != second {
		t.Fatalf("device IDs: first=%q second=%q", first, second)
	}
	info, err := os.Stat(configPath())
	if !os.IsNotExist(err) {
		t.Fatalf("device ID must not create settings file: info=%v err=%v", info, err)
	}
	info, err = os.Stat(filepath.Join(filepath.Dir(configPath()), "device-id"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports POSIX mode bits as 0666; its access policy is an ACL.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
}

func TestBeforeCloseDefersOnlyWhileStopping(t *testing.T) {
	idle := &App{}
	if idle.beforeClose(nil) {
		t.Fatal("без VPN окно должно закрываться сразу")
	}
	stopping := &App{closing: true}
	if !stopping.beforeClose(nil) {
		t.Fatal("повторное закрытие во время остановки должно ждать её")
	}
	stopped := &App{closing: true, closeReady: true}
	if stopped.beforeClose(nil) {
		t.Fatal("после остановки окно должно закрываться")
	}
}
