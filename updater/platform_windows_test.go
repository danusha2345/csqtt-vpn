//go:build windows

package updater

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

// Запускать на настоящей Windows: go test ./updater -v (Administrator).
func TestWindowsLockedFileRollback(t *testing.T) {
	d := t.TempDir()
	install := filepath.Join(d, "install")
	stage := filepath.Join(d, "stage")
	os.MkdirAll(filepath.Join(install, "bin"), 0700)
	os.MkdirAll(filepath.Join(stage, "new", "bin"), 0700)
	for _, n := range BundleFiles[:3] {
		os.WriteFile(filepath.Join(install, n), []byte("old"), 0700)
		os.WriteFile(filepath.Join(stage, "new", n), []byte("new"), 0700)
	}
	tx, e := Prepare(install, stage)
	if e != nil {
		t.Fatal(e)
	}
	path, _ := windows.UTF16PtrFromString(filepath.Join(install, "wintun.dll"))
	handle, e := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	e = tx.Apply()
	windows.CloseHandle(handle)
	if e == nil {
		t.Fatal("замена занятого DLL должна отказать")
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	for _, n := range BundleFiles[:3] {
		b, _ := os.ReadFile(filepath.Join(install, n))
		if string(b) != "old" {
			t.Fatal("rollback", n)
		}
	}
}
func TestWindowsStageDACL(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires Administrator")
	}
	stage, e := NewStage(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(stage)
	sd, e := windows.GetNamedSecurityInfo(stage, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal(e)
	}
	owner, _, e := sd.Owner()
	if e != nil {
		t.Fatal(e)
	}
	if owner.String() != "S-1-5-32-544" {
		t.Fatalf("owner is not Administrators: %s", owner)
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		t.Fatalf("missing DACL: %v", e)
	}
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL not protected: %v", e)
	}
}
