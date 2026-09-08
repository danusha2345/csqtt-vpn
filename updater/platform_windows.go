//go:build windows

package updater

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func platformDirectoryCheck(dir string) error {
	for p := dir; ; p = filepath.Dir(p) {
		u, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return e
		}
		a, e := windows.GetFileAttributes(u)
		if e != nil {
			return e
		}
		if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("reparse point запрещён: %s", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func NewStage(install string) (string, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return "", fmt.Errorf("запустите CSQTT от Administrator (UAC)")
	}
	if e := CheckDirectory(install); e != nil {
		return "", e
	}
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	path := filepath.Join(install, ".csqtt-update-"+hex.EncodeToString(b))
	// DACL устанавливается атомарно при создании: обычный процесс пользователя
	// не может подменить ZIP/helper между проверкой и запуском с правами admin.
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if e != nil {
		return "", e
	}
	u, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return "", e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if e = windows.CreateDirectory(u, &sa); e != nil {
		return "", e
	}
	return path, nil
}
func hidden(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
func LaunchHelper(install, stage string) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	if !strings.EqualFold(exe, filepath.Join(install, "CSQTT-VPN.exe")) {
		return fmt.Errorf("обновлять можно только установленный CSQTT-VPN.exe")
	}
	helper := filepath.Join(stage, "updater.exe")
	if e = copyFile(exe, helper); e != nil {
		return e
	}
	cmd := exec.Command(helper, "--csqtt-update-helper", strconv.Itoa(os.Getpid()))
	cmd.Dir = stage
	hidden(cmd)
	if e = cmd.Start(); e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case e := <-done:
			return fmt.Errorf("helper не готов: %v", e)
		case <-deadline.C:
			cmd.Process.Kill()
			<-done
			return fmt.Errorf("helper не ответил")
		case <-tick.C:
			if _, e := os.Stat(filepath.Join(stage, "ready")); e == nil {
				return nil
			}
		}
	}
}
func RunHelper() bool {
	if len(os.Args) < 2 || os.Args[1] != "--csqtt-update-helper" {
		return false
	}
	exe, e := os.Executable()
	if e != nil {
		return true
	}
	stage := filepath.Dir(exe)
	if e = runHelper(stage); e != nil {
		os.WriteFile(filepath.Join(stage, "error.txt"), []byte(e.Error()), 0600)
	}
	return true
}
func runHelper(stage string) error {
	if len(os.Args) != 3 || !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("helper требует Administrator и PID")
	}
	if !strings.HasPrefix(filepath.Base(stage), ".csqtt-update-") {
		return fmt.Errorf("неверный stage")
	}
	if e := CheckDirectory(stage); e != nil {
		return e
	}
	install := filepath.Dir(stage)
	key := sha256.Sum256([]byte(strings.ToLower(install)))
	mutexName, _ := windows.UTF16PtrFromString(fmt.Sprintf("Global\\CSQTT-Update-%x", key[:16]))
	mutex, lockErr := windows.CreateMutex(nil, true, mutexName)
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if lockErr != nil {
		return fmt.Errorf("другая установка уже запущена или lock недоступен: %w", lockErr)
	}
	defer windows.ReleaseMutex(mutex)

	pid, e := strconv.ParseUint(os.Args[2], 10, 32)
	if e != nil {
		return e
	}
	h, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if e = windows.QueryFullProcessImageName(h, 0, &buf[0], &n); e != nil {
		return e
	}
	if !strings.EqualFold(windows.UTF16ToString(buf[:n]), filepath.Join(install, "CSQTT-VPN.exe")) {
		return fmt.Errorf("PID не принадлежит исходному GUI")
	}
	data, e := os.ReadFile(filepath.Join(stage, "ticket.json"))
	if e != nil {
		return e
	}
	var ticket Ticket
	if e = json.Unmarshal(data, &ticket); e != nil {
		return e
	}
	sum, e := HashFile(filepath.Join(stage, "bundle.zip"))
	if e != nil || sum != ticket.Hash || !versionPattern.MatchString(ticket.Version) {
		return fmt.Errorf("stage checksum/version не совпадает")
	}
	// Повторная проверка непосредственно в helper; new уже извлечён GUI в защищённом stage.
	if e = ValidatePE(filepath.Join(stage, "new")); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(stage, "ready"), []byte("ready"), 0600); e != nil {
		return e
	}
	status, e := windows.WaitForSingleObject(h, 60000)
	if e != nil || status != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("старый GUI не завершился")
	}
	t, e := Prepare(install, stage)
	if e != nil {
		return e
	}
	rollback := func(cause error) error {
		if r := t.Rollback(); r != nil {
			return fmt.Errorf("%v; %w; backup сохранён в %s", cause, r, stage)
		}
		old := exec.Command(filepath.Join(install, "CSQTT-VPN.exe"))
		old.Dir = install
		if r := old.Start(); r != nil {
			return fmt.Errorf("%v; rollback выполнен, запуск старого GUI: %w", cause, r)
		}
		return fmt.Errorf("%v; восстановлена предыдущая версия", cause)
	}
	if e = t.Apply(); e != nil {
		return rollback(e)
	}
	cmd := exec.Command(filepath.Join(install, "CSQTT-VPN.exe"), "--csqtt-update-health", stage, ticket.Version)
	cmd.Dir = install
	if e = cmd.Start(); e != nil {
		return rollback(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timeout := time.NewTimer(60 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case e := <-done:
			return rollback(fmt.Errorf("новый GUI завершился: %v", e))
		case <-timeout.C:
			if e = cmd.Process.Kill(); e != nil {
				return fmt.Errorf("нет подтверждения, процесс не остановлен: %w; backup: %s", e, stage)
			}
			<-done
			return rollback(fmt.Errorf("нет подтверждения запуска новой версии"))
		case <-tick.C:
			b, e := os.ReadFile(filepath.Join(stage, "healthy"))
			if e == nil && string(b) == ticket.Version {
				os.WriteFile(filepath.Join(stage, "success"), []byte(ticket.Version), 0600)
				// Сам helper занят Windows; небольшой каталог остаётся для диагностики.
				os.RemoveAll(filepath.Join(stage, "backup"))
				os.RemoveAll(filepath.Join(stage, "new"))
				os.Remove(filepath.Join(stage, "bundle.zip"))
				return nil
			}
		}
	}
}

// Acknowledge вызывается после готовности frontend, а не просто CreateProcess.
func Acknowledge(version string) {
	if len(os.Args) != 4 || os.Args[1] != "--csqtt-update-health" || os.Args[3] != version {
		return
	}
	exe, e := os.Executable()
	if e != nil {
		return
	}
	stage := os.Args[2]
	if filepath.Dir(stage) != filepath.Dir(exe) || !strings.HasPrefix(filepath.Base(stage), ".csqtt-update-") || CheckDirectory(stage) != nil {
		return
	}
	os.WriteFile(filepath.Join(stage, "healthy"), []byte(version), 0600)
}

// После перемещения из private stage EXE должны читаться обычным Explorer/UAC.
func installPermissions(path string) error {
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
