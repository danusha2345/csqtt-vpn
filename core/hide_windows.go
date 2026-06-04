//go:build windows

package core

import (
	"os/exec"
	"syscall"
)

// hideConsole прячет консольное окно дочернего процесса (wdtt-client.exe,
// wireproxy.exe, tun2socks.exe). Без этого при запуске из GUI всплывают
// пустые окна cmd. CREATE_NO_WINDOW = 0x08000000.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
}
