//go:build windows

package core

import (
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hideConsole прячет консольное окно дочернего csqtt-client.exe.
// CREATE_NO_WINDOW = 0x08000000.
func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
}

var (
	jobOnce sync.Once
	jobH    windows.Handle
)

// killJob возвращает job-объект с JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: когда GUI
// умирает (в том числе при снятии из Task Manager), Windows сама убивает всю
// цепочку. Без этого transport может пережить GUI и оставить системные маршруты.
func killJob() windows.Handle {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			_ = windows.CloseHandle(h)
			return
		}
		jobH = h
	})
	return jobH
}

// attachJob привязывает уже запущенный процесс к job-объекту. Вызывается сразу
// после cmd.Start(); ошибка не фатальна — процесс работает и без привязки, просто
// теряется гарантия его убийства вместе с GUI.
func attachJob(cmd *exec.Cmd) {
	j := killJob()
	if j == 0 || cmd.Process == nil {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return
	}
	defer func() { _ = windows.CloseHandle(h) }()
	_ = windows.AssignProcessToJobObject(j, h)
}
