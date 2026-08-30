//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const autoStartName = "CSQTT-VPN"

// SetAutoStart включает/выключает автозапуск при входе в Windows (HKCU\...\Run).
func (a *App) SetAutoStart(v bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !v {
		err = k.DeleteValue(autoStartName)
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue(autoStartName, exe)
}

// GetAutoStart сообщает, включён ли автозапуск.
func (a *App) GetAutoStart() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(autoStartName)
	return err == nil
}
