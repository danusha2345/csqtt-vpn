//go:build !windows

package main

func (a *App) SetAutoStart(v bool) error { return nil }
func (a *App) GetAutoStart() bool        { return false }
