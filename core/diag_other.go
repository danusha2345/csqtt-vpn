//go:build !windows

package core

func Diagnostics() string { return "диагностика доступна только на Windows" }
