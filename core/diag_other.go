//go:build !windows && !linux

package core

func Diagnostics() string {
	return "диагностика недоступна на этой платформе"
}
