//go:build !windows

package core

// isElevated — заглушка для сборки/vet на не-Windows (системный VPN там всё равно
// не поддерживается, см. tun_other.go).
func isElevated() bool { return false }
