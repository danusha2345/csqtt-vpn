//go:build !windows

package core

import "os/exec"

// hideConsole — no-op на не-Windows (нужно для сборки/vet на Linux).
func hideConsole(cmd *exec.Cmd) {}
