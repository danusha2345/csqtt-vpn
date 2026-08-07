//go:build !windows

package core

import "os/exec"

// hideConsole — no-op на не-Windows (нужно для сборки/vet на Linux).
func hideConsole(cmd *exec.Cmd) {}

// attachJob — no-op на не-Windows: job-объекты есть только в Windows.
func attachJob(cmd *exec.Cmd) {}
