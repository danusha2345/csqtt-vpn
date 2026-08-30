//go:build linux

package core

import "os"

func isElevated() bool { return os.Geteuid() == 0 }
