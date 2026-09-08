//go:build !windows

package core

import "context"

func verifyUpdateCleanup(context.Context, []string, string) error { return nil }
