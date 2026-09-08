package core

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

func runCommandContext(parent context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if err := parent.Err(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	decoded := decodeCommandOutput(out)
	if ctx.Err() != nil {
		return decoded, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	return decoded, err
}
