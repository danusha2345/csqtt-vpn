//go:build windows

package core

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"testing"
)

func TestWintunPacketErrorClassification(t *testing.T) {
	for _, err := range []error{windows.ERROR_INVALID_DATA, windows.ERROR_BAD_LENGTH} {
		if !isRejectedWintunPacket(fmt.Errorf("Write failed: %w", err)) {
			t.Fatal(err)
		}
	}
	for _, err := range []error{os.ErrClosed, windows.ERROR_ACCESS_DENIED, windows.ERROR_HANDLE_EOF, windows.ERROR_INVALID_PARAMETER} {
		if isRejectedWintunPacket(err) {
			t.Fatal("fatal error classified as bad packet", err)
		}
	}
}
