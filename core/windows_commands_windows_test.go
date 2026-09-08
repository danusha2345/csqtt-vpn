//go:build windows

package core

import (
	"context"
	"strings"
	"testing"
)

func TestPowerShellBatchStopsAtIPv6Failure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		script, err := windowsSplitScript("12")
		if err != nil {
			t.Fatal(err)
		}
		failure := ""
		if fail {
			failure = "if ($DestinationPrefix -eq '::/1') { throw 'injected IPv6 failure' }"
		}
		// Functions shadow the real cmdlets. No routes or adapters are modified.
		mock := `function New-NetRoute { param($DestinationPrefix,$InterfaceIndex,$NextHop,$RouteMetric,$PolicyStore,$ErrorAction)
            Write-Host ('TRY:'+$DestinationPrefix)
            ` + failure + `
        }
        function Get-NetRoute { param($DestinationPrefix,$InterfaceIndex,$ErrorAction)
            [pscustomobject]@{DestinationPrefix=$DestinationPrefix}
        }
        `
		out, err := runHiddenContext(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", mock+script)
		if fail {
			if err == nil || !strings.Contains(out, "injected IPv6 failure") || strings.Contains(out, "TRY:8000::/1") {
				t.Fatalf("failed batch continued: %v %s", err, out)
			}
		} else if err != nil || !strings.Contains(out, "TRY:8000::/1") {
			t.Fatalf("successful batch incomplete: %v %s", err, out)
		}
	}
}
