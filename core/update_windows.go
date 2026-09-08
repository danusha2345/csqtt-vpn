//go:build windows

package core

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func verifyUpdateCleanup(ctx context.Context, routes []string, physIf string) error {
	// Не полагаемся на best-effort Disconnect: PowerShell errors запрещают install.
	script := `$ErrorActionPreference='Stop'; $allRoutes=@(Get-NetRoute -ErrorAction Stop); $a=Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {$_.Name -eq 'CSQTT'}; if($a){ Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses; if($allRoutes | Where-Object {$_.InterfaceIndex -eq $a.ifIndex -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')}){throw 'CSQTT routes remain'} }; if(Get-DnsClientNrptRule | Where-Object {$_.Comment -eq 'CSQTT_MANAGED' -or $_.DisplayName -eq 'CSQTT DNS'}){throw 'CSQTT NRPT remains'};`
	if len(routes) > 0 {
		idx, e := strconv.Atoi(physIf)
		if e != nil || idx <= 0 {
			return fmt.Errorf("неизвестен физический ifIndex для проверки bypass")
		}
		for _, r := range routes {
			p := strings.SplitN(r, " mask ", 2)
			if len(p) != 2 {
				return fmt.Errorf("неверный bypass route")
			}
			ip, mask := net.ParseIP(p[0]).To4(), net.ParseIP(p[1]).To4()
			if ip == nil || mask == nil {
				return fmt.Errorf("неверный bypass IP")
			}
			ones, bits := net.IPMask(mask).Size()
			if bits != 32 {
				return fmt.Errorf("неверная bypass mask")
			}
			prefix := fmt.Sprintf("%s/%d", ip.Mask(net.IPMask(mask)), ones)
			script += fmt.Sprintf(`if($allRoutes | Where-Object {$_.InterfaceIndex -eq %d -and $_.DestinationPrefix -eq '%s'}){throw 'CSQTT bypass remains'};`, idx, prefix)
		}
	}
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	hideConsole(cmd)
	if out, e := cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("очистка сети не подтверждена: %w: %s", e, decodeCommandOutput(out))
	}
	return nil
}
