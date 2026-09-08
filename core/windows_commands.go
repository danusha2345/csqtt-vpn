package core

import (
	"fmt"
	"strconv"
	"strings"
)

func psQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

// Keep cleanup restricted to this installation, adapter and managed NRPT rules.
func windowsCleanupScript(target, adapter, display, comment string) string {
	script := "$ErrorActionPreference = 'Stop'\n"
	if target != "" {
		script += fmt.Sprintf("$target = %s\nGet-CimInstance Win32_Process -Filter \"Name='csqtt-client.exe'\" -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -eq $target } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }\n", psQuote(target))
	}
	return script + fmt.Sprintf(`Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq %s -or $_.Comment -eq %s } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }
foreach ($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
    Get-NetRoute -DestinationPrefix $prefix -InterfaceAlias %s -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
}
Clear-DnsClientCache -ErrorAction SilentlyContinue
`, psQuote(display), psQuote(comment), psQuote(adapter))
}

func windowsSplitScript(index string) (string, error) {
	n, err := strconv.ParseUint(index, 10, 32)
	if err != nil || n == 0 {
		return "", fmt.Errorf("invalid adapter index %q", index)
	}
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$routes = [ordered]@{'0.0.0.0/1'='0.0.0.0';'128.0.0.0/1'='0.0.0.0';'::/1'='::';'8000::/1'='::'}
foreach ($prefix in $routes.Keys) {
    New-NetRoute -DestinationPrefix $prefix -InterfaceIndex %d -NextHop $routes[$prefix] -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    $installed = Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex %d -ErrorAction Stop
    if ($null -eq $installed) { throw "Route verification failed: $prefix" }
}
`, n, n), nil
}
