[CmdletBinding()]
param(
    [string]$Domains = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$utf8 = New-Object System.Text.UTF8Encoding($true)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $env:TEMP "WDTT-Diagnostics"
}
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $OutputDirectory "WDTT-diagnostics-$stamp.txt"
$script:report = New-Object System.Collections.Generic.List[string]
[System.IO.File]::WriteAllText($reportPath, "", $utf8)

function Add-Line {
    param([AllowEmptyString()][string]$Text = "")
    [void]$script:report.Add($Text)
    [System.IO.File]::AppendAllText($reportPath, $Text + [Environment]::NewLine, $utf8)
}

function Add-Section {
    param([string]$Title)
    Add-Line ""
    Add-Line ("=" * 78)
    Add-Line $Title
    Add-Line ("=" * 78)
}

function Protect-Text {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return "" }
    $safe = $Text
    $safe = $safe -replace '(?im)^\s*(Password|PrivateKey|PresharedKey)\s*[:=].*$', '$1 = [REDACTED]'
    $safe = $safe -replace '(?i)(https?://vk\.com/call/join/)[^\s"''&]+', '$1[REDACTED]'
    $safe = $safe -replace '(?i)(CAPTCHA_RESULT\|)[^\s]+', '$1[REDACTED]'
    return $safe
}

function Add-Result {
    param(
        [string]$Title,
        [scriptblock]$Action
    )
    Add-Line ""
    Add-Line ("--- {0} ---" -f $Title)
    try {
        $text = (& $Action 2>&1 | Out-String -Width 300).TrimEnd()
        if ([string]::IsNullOrWhiteSpace($text)) { $text = "[нет данных]" }
        Add-Line (Protect-Text $text)
    } catch {
        Add-Line ("[ошибка] {0}" -f $_.Exception.Message)
    }
}

trap {
    try {
        Add-Line ""
        Add-Line ("[КРИТИЧЕСКАЯ ОШИБКА] {0}" -f $_.Exception.Message)
        Add-Line ("Строка: {0}" -f $_.InvocationInfo.ScriptLineNumber)
    } catch {}
    continue
}

& chcp.com 65001 2>&1 | Out-Null

function Test-TcpPort {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 2500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return "TIMEOUT"
        }
        $client.EndConnect($pending)
        return "OPEN"
    } catch {
        $message = $_.Exception.Message
        if ($null -ne $_.Exception.InnerException) {
            $message = $_.Exception.InnerException.Message
        }
        return "CLOSED: $message"
    } finally {
        $client.Close()
    }
}

function Get-SafeWDTTConfig {
    $candidates = @(
        (Join-Path $env:APPDATA "wdtt\config.json"),
        (Join-Path $env:LOCALAPPDATA "wdtt\config.json")
    ) | Select-Object -Unique

    foreach ($path in $candidates) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $cfg = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
            [pscustomobject]@{
                Path       = $path
                Modified   = (Get-Item -LiteralPath $path).LastWriteTime
                Server     = $cfg.server
                Workers    = $cfg.workers
                SystemVPN  = $cfg.systemVPN
                ObfsMode   = $cfg.obfsMode
                Excludes   = $cfg.excludes
                VKLinkCount = @($cfg.vkLinks -split '[,\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
                Password   = "[REDACTED]"
            }
        } catch {
            [pscustomobject]@{ Path = $path; Error = $_.Exception.Message }
        }
    }
}

function Normalize-DomainList {
    param([string]$Raw)
    $items = @("ya.ru", "google.com", "github.com", "microsoft.com", "vk.com")
    if (-not [string]::IsNullOrWhiteSpace($Raw)) {
        $items += $Raw -split '[,;\s]+'
    }
    $clean = foreach ($item in $items) {
        $name = $item.Trim().ToLowerInvariant()
        $name = $name -replace '^https?://', ''
        $name = ($name -split '/')[0]
        $name = $name.TrimEnd('.')
        if ($name -match '^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$') { $name }
    }
    return @($clean | Select-Object -Unique)
}

Add-Line "WDTT Windows Diagnostics v2"
Add-Line "ВАЖНО: для диагностики сбоя отчёт нужно собирать при ВКЛЮЧЁННОМ VPN."
Add-Line "Утилита ничего не меняет: не перезапускает процессы, сеть или службы."
Add-Line "Created: $((Get-Date).ToString('o'))"
Add-Line "Computer: $env:COMPUTERNAME"
Add-Line "User: $env:USERNAME"
Add-Line "PowerShell: $($PSVersionTable.PSVersion)"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
Add-Line "Administrator: $($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"

Add-Section "1. WDTT: процессы, конфигурация и локальные порты"
Add-Result "Процессы (без CommandLine, чтобы не раскрывать пароль/VK links)" {
    Get-Process -Name "WDTT-VPN", "wdtt-client", "wireproxy", "tun2socks" -ErrorAction SilentlyContinue |
        Select-Object ProcessName, Id, StartTime, Path, FileVersion |
        Format-Table -AutoSize
}
Add-Result "Безопасная часть config.json" { Get-SafeWDTTConfig | Format-List }
Add-Result "Локальные TCP-порты" {
    [pscustomobject]@{ Address = "127.0.0.1"; Port = 9000; Purpose = "wdtt-client"; State = (Test-TcpPort "127.0.0.1" 9000) }
    [pscustomobject]@{ Address = "127.0.0.1"; Port = 1080; Purpose = "wireproxy SOCKS5"; State = (Test-TcpPort "127.0.0.1" 1080) }
}
Add-Result "Listeners :53/:9000/:1080" {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in 53, 9000, 1080 } |
        Select-Object LocalAddress, LocalPort, OwningProcess, State | Format-Table -AutoSize
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in 53, 9000, 1080 } |
        Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
}

Add-Section "2. Адаптеры, адреса и DNS"
Add-Result "Get-NetAdapter" {
    Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed |
        Sort-Object ifIndex | Format-Table -AutoSize
}
Add-Result "Get-NetIPConfiguration" {
    Get-NetIPConfiguration -All -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, InterfaceIndex, IPv4Address, IPv4DefaultGateway, IPv6Address, IPv6DefaultGateway, DNSServer |
        Format-List
}
Add-Result "DNS по интерфейсам" {
    Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses.Count -gt 0 } |
        Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses |
        Sort-Object InterfaceIndex, AddressFamily | Format-Table -AutoSize
}
Add-Result "ipconfig /all" { & ipconfig.exe /all }

Add-Section "3. Маршрутизация IPv4 и IPv6"
Add-Result "Ключевые IPv4 routes" {
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DestinationPrefix -in "0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "10.7.0.0/24" -or
            $_.InterfaceAlias -like "*wdtt*"
        } |
        Select-Object DestinationPrefix, NextHop, RouteMetric, ifIndex, InterfaceAlias, State |
        Sort-Object DestinationPrefix, RouteMetric | Format-Table -AutoSize
}
Add-Result "Ключевые IPv6 routes" {
    Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DestinationPrefix -in "::/0", "::/1", "8000::/1" -or
            $_.InterfaceAlias -like "*wdtt*"
        } |
        Select-Object DestinationPrefix, NextHop, RouteMetric, ifIndex, InterfaceAlias, State |
        Sort-Object DestinationPrefix, RouteMetric | Format-Table -AutoSize
}
Add-Result "route print -4" { & route.exe print -4 }
Add-Result "route print -6" { & route.exe print -6 }

Add-Section "4. DNS-проверки"
$domains = Normalize-DomainList $Domains
foreach ($domain in $domains) {
    Add-Result "System DNS A/AAAA: $domain" {
        Resolve-DnsName -Name $domain -Type A -DnsOnly -ErrorAction Continue |
            Select-Object Name, Type, IPAddress, NameHost, QueryType | Format-Table -AutoSize
        Resolve-DnsName -Name $domain -Type AAAA -DnsOnly -ErrorAction Continue |
            Select-Object Name, Type, IPAddress, NameHost, QueryType | Format-Table -AutoSize
    }
}
Add-Result "nslookup ya.ru через DNS WDTT 10.7.0.2" { & nslookup.exe -timeout=3 ya.ru 10.7.0.2 }
Add-Result "nslookup ya.ru через Cloudflare 1.1.1.1" { & nslookup.exe -timeout=3 ya.ru 1.1.1.1 }

Add-Section "5. Доступность, HTTP, SOCKS5 и MTU"
Add-Result "Ping через предполагаемый туннель" {
    & ping.exe -n 2 -w 2500 10.7.0.2
    & ping.exe -n 2 -w 2500 1.1.1.1
    & ping.exe -n 2 -w 2500 77.88.55.242
}
Add-Result "MTU/fragmentation IPv4" {
    & ping.exe -4 -n 2 -w 2500 -f -l 1200 1.1.1.1
    & ping.exe -4 -n 2 -w 2500 -f -l 1252 1.1.1.1
}

$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($null -eq $curl) {
    Add-Line ""
    Add-Line "[предупреждение] curl.exe не найден; HTTP/SOCKS проверки пропущены."
} else {
    Add-Result "Публичный IP: системный путь IPv4" {
        & curl.exe -4 --connect-timeout 5 --max-time 12 --silent --show-error https://api.ipify.org
    }
    Add-Result "Публичный IP: системный путь IPv6" {
        & curl.exe -6 --connect-timeout 5 --max-time 12 --silent --show-error https://api64.ipify.org
    }
    Add-Result "Публичный IP через SOCKS5 127.0.0.1:1080" {
        & curl.exe -4 --socks5-hostname 127.0.0.1:1080 --connect-timeout 5 --max-time 15 --silent --show-error https://api.ipify.org
    }
    foreach ($domain in $domains) {
        Add-Result "HTTPS IPv4: $domain" {
            & curl.exe -4 --connect-timeout 6 --max-time 15 --location --output NUL --silent --show-error `
                --write-out "http=%{http_code} remote=%{remote_ip} dns=%{time_namelookup}s connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s`n" `
                "https://$domain/"
        }
        Add-Result "HTTPS IPv6: $domain" {
            & curl.exe -6 --connect-timeout 4 --max-time 8 --location --output NUL --silent --show-error `
                --write-out "http=%{http_code} remote=%{remote_ip} total=%{time_total}s`n" `
                "https://$domain/"
        }
    }
}

Add-Section "6. Итоговые признаки"
$wdttAdapter = Get-NetAdapter -Name "wdtt" -ErrorAction SilentlyContinue
$split4 = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in "0.0.0.0/1", "128.0.0.0/1" }).Count
$split6 = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in "::/1", "8000::/1" }).Count
$socksState = Test-TcpPort "127.0.0.1" 1080
$dns53 = Test-TcpPort "10.7.0.2" 53
Add-Line "wdtt adapter present: $($null -ne $wdttAdapter)"
Add-Line "IPv4 split-default routes: $split4/2"
Add-Line "IPv6 blackhole routes: $split6/2"
Add-Line "wireproxy SOCKS5 127.0.0.1:1080: $socksState"
Add-Line "WDTT DNS TCP 10.7.0.2:53: $dns53"
Add-Line ""
Add-Line "Перед отправкой можно открыть файл и дополнительно проверить его содержимое."

Write-Host ""
Write-Host "Диагностика завершена:" -ForegroundColor Green
Write-Host $reportPath -ForegroundColor Cyan
Write-Output $reportPath
