# open-rmm winget module.
#
# winget is not on the PATH of the system account: the module runs the
# executable of the App Installer package directly. winget has no
# machine-readable output for upgrades, so the table is parsed using the
# column positions of its header (works with any display language).
#
# scan     applications with an available upgrade
# upgrade  { "ids": ["Mozilla.Firefox"] } or { "all": true, "exclude": ["Oracle.JavaRuntimeEnvironment"] }
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-List($Object, [string]$Name) {
    $v = Get-Prop $Object $Name
    if ($null -eq $v) { return , @() }
    return , @($v)
}

$idPattern = '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'

function Find-Winget {
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
    $found = Get-ChildItem -Path (Join-Path $env:ProgramFiles 'WindowsApps') -Filter "Microsoft.DesktopAppInstaller_*_${arch}__8wekyb3d8bbwe" -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'winget.exe') } |
        Sort-Object { try { [version]($_.Name -split '_')[1] } catch { [version]'0.0' } } -Descending |
        Select-Object -First 1
    if ($found) { return (Join-Path $found.FullName 'winget.exe') }
    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw 'winget (App Installer) is not installed on this endpoint'
}

function Invoke-Winget([string]$Exe, [string[]]$Arguments) {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $out = & $Exe @Arguments 2>&1 | ForEach-Object { [string]$_ }
    @{ code = $LASTEXITCODE; lines = @($out) }
}

# Parses winget tables: a header line, a line of dashes, then rows. Column
# starts come from the header words.
function ConvertFrom-WingetTable([string[]]$Lines) {
    $rows = @()
    $clean = @($Lines | ForEach-Object { ($_ -split "`r")[-1] })
    for ($i = 1; $i -lt $clean.Count; $i++) {
        if ($clean[$i] -notmatch '^-{10,}\s*$') { continue }
        $header = $clean[$i - 1]
        $starts = @([regex]::Matches($header, '\S+') | ForEach-Object { $_.Index })
        if ($starts.Count -lt 4) { continue }
        for ($j = $i + 1; $j -lt $clean.Count; $j++) {
            $line = $clean[$j]
            if ($line.Trim() -eq '' -or $line.Length -lt $starts[2]) { break }
            $cols = @()
            for ($c = 0; $c -lt $starts.Count; $c++) {
                $from = $starts[$c]
                if ($from -ge $line.Length) { $cols += ''; continue }
                $to = if ($c + 1 -lt $starts.Count) { [Math]::Min($starts[$c + 1], $line.Length) } else { $line.Length }
                $cols += $line.Substring($from, $to - $from).Trim()
            }
            $rows += , $cols
        }
    }
    $rows
}

function Get-Upgrades([string]$Exe) {
    $r = Invoke-Winget $Exe @('upgrade', '--include-unknown', '--accept-source-agreements', '--disable-interactivity')
    $apps = @()
    foreach ($cols in @(ConvertFrom-WingetTable $r.lines)) {
        # Name, Id, Version, Available, Source
        if ($cols.Count -lt 4) { continue }
        $id = $cols[1]
        if ($id -notmatch $idPattern) {
            Send-RmmLog "row skipped (truncated or unexpected id): $($cols -join ' | ')" 'warn'
            continue
        }
        $apps += @{ name = $cols[0]; id = $id; version = $cols[2]; available = $cols[3]; source = if ($cols.Count -gt 4) { $cols[4] } else { '' } }
    }
    $apps
}

function New-Report([string]$Exe) {
    $apps = @(Get-Upgrades $Exe)
    $check = if ($apps.Count -eq 0) {
        @{ id = 'thirdparty'; status = 'ok'; summary = 'Nessuna applicazione da aggiornare (winget)' }
    }
    else {
        @{ id = 'thirdparty'; status = 'warning'; summary = "$($apps.Count) applicazioni da aggiornare: $((@($apps | Select-Object -First 5 | ForEach-Object { $_.name })) -join ', ')" }
    }
    @{ scanned_at = (Get-Date).ToUniversalTime().ToString('o'); upgrades = $apps; checks = @($check) }
}

Invoke-RmmModule @{
    scan    = {
        param($Params, $Request)
        New-Report (Find-Winget)
    }
    upgrade = {
        param($Params, $Request)
        $exe = Find-Winget
        $ids = Get-List $Params 'ids'
        $exclude = Get-List $Params 'exclude'
        if (Get-Prop $Params 'all') {
            $ids = @(Get-Upgrades $exe | ForEach-Object { $_.id } | Where-Object { $exclude -notcontains $_ })
        }
        if ($ids.Count -eq 0) { throw 'no applications to upgrade: give ids, or all' }
        $results = @()
        $n = 0
        foreach ($id in $ids) {
            $id = [string]$id
            if ($id -notmatch $idPattern) { throw "invalid package id: $id" }
            $n++
            Send-RmmProgress ([int](100 * $n / ($ids.Count + 1))) $id
            $r = Invoke-Winget $exe @('upgrade', '--id', $id, '--exact', '--silent', '--include-unknown',
                '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
            $results += @{ id = $id; exit_code = ('0x{0:X8}' -f $r.code); ok = ($r.code -eq 0); output = (($r.lines | Select-Object -Last 5) -join "`n") }
        }
        $report = New-Report $exe
        $report.upgraded = $results
        $report
    }
}
