# open-rmm firmware module: BIOS, firmware and driver updates through the
# vendor tools, which know the right packages for each model.
#
#   Dell    Dell Command Update (dcu-cli.exe), winget id Dell.CommandUpdate
#   Lenovo  Lenovo System Update (tvsu.exe), winget id Lenovo.SystemUpdate
#   HP      HP Image Assistant (HPImageAssistant.exe), business models only
#
# The tools are not installed by this module: distribute them from the
# Software page. Nothing here reboots: a needed reboot is recorded for the
# reboot module. Before a BIOS update BitLocker is suspended for one reboot,
# or the next start would ask for the recovery key.
#
# scan
# install  { "types": ["firmware", "driver"], "include_bios": false,
#            "severity": "all" | "recommended" | "critical" }
#
# Tool paths and arguments can be overridden for validation on real
# endpoints: { "dcu_path": "...", "tvsu_path": "...", "lenovo_wmi_class": "...",
#              "hpia_path": "..." }
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

function Get-Prop($Object, [string]$Name, $Default = $null) {
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return $p.Value }
    return $Default
}

function Set-RebootMarker([string]$Reason) {
    $key = 'HKLM:\SOFTWARE\open-rmm-modules'
    if (-not (Test-Path $key)) { [void](New-Item -Path $key -Force) }
    Set-ItemProperty -Path $key -Name 'RebootRequiredAt' -Value (Get-Date).ToUniversalTime().ToString('o')
    Set-ItemProperty -Path $key -Name 'RebootRequiredBy' -Value $Reason
}

function Get-Vendor {
    $m = [string](Get-CimInstance Win32_ComputerSystem).Manufacturer
    switch -Regex ($m) {
        '^\s*Dell' { return 'dell' }
        '^\s*LENOVO' { return 'lenovo' }
        '^\s*(HP|Hewlett)' { return 'hp' }
        default { return $m.Trim() }
    }
}

function Find-Tool([string[]]$Candidates) {
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    return $null
}

# Normalized categories and severities.
function ConvertTo-Category([string]$Type) {
    switch -Regex ($Type) {
        'bios' { 'bios' }
        'firmware' { 'firmware' }
        'driver' { 'driver' }
        'application|utility|software' { 'application' }
        default { 'other' }
    }
}

function ConvertTo-Severity([string]$Value) {
    switch -Regex ($Value) {
        'urgent|critical|security' { 'critical' }
        'recommended' { 'recommended' }
        default { 'optional' }
    }
}

function ConvertTo-IsoDate([string]$Value) {
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) {
        return $d.ToUniversalTime().ToString('o')
    }
    return $null
}

# ---- Dell ----

function Get-DcuPath($Params) {
    Find-Tool @((Get-Prop $Params 'dcu_path'),
        (Join-Path $env:ProgramFiles 'Dell\CommandUpdate\dcu-cli.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Dell\CommandUpdate\dcu-cli.exe'))
}

function Get-DellUpdates([string]$Dcu) {
    $dir = Join-Path $env:OPENRMM_WORK_DIR 'dcu-report'
    [void](New-Item -ItemType Directory -Path $dir -Force)
    $out = & $Dcu /scan "-report=$dir" -silent 2>&1 | ForEach-Object { [string]$_ }
    $code = $LASTEXITCODE
    # 500: no updates found.
    if ($code -ne 0 -and $code -ne 500) {
        throw "dcu-cli /scan failed with exit code $code`: $((@($out) | Select-Object -Last 3) -join ' ')"
    }
    $file = Get-ChildItem -Path $dir -Filter '*.xml' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $file) { return @() }
    [xml]$xml = Get-Content -LiteralPath $file.FullName -Raw
    $list = @()
    foreach ($u in @($xml.updates.update)) {
        if ($null -eq $u) { continue }
        $list += @{
            id        = [string]$u.release
            title     = [string]$u.name
            version   = [string]$u.version
            category  = ConvertTo-Category ([string]$u.type)
            severity  = ConvertTo-Severity ([string]$u.urgency)
            released  = ConvertTo-IsoDate ([string]$u.date)
            size_bytes = [int64]([string]$u.bytes -as [int64])
        }
    }
    $list
}

function Install-Dell([string]$Dcu, [string[]]$Types, [string]$Severity) {
    $sev = switch ($Severity) { 'critical' { 'security,critical' } 'recommended' { 'security,critical,recommended' } default { 'security,critical,recommended,optional' } }
    $log = Join-Path $env:OPENRMM_WORK_DIR 'dcu-apply.log'
    $out = & $Dcu /applyUpdates -silent -reboot=disable "-updateType=$($Types -join ',')" "-updateSeverity=$sev" -autoSuspendBitLocker=enable "-outputLog=$log" 2>&1 | ForEach-Object { [string]$_ }
    $code = $LASTEXITCODE
    # 0 done, 1 and 5 reboot needed, 500 nothing to install.
    $reboot = $code -eq 1 -or $code -eq 5
    if ($code -ne 0 -and -not $reboot -and $code -ne 500) {
        throw "dcu-cli /applyUpdates failed with exit code $code`: $((@($out) | Select-Object -Last 3) -join ' ')"
    }
    @{ exit_code = $code; reboot = $reboot }
}

# ---- Lenovo ----

function Get-TvsuPath($Params) {
    Find-Tool @((Get-Prop $Params 'tvsu_path'),
        (Join-Path ${env:ProgramFiles(x86)} 'Lenovo\System Update\tvsu.exe'),
        (Join-Path $env:ProgramFiles 'Lenovo\System Update\tvsu.exe'))
}

# System Update package types: 1 application, 2 driver, 3 BIOS, 4 firmware.
$LenovoTypes = @{ application = 1; driver = 2; bios = 3; firmware = 4 }

function Invoke-Tvsu([string]$Tvsu, [string[]]$Arguments) {
    $p = Start-Process -FilePath $Tvsu -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    $p.ExitCode
}

function Get-LenovoUpdates([string]$Tvsu, [string]$WmiClass) {
    # -exporttowmi publishes the result in WMI, the documented way to read
    # System Update from scripts.
    [void](Invoke-Tvsu $Tvsu @('/CM', '-search', 'A', '-action', 'LIST', '-includerebootpackages', '1,3,4', '-noicon', '-nolicense', '-exporttowmi'))
    $items = @(Get-CimInstance -Namespace 'root\Lenovo' -ClassName $WmiClass -ErrorAction SilentlyContinue)
    $list = @()
    foreach ($u in $items) {
        $status = [string](Get-Prop $u 'Status' '')
        if ($status -and $status -notmatch 'applicable|available|not installed') { continue }
        $title = [string](Get-Prop $u 'Title' '')
        $list += @{
            id       = [string](Get-Prop $u 'PackageID' '')
            title    = $title
            version  = [string](Get-Prop $u 'Version' '')
            category = ConvertTo-Category ("$(Get-Prop $u 'PackageType' '') $title")
            severity = ConvertTo-Severity ([string](Get-Prop $u 'Severity' ''))
            released = ConvertTo-IsoDate ([string](Get-Prop $u 'ReleaseDate' ''))
        }
    }
    $list
}

function Install-Lenovo([string]$Tvsu, [string[]]$Types, [string]$Severity) {
    $search = switch ($Severity) { 'critical' { 'C' } 'recommended' { 'R' } default { 'A' } }
    $pt = (@($Types | ForEach-Object { $LenovoTypes[$_] } | Where-Object { $_ }) -join ',')
    $code = Invoke-Tvsu $Tvsu @('/CM', '-search', $search, '-action', 'INSTALL', '-packagetypes', $pt,
        '-includerebootpackages', '1,3,4', '-noreboot', '-noicon', '-nolicense', '-exporttowmi')
    @{ exit_code = $code; reboot = ($Types -contains 'bios') -or ($Types -contains 'firmware') }
}

# ---- HP ----

function Get-HpiaPath($Params) {
    Find-Tool @((Get-Prop $Params 'hpia_path'),
        (Join-Path $env:ProgramFiles 'HP\HPIA\HPImageAssistant.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'HP\HPIA\HPImageAssistant.exe'),
        (Join-Path $env:ProgramFiles 'HPImageAssistant\HPImageAssistant.exe'),
        (Join-Path $env:SystemDrive 'HPIA\HPImageAssistant.exe'))
}

# HP Image Assistant categories and selections.
$HpCategories = @{ bios = 'BIOS'; driver = 'Drivers'; firmware = 'Firmware'; application = 'Software' }

# Exit codes: 0 done, 256/257 nothing to do, 3010 reboot needed, 3020 some
# packages failed, 4096 platform not supported.
function Invoke-Hpia([string]$Hpia, [string[]]$Arguments) {
    $p = Start-Process -FilePath $Hpia -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    $p.ExitCode
}

function Read-HpiaReport([string]$Dir) {
    $file = Get-ChildItem -Path $Dir -Filter '*.json' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $file) { return @() }
    $json = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    $recs = @(Get-Prop (Get-Prop $json 'HPIA') 'Recommendations' @())
    $list = @()
    foreach ($r in $recs) {
        $sp = Get-Prop $r 'SoftPaq'
        $component = "$(Get-Prop $r 'Category' '') $(Get-Prop $r 'TargetComponent' '')"
        $category = switch -Regex ($component) {
            'bios' { 'bios' }
            'firmware' { 'firmware' }
            'software|application|accessor' { 'application' }
            default { 'driver' }
        }
        $list += @{
            id       = [string](Get-Prop $sp 'Id' '')
            title    = [string](Get-Prop $sp 'Name' (Get-Prop $r 'TargetComponent' ''))
            version  = [string](Get-Prop $sp 'Version' (Get-Prop $r 'ReferenceVersion' ''))
            category = $category
            severity = ConvertTo-Severity ([string](Get-Prop $r 'RecommendationValue' ''))
            released = ConvertTo-IsoDate ([string](Get-Prop $sp 'ReleaseDate' ''))
        }
    }
    $list
}

function Get-HpUpdates([string]$Hpia) {
    $dir = Join-Path $env:OPENRMM_WORK_DIR 'hpia-report'
    [void](New-Item -ItemType Directory -Path $dir -Force)
    $code = Invoke-Hpia $Hpia @('/Operation:Analyze', '/Action:List', '/Category:All', '/Selection:All', '/Silent', "/ReportFolder:$dir")
    if ($code -eq 4096) { return $null }
    if ($code -notin 0, 256, 257, 3010) { throw "HP Image Assistant analysis failed with exit code $code" }
    @(Read-HpiaReport $dir)
}

function Install-Hp([string]$Hpia, [string[]]$Types, [string]$Severity) {
    $dir = Join-Path $env:OPENRMM_WORK_DIR 'hpia-report'
    $dl = Join-Path $env:OPENRMM_WORK_DIR 'hpia-softpaqs'
    [void](New-Item -ItemType Directory -Path $dir, $dl -Force)
    $cats = (@($Types | ForEach-Object { $HpCategories[$_] } | Where-Object { $_ }) -join ',')
    $sel = switch ($Severity) { 'critical' { 'Critical' } 'recommended' { 'Recommended' } default { 'All' } }
    $code = Invoke-Hpia $Hpia @('/Operation:Analyze', '/Action:Install', "/Category:$cats", "/Selection:$sel", '/Silent',
        "/ReportFolder:$dir", "/SoftpaqDownloadFolder:$dl")
    if ($code -notin 0, 256, 257, 3010, 3020) { throw "HP Image Assistant install failed with exit code $code" }
    if ($code -eq 3020) { Send-RmmLog 'HP Image Assistant: some packages failed to install' 'warn' }
    @{ exit_code = $code; reboot = ($code -eq 3010) -or ($Types -contains 'bios') }
}

# ---- common ----

# A BIOS update on battery can leave the PC unbootable: laptops must be on
# mains power with enough charge.
function Test-PowerForBios([int]$MinPercent) {
    $batteries = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
    if ($batteries.Count -eq 0) { return $null }
    foreach ($b in $batteries) {
        # BatteryStatus 2, 3, 6-9, 11: on mains power.
        if ([int]$b.BatteryStatus -notin 2, 3, 6, 7, 8, 9, 11) { return 'the PC is running on battery' }
        if ([int]$b.EstimatedChargeRemaining -lt $MinPercent) { return "battery below $MinPercent%" }
    }
    return $null
}

function Suspend-BitLockerOnce {
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if ($vol -and [string]$vol.ProtectionStatus -eq 'On') {
        Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 1 | Out-Null
        Send-RmmLog 'BitLocker suspended for one reboot (BIOS update)'
        return $true
    }
    return $false
}

function New-Report($Params) {
    $vendor = Get-Vendor
    $report = @{ scanned_at = (Get-Date).ToUniversalTime().ToString('o'); vendor = $vendor; supported = $false; updates = @() }
    switch ($vendor) {
        'dell' {
            $dcu = Get-DcuPath $Params
            if (-not $dcu) {
                $report.tool_missing = 'Dell Command Update'
                $report.checks = @(@{ id = 'firmware'; status = 'warning'; summary = 'Dell Command Update non installato: distribuiscilo dalla pagina Software (Dell.CommandUpdate)' })
                return $report
            }
            $report.supported, $report.tool = $true, 'Dell Command Update'
            $report.updates = @(Get-DellUpdates $dcu)
        }
        'lenovo' {
            $tvsu = Get-TvsuPath $Params
            if (-not $tvsu) {
                $report.tool_missing = 'Lenovo System Update'
                $report.checks = @(@{ id = 'firmware'; status = 'warning'; summary = 'Lenovo System Update non installato: distribuiscilo dalla pagina Software (Lenovo.SystemUpdate)' })
                return $report
            }
            $report.supported, $report.tool = $true, 'Lenovo System Update'
            $report.updates = @(Get-LenovoUpdates $tvsu (Get-Prop $Params 'lenovo_wmi_class' 'Lenovo_Updates'))
        }
        'hp' {
            $hpia = Get-HpiaPath $Params
            if (-not $hpia) {
                $report.tool_missing = 'HP Image Assistant'
                $report.checks = @(@{ id = 'firmware'; status = 'warning'; summary = 'HP Image Assistant non installato: distribuiscilo dalla pagina Software' })
                return $report
            }
            $updates = Get-HpUpdates $hpia
            if ($null -eq $updates) {
                $report.checks = @(@{ id = 'firmware'; status = 'ok'; summary = 'Modello HP non supportato da HP Image Assistant' })
                return $report
            }
            $report.supported, $report.tool = $true, 'HP Image Assistant'
            $report.updates = @($updates)
        }
        default {
            $report.checks = @(@{ id = 'firmware'; status = 'ok'; summary = "Produttore $vendor non supportato per gli aggiornamenti firmware" })
            return $report
        }
    }
    $bios = @($report.updates | Where-Object { $_.category -eq 'bios' })
    $critical = @($report.updates | Where-Object { $_.severity -eq 'critical' })
    $check = if ($report.updates.Count -eq 0) {
        @{ id = 'firmware'; status = 'ok'; summary = 'BIOS, firmware e driver aggiornati' }
    }
    else {
        $parts = @("$($report.updates.Count) aggiornamenti firmware/driver")
        if ($bios.Count) { $parts += 'BIOS da aggiornare' }
        if ($critical.Count) { $parts += "$($critical.Count) critici" }
        @{ id = 'firmware'; status = $(if ($critical.Count -or $bios.Count) { 'warning' } else { 'ok' }); summary = $parts -join ', ' }
    }
    $report.checks = @($check)
    $report
}

Invoke-RmmModule @{
    scan    = {
        param($Params, $Request)
        New-Report $Params
    }
    install = {
        param($Params, $Request)
        $types = @(Get-Prop $Params 'types' @('firmware', 'driver')) | ForEach-Object { ([string]$_).ToLowerInvariant() }
        $types = @($types | Where-Object { $_ -in 'firmware', 'driver', 'application' })
        if (Get-Prop $Params 'include_bios' $false) { $types += 'bios' }
        if ($types.Count -eq 0) { throw 'no update types selected' }
        $severity = [string](Get-Prop $Params 'severity' 'all')
        $vendor = Get-Vendor
        if ($types -contains 'bios') {
            $why = Test-PowerForBios ([int](Get-Prop $Params 'min_battery_percent' 50))
            if ($why) { throw "BIOS update refused: $why" }
        }
        $suspended = $false
        if ($types -contains 'bios' -and $vendor -in 'lenovo', 'hp') { $suspended = Suspend-BitLockerOnce }
        Send-RmmProgress 10 "installing $($types -join ', ')"
        $r = switch ($vendor) {
            'dell' {
                $dcu = Get-DcuPath $Params
                if (-not $dcu) { throw 'Dell Command Update is not installed' }
                Install-Dell $dcu $types $severity
            }
            'lenovo' {
                $tvsu = Get-TvsuPath $Params
                if (-not $tvsu) { throw 'Lenovo System Update is not installed' }
                Install-Lenovo $tvsu $types $severity
            }
            'hp' {
                $hpia = Get-HpiaPath $Params
                if (-not $hpia) { throw 'HP Image Assistant is not installed' }
                Install-Hp $hpia $types $severity
            }
            default { throw "vendor $vendor is not supported" }
        }
        if ($r.reboot) { Set-RebootMarker 'firmware' }
        Send-RmmProgress 90 'rescanning'
        $report = New-Report $Params
        $report.installed = @{ types = $types; exit_code = $r.exit_code; reboot_required = $r.reboot; bitlocker_suspended = $suspended }
        $report
    }
}
