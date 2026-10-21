# open-rmm Windows Update module (Windows Update Agent COM API).
#
# scan     lists the missing updates, the pending reboot and who manages
#          updates on the endpoint (WSUS, Intune or nobody).
# install  downloads and installs the selected updates. It never reboots:
#          the reboot module does, according to the reboot policy. On an
#          endpoint managed by WSUS or Intune it refuses to install unless
#          allow_managed is set (observation mode).
#
# Parameters (install):
#   { "classifications": ["security","critical","rollup","update","definition"],
#     "exclude_kbs": ["KB5030000"], "include_kbs": [], "allow_managed": false,
#     "max_age_days": 30 }
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

# Classification category ids (names are localized, ids are not).
$classifications = @{
    '0fa1201d-4330-4fa8-8ae9-b877473b6441' = 'security'
    'e6cf1350-c01b-414d-a61f-263d14d133b4' = 'critical'
    '28bc880e-0592-4cbf-8f95-c79b17911d5f' = 'rollup'
    'cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83' = 'update'
    'e0789628-ce08-4437-be74-2495b842f43b' = 'definition'
    'b54e7d24-7add-428f-8b75-90a396fa584f' = 'feature_pack'
    '68c5b0a3-d1a6-4553-ae49-01d3a7827828' = 'service_pack'
    '3689bdc8-b205-4af4-8d4a-a63924c5e9d5' = 'upgrade'
    'b4832bd8-e735-4761-8daf-37f882276dab' = 'tools'
    'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0' = 'driver'
}

function Get-Management {
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $server = [string](Get-ItemProperty -Path $wu -Name WUServer -ErrorAction SilentlyContinue).WUServer
    $use = (Get-ItemProperty -Path "$wu\AU" -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
    $mdm = Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -ErrorAction SilentlyContinue
    $by = 'none'
    if ($use -eq 1 -and $server) { $by = 'wsus' }
    elseif ($mdm -and @($mdm.GetValueNames()).Count -gt 0) { $by = 'intune' }
    @{ managed_by = $by; wsus_server = $server }
}

# Pending reboot and its reasons; the first time it was seen is kept in the
# module state directory.
function Get-PendingReboot([string]$StateDir) {
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'windows_update' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'component_servicing' }
    try { if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired -and $reasons -notcontains 'windows_update') { $reasons += 'windows_update' } } catch { }
    # Marker of the software module, valid until the next boot.
    $marker = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\open-rmm-modules' -Name RebootRequiredAt -ErrorAction SilentlyContinue).RebootRequiredAt
    if ($marker) {
        try {
            $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
            if ([datetime]::Parse($marker).ToUniversalTime() -gt $boot) { $reasons += 'software' }
        }
        catch { }
    }
    $rename = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($rename) { $reasons += 'file_rename' }
    # File renames alone are frequent and harmless: they do not make a reboot required.
    $required = [bool]($reasons | Where-Object { $_ -ne 'file_rename' })
    $since = $null
    if ($StateDir) {
        $f = Join-Path $StateDir 'reboot-pending-since.txt'
        if ($required) {
            if (Test-Path -LiteralPath $f) { $since = (Get-Content -LiteralPath $f -Raw).Trim() }
            else {
                $since = (Get-Date).ToUniversalTime().ToString('o')
                Set-Content -LiteralPath $f -Value $since -Encoding ASCII
            }
        }
        elseif (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
    }
    @{ required = $required; reasons = $reasons; since = $since }
}

function ConvertTo-UpdateInfo($u) {
    $class = ''
    $cats = @()
    foreach ($c in $u.Categories) {
        $id = ([string]$c.CategoryID).ToLower()
        if ($classifications.ContainsKey($id)) { $class = $classifications[$id] }
        elseif ([string]$c.Type -eq 'Product') { $cats += [string]$c.Name }
    }
    $released = $null
    if ($u.LastDeploymentChangeTime -is [datetime]) { $released = $u.LastDeploymentChangeTime.ToUniversalTime().ToString('o') }
    @{
        id              = [string]$u.Identity.UpdateID
        revision        = [int]$u.Identity.RevisionNumber
        title           = [string]$u.Title
        kbs             = @(foreach ($k in $u.KBArticleIDs) { "KB$k" })
        classification  = $class
        severity        = [string]$u.MsrcSeverity
        products        = $cats
        released        = $released
        size_bytes      = [int64]$u.MaxDownloadSize
        downloaded      = [bool]$u.IsDownloaded
        reboot_behavior = [int]$u.InstallationBehavior.RebootBehavior
    }
}

function Get-LastSuccess($Searcher) {
    try {
        $n = $Searcher.GetTotalHistoryCount()
        if ($n -le 0) { return $null }
        $last = $null
        foreach ($h in $Searcher.QueryHistory(0, [Math]::Min($n, 100))) {
            # Operation 1 = installation, ResultCode 2 = succeeded.
            if ($h.Operation -eq 1 -and $h.ResultCode -eq 2 -and ($null -eq $last -or $h.Date -gt $last)) { $last = $h.Date }
        }
        if ($last) { return $last.ToUniversalTime().ToString('o') }
    }
    catch { Send-RmmLog "history: $($_.Exception.Message)" 'warn' }
    return $null
}

function Invoke-Scan($Session) {
    $searcher = $Session.CreateUpdateSearcher()
    $searcher.Online = $true
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    @{ searcher = $searcher; updates = @(foreach ($u in $result.Updates) { $u }) }
}

function Get-Checks($Updates, $Pending, [int]$MaxAgeDays) {
    $now = (Get-Date).ToUniversalTime()
    $important = @($Updates | Where-Object { $_.classification -in 'security', 'critical' })
    $old = @($important | Where-Object { $_.released -and ($now - [datetime]$_.released).TotalDays -gt $MaxAgeDays })
    $checks = @()
    if ($old.Count -gt 0) {
        $checks += @{ id = 'updates'; status = 'failing'; summary = "$($important.Count) aggiornamenti di sicurezza mancanti, $($old.Count) usciti da più di $MaxAgeDays giorni" }
    }
    elseif ($important.Count -gt 0) {
        $checks += @{ id = 'updates'; status = 'warning'; summary = "$($important.Count) aggiornamenti di sicurezza da installare" }
    }
    else {
        $checks += @{ id = 'updates'; status = 'ok'; summary = "Nessun aggiornamento di sicurezza mancante ($($Updates.Count) altri disponibili)" }
    }
    if ($Pending.required) {
        $days = 0
        if ($Pending.since) { $days = [int]($now - [datetime]$Pending.since).TotalDays }
        $status = if ($days -ge 3) { 'warning' } else { 'ok' }
        $checks += @{ id = 'reboot'; status = $status; summary = "Riavvio in sospeso da $days giorni" }
    }
    else {
        $checks += @{ id = 'reboot'; status = 'ok'; summary = 'Nessun riavvio in sospeso' }
    }
    $checks
}

# Get-History lists the latest installations recorded by Windows Update,
# newest first: what is already installed, and what failed.
function Get-History($Searcher) {
    $out = @()
    try {
        $n = $Searcher.GetTotalHistoryCount()
        if ($n -le 0) { return @() }
        foreach ($h in $Searcher.QueryHistory(0, [Math]::Min($n, 200))) {
            if ($h.Operation -ne 1) { continue } # 1 = installation
            $title = [string]$h.Title
            $kbs = @([regex]::Matches($title, 'KB\d{6,8}') | ForEach-Object { $_.Value.ToUpper() } | Select-Object -Unique)
            $date = $null
            if ($h.Date -is [datetime]) { $date = $h.Date.ToUniversalTime().ToString('o') }
            $entry = @{ title = $title; kbs = $kbs; date = $date; result = $resultCodes[[int]$h.ResultCode] }
            if ([int]$h.ResultCode -ge 3) { $entry.hresult = ('0x{0:X8}' -f $h.HResult) }
            $out += $entry
        }
    }
    catch { Send-RmmLog "history: $($_.Exception.Message)" 'warn' }
    $out
}

function New-Report($Session, $Request, $Params) {
    $mgmt = Get-Management
    $scan = Invoke-Scan $Session
    $updates = @(foreach ($u in $scan.updates) { ConvertTo-UpdateInfo $u })
    $pending = Get-PendingReboot ([string]$Request.state_dir)
    $maxAge = Get-Prop $Params 'max_age_days'
    if (-not $maxAge) { $maxAge = 30 }
    @{
        managed_by     = $mgmt.managed_by
        wsus_server    = $mgmt.wsus_server
        scanned_at     = (Get-Date).ToUniversalTime().ToString('o')
        updates        = $updates
        pending_reboot = $pending
        last_success   = Get-LastSuccess $scan.searcher
        history        = @(Get-History $scan.searcher)
        checks         = @(Get-Checks $updates $pending ([int]$maxAge))
    }
}

function New-Session {
    $s = New-Object -ComObject Microsoft.Update.Session
    $s.ClientApplicationID = 'open-rmm'
    $s
}

$resultCodes = @{ 0 = 'not_started'; 1 = 'in_progress'; 2 = 'succeeded'; 3 = 'succeeded_with_errors'; 4 = 'failed'; 5 = 'aborted' }

Invoke-RmmModule @{
    scan    = {
        param($Params, $Request)
        Send-RmmProgress 10 'ricerca aggiornamenti'
        New-Report (New-Session) $Request $Params
    }
    install = {
        param($Params, $Request)
        $mgmt = Get-Management
        if ($mgmt.managed_by -ne 'none' -and -not (Get-Prop $Params 'allow_managed')) {
            throw "Windows Update is managed by $($mgmt.managed_by) on this endpoint: open-rmm only observes it (set allow_managed to install anyway)"
        }
        $want = Get-List $Params 'classifications'
        if ($want.Count -eq 0) { $want = @('security', 'critical', 'rollup', 'update', 'definition') }
        $exclude = @((Get-List $Params 'exclude_kbs') | ForEach-Object { ([string]$_).ToUpper() })
        $include = @((Get-List $Params 'include_kbs') | ForEach-Object { ([string]$_).ToUpper() })

        $session = New-Session
        Send-RmmProgress 5 'ricerca aggiornamenti'
        $scan = Invoke-Scan $session
        $coll = New-Object -ComObject Microsoft.Update.UpdateColl
        $selected = @()
        foreach ($u in $scan.updates) {
            $info = ConvertTo-UpdateInfo $u
            $kbs = @($info.kbs | ForEach-Object { $_.ToUpper() })
            if ($include.Count -gt 0) { if (-not ($kbs | Where-Object { $include -contains $_ })) { continue } }
            elseif ($want -notcontains $info.classification) { continue }
            if ($kbs | Where-Object { $exclude -contains $_ }) { continue }
            if ($u.InstallationBehavior.CanRequestUserInput) { Send-RmmLog "skipped (needs user input): $($info.title)" 'warn'; continue }
            if (-not $u.EulaAccepted) { $u.AcceptEula() }
            [void]$coll.Add($u)
            $selected += $info
        }
        $results = @()
        $rebootRequired = $false
        if ($coll.Count -gt 0) {
            Send-RmmProgress 15 "download di $($coll.Count) aggiornamenti"
            $dl = $session.CreateUpdateDownloader()
            $dl.Updates = $coll
            $dlres = $dl.Download()
            $ready = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($u in $coll) { if ($u.IsDownloaded) { [void]$ready.Add($u) } }
            if ($ready.Count -gt 0) {
                Send-RmmProgress 50 "installazione di $($ready.Count) aggiornamenti"
                $inst = $session.CreateUpdateInstaller()
                $inst.ForceQuiet = $true
                $inst.Updates = $ready
                $res = $inst.Install()
                $rebootRequired = [bool]$res.RebootRequired
                for ($i = 0; $i -lt $ready.Count; $i++) {
                    $r = $res.GetUpdateResult($i)
                    $results += @{
                        title  = [string]$ready.Item($i).Title
                        kbs    = @(foreach ($k in $ready.Item($i).KBArticleIDs) { "KB$k" })
                        result = $resultCodes[[int]$r.ResultCode]
                        hresult = ('0x{0:X8}' -f $r.HResult)
                    }
                }
            }
            for ($i = 0; $i -lt $coll.Count; $i++) {
                $u = $coll.Item($i)
                if ($u.IsDownloaded) { continue }
                $code = ''
                try { $code = ('0x{0:X8}' -f $dlres.GetUpdateResult($i).HResult) } catch { }
                $results += @{ title = [string]$u.Title; kbs = @(foreach ($k in $u.KBArticleIDs) { "KB$k" }); result = 'download_failed'; hresult = $code }
            }
        }
        Send-RmmProgress 90 'verifica'
        $report = New-Report $session $Request $Params
        $report.installed = $results
        $report.reboot_required_by_install = $rebootRequired
        $failed = @($results | Where-Object { $_.result -notin 'succeeded', 'succeeded_with_errors' })
        if ($failed.Count -gt 0) { Send-RmmLog "$($failed.Count) updates not installed" 'warn' }
        $report
    }
}
