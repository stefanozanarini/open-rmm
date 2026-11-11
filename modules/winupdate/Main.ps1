# open-rmm Windows Update module (Windows Update Agent COM API).
#
# scan     lists the missing updates, the pending reboot and who manages
#          updates on the endpoint (WSUS, Intune or nobody).
# install  downloads and installs the selected updates. It never reboots:
#          the reboot module does, according to the reboot policy. On an
#          endpoint managed by WSUS or Intune it refuses to install unless
#          allow_managed is set (observation mode). When updates fail, the
#          result carries a short diagnosis (recent errors, blockers).
# logs     collects what explains failed updates: Windows Update events,
#          the errors in CBS.log (and optionally WindowsUpdate.log), the
#          services, free space, pending operations, failed installations.
# repair   repairs the component store (DISM /RestoreHealth, optionally
#          from a source of the same build) and the system files (SFC),
#          optionally resetting the Windows Update cache first. Fixes
#          errors such as 0x800f0983 (component store missing a binary).
#
# Every report lists the settings that keep updates from being offered or
# installed ("blockers"): a pinned release (TargetReleaseVersion, also when
# only left over in UpdatePolicy\PolicyState), Windows Update access turned
# off (by policy, Explorer policy or Internet Communication Management), a
# WSUS server unreachable, not answering or with no successful search for
# weeks, update servers redirected in the hosts file, pauses and deferrals,
# disabled services, low disk space.
#
# Parameters (install):
#   { "classifications": ["security","critical","rollup","update","definition"],
#     "exclude_kbs": ["KB5030000"], "include_kbs": [], "allow_managed": false,
#     "max_age_days": 30 }
# Parameters (repair):
#   { "source": "WIM:D:\sources\install.wim:1", "sfc": true, "reset_components": false }
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

# ---- blockers ----

function Read-Reg([string]$Path, [string]$Name) {
    $v = Get-ItemProperty -Path ("Registry::" + $Path) -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $v) { return $null }
    return $v.$Name
}

function Test-TcpPort([string]$HostName, [int]$Port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $t = $c.ConnectAsync($HostName, $Port)
        return ($t.Wait(3000) -and $c.Connected)
    }
    catch { return $false }
    finally { $c.Dispose() }
}

# Test-Wsus asks the WSUS client web service for its description: '' when
# it answers, else the reason (HTTP 503 when the IIS pool is stopped, a
# timeout, a certificate error).
function Test-Wsus([string]$Url) {
    try {
        $req = [Net.HttpWebRequest]::Create($Url.TrimEnd('/') + '/ClientWebService/client.asmx')
        $req.Timeout = 15000
        $req.UseDefaultCredentials = $true
        $req.GetResponse().Close()
        return ''
    }
    catch {
        $e = $_.Exception
        while ($e -and -not ($e -is [Net.WebException])) { $e = $e.InnerException }
        if (-not $e) { return $_.Exception.Message }
        if ($e.Response) {
            $code = [int]$e.Response.StatusCode
            $e.Response.Close()
            if ($code -ge 500) { return "HTTP $code" }
            return ''
        }
        return [string]$e.Status
    }
}

# Get-AutoUpdateResults: the last successful search and installation of
# the Windows Update client, whoever started them.
function Get-AutoUpdateResults {
    try {
        $r = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
        $out = @{}
        foreach ($n in 'LastSearchSuccessDate', 'LastInstallationSuccessDate') {
            $d = $r.$n
            if ($d -is [datetime] -and $d.Year -gt 2000) { $out[$n] = $d.ToUniversalTime() }
        }
        return $out
    }
    catch { return @{} }
}

# Get-Blockers lists the settings that keep updates from being offered or
# installed. severity: block (no updates), limit (some updates held back),
# info (worth knowing).
function Get-Blockers {
    $pol = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $state = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState'
    $mdm = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    $ux = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    $out = New-Object System.Collections.ArrayList
    $add = { param($Id, $Severity, $Summary, $Path, $Value)
        [void]$out.Add(@{ id = $Id; severity = $Severity; summary = $Summary; path = $Path; value = [string]$Value }) }

    # Pinned Windows release: by policy, by MDM, or left over in the
    # effective policy state after the policy was removed.
    $current = [string](Read-Reg 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion')
    $pinned = $false
    if ((Read-Reg $pol 'TargetReleaseVersion') -eq 1) {
        $info = [string](Read-Reg $pol 'TargetReleaseVersionInfo')
        $prod = [string](Read-Reg $pol 'ProductVersion')
        & $add 'target_release' 'limit' ("Versione di Windows bloccata a " + (("$prod $info").Trim()) + " da policy (attuale: $current): le versioni successive non vengono offerte") "$pol\TargetReleaseVersion" "$prod $info"
        $pinned = $true
    }
    $mdmTarget = [string](Read-Reg $mdm 'TargetReleaseVersion')
    if ($mdmTarget -and -not $pinned) {
        & $add 'target_release' 'limit' "Versione di Windows bloccata a $mdmTarget da Intune/MDM (attuale: $current): le versioni successive non vengono offerte" "$mdm\TargetReleaseVersion" $mdmTarget
        $pinned = $true
    }
    foreach ($name in 'TargetReleaseVersion', 'TargetReleaseVersionInfo', 'TargetProductVersion', 'ProductVersion') {
        $v = Read-Reg $state $name
        if ($null -ne $v -and "$v" -ne '' -and "$v" -ne '0' -and -not $pinned) {
            & $add 'target_release_state' 'limit' "Versione di Windows bloccata in UpdatePolicy\PolicyState ($name = $v) senza una policy che la imposti: probabilmente un residuo da rimuovere" "$state\$name" $v
            $pinned = $true
        }
    }

    if ((Read-Reg $pol 'DisableWindowsUpdateAccess') -eq 1) {
        & $add 'access_disabled' 'block' 'Accesso a Windows Update disattivato da policy (DisableWindowsUpdateAccess)' "$pol\DisableWindowsUpdateAccess" 1
    }
    $explorer = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if ((Read-Reg $explorer 'NoWindowsUpdate') -eq 1) {
        & $add 'no_windows_update' 'block' 'Windows Update disattivato da policy (NoWindowsUpdate)' "$explorer\NoWindowsUpdate" 1
    }
    foreach ($icm in 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Communication Management\Internet Communication',
        'HKEY_LOCAL_MACHINE\SYSTEM\Internet Communication Management\Internet Communication') {
        if ((Read-Reg $icm 'DisableWindowsUpdateAccess') -eq 1) {
            & $add 'icm_disabled' 'block' 'Accesso a Windows Update disattivato da Gestione comunicazioni Internet (DisableWindowsUpdateAccess)' "$icm\DisableWindowsUpdateAccess" 1
            break
        }
    }
    $useWsus = (Read-Reg "$pol\AU" 'UseWUServer') -eq 1
    $wsus = [string](Read-Reg $pol 'WUServer')
    if ($useWsus -and -not $wsus) {
        & $add 'wsus_missing' 'block' 'Server WSUS attivato (UseWUServer) ma nessun indirizzo configurato (WUServer)' "$pol\AU\UseWUServer" 1
    }
    elseif ($useWsus) {
        $reachable = $false
        try {
            $u = [Uri]$wsus
            if (-not (Test-TcpPort $u.Host $u.Port)) {
                & $add 'wsus_unreachable' 'block' "Server WSUS $wsus non raggiungibile" "$pol\WUServer" $wsus
            }
            else { $reachable = $true }
        }
        catch { & $add 'wsus_invalid' 'block' "Indirizzo del server WSUS non valido: $wsus" "$pol\WUServer" $wsus }
        if ($reachable) {
            $why = Test-Wsus $wsus
            if ($why) { & $add 'wsus_not_responding' 'block' "Server WSUS $wsus raggiungibile ma il servizio non risponde ($why)" "$pol\WUServer" $wsus }
        }
        # A WSUS server that answers but no longer works (database, sync,
        # approvals): no successful search, or nothing installed, for weeks.
        $res = Get-AutoUpdateResults
        $now = (Get-Date).ToUniversalTime()
        if ($res.LastSearchSuccessDate) {
            $days = [int]($now - $res.LastSearchSuccessDate).TotalDays
            if ($days -ge 14) { & $add 'wsus_stale' 'block' "Server WSUS $wsus configurato: nessuna ricerca di aggiornamenti riuscita da $days giorni" "$pol\WUServer" $wsus }
        }
        if ($res.LastInstallationSuccessDate) {
            $days = [int]($now - $res.LastInstallationSuccessDate).TotalDays
            if ($days -ge 60) { & $add 'wsus_no_installs' 'limit' "Server WSUS $wsus configurato: nessun aggiornamento installato da $days giorni (il server non approva più aggiornamenti?)" "$pol\WUServer" $wsus }
        }
    }
    elseif ((Read-Reg $pol 'DoNotConnectToWindowsUpdateInternetLocations') -eq 1) {
        & $add 'no_internet_wu' 'block' 'Connessione a Windows Update su internet disattivata (DoNotConnectToWindowsUpdateInternetLocations) senza un server WSUS' "$pol\DoNotConnectToWindowsUpdateInternetLocations" 1
    }
    # Update servers redirected (often to 0.0.0.0) by "privacy" tools.
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $redirected = @(Get-Content -Path $hosts -ErrorAction SilentlyContinue | ForEach-Object { ($_ -replace '#.*$', '').Trim() } |
        Where-Object { $_ -match '(?i)(windowsupdate\.(com|microsoft\.com)|update\.microsoft\.com|delivery\.mp\.microsoft\.com|download\.microsoft\.com)\s*$' } |
        ForEach-Object { ($_ -split '\s+')[-1] } | Select-Object -Unique -First 5)
    if ($redirected.Count) {
        & $add 'hosts' 'block' "Il file hosts reindirizza i server di Windows Update: $($redirected -join ', ')" $hosts ($redirected -join ', ')
    }
    if ((Read-Reg "$pol\AU" 'NoAutoUpdate') -eq 1) {
        & $add 'no_auto_update' 'info' 'Aggiornamenti automatici disattivati da policy (NoAutoUpdate): li installa open-rmm' "$pol\AU\NoAutoUpdate" 1
    }
    $q = Read-Reg $pol 'DeferQualityUpdatesPeriodInDays'
    if ((Read-Reg $pol 'DeferQualityUpdates') -eq 1 -and $q -gt 0) {
        & $add 'defer_quality' 'limit' "Aggiornamenti di qualità differiti di $q giorni da policy" "$pol\DeferQualityUpdatesPeriodInDays" $q
    }
    $f = Read-Reg $pol 'DeferFeatureUpdatesPeriodInDays'
    if ((Read-Reg $pol 'DeferFeatureUpdates') -eq 1 -and $f -gt 0) {
        & $add 'defer_feature' 'info' "Aggiornamenti di funzionalità differiti di $f giorni da policy" "$pol\DeferFeatureUpdatesPeriodInDays" $f
    }
    $now = (Get-Date).ToUniversalTime()
    foreach ($p in @(@($ux, 'PauseUpdatesExpiryTime'), @($ux, 'PauseQualityUpdatesEndTime'), @($pol, 'PauseQualityUpdatesStartTime'))) {
        $v = [string](Read-Reg $p[0] $p[1])
        if (-not $v) { continue }
        $t = [datetime]::MinValue
        if ([datetime]::TryParse($v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$t)) {
            if ($p[1] -eq 'PauseQualityUpdatesStartTime') { $t = $t.AddDays(35) }
            if ($t -gt $now) {
                & $add 'paused' 'limit' ("Aggiornamenti in pausa fino al " + $t.ToString('yyyy-MM-dd')) "$($p[0])\$($p[1])" $v
                break
            }
        }
    }
    if ((Read-Reg $pol 'ExcludeWUDriversInQualityUpdate') -eq 1) {
        & $add 'no_drivers' 'info' 'Driver esclusi dagli aggiornamenti di qualità da policy (ExcludeWUDriversInQualityUpdate)' "$pol\ExcludeWUDriversInQualityUpdate" 1
    }
    # WaaSMedicSvc repairs Windows Update: without it updates still work.
    foreach ($svc in 'wuauserv', 'bits', 'UsoSvc', 'TrustedInstaller', 'CryptSvc', 'WaaSMedicSvc') {
        $s = Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction SilentlyContinue
        if ($s -and $s.StartMode -eq 'Disabled') {
            $sev = if ($svc -eq 'WaaSMedicSvc') { 'limit' } else { 'block' }
            & $add "service_$($svc.ToLowerInvariant())" $sev "Servizio $svc disabilitato" "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$svc\Start" 4
        }
    }
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction SilentlyContinue
    if ($drive) {
        $gb = [Math]::Round($drive.FreeSpace / 1GB, 1)
        if ($gb -lt 5) { & $add 'disk_space' 'block' "Spazio libero insufficiente su $($env:SystemDrive) ($gb GB)" $env:SystemDrive $gb }
        elseif ($gb -lt 10) { & $add 'disk_space' 'limit' "Poco spazio libero su $($env:SystemDrive) ($gb GB)" $env:SystemDrive $gb }
    }
    $out
}

function Get-BlockerCheck($Blockers) {
    $b = @($Blockers | Where-Object { $_.severity -eq 'block' })
    $l = @($Blockers | Where-Object { $_.severity -eq 'limit' })
    if ($b.Count) { return @{ id = 'policy'; status = 'failing'; summary = "Aggiornamenti bloccati: $(($b | ForEach-Object { $_.summary }) -join '; ')" } }
    if ($l.Count) { return @{ id = 'policy'; status = 'warning'; summary = "Aggiornamenti limitati: $(($l | ForEach-Object { $_.summary }) -join '; ')" } }
    @{ id = 'policy'; status = 'ok'; summary = 'Nessuna impostazione blocca gli aggiornamenti' }
}

# ---- logs ----

function Get-WuEvents([int]$Days, [int]$Max) {
    $since = (Get-Date).AddDays(-$Days)
    $out = @()
    $queries = @(
        @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; StartTime = $since; Level = 1, 2, 3 },
        @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient', 'Microsoft-Windows-Servicing', 'Microsoft-Windows-WUSA'; StartTime = $since; Level = 1, 2, 3 },
        @{ LogName = 'Setup'; StartTime = $since; Level = 1, 2, 3 }
    )
    foreach ($q in $queries) {
        $events = @(Get-WinEvent -FilterHashtable $q -MaxEvents $Max -ErrorAction SilentlyContinue)
        foreach ($e in $events) {
            $m = [string]$e.Message
            if ($m.Length -gt 600) { $m = $m.Substring(0, 600) + '…' }
            $out += @{ time = $e.TimeCreated.ToUniversalTime().ToString('o'); log = $q.LogName; id = $e.Id
                level = @{ 1 = 'critical'; 2 = 'error'; 3 = 'warning' }[[int]$e.Level]; provider = [string]$e.ProviderName; message = $m.Trim() }
        }
    }
    @($out | Sort-Object { $_.time } -Descending | Select-Object -First $Max)
}

# Read-LogTail returns the last lines of a log matching a pattern; the file
# is read shared, it may be open for writing.
function Read-LogTail([string]$Path, [string]$Pattern, [int]$Lines, [int]$TailBytes) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
        $start = [Math]::Max(0, $fs.Length - $TailBytes)
        [void]$fs.Seek($start, 'Begin')
        $text = (New-Object System.IO.StreamReader($fs)).ReadToEnd()
    }
    finally { $fs.Dispose() }
    @($text -split "`r?`n" | Where-Object { $_ -match $Pattern } | ForEach-Object { if ($_.Length -gt 400) { $_.Substring(0, 400) } else { $_ } } | Select-Object -Last $Lines)
}

function Get-Diagnostics($Params, [bool]$Short) {
    $days = 7
    $d = Get-Prop $Params 'days'
    if ($d) { $days = [Math]::Max(1, [Math]::Min(30, [int]$d)) }
    if ($Short) { $days = 1 }
    $errPattern = ', Error|Failed|FAILED|error 0x|0x8[0-9A-Fa-f]{7}'
    $cbs = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
    $r = @{
        events  = @(Get-WuEvents $days $(if ($Short) { 20 } else { 100 }))
        cbs_log = @(Read-LogTail $cbs $errPattern $(if ($Short) { 40 } else { 200 }) (4MB))
    }
    if ($Short) { return $r }
    $cv = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $r.windows = "$(Read-Reg $cv 'ProductName') $(Read-Reg $cv 'DisplayVersion') (build $(Read-Reg $cv 'CurrentBuild').$(Read-Reg $cv 'UBR'))"
    $r.services = @(foreach ($svc in 'wuauserv', 'bits', 'UsoSvc', 'TrustedInstaller', 'CryptSvc', 'msiserver') {
            $s = Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction SilentlyContinue
            if ($s) { @{ name = $svc; status = [string]$s.State; start_type = [string]$s.StartMode } }
        })
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction SilentlyContinue
    if ($drive) { $r.disk_free_gb = [Math]::Round($drive.FreeSpace / 1GB, 1) }
    $r.pending_xml = Test-Path (Join-Path $env:SystemRoot 'WinSxS\pending.xml')
    $r.blockers = @(Get-Blockers)
    if (Get-Prop $Params 'windowsupdate_log') {
        # Get-WindowsUpdateLog decodes the ETW traces: slow (minutes).
        $out = Join-Path $env:OPENRMM_WORK_DIR 'WindowsUpdate.log'
        try {
            Send-RmmProgress 40 'decodifica WindowsUpdate.log'
            Get-WindowsUpdateLog -LogPath $out -ErrorAction Stop *> $null
            $r.windowsupdate_log = @(Read-LogTail $out 'FATAL|[Ee]rror|0x8[0-9A-Fa-f]{7}' 300 (16MB))
        }
        catch { $r.windowsupdate_log = @("Get-WindowsUpdateLog: $($_.Exception.Message)") }
    }
    $r
}

function New-Report($Session, $Request, $Params) {
    $mgmt = Get-Management
    $scan = Invoke-Scan $Session
    $updates = @(foreach ($u in $scan.updates) { ConvertTo-UpdateInfo $u })
    $pending = Get-PendingReboot ([string]$Request.state_dir)
    $maxAge = Get-Prop $Params 'max_age_days'
    if (-not $maxAge) { $maxAge = 30 }
    $blockers = @(Get-Blockers)
    @{
        managed_by     = $mgmt.managed_by
        wsus_server    = $mgmt.wsus_server
        scanned_at     = (Get-Date).ToUniversalTime().ToString('o')
        updates        = $updates
        pending_reboot = $pending
        last_success   = Get-LastSuccess $scan.searcher
        history        = @(Get-History $scan.searcher)
        blockers       = $blockers
        checks         = @(Get-Checks $updates $pending ([int]$maxAge)) + @(Get-BlockerCheck $blockers)
    }
}

# ---- repair ----

# Invoke-Tool runs a console tool and keeps its meaningful lines (no
# progress bars). SFC writes UTF-16.
function Invoke-Tool([string]$Exe, [string[]]$Arguments, [Text.Encoding]$Encoding) {
    $prev = [Console]::OutputEncoding
    [Console]::OutputEncoding = $Encoding
    try { $out = & $Exe @Arguments 2>&1 | ForEach-Object { ([string]$_ -replace "`0", '').Trim() } }
    finally { [Console]::OutputEncoding = $prev }
    $code = $LASTEXITCODE
    $lines = @($out | Where-Object { $_ -and $_ -notmatch '^\[[ =.\d%]*\]?$' -and $_ -notmatch '^[\d.]+%$' })
    @{ exit_code = ('0x{0:X8}' -f $code); ok = ($code -eq 0); output = (($lines | Select-Object -Last 8) -join "`n"); code = $code }
}

# Reset-WuComponents empties the Windows Update cache: the services are
# stopped, SoftwareDistribution and catroot2 renamed (kept as .old).
function Reset-WuComponents {
    $svcs = 'wuauserv', 'bits', 'cryptsvc', 'UsoSvc'
    foreach ($svc in $svcs) { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
    $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
    $renamed = @()
    foreach ($dir in (Join-Path $env:SystemRoot 'SoftwareDistribution'), (Join-Path $env:SystemRoot 'System32\catroot2')) {
        if (Test-Path $dir) {
            Rename-Item -Path $dir -NewName "$(Split-Path $dir -Leaf).old-$stamp" -ErrorAction Stop
            $renamed += $dir
        }
    }
    foreach ($svc in $svcs) { Start-Service -Name $svc -ErrorAction SilentlyContinue }
    @{ step = 'reset_components'; ok = $true; output = "renamed: $($renamed -join ', ') (.old-$stamp)" }
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
        if ($failed.Count -gt 0) {
            Send-RmmLog "$($failed.Count) updates not installed" 'warn'
            try { $report.diagnostics = Get-Diagnostics $Params $true } catch { Send-RmmLog "diagnostics: $($_.Exception.Message)" 'warn' }
        }
        $report
    }
    repair  = {
        param($Params, $Request)
        $steps = @()
        if (Get-Prop $Params 'reset_components') {
            Send-RmmProgress 5 'azzeramento della cache di Windows Update'
            $steps += Reset-WuComponents
        }
        $dismArgs = @('/Online', '/Cleanup-Image', '/RestoreHealth', '/English')
        $source = [string](Get-Prop $Params 'source')
        if ($source) {
            if ($source -match '["\r\n]' -or $source.Length -gt 260) { throw "invalid source: $source" }
            $dismArgs += @("/Source:$source", '/LimitAccess')
        }
        Send-RmmProgress 15 'DISM /RestoreHealth (anche 30 minuti)'
        $dism = Invoke-Tool (Join-Path $env:SystemRoot 'System32\dism.exe') $dismArgs ([Text.Encoding]::UTF8)
        $steps += @{ step = 'dism_restorehealth'; ok = $dism.ok; exit_code = $dism.exit_code; output = $dism.output }
        Send-RmmLog "DISM $($dism.exit_code): $($dism.output)" $(if ($dism.ok) { 'info' } else { 'warn' })
        $sfcOk = $true
        $runSfc = Get-Prop $Params 'sfc'
        if ($null -eq $runSfc) { $runSfc = $true }
        # SFC repairs the system files from the component store: only once
        # the store is sound.
        if ($dism.ok -and $runSfc) {
            Send-RmmProgress 60 'sfc /scannow'
            $sfc = Invoke-Tool (Join-Path $env:SystemRoot 'System32\sfc.exe') @('/scannow') ([Text.Encoding]::Unicode)
            $steps += @{ step = 'sfc'; ok = $sfc.ok; exit_code = $sfc.exit_code; output = $sfc.output }
            Send-RmmLog "SFC $($sfc.exit_code): $($sfc.output)" $(if ($sfc.ok) { 'info' } else { 'warn' })
            $sfcOk = $sfc.ok
        }
        if (-not $dism.ok) {
            # 0x800F081F: no source with the files; 0x800F0906: download refused.
            throw "DISM /RestoreHealth failed ($($dism.exit_code)): $(($dism.output -split "`n")[-1]). With 0x800F081F give a source of the same build (WIM:D:\sources\install.wim:1) or repair Windows with an in-place upgrade"
        }
        @{ repaired_at = (Get-Date).ToUniversalTime().ToString('o'); steps = $steps; ok = ($dism.ok -and $sfcOk)
            note = 'Restart the computer, then install the updates again' }
    }
    logs    = {
        param($Params, $Request)
        Send-RmmProgress 10 'raccolta dei log di Windows Update'
        $r = Get-Diagnostics $Params $false
        $session = New-Session
        $searcher = $session.CreateUpdateSearcher()
        $r.failed_installations = @(Get-History $searcher | Where-Object { $_.result -notin 'succeeded', 'succeeded_with_errors', 'in_progress' } | Select-Object -First 20)
        $r.collected_at = (Get-Date).ToUniversalTime().ToString('o')
        $r
    }
}
