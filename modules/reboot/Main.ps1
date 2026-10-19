# open-rmm reboot module. Other modules never reboot: they report that a
# reboot is pending, and this module applies the reboot policy. When to
# reboot (maintenance window, days) is decided by the policy rule window.
#
# Parameters (defaults in brackets):
#   only_if_pending      [true]  reboot only when a reboot is pending
#   min_pending_hours    [0]     ... and has been pending at least this long
#   notice_minutes       [15]    countdown shown to logged-on users
#   skip_if_user         [false] do not reboot while a user is logged on
#   min_battery_percent  [30]    on battery below this charge, skip
#   message                      text of the notice
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

function Get-Prop($Object, [string]$Name, $Default) {
    if ($null -ne $Object) {
        $p = $Object.PSObject.Properties[$Name]
        if ($p -and $null -ne $p.Value) { return $p.Value }
    }
    return $Default
}

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
    $required = $reasons.Count -gt 0
    $since = $null
    $f = Join-Path $StateDir 'pending-since.txt'
    if ($required) {
        if (Test-Path -LiteralPath $f) { $since = [datetime]::Parse((Get-Content -LiteralPath $f -Raw).Trim()).ToUniversalTime() }
        else {
            $since = (Get-Date).ToUniversalTime()
            Set-Content -LiteralPath $f -Value $since.ToString('o') -Encoding ASCII
        }
    }
    elseif (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
    @{ required = $required; reasons = $reasons; since = $since }
}

function Skip([string]$Reason, $Pending) {
    @{ action = 'skipped'; reason = $Reason; pending = $Pending.required; reasons = $Pending.reasons }
}

Invoke-RmmModule @{
    reboot = {
        param($Params, $Request)
        $stateDir = [string]$Request.state_dir
        if (-not $stateDir) { throw 'this agent does not provide a module state directory; update the agent' }
        $pending = Get-PendingReboot $stateDir
        if ((Get-Prop $Params 'only_if_pending' $true) -and -not $pending.required) { return Skip 'nessun riavvio in sospeso' $pending }
        $minHours = [double](Get-Prop $Params 'min_pending_hours' 0)
        if ($pending.required -and $minHours -gt 0 -and ((Get-Date).ToUniversalTime() - $pending.since).TotalHours -lt $minHours) {
            return Skip "riavvio in sospeso da meno di $minHours ore" $pending
        }
        $battery = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
        $minBattery = [int](Get-Prop $Params 'min_battery_percent' 30)
        # BatteryStatus 1 = discharging (on battery).
        if ($battery.Count -gt 0 -and $battery[0].BatteryStatus -eq 1 -and $battery[0].EstimatedChargeRemaining -lt $minBattery) {
            return Skip "a batteria con carica $($battery[0].EstimatedChargeRemaining)%" $pending
        }
        $users = @(Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue)
        if ($users.Count -gt 0 -and (Get-Prop $Params 'skip_if_user' $false)) { return Skip 'utente collegato' $pending }
        $notice = 60
        if ($users.Count -gt 0) { $notice = [int](Get-Prop $Params 'notice_minutes' 15) * 60 }
        $notice = [Math]::Max(30, [Math]::Min($notice, 86400))
        $minutes = [Math]::Ceiling($notice / 60)
        $message = [string](Get-Prop $Params 'message' "Il computer verrà riavviato tra $minutes minuti per completare gli aggiornamenti. Salva il lavoro.")
        if ($message.Length -gt 500) { $message = $message.Substring(0, 500) }
        # p:2:17 = planned, operating system: hot fix.
        $out = & "$env:SystemRoot\System32\shutdown.exe" /r /t $notice /c $message /d p:2:17 2>&1
        $code = $LASTEXITCODE
        if ($code -eq 1190) { return @{ action = 'already_scheduled'; pending = $pending.required; reasons = $pending.reasons } }
        if ($code -ne 0) { throw "shutdown.exe failed ($code): $out" }
        Send-RmmLog "reboot scheduled in $notice seconds" 'info'
        @{ action = 'scheduled'; delay_seconds = $notice; users_logged_on = $users.Count; pending = $pending.required; reasons = $pending.reasons }
    }
}
