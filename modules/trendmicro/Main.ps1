# open-rmm Trend Micro status module. Read-only.
#
# Products are recognized by their services and by their Uninstall entry.
# The names below are the most common ones; every field can be overridden by
# the policy parameters without publishing a new module version:
#
#   { "expect": ["sep"],                      # failing when not installed
#     "products": ["sep", "basecamp"],        # report only these
#     "definitions": { "ztsa": { "services": ["MyService"], "required": ["MyService"] } } }
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

$catalog = [ordered]@{
    sep      = @{
        name      = 'Trend Micro Standard Endpoint Protection'
        services  = @('ntrtscan', 'tmlisten', 'TMBMServer', 'TmCCSF')
        required  = @('ntrtscan', 'tmlisten')
        uninstall = 'Apex One|OfficeScan|Trend Micro Security Agent|Standard Endpoint Protection'
    }
    swp      = @{
        name      = 'Trend Micro Server & Workload Protection'
        services  = @('ds_agent', 'ds_notifier', 'AMSP')
        required  = @('ds_agent')
        uninstall = 'Deep Security Agent|Workload Security|Server & Workload Protection'
    }
    basecamp = @{
        name      = 'Trend Vision One Endpoint Basecamp'
        services  = @('EndpointBasecamp')
        required  = @('EndpointBasecamp')
        uninstall = 'Endpoint Basecamp|Trend Micro Endpoint Sensor'
    }
    ztsa     = @{
        name      = 'Trend Vision One Zero Trust Secure Access'
        services  = @('TMSAM', 'TmSecureAccess', 'ZTSA')
        required  = @()
        uninstall = 'Secure Access Module|Zero Trust Secure Access'
    }
}

function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# Get-List returns a parameter as an array (empty when absent: @($null)
# would have one element).
function Get-List($Object, [string]$Name) {
    $v = Get-Prop $Object $Name
    if ($null -eq $v) { return , @() }
    return , @($v)
}

function Get-UninstallEntries {
    $out = @()
    foreach ($path in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $k = $hklm.OpenSubKey($path)
        if ($null -eq $k) { continue }
        foreach ($n in $k.GetSubKeyNames()) {
            $e = $k.OpenSubKey($n)
            if ($null -eq $e) { continue }
            $name = [string]$e.GetValue('DisplayName')
            if ($name) { $out += [pscustomobject]@{ Name = $name.Trim(); Version = [string]$e.GetValue('DisplayVersion') } }
            $e.Close()
        }
        $k.Close()
    }
    $out
}

$startTypes = @{ 0 = 'boot'; 1 = 'system'; 2 = 'automatic'; 3 = 'manual'; 4 = 'disabled' }

function Get-ServiceState([string]$Name) {
    $svc = Get-CimInstance Win32_Service -Filter ("Name = '{0}'" -f $Name.Replace("'", "''"))
    if (-not $svc) { return @{ name = $Name; exists = $false } }
    @{ name = $Name; exists = $true; state = [string]$svc.State; start_mode = [string]$svc.StartMode; running = ($svc.State -eq 'Running') }
}

Invoke-RmmModule @{
    status = {
        param($Params, $Request)
        $expect = Get-List $Params 'expect'
        $only = Get-List $Params 'products'
        $overrides = Get-Prop $Params 'definitions'
        $entries = @()
        try { $entries = @(Get-UninstallEntries) }
        catch { Send-RmmLog "uninstall entries: $($_.Exception.Message)" 'warn' }
        $products = @()
        $checks = @()
        foreach ($id in $catalog.Keys) {
            if ($only.Count -gt 0 -and $only -notcontains $id) { continue }
            $def = $catalog[$id].Clone()
            $o = Get-Prop $overrides $id
            foreach ($f in 'name', 'services', 'required', 'uninstall') {
                $v = Get-Prop $o $f
                if ($null -ne $v) { $def[$f] = $v }
            }
            $services = @(foreach ($s in @($def.services)) { Get-ServiceState $s })
            $entry = $null
            if ($def.uninstall) { $entry = $entries | Where-Object { $_.Name -match $def.uninstall } | Select-Object -First 1 }
            $installed = [bool]$entry -or [bool]($services | Where-Object { $_.exists })
            $product = @{
                id = $id; name = $def.name; installed = $installed
                display_name = if ($entry) { $entry.Name } else { '' }
                version = if ($entry) { $entry.Version } else { '' }
                services = $services
            }
            $products += $product
            if (-not $installed) {
                if ($expect -contains $id) {
                    $checks += @{ id = $id; status = 'failing'; summary = "$($def.name) non installato" }
                }
                continue
            }
            $problems = @()
            foreach ($r in @($def.required)) {
                $st = $services | Where-Object { $_.name -eq $r } | Select-Object -First 1
                if (-not $st -or -not $st.exists) { $problems += "servizio $r assente" }
                elseif (-not $st.running) { $problems += "servizio $r $($st.state)" }
                elseif ($st.start_mode -eq 'Disabled') { $problems += "servizio $r disabilitato" }
            }
            $label = "$($def.name) $($product.version)".Trim()
            if ($problems.Count -gt 0) {
                $checks += @{ id = $id; status = 'failing'; summary = "${label}: $($problems -join ', ')" }
            }
            elseif (@($def.required).Count -eq 0 -and -not ($services | Where-Object { $_.running })) {
                $checks += @{ id = $id; status = 'warning'; summary = "${label}: installato, nessun servizio noto in esecuzione (verificare i nomi dei servizi)" }
            }
            else {
                $checks += @{ id = $id; status = 'ok'; summary = "$label attivo" }
            }
        }
        @{ products = $products; checks = $checks }
    }
}
