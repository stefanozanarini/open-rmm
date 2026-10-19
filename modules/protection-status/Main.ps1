# open-rmm protection status module. Read-only.
#
# Windows Security Center (clients only) lists the registered antivirus
# products and whether they are enabled and up to date. Servers have no
# Security Center: there the antivirus is checked by its own module
# (e.g. trendmicro) and only Defender and the firewall are reported here.
#
# Parameters: { "max_signature_age_days": 3 }
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# productState: byte 2 is the scanner state (0x10/0x11 = on), byte 3 the
# signature state (0x00 = up to date).
function ConvertFrom-ProductState([int]$State) {
    $hex = '{0:X6}' -f $State
    @{ enabled = @('10', '11') -contains $hex.Substring(2, 2); up_to_date = $hex.Substring(4, 2) -eq '00' }
}

Invoke-RmmModule @{
    status = {
        param($Params, $Request)
        $maxAge = Get-Prop $Params 'max_signature_age_days'
        if (-not $maxAge) { $maxAge = 3 }
        $checks = @()
        $out = @{}

        $av = $null
        try { $av = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct) } catch { }
        if ($null -ne $av) {
            $out.antivirus = @(foreach ($p in $av) {
                $s = ConvertFrom-ProductState ([int]$p.productState)
                @{ name = [string]$p.displayName; enabled = $s.enabled; up_to_date = $s.up_to_date }
            })
            $on = @($out.antivirus | Where-Object { $_.enabled })
            if ($on.Count -eq 0) {
                $checks += @{ id = 'antivirus'; status = 'failing'; summary = 'Nessun antivirus attivo registrato in Sicurezza di Windows' }
            }
            elseif (-not ($on | Where-Object { $_.up_to_date })) {
                $checks += @{ id = 'antivirus'; status = 'warning'; summary = "Antivirus non aggiornato: $(($on | ForEach-Object { $_.name }) -join ', ')" }
            }
            else {
                $checks += @{ id = 'antivirus'; status = 'ok'; summary = "Antivirus attivo: $(($on | ForEach-Object { $_.name }) -join ', ')" }
            }
        }

        try {
            $mp = Get-MpComputerStatus
            $out.defender = @{
                service_enabled   = [bool]$mp.AMServiceEnabled
                realtime_enabled  = [bool]$mp.RealTimeProtectionEnabled
                running_mode      = [string]$mp.AMRunningMode
                signature_age_days = [int]$mp.AntivirusSignatureAge
                signature_version = [string]$mp.AntivirusSignatureVersion
            }
            # In passive mode (another antivirus is primary) Defender is not checked.
            if ($mp.AMRunningMode -eq 'Normal') {
                if (-not $mp.RealTimeProtectionEnabled) {
                    $checks += @{ id = 'defender'; status = 'failing'; summary = 'Microsoft Defender: protezione in tempo reale disattivata' }
                }
                elseif ($mp.AntivirusSignatureAge -gt $maxAge) {
                    $checks += @{ id = 'defender'; status = 'warning'; summary = "Microsoft Defender: firme vecchie di $($mp.AntivirusSignatureAge) giorni" }
                }
                else {
                    $checks += @{ id = 'defender'; status = 'ok'; summary = 'Microsoft Defender attivo e aggiornato' }
                }
            }
        }
        catch { Send-RmmLog "defender: $($_.Exception.Message)" 'info' }

        try {
            $profiles = @(Get-NetFirewallProfile)
            $out.firewall = @(foreach ($p in $profiles) { @{ profile = [string]$p.Name; enabled = [bool]$p.Enabled } })
            $off = @($profiles | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Name })
            if ($off.Count -gt 0) {
                $checks += @{ id = 'firewall'; status = 'warning'; summary = "Windows Firewall disattivato per: $($off -join ', ')" }
            }
            else {
                $checks += @{ id = 'firewall'; status = 'ok'; summary = 'Windows Firewall attivo su tutti i profili' }
            }
        }
        catch { Send-RmmLog "firewall: $($_.Exception.Message)" 'warn' }

        $out.checks = $checks
        $out
    }
}
