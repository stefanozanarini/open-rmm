# open-rmm software module: install a package of the console's library, or
# uninstall an application. Never reboots: a needed reboot is recorded for
# the reboot module.
#
# install    { "kind": "msi|exe|inno|nullsoft|burn", "silent_args": "...",
#              "msi_properties": "ALLUSERS=1", "allow_unsigned": false }
#            The package comes with the signed job (already hash-checked by
#            the agent); its Authenticode signature must be valid unless
#            allow_unsigned is set.
# uninstall  { "product_code": "{GUID}" } or { "name": "exact display name",
#              "version": "optional", "uninstall_args": "only for installers
#              without a silent uninstall command, e.g. /S" }
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

function Get-Prop($Object, [string]$Name, $Default) {
    if ($null -ne $Object) {
        $p = $Object.PSObject.Properties[$Name]
        if ($p -and $null -ne $p.Value) { return $p.Value }
    }
    return $Default
}

$guidPattern = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'

$defaultSilent = @{
    inno     = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
    nullsoft = '/S'
    burn     = '/quiet /norestart'
}

# Exit codes that mean success; 3010/1641 also mean a reboot is needed.
$okCodes = @(0, 3010, 1641)
$rebootCodes = @(3010, 1641)
$knownCodes = @{
    1602 = 'annullato'; 1603 = 'errore irreversibile durante l''installazione'; 1618 = 'un''altra installazione è in corso'
    1619 = 'pacchetto non apribile'; 1620 = 'pacchetto non valido'; 1633 = 'piattaforma non supportata'
    1638 = 'un''altra versione del prodotto è già installata'; 1639 = 'argomenti non validi'
}

# Records that a reboot is needed; the reboot module honours it until the
# next boot.
function Set-RebootMarker([string]$Reason) {
    $key = 'HKLM:\SOFTWARE\open-rmm-modules'
    if (-not (Test-Path $key)) { [void](New-Item -Path $key -Force) }
    Set-ItemProperty -Path $key -Name 'RebootRequiredAt' -Value (Get-Date).ToUniversalTime().ToString('o')
    Set-ItemProperty -Path $key -Name 'RebootRequiredBy' -Value $Reason
}

# Splits a registered command line into executable and arguments.
function Split-CommandLine([string]$Line) {
    $Line = $Line.Trim()
    if ($Line.StartsWith('"')) {
        $end = $Line.IndexOf('"', 1)
        if ($end -lt 0) { throw "malformed command line: $Line" }
        return @{ file = $Line.Substring(1, $end - 1); args = $Line.Substring($end + 1).Trim() }
    }
    $i = $Line.ToLower().IndexOf('.exe')
    if ($i -lt 0) { throw "malformed command line: $Line" }
    return @{ file = $Line.Substring(0, $i + 4); args = $Line.Substring($i + 4).Trim() }
}

function Invoke-Installer([string]$File, [string]$Arguments) {
    Send-RmmLog "running: $File $Arguments" 'info'
    $p = if ($Arguments) { Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden }
    else { Start-Process -FilePath $File -Wait -PassThru -WindowStyle Hidden }
    [int]$p.ExitCode
}

function Get-LogTail([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    # msiexec writes UTF-16 logs.
    ((Get-Content -LiteralPath $Path -Encoding Unicode -Tail 40 -ErrorAction SilentlyContinue) -join "`n")
}

# MSI properties read through the Windows Installer COM object.
function Get-MsiInfo([string]$Path) {
    try {
        $wi = New-Object -ComObject WindowsInstaller.Installer
        $db = $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($Path, 0))
        $out = @{}
        foreach ($name in 'ProductCode', 'ProductName', 'ProductVersion', 'Manufacturer') {
            $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT Value FROM Property WHERE Property = '$name'"))
            [void]$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
            $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if ($rec) { $out[$name] = [string]$rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, 1) }
            [void]$view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
        }
        return $out
    }
    catch { Send-RmmLog "msi properties: $($_.Exception.Message)" 'warn'; return @{} }
}

function Get-UninstallEntries {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    foreach ($path in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
        $k = $hklm.OpenSubKey($path)
        if ($null -eq $k) { continue }
        foreach ($n in $k.GetSubKeyNames()) {
            $e = $k.OpenSubKey($n)
            if ($null -eq $e) { continue }
            $name = [string]$e.GetValue('DisplayName')
            if ($name) {
                [pscustomobject]@{
                    Key = $n; Name = $name.Trim(); Version = [string]$e.GetValue('DisplayVersion')
                    Msi = ([int]$e.GetValue('WindowsInstaller', 0) -eq 1)
                    Quiet = [string]$e.GetValue('QuietUninstallString'); Uninstall = [string]$e.GetValue('UninstallString')
                }
            }
            $e.Close()
        }
        $k.Close()
    }
}

function Test-Agent([string]$Name) { return $Name -match '^open-rmm' }

Invoke-RmmModule @{
    install   = {
        param($Params, $Request)
        $pkg = @($Request.packages)[0]
        if (-not $pkg) { throw 'the job carries no package' }
        $path = [string]$pkg.path
        $kind = [string](Get-Prop $Params 'kind' '')
        if (-not $kind) { $kind = if ($path -match '\.msi$') { 'msi' } else { 'exe' } }

        $sig = Get-AuthenticodeSignature -LiteralPath $path
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
        if ($sig.Status -ne 'Valid' -and -not (Get-Prop $Params 'allow_unsigned' $false)) {
            throw "package signature is not valid ($($sig.Status)); allow unsigned packages explicitly in the library to install it"
        }
        $log = Join-Path ([string]$Request.work_dir) 'install.log'
        $msi = @{}
        Send-RmmProgress 20 "installazione di $($pkg.file_name)"
        switch ($kind) {
            'msi' {
                $msi = Get-MsiInfo $path
                $props = [string](Get-Prop $Params 'msi_properties' '')
                $code = Invoke-Installer "$env:SystemRoot\System32\msiexec.exe" "/i `"$path`" /qn /norestart /l*v `"$log`" $props"
            }
            default {
                $silent = [string](Get-Prop $Params 'silent_args' '')
                if (-not $silent) { $silent = $defaultSilent[$kind] }
                if (-not $silent) { throw "no silent arguments for a package of kind '$kind'" }
                $code = Invoke-Installer $path $silent
            }
        }
        $reboot = $rebootCodes -contains $code
        if ($reboot) { Set-RebootMarker "install $($pkg.file_name)" }
        $result = @{
            exit_code = $code; reboot_required = $reboot; signer = $signer; signature = [string]$sig.Status
            product_code = [string]$msi['ProductCode']; product_name = [string]$msi['ProductName']; product_version = [string]$msi['ProductVersion']
        }
        if ($okCodes -notcontains $code) {
            $why = $knownCodes[$code]
            $tail = Get-LogTail $log
            throw "installer exit code $code$(if ($why) { " ($why)" })$(if ($tail) { "`n$tail" })"
        }
        $result
    }
    uninstall = {
        param($Params, $Request)
        $code = [string](Get-Prop $Params 'product_code' '')
        $name = [string](Get-Prop $Params 'name' '')
        $version = [string](Get-Prop $Params 'version' '')
        $entries = @(Get-UninstallEntries)
        if ($code) {
            if ($code -notmatch $guidPattern) { throw "invalid product code $code" }
            $target = $entries | Where-Object { $_.Key -eq $code } | Select-Object -First 1
        }
        elseif ($name) {
            $found = @($entries | Where-Object { $_.Name -eq $name -and (-not $version -or $_.Version -eq $version) })
            if ($found.Count -eq 0) { throw "application not found: $name $version (installed only for a user, or already removed)" }
            if ($found.Count -gt 1) { throw "more than one application named ${name}: give the version or the product code" }
            $target = $found[0]
        }
        else { throw 'give product_code or name' }
        if ($target -and (Test-Agent $target.Name)) { throw 'the open-rmm agent cannot be uninstalled from the console' }
        if (-not $target -and -not $code) { throw 'application not found' }

        $log = Join-Path ([string]$Request.work_dir) 'uninstall.log'
        $msiCode = $null
        if ($code) { $msiCode = $code }
        elseif ($target.Msi -and $target.Key -match $guidPattern) { $msiCode = $target.Key }
        elseif (-not $target.Quiet -and $target.Uninstall -match '(?i)msiexec(\.exe)?\s+/[IX]\s*(\{[0-9A-F-]{36}\})') { $msiCode = $Matches[2] }

        Send-RmmProgress 20 "disinstallazione di $(if ($target) { $target.Name } else { $code })"
        if ($msiCode) {
            $exit = Invoke-Installer "$env:SystemRoot\System32\msiexec.exe" "/x $msiCode /qn /norestart /l*v `"$log`""
            $method = 'msiexec'
        }
        elseif ($target.Quiet) {
            $cl = Split-CommandLine $target.Quiet
            $exit = Invoke-Installer $cl.file $cl.args
            $method = 'quiet_uninstall_string'
        }
        elseif ((Get-Prop $Params 'uninstall_args' '') -and $target.Uninstall) {
            $cl = Split-CommandLine $target.Uninstall
            $exit = Invoke-Installer $cl.file ("$($cl.args) $(Get-Prop $Params 'uninstall_args' '')".Trim())
            $method = 'uninstall_string_with_args'
        }
        else {
            throw "$($target.Name) has no silent uninstall command; give uninstall_args (e.g. /S) if you know its silent switch"
        }
        $reboot = $rebootCodes -contains $exit
        if ($reboot) { Set-RebootMarker "uninstall $($target.Name)" }
        $still = @(Get-UninstallEntries | Where-Object { ($msiCode -and $_.Key -eq $msiCode) -or ($target -and $_.Name -eq $target.Name -and $_.Version -eq $target.Version) })
        $result = @{ exit_code = $exit; method = $method; reboot_required = $reboot; removed = ($still.Count -eq 0)
            name = if ($target) { $target.Name } else { '' }; version = if ($target) { $target.Version } else { '' } }
        if ($okCodes -notcontains $exit) {
            $why = $knownCodes[$exit]
            throw "uninstaller exit code $exit$(if ($why) { " ($why)" })`n$(Get-LogTail $log)"
        }
        if (-not $result.removed -and -not $reboot) { Send-RmmLog 'the application is still registered after the uninstaller finished' 'warn' }
        $result
    }
}
