# open-rmm inventory module (Windows). Read-only: it never changes the system.
# Every section is collected on its own, so a failing WMI class only leaves
# that section empty (with a warning) instead of failing the inventory.
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

function Get-Section {
    param([string]$Name, [scriptblock]$Block, $Default)
    try { & $Block }
    catch {
        Send-RmmLog "${Name}: $($_.Exception.Message)" 'warn'
        $Default
    }
}

function ConvertTo-Iso($Date) {
    if ($Date -is [datetime]) { return $Date.ToUniversalTime().ToString('o') }
    return $null
}

function Get-Str($Value) {
    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim()
}

# Decodes the uint16 arrays of WmiMonitorID.
function ConvertFrom-WmiChars($Chars) {
    if (-not $Chars) { return '' }
    return (-join ($Chars | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })).Trim()
}

function Open-HKLM {
    [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
}

function Get-RegValue([Microsoft.Win32.RegistryKey]$Base, [string]$Path, [string]$Name) {
    $k = $Base.OpenSubKey($Path)
    if ($null -eq $k) { return $null }
    try { return $k.GetValue($Name) } finally { $k.Close() }
}

$chassisTypes = @{
    3 = 'desktop'; 4 = 'desktop'; 5 = 'desktop'; 6 = 'desktop'; 7 = 'desktop'; 13 = 'all-in-one'; 15 = 'desktop'; 16 = 'desktop'; 35 = 'mini-pc'; 36 = 'desktop'
    8 = 'laptop'; 9 = 'laptop'; 10 = 'laptop'; 14 = 'laptop'; 31 = 'laptop'; 32 = 'laptop'; 30 = 'tablet'
    17 = 'server'; 23 = 'server'; 28 = 'server'
}

function Get-SystemInfo {
    $cs = Get-CimInstance Win32_ComputerSystem
    $csp = Get-CimInstance Win32_ComputerSystemProduct
    $bios = Get-CimInstance Win32_BIOS
    $enc = @(Get-CimInstance Win32_SystemEnclosure)[0]
    $manufacturer = Get-Str $cs.Manufacturer
    $model = Get-Str $cs.Model
    $sku = Get-Str $cs.SystemSKUNumber
    # Lenovo puts the machine type in Model and the marketing name in Version.
    if ($manufacturer -match '^LENOVO' -and (Get-Str $csp.Version)) {
        $sku = $model
        $model = Get-Str $csp.Version
    }
    $chassis = ''
    if ($enc -and $enc.ChassisTypes) { $chassis = $chassisTypes[[int]$enc.ChassisTypes[0]] }
    @{
        manufacturer   = $manufacturer
        model          = $model
        sku            = $sku
        serial         = Get-Str $bios.SerialNumber
        chassis        = Get-Str $chassis
        domain         = Get-Str $cs.Domain
        part_of_domain = [bool]$cs.PartOfDomain
        virtual        = [bool]("$manufacturer $model" -match 'VMware|VirtualBox|Virtual Machine|QEMU|KVM|Xen|Parallels|Hyper-V')
    }
}

function Get-OSInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $hklm = Open-HKLM
    $cv = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $type = Get-Str (Get-RegValue $hklm $cv 'InstallationType')
    $ubr = Get-RegValue $hklm $cv 'UBR'
    $family = if ($type -eq 'Client') { 'client' } elseif ($type -match 'Server') { 'server' } else { '' }
    $build = Get-Str $os.BuildNumber
    if ($null -ne $ubr) { $build = "$build.$ubr" }
    @{
        name              = Get-Str $os.Caption
        version           = Get-Str $os.Version
        build             = $build
        display_version   = Get-Str (Get-RegValue $hklm $cv 'DisplayVersion')
        family            = $family
        installation_type = $type
        architecture      = Get-Str $os.OSArchitecture
        install_date      = ConvertTo-Iso $os.InstallDate
        last_boot         = ConvertTo-Iso $os.LastBootUpTime
        logged_on_user    = Get-Str $cs.UserName
    }
}

function Get-FirmwareInfo {
    $bios = Get-CimInstance Win32_BIOS
    $uefi = $null
    $secureBoot = $null
    try {
        $secureBoot = [bool](Confirm-SecureBootUEFI)
        $uefi = $true
    }
    catch [System.PlatformNotSupportedException] { $uefi = $false; $secureBoot = $false }
    catch { }
    $date = ''
    if ($bios.ReleaseDate -is [datetime]) { $date = $bios.ReleaseDate.ToString('yyyy-MM-dd') }
    @{
        vendor      = Get-Str $bios.Manufacturer
        version     = Get-Str $bios.SMBIOSBIOSVersion
        date        = $date
        uefi        = $uefi
        secure_boot = $secureBoot
    }
}

function Get-CpuInfo {
    foreach ($p in Get-CimInstance Win32_Processor) {
        @{ name = Get-Str $p.Name; cores = [int]$p.NumberOfCores; threads = [int]$p.NumberOfLogicalProcessors }
    }
}

function Get-MemoryInfo {
    $modules = @(foreach ($m in Get-CimInstance Win32_PhysicalMemory) {
        $speed = $m.ConfiguredClockSpeed
        if (-not $speed) { $speed = $m.Speed }
        @{
            slot           = Get-Str $m.DeviceLocator
            capacity_bytes = [int64]$m.Capacity
            speed_mhz      = [int]$speed
            manufacturer   = Get-Str $m.Manufacturer
            part_number    = Get-Str $m.PartNumber
            serial         = Get-Str $m.SerialNumber
        }
    })
    $total = [int64]0
    foreach ($m in $modules) { $total += $m.capacity_bytes }
    if ($total -eq 0) { $total = [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }
    @{ total_bytes = $total; modules = $modules }
}

function Get-DiskInfo {
    foreach ($d in Get-PhysicalDisk) {
        $media = Get-Str $d.MediaType
        if ($media -eq 'Unspecified') { $media = '' }
        @{
            model      = Get-Str $d.FriendlyName
            serial     = Get-Str $d.SerialNumber
            media_type = $media
            bus        = Get-Str $d.BusType
            size_bytes = [int64]$d.Size
            health     = Get-Str $d.HealthStatus
        }
    }
}

$encryptionMethods = @{ 1 = 'AES-128-Diffuser'; 2 = 'AES-256-Diffuser'; 3 = 'AES-128'; 4 = 'AES-256'; 6 = 'XTS-AES-128'; 7 = 'XTS-AES-256' }

function Get-BitLockerStates {
    $out = @{}
    $vols = Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume
    foreach ($v in $vols) {
        if (-not $v.DriveLetter) { continue }
        $state = switch ([int]$v.ConversionStatus) {
            0 { 'off' }
            1 { if ([int]$v.ProtectionStatus -eq 1) { 'on' } else { 'suspended' } }
            2 { 'encrypting' }
            3 { 'decrypting' }
            4 { 'encrypting' }
            5 { 'decrypting' }
            default { '' }
        }
        $method = ''
        $r = Invoke-CimMethod -InputObject $v -MethodName GetEncryptionMethod -ErrorAction SilentlyContinue
        if ($r -and $encryptionMethods.ContainsKey([int]$r.EncryptionMethod)) { $method = $encryptionMethods[[int]$r.EncryptionMethod] }
        $out[(Get-Str $v.DriveLetter).ToUpper()] = @{ state = $state; method = $method }
    }
    $out
}

function Get-VolumeInfo {
    $bl = Get-Section 'bitlocker' { Get-BitLockerStates } @{}
    foreach ($v in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3') {
        $letter = (Get-Str $v.DeviceID).ToUpper()
        $b = $bl[$letter]
        @{
            mount      = $letter
            label      = Get-Str $v.VolumeName
            fs         = Get-Str $v.FileSystem
            size_bytes = [int64]$v.Size
            free_bytes = [int64]$v.FreeSpace
            bitlocker  = if ($b) { $b.state } else { '' }
            encryption = if ($b) { $b.method } else { '' }
        }
    }
}

function Get-NetworkInfo {
    foreach ($n in Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE') {
        $ips = @($n.IPAddress)
        @{
            name    = Get-Str $n.Description
            mac     = Get-Str $n.MACAddress
            ipv4    = @($ips | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
            ipv6    = @($ips | Where-Object { $_ -match ':' })
            gateway = @($n.DefaultIPGateway | Where-Object { $_ })
            dns     = @($n.DNSServerSearchOrder | Where-Object { $_ })
            dhcp    = [bool]$n.DHCPEnabled
        }
    }
}

function Get-TpmInfo {
    $t = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    if (-not $t) { return @{ present = $false } }
    $version = ''
    if ($t.SpecVersion) { $version = (Get-Str $t.SpecVersion).Split(',')[0].Trim() }
    @{ present = $true; ready = [bool]($t.IsEnabled_InitialValue -and $t.IsActivated_InitialValue); version = $version }
}

function Get-BatteryInfo {
    $static = @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryStaticData -ErrorAction SilentlyContinue)
    if ($static.Count -eq 0) { return }
    $full = @{}
    foreach ($f in @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue)) { $full[$f.InstanceName] = [int64]$f.FullChargedCapacity }
    $cycles = @{}
    foreach ($c in @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryCycleCount -ErrorAction SilentlyContinue)) { $cycles[$c.InstanceName] = [int]$c.CycleCount }
    $charge = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
    $i = 0
    foreach ($s in $static) {
        $design = [int64]$s.DesignedCapacity
        $fc = [int64]$full[$s.InstanceName]
        $health = 0
        if ($design -gt 0 -and $fc -gt 0) { $health = [int][math]::Round(100 * $fc / $design) }
        $pct = 0
        if ($i -lt $charge.Count) { $pct = [int]$charge[$i].EstimatedChargeRemaining }
        $i++
        @{
            name                 = Get-Str $s.DeviceName
            design_capacity      = $design
            full_charge_capacity = $fc
            health_percent       = $health
            charge_percent       = $pct
            cycle_count          = [int]$cycles[$s.InstanceName]
        }
    }
}

function Get-MonitorInfo {
    foreach ($m in @(Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorID -ErrorAction SilentlyContinue)) {
        @{
            manufacturer = ConvertFrom-WmiChars $m.ManufacturerName
            model        = ConvertFrom-WmiChars $m.UserFriendlyName
            serial       = ConvertFrom-WmiChars $m.SerialNumberID
        }
    }
}

# Reads one Uninstall key. Updates and entries without a name are skipped.
function Read-UninstallKey([Microsoft.Win32.RegistryKey]$Root, [string]$Path, [string]$Arch, [string]$Scope) {
    $k = $Root.OpenSubKey($Path)
    if ($null -eq $k) { return }
    try {
        foreach ($name in $k.GetSubKeyNames()) {
            $e = $k.OpenSubKey($name)
            if ($null -eq $e) { continue }
            try {
                $display = Get-Str $e.GetValue('DisplayName')
                if (-not $display) { continue }
                if ($e.GetValue('ParentKeyName')) { continue }
                if ((Get-Str $e.GetValue('ReleaseType')) -match 'Update|Hotfix') { continue }
                $productCode = ''
                if ([int]$e.GetValue('WindowsInstaller', 0) -eq 1 -and $name -match '^\{[0-9A-Fa-f-]{36}\}$') { $productCode = $name.ToUpper() }
                @{
                    name             = $display
                    version          = Get-Str $e.GetValue('DisplayVersion')
                    publisher        = Get-Str $e.GetValue('Publisher')
                    install_date     = Get-Str $e.GetValue('InstallDate')
                    arch             = $Arch
                    scope            = $Scope
                    product_code     = $productCode
                    quiet_uninstall  = [bool](Get-Str $e.GetValue('QuietUninstallString'))
                    system_component = ([int]$e.GetValue('SystemComponent', 0) -eq 1)
                }
            }
            finally { $e.Close() }
        }
    }
    finally { $k.Close() }
}

function Get-SoftwareInfo {
    $path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $hklm = Open-HKLM
    Read-UninstallKey $hklm $path 'x64' 'machine'
    Read-UninstallKey $hklm 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' 'x86' 'machine'
    # Per-user installations of the users whose profile is loaded.
    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    foreach ($sid in $users.GetSubKeyNames()) {
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        Read-UninstallKey $users "$sid\$path" '' 'user'
    }
}

# Remote-access tool ids. Supremo (NanoSystems) is 32-bit and normally
# registers under WOW6432Node; the id may be a string with spaces or a DWORD.
function Get-RegistryId([string[]]$Paths, [string]$Name) {
    $hklm = Open-HKLM
    foreach ($p in $Paths) {
        $v = Get-RegValue $hklm $p $Name
        if ($null -ne $v -and "$v" -ne '' -and "$v" -ne '0') { return "$v" }
    }
    return ''
}

function Get-AnyDeskId {
    foreach ($dir in Get-ChildItem -Path $env:ProgramData -Filter 'AnyDesk*' -Directory -ErrorAction SilentlyContinue) {
        $conf = Join-Path $dir.FullName 'system.conf'
        if (-not (Test-Path -LiteralPath $conf)) { continue }
        foreach ($line in Get-Content -LiteralPath $conf -ErrorAction SilentlyContinue) {
            if ($line -match '^\s*ad\.anynet\.id\s*=\s*(\d+)') { return $Matches[1] }
        }
    }
    return ''
}

function Get-RemoteAccessInfo {
    @{
        supremo_id    = Get-RegistryId @('SOFTWARE\WOW6432Node\Supremo', 'SOFTWARE\Supremo') 'ClientID'
        anydesk_id    = Get-AnyDeskId
        teamviewer_id = Get-RegistryId @('SOFTWARE\WOW6432Node\TeamViewer', 'SOFTWARE\TeamViewer') 'ClientID'
    }
}

Invoke-RmmModule @{
    collect = {
        param($Params, $Request)
        $inv = @{ schema = 1; collected_at = (Get-Date).ToUniversalTime().ToString('o') }
        Send-RmmProgress 5 'system'
        $inv.system = Get-Section 'system' { Get-SystemInfo } @{}
        $inv.os = Get-Section 'os' { Get-OSInfo } @{}
        $inv.firmware = Get-Section 'firmware' { Get-FirmwareInfo } @{}
        Send-RmmProgress 25 'hardware'
        $inv.cpus = @(Get-Section 'cpu' { Get-CpuInfo } @())
        $inv.memory = Get-Section 'memory' { Get-MemoryInfo } @{}
        $inv.disks = @(Get-Section 'disks' { Get-DiskInfo } @())
        $inv.volumes = @(Get-Section 'volumes' { Get-VolumeInfo } @())
        $inv.network = @(Get-Section 'network' { Get-NetworkInfo } @())
        $inv.tpm = Get-Section 'tpm' { Get-TpmInfo } @{}
        $inv.batteries = @(Get-Section 'batteries' { Get-BatteryInfo } @())
        $inv.monitors = @(Get-Section 'monitors' { Get-MonitorInfo } @())
        Send-RmmProgress 60 'software'
        $inv.software = @(Get-Section 'software' { Get-SoftwareInfo } @())
        $inv.remote_access = Get-Section 'remote_access' { Get-RemoteAccessInfo } @{}
        $inv
    }
}
