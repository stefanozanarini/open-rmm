Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

Invoke-RmmModule @{
    info = {
        param($Params, $Request)
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        Send-RmmProgress 50 'operating system read'
        @{
            hostname         = $env:COMPUTERNAME
            domain           = $cs.Domain
            os               = $os.Caption
            os_version       = $os.Version
            os_build         = $os.BuildNumber
            last_boot        = $os.LastBootUpTime.ToUniversalTime().ToString('o')
            uptime_seconds   = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
            powershell       = $PSVersionTable.PSVersion.ToString()
        }
    }
}
