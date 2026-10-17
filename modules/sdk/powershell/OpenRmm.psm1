# open-rmm module SDK for PowerShell (protocol version 1).
#
# A module script imports this file (packed as _sdk/OpenRmm.psm1) and calls
# Invoke-RmmModule with one script block per action:
#
#   Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')
#   Invoke-RmmModule @{
#       info = { param($Params, $Request)
#           Send-RmmProgress 50 'collecting'
#           @{ hostname = $env:COMPUTERNAME }      # the result
#       }
#   }
#
# The value returned by the script block is the result, serialized as JSON.
# Anything else written to stdout (Write-Host, stray output) is recorded by
# the agent as log lines and never breaks the protocol.
#
# Works on Windows PowerShell 5.1 and PowerShell 7.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# The protocol is UTF-8 in both directions. Dedicated streams are used
# instead of changing the console encoding, which fails when the process has
# no console (as when started by the agent service).
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Out = New-Object System.IO.StreamWriter([Console]::OpenStandardOutput(), $script:Utf8)
$script:Out.AutoFlush = $true
$script:In = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $script:Utf8)

function Write-RmmEvent {
    param([Parameter(Mandatory)][hashtable]$Event)
    $json = ConvertTo-Json -InputObject $Event -Compress -Depth 32
    $script:Out.WriteLine($json)
}

function Read-RmmRequest {
    $line = $script:In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) { throw 'no request received from the agent' }
    ConvertFrom-Json -InputObject $line
}

function Send-RmmProgress {
    param([Parameter(Mandatory)][ValidateRange(0, 100)][int]$Percent, [string]$Message = '')
    Write-RmmEvent @{ type = 'progress'; percent = $Percent; message = $Message }
}

function Send-RmmLog {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet('debug', 'info', 'warn', 'error')][string]$Level = 'info')
    Write-RmmEvent @{ type = 'log'; level = $Level; message = $Message }
}

function Send-RmmResult {
    param([AllowNull()]$Data)
    if ($null -eq $Data) { $Data = @{} }
    Write-RmmEvent @{ type = 'result'; data = $Data }
}

function Send-RmmError {
    param([Parameter(Mandatory)][string]$Message)
    Write-RmmEvent @{ type = 'error'; message = $Message }
}

function Invoke-RmmModule {
    param([Parameter(Mandatory)][hashtable]$Actions)
    try {
        $request = Read-RmmRequest
        if ($request.protocol_version -ne 1) { throw "unsupported protocol version $($request.protocol_version)" }
        $handler = $Actions[$request.action]
        if ($null -eq $handler) { throw "unknown action '$($request.action)'" }
        $result = & $handler $request.params $request
        # A script block returning several objects yields an array; one
        # object stays as is.
        Send-RmmResult $result
    }
    catch {
        $msg = $_.Exception.Message
        # The position helps when the error comes from the module, not when
        # it comes from the SDK itself (e.g. an unknown action).
        $inv = $_.InvocationInfo
        if ($inv -and $inv.PositionMessage -and $inv.ScriptName -ne $PSCommandPath) { $msg += "`n" + $inv.PositionMessage }
        Send-RmmError $msg
        exit 1
    }
}

Export-ModuleMember -Function Invoke-RmmModule, Read-RmmRequest, Send-RmmProgress, Send-RmmLog, Send-RmmResult, Send-RmmError
