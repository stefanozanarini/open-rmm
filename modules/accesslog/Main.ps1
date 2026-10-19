# open-rmm logon events module. Read-only.
#
# Each run reads only the events after the previous run (a record id per
# event log, kept in the module state directory). The first run reads the
# last initial_hours. Only normalized fields are sent; the console stores
# them and evaluates the unusual-logon rules.
#
# Parameters: { "initial_hours": 24, "max_events": 2000 }
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

$logs = [ordered]@{
    security = 'Security'
    rcm      = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    lsm      = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
}

# Interactive (2), unlock (7), remote desktop (10), cached (11).
$logonTypes = "Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11'"

$queries = @(
    @{ channel = 'security'; ids = @(4624); extra = " and *[EventData[$logonTypes]]" }
    @{ channel = 'security'; ids = @(4625, 4740); extra = '' }
    @{ channel = 'rcm'; ids = @(1149); extra = '' }
    @{ channel = 'lsm'; ids = @(21, 24, 25); extra = '' }
)

$kinds = @{ 4624 = 'logon'; 4625 = 'logon_failed'; 4740 = 'lockout'; 1149 = 'rdp_auth'; 21 = 'rdp_session_logon'; 24 = 'rdp_disconnect'; 25 = 'rdp_reconnect' }

# Service and system accounts are not user logons.
function Test-SystemAccount([string]$User) {
    return ($User -match '\$$' -or $User -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON)$' -or $User -match '^(DWM|UMFD)-\d+$')
}

function Get-LatestRecordId([string]$Log) {
    try { return [int64](Get-WinEvent -LogName $Log -MaxEvents 1).RecordId }
    catch { return $null }
}

function Read-Events([string]$Log, [int[]]$Ids, [string]$Extra, $After, [int64]$Upto, [int]$Hours, [int]$Max) {
    $idExpr = ($Ids | ForEach-Object { "EventID=$_" }) -join ' or '
    if ($null -ne $After) { $range = "EventRecordID > $After and EventRecordID <= $Upto" }
    else { $range = "EventRecordID <= $Upto and TimeCreated[timediff(@SystemTime) <= $([int64]$Hours * 3600000)]" }
    $xpath = "*[System[($idExpr) and $range]]$Extra"
    try { return @(Get-WinEvent -LogName $Log -FilterXPath $xpath -MaxEvents $Max) }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }
}

function ConvertTo-LogonEvent([string]$Channel, $Event) {
    $x = [xml]$Event.ToXml()
    $d = @{}
    if ($x.Event.EventData) { foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' } }
    if ($x.Event.UserData) { foreach ($n in $x.Event.UserData.FirstChild.ChildNodes) { $d[[string]$n.LocalName] = [string]$n.InnerText } }
    $id = [int]$Event.Id
    $e = @{
        channel = $Channel; record_id = [int64]$Event.RecordId; event_id = $id; kind = $kinds[$id]
        time = $Event.TimeCreated.ToUniversalTime().ToString('o')
    }
    switch ($id) {
        { $_ -in 4624, 4625 } {
            $e.user = $d['TargetUserName']; $e.domain = $d['TargetDomainName']; $e.logon_type = [int]$d['LogonType']
            $e.source_ip = $d['IpAddress']; $e.source_host = $d['WorkstationName']
            if ($id -eq 4625) { $e.status = ('{0} {1}' -f $d['Status'], $d['SubStatus']).Trim() }
        }
        4740 { $e.user = $d['TargetUserName']; $e.source_host = $d['TargetDomainName'] }
        1149 { $e.user = $d['Param1']; $e.domain = $d['Param2']; $e.source_ip = $d['Param3'] }
        default { $e.user = $d['User']; $e.source_ip = $d['Address'] }
    }
    if ($id -eq 4624 -and (Test-SystemAccount $e.user)) { return }
    $e
}

Invoke-RmmModule @{
    collect = {
        param($Params, $Request)
        $hours = Get-Prop $Params 'initial_hours'
        if (-not $hours) { $hours = 24 }
        $max = Get-Prop $Params 'max_events'
        if (-not $max) { $max = 2000 }
        $stateDir = [string]$Request.state_dir
        if (-not $stateDir) { throw 'this agent does not provide a module state directory; update the agent' }
        $stateFile = Join-Path $stateDir 'bookmarks.json'
        $bookmarks = @{}
        if (Test-Path -LiteralPath $stateFile) {
            $saved = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
            foreach ($p in $saved.PSObject.Properties) { $bookmarks[$p.Name] = [int64]$p.Value }
        }
        $next = @{}
        $events = @()
        $truncated = $false
        foreach ($ch in $logs.Keys) {
            $latest = Get-LatestRecordId $logs[$ch]
            if ($null -eq $latest) { continue }   # log missing or empty
            $after = $bookmarks[$ch]
            # A cleared log restarts from lower record ids.
            if ($null -ne $after -and $after -gt $latest) { $after = $null }
            foreach ($q in $queries | Where-Object { $_.channel -eq $ch }) {
                $found = Read-Events $logs[$ch] $q.ids $q.extra $after $latest $hours $max
                if ($found.Count -ge $max) { $truncated = $true }
                foreach ($ev in $found) {
                    $e = ConvertTo-LogonEvent $ch $ev
                    if ($e) { $events += $e }
                }
            }
            $next[$ch] = $latest
        }
        # Saved before the result is sent: the agent's outbox delivers it.
        $tmp = "$stateFile.tmp"
        Set-Content -LiteralPath $tmp -Value (ConvertTo-Json -InputObject $next -Compress) -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $stateFile -Force
        Send-RmmLog "$($events.Count) events" 'info'
        @{ events = $events; truncated = $truncated }
    }
}
