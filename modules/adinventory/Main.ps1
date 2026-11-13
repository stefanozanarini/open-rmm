# open-rmm adinventory module.
#
# Lists the computer objects of the domain the endpoint belongs to, and its
# enabled user accounts with their names (so the console finds computers by
# the name of their user), through
# ADSI (no RSAT needed). It runs as SYSTEM, so the directory is read with the
# computer account, which every domain member has: the console holds no AD
# credentials. Run it on one server per domain.
#
# collect   { "max": 10000 }   (computers; users are at most 20000)
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

$Accountdisable = 0x2

function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# First value of a search result property.
function Get-First($Result, [string]$Name) {
    $v = $Result.Properties[$Name]
    if ($null -eq $v -or $v.Count -eq 0) { return $null }
    return $v[0]
}

# FILETIME (Int64) or DateTime to ISO 8601 UTC; $null for "never".
function ConvertTo-IsoTime($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    $ft = [int64]$Value
    if ($ft -le 0 -or $ft -eq [int64]::MaxValue) { return $null }
    return [datetime]::FromFileTimeUtc($ft).ToString('o')
}

function Get-DomainName {
    try {
        return [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
    }
    catch {
        throw "this endpoint is not a member of an Active Directory domain, or no domain controller is reachable: $($_.Exception.Message)"
    }
}

function Get-AdComputers([string]$Domain, [int]$Max) {
    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = '(objectCategory=computer)'
    $searcher.PageSize = 1000
    $searcher.SizeLimit = 0
    foreach ($p in 'name', 'samaccountname', 'dnshostname', 'distinguishedname', 'operatingsystem',
        'operatingsystemversion', 'useraccountcontrol', 'lastlogontimestamp', 'pwdlastset', 'whencreated') {
        [void]$searcher.PropertiesToLoad.Add($p)
    }
    $list = New-Object System.Collections.ArrayList
    $truncated = $false
    $results = $searcher.FindAll()
    try {
        foreach ($r in $results) {
            if ($list.Count -ge $Max) { $truncated = $true; break }
            $sam = [string](Get-First $r 'samaccountname')
            $name = if ($sam) { $sam.TrimEnd('$') } else { [string](Get-First $r 'name') }
            $uac = [int](Get-First $r 'useraccountcontrol')
            [void]$list.Add(@{
                    name          = $name
                    dns_host_name = [string](Get-First $r 'dnshostname')
                    dn            = [string](Get-First $r 'distinguishedname')
                    os            = [string](Get-First $r 'operatingsystem')
                    os_version    = [string](Get-First $r 'operatingsystemversion')
                    enabled       = (($uac -band $Accountdisable) -eq 0)
                    last_logon    = ConvertTo-IsoTime (Get-First $r 'lastlogontimestamp')
                    pwd_last_set  = ConvertTo-IsoTime (Get-First $r 'pwdlastset')
                    created       = ConvertTo-IsoTime (Get-First $r 'whencreated')
                })
        }
    }
    finally {
        $results.Dispose()
    }
    @{ computers = $list; truncated = $truncated }
}

# Enabled user accounts: account name, UPN and names. They fill what is left
# of $Budget bytes of the result (the gateway takes messages up to 4 MiB);
# the rest is left out.
function Get-AdUsers([string]$Domain, [int]$Max, [int64]$Budget) {
    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $searcher.PageSize = 1000
    $searcher.SizeLimit = 0
    foreach ($p in 'samaccountname', 'userprincipalname', 'givenname', 'sn', 'displayname') {
        [void]$searcher.PropertiesToLoad.Add($p)
    }
    $list = New-Object System.Collections.ArrayList
    $truncated = $false
    $results = $searcher.FindAll()
    try {
        foreach ($r in $results) {
            $u = @{
                sam          = [string](Get-First $r 'samaccountname')
                upn          = [string](Get-First $r 'userprincipalname')
                given_name   = [string](Get-First $r 'givenname')
                surname      = [string](Get-First $r 'sn')
                display_name = [string](Get-First $r 'displayname')
            }
            if (-not $u.sam -or -not ($u.given_name -or $u.surname -or $u.display_name)) { continue }
            $size = 90 + $u.sam.Length + $u.upn.Length + $u.given_name.Length + $u.surname.Length + $u.display_name.Length
            if ($list.Count -ge $Max -or $size -gt $Budget) { $truncated = $true; break }
            $Budget -= $size
            [void]$list.Add($u)
        }
    }
    finally {
        $results.Dispose()
    }
    @{ users = $list; truncated = $truncated }
}

# Rough size of the computer list once encoded as JSON.
function Measure-Computers($Computers) {
    [int64]$n = 0
    foreach ($c in $Computers) {
        $n += 230 + $c.name.Length + $c.dns_host_name.Length + $c.dn.Length + $c.os.Length + $c.os_version.Length
    }
    $n
}

Invoke-RmmModule @{
    collect = {
        param($Params, $Request)
        $max = 10000
        $m = Get-Prop $Params 'max'
        if ($null -ne $m) { $max = [Math]::Max(1, [Math]::Min(10000, [int]$m)) }
        $domain = Get-DomainName
        Send-RmmProgress 10 "reading $domain"
        $r = Get-AdComputers $domain $max
        if ($r.truncated) { Send-RmmLog "more than $max computer objects: list truncated" 'warn' }
        Send-RmmProgress 60 "reading the users of $domain"
        $u = Get-AdUsers $domain 20000 (3600000 - (Measure-Computers $r.computers))
        if ($u.truncated) { Send-RmmLog "too many user accounts: user list truncated" 'warn' }
        @{
            schema          = 1
            domain          = $domain
            collected_at    = (Get-Date).ToUniversalTime().ToString('o')
            computers       = @($r.computers)
            truncated       = $r.truncated
            users           = @($u.users)
            users_truncated = $u.truncated
        }
    }
}
