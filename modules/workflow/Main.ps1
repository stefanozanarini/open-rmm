# open-rmm workflow module: runs a software distribution workflow of the
# console (internal/workflow).
#
# run  { "workflow_id": "...", "name": "...", "revision": 3,
#        "workflow": { "detection": { "match": "all|any", "rules": [...] },
#                      "steps": [ { "type": "script|command|download|http|install",
#                                   "when": { "match": ..., "rules": [...] }, ... } ] } }
#
# Detection rules first: when they hold the computer is compliant and no
# step runs. Otherwise the steps run in order, each only when its conditions
# hold; a failed step stops the workflow unless continue_on_error. At the
# end the detection rules must hold. Library packages come with the signed
# job, already hash-checked by the agent. Environment variables (%VAR%) are
# expanded in paths, arguments, URLs, headers and bodies; %RMM_WORK% is the
# work folder of the job. Never reboots: a needed reboot is recorded for the
# reboot module.
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

$MaxLog = 4000
$okInstallCodes = @(0, 3010, 1641)
$rebootCodes = @(3010, 1641)
$defaultSilent = @{
    inno     = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
    nullsoft = '/S'
    burn     = '/quiet /norestart'
}

function Get-Prop($Object, [string]$Name, $Default = $null) {
    if ($null -ne $Object) {
        $p = $Object.PSObject.Properties[$Name]
        if ($p -and $null -ne $p.Value) { return $p.Value }
    }
    return $Default
}

function Expand-Text([string]$Text) { [Environment]::ExpandEnvironmentVariables($Text) }

function Limit-Text([string]$Text, [int]$Max = $MaxLog) {
    if ($Text.Length -le $Max) { return $Text }
    $Text.Substring(0, $Max) + ' ...'
}

# Leading numeric part of a version string ("24.08 (x64)" is 24.8).
function ConvertTo-Version([string]$Text) {
    if ($Text -match '^\s*v?(\d+(\.\d+){0,3})') { return [version]($Matches[1] + $(if ($Matches[1] -notmatch '\.') { '.0' })) }
    return $null
}

function Test-VersionAtLeast([string]$Have, [string]$Want) {
    $h = ConvertTo-Version $Have
    $w = ConvertTo-Version $Want
    if ($null -eq $h -or $null -eq $w) { return $false }
    return $h -ge $w
}

function Set-RebootMarker([string]$Reason) {
    $key = 'HKLM:\SOFTWARE\open-rmm-modules'
    if (-not (Test-Path $key)) { [void](New-Item -Path $key -Force) }
    Set-ItemProperty -Path $key -Name 'RebootRequiredAt' -Value (Get-Date).ToUniversalTime().ToString('o')
    Set-ItemProperty -Path $key -Name 'RebootRequiredBy' -Value $Reason
}

# ---- rules ----

function Get-UninstallEntries {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    foreach ($path in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
        $k = $hklm.OpenSubKey($path)
        if ($null -eq $k) { continue }
        foreach ($n in $k.GetSubKeyNames()) {
            $e = $k.OpenSubKey($n)
            if ($null -eq $e) { continue }
            $name = [string]$e.GetValue('DisplayName')
            if ($name) { [pscustomobject]@{ Name = $name.Trim(); Version = [string]$e.GetValue('DisplayVersion') } }
            $e.Close()
        }
        $k.Close()
    }
}

function Initialize-RegistryDrive([string]$Path) {
    $root = ($Path -split ':')[0].ToUpper()
    $hives = @{ HKU = 'HKEY_USERS'; HKCR = 'HKEY_CLASSES_ROOT' }
    if ($hives.ContainsKey($root) -and -not (Get-PSDrive -Name $root -ErrorAction SilentlyContinue)) {
        [void](New-PSDrive -Name $root -PSProvider Registry -Root $hives[$root] -Scope Script)
    }
}

# The user to check AD groups for: the one logged on, or the last one.
function Get-CurrentUser {
    $u = [string](Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $u) {
        $u = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -ErrorAction SilentlyContinue).LastLoggedOnSAMUser
        if ($u) { Send-RmmLog "nobody is logged on: checking the last user $u" 'info' }
    }
    return $u
}

$script:GroupCache = @{}

# Names (sAMAccountName and name, lower case) of the AD security groups of a
# principal, nested groups included; read with the computer account.
function Get-AdGroups([string]$Kind) {
    if ($script:GroupCache.ContainsKey($Kind)) { return $script:GroupCache[$Kind] }
    $names = @()
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain)
    if ($Kind -eq 'computer') {
        $p = [System.DirectoryServices.AccountManagement.ComputerPrincipal]::FindByIdentity($ctx, "$env:COMPUTERNAME`$")
        $who = $env:COMPUTERNAME
    }
    else {
        $who = Get-CurrentUser
        $p = $null
        if ($who) { $p = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, ($who -split '\\')[-1]) }
    }
    if ($null -eq $p) {
        Send-RmmLog "no Active Directory account found for the $Kind $(if ($who) { $who } else { '(nobody logged on)' })" 'warn'
    }
    else {
        foreach ($g in $p.GetAuthorizationGroups()) {
            if ($g.SamAccountName) { $names += $g.SamAccountName.ToLower() }
            if ($g.Name) { $names += $g.Name.ToLower() }
        }
    }
    $script:GroupCache[$Kind] = $names
    return $names
}

function Test-Rule($Rule) {
    $type = [string](Get-Prop $Rule 'type' '')
    $op = [string](Get-Prop $Rule 'op' 'exists')
    $value = [string](Get-Prop $Rule 'value' '')
    $name = [string](Get-Prop $Rule 'name' '')
    $path = Expand-Text ([string](Get-Prop $Rule 'path' ''))
    switch ($type) {
        'script' {
            $out = @(& ([scriptblock]::Create([string](Get-Prop $Rule 'script' ''))))
            return ($out.Count -gt 0 -and $out[-1] -eq $true)
        }
        'registry' {
            Initialize-RegistryDrive $path
            if (-not (Test-Path -LiteralPath $path)) { return $false }
            if (-not $name) { return $op -eq 'exists' }
            $item = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue
            if ($null -eq $item) { return $false }
            if ($op -eq 'equals') { return [string]$item.$name -eq $value }
            return $true
        }
        'file' {
            if (-not (Test-Path -LiteralPath $path)) { return $false }
            if ($op -eq 'version_ge') {
                $v = (Get-Item -LiteralPath $path).VersionInfo
                return (Test-VersionAtLeast "$($v.FileMajorPart).$($v.FileMinorPart).$($v.FileBuildPart).$($v.FilePrivatePart)" $value)
            }
            return $true
        }
        'app' {
            $found = @(Get-UninstallEntries | Where-Object { $_.Name -like $name })
            if ($op -eq 'version_ge') { return @($found | Where-Object { Test-VersionAtLeast $_.Version $value }).Count -gt 0 }
            return $found.Count -gt 0
        }
        { $_ -in 'user_group', 'computer_group' } {
            $want = ($name -split '\\')[-1].ToLower()
            return (Get-AdGroups $(if ($type -eq 'user_group') { 'user' } else { 'computer' })) -contains $want
        }
        default { throw "unknown rule type '$type'" }
    }
}

function Format-Rule($Rule) {
    $t = [string](Get-Prop $Rule 'type' '')
    $what = @((Get-Prop $Rule 'name' ''), (Get-Prop $Rule 'path' ''), (Get-Prop $Rule 'op' ''), (Get-Prop $Rule 'value' '')) | Where-Object { $_ }
    $text = "$t $($what -join ' ')".Trim()
    if (Get-Prop $Rule 'negate' $false) { $text = "NOT $text" }
    return $text
}

# Evaluates rules joined by all (AND) or any (OR); no rules hold.
function Test-Conditions($Conditions, [string]$Label) {
    $rules = @(Get-Prop $Conditions 'rules' @())
    if ($rules.Count -eq 0) { return $true }
    $any = ([string](Get-Prop $Conditions 'match' 'all')) -eq 'any'
    foreach ($r in $rules) {
        try { $ok = [bool](Test-Rule $r) }
        catch { Send-RmmLog "$Label, $(Format-Rule $r): $($_.Exception.Message)" 'warn'; $ok = $false }
        if (Get-Prop $r 'negate' $false) { $ok = -not $ok }
        Send-RmmLog "$Label, $(Format-Rule $r): $(if ($ok) { 'true' } else { 'false' })" 'info'
        if ($any -and $ok) { return $true }
        if (-not $any -and -not $ok) { return $false }
    }
    return (-not $any)
}

# ---- steps ----

# Runs a program and waits at most $Timeout seconds; returns the exit code
# and the end of its output.
function Invoke-Program([string]$File, [string]$Arguments, [int]$Timeout, [string]$Work) {
    $out = Join-Path $Work ([guid]::NewGuid().ToString('n') + '.out')
    $err = "$out.err"
    Send-RmmLog "running: $File $Arguments" 'info'
    $sp = @{ FilePath = $File; PassThru = $true; NoNewWindow = $true; RedirectStandardOutput = $out; RedirectStandardError = $err }
    if ($Arguments) { $sp.ArgumentList = $Arguments }
    $p = Start-Process @sp
    if (-not $p.WaitForExit($Timeout * 1000)) {
        try { $p.Kill() } catch { }
        throw "still running after $Timeout seconds: stopped"
    }
    $p.WaitForExit()
    $text = ''
    foreach ($f in $out, $err) {
        if (Test-Path -LiteralPath $f) { $text += (Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue) }
    }
    @{ code = [int]$p.ExitCode; output = (Limit-Text ([string]$text).Trim()) }
}

function Resolve-File([string]$Name, $Files, [string]$Work) {
    $n = Expand-Text $Name
    if ($Files.ContainsKey($n.ToLower())) { return $Files[$n.ToLower()] }
    if ([System.IO.Path]::IsPathRooted($n)) { return $n }
    $local = Join-Path $Work $n
    if (Test-Path -LiteralPath $local) { return $local }
    return $n # a program on the PATH (cmd.exe, msiexec.exe...)
}

function Get-Destination([string]$SaveAs, [string]$Default, [string]$Work) {
    $n = Expand-Text $SaveAs
    if (-not $n) { $n = $Default }
    $dest = if ([System.IO.Path]::IsPathRooted($n)) { $n } else { Join-Path $Work $n }
    $dir = Split-Path -Parent $dest
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    return $dest
}

function Invoke-Step($Step, $Ctx) {
    $type = [string](Get-Prop $Step 'type' '')
    $timeout = [int](Get-Prop $Step 'timeout_seconds' 0)
    if ($timeout -le 0) { $timeout = 1800 }
    $work = $Ctx.work
    switch ($type) {
        'script' {
            $file = Join-Path $work ([guid]::NewGuid().ToString('n') + '.ps1')
            # UTF-8 with BOM, so Windows PowerShell 5.1 reads it right.
            [System.IO.File]::WriteAllText($file, [string](Get-Prop $Step 'script' ''), (New-Object System.Text.UTF8Encoding($true)))
            $ps = (Get-Process -Id $PID).Path
            $r = Invoke-Program $ps "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$file`"" $timeout $work
            if ($r.output) { Send-RmmLog $r.output 'info' }
            if ($r.code -ne 0) { throw "the script ended with exit code $($r.code)" }
            return @{ detail = ''; exit_code = $r.code }
        }
        'command' {
            $file = Resolve-File ([string](Get-Prop $Step 'command' '')) $Ctx.files $work
            $r = Invoke-Program $file (Expand-Text ([string](Get-Prop $Step 'args' ''))) $timeout $work
            if ($r.output) { Send-RmmLog $r.output 'info' }
            $ok = @(Get-Prop $Step 'success_codes' @(0))
            if ($ok -notcontains $r.code) { throw "exit code $($r.code)" }
            return @{ detail = ''; exit_code = $r.code }
        }
        'download' {
            $sha = [string](Get-Prop $Step 'package' '')
            $saveAs = [string](Get-Prop $Step 'save_as' '')
            if ($sha) {
                $pkg = $Ctx.packages[$sha]
                if (-not $pkg) { throw "the job does not carry the package $sha" }
                $dest = Get-Destination $saveAs ([string]$pkg.file_name) $work
                Copy-Item -LiteralPath ([string]$pkg.path) -Destination $dest -Force
            }
            else {
                $url = Expand-Text ([string](Get-Prop $Step 'url' ''))
                $dest = Get-Destination $saveAs '' $work
                Send-RmmLog "downloading $url" 'info'
                Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -TimeoutSec $timeout
                $want = [string](Get-Prop $Step 'sha256' '')
                if ($want) {
                    $got = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLower()
                    if ($got -ne $want) { Remove-Item -LiteralPath $dest -Force; throw "SHA-256 mismatch: got $got" }
                }
            }
            $Ctx.files[(Split-Path -Leaf $dest).ToLower()] = $dest
            if ($saveAs) { $Ctx.files[(Expand-Text $saveAs).ToLower()] = $dest }
            return @{ detail = $dest }
        }
        'http' {
            $method = [string](Get-Prop $Step 'method' 'GET')
            $req = @{ Uri = (Expand-Text ([string](Get-Prop $Step 'url' ''))); Method = $method; UseBasicParsing = $true; TimeoutSec = [Math]::Min($timeout, 300) }
            $headers = @{}
            foreach ($line in ([string](Get-Prop $Step 'headers' '')) -split "`r?`n") {
                if ($line -match '^\s*([^:\s]+)\s*:\s*(.*)$') { $headers[$Matches[1]] = Expand-Text $Matches[2] }
            }
            if ($headers.Count) { $req.Headers = $headers }
            if ($method -eq 'POST') {
                $req.Body = [System.Text.Encoding]::UTF8.GetBytes((Expand-Text ([string](Get-Prop $Step 'body' ''))))
                $ct = [string](Get-Prop $Step 'content_type' '')
                $req.ContentType = if ($ct) { $ct } else { 'application/json; charset=utf-8' }
            }
            Send-RmmLog "$method $($req.Uri)" 'info'
            try { $resp = Invoke-WebRequest @req }
            catch {
                $code = $null
                if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                throw "HTTP $(if ($code) { $code } else { 'error' }): $($_.Exception.Message)"
            }
            Send-RmmLog "HTTP $($resp.StatusCode): $(Limit-Text ([string]$resp.Content) 2000)" 'info'
            return @{ detail = "HTTP $($resp.StatusCode)" }
        }
        'install' {
            $sha = [string](Get-Prop $Step 'package' '')
            if ($sha) {
                $pkg = $Ctx.packages[$sha]
                if (-not $pkg) { throw "the job does not carry the package $sha" }
                $path = [string]$pkg.path
            }
            else {
                $path = Resolve-File ([string](Get-Prop $Step 'file' '')) $Ctx.files $work
                if (-not (Test-Path -LiteralPath $path)) { throw "file not found: $path" }
            }
            $sig = Get-AuthenticodeSignature -LiteralPath $path
            if ($sig.Status -ne 'Valid' -and -not (Get-Prop $Step 'allow_unsigned' $false)) {
                throw "the signature of $(Split-Path -Leaf $path) is not valid ($($sig.Status)); allow unsigned installers in the step to install it"
            }
            $kind = [string](Get-Prop $Step 'kind' '')
            if (-not $kind) { $kind = if ($path -match '\.msi$') { 'msi' } else { 'exe' } }
            $extra = Expand-Text ([string](Get-Prop $Step 'args' ''))
            if ($kind -eq 'msi') {
                $log = Join-Path $work ([guid]::NewGuid().ToString('n') + '.log')
                $r = Invoke-Program "$env:SystemRoot\System32\msiexec.exe" "/i `"$path`" /qn /norestart /l*v `"$log`" $extra".Trim() $timeout $work
            }
            else {
                $silent = $defaultSilent[$kind]
                if ($kind -eq 'exe' -and -not $extra) { throw 'give the silent arguments of the setup program (e.g. /S or /quiet)' }
                $r = Invoke-Program $path "$silent $extra".Trim() $timeout $work
            }
            $ok = @(Get-Prop $Step 'success_codes' $okInstallCodes)
            if ($rebootCodes -contains $r.code) {
                $Ctx.reboot = $true
                Set-RebootMarker "workflow $($Ctx.name): $(Split-Path -Leaf $path)"
            }
            if ($ok -notcontains $r.code) { throw "installer exit code $($r.code)$(if ($r.output) { "`n$($r.output)" })" }
            return @{ detail = (Split-Path -Leaf $path); exit_code = $r.code }
        }
        default { throw "unknown step type '$type'" }
    }
}

Invoke-RmmModule @{
    run = {
        param($Params, $Request)
        $wf = Get-Prop $Params 'workflow'
        if ($null -eq $wf) { throw 'params.workflow is required' }
        $work = [string]$Request.work_dir
        $env:RMM_WORK = $work
        $env:NO_COLOR = '1' # plain error text from PowerShell 7 scripts
        $ctx = @{ work = $work; files = @{}; packages = @{}; reboot = $false
            name = "$(Get-Prop $Params 'name' '') rev. $(Get-Prop $Params 'revision' '')" }
        foreach ($p in @(Get-Prop $Request 'packages' @())) { $ctx.packages[([string]$p.sha256).ToLower()] = $p }

        $detection = Get-Prop $wf 'detection'
        $hasDetection = @(Get-Prop $detection 'rules' @()).Count -gt 0
        if ($hasDetection -and (Test-Conditions $detection 'detection')) {
            Send-RmmLog 'the detection rules hold: the computer is compliant, no step runs' 'info'
            return @{ compliant = $true; verified = $true; steps = @(); reboot_required = $false }
        }

        $steps = @(Get-Prop $wf 'steps' @())
        $results = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $steps.Count; $i++) {
            $s = $steps[$i]
            $type = [string](Get-Prop $s 'type' '')
            $name = [string](Get-Prop $s 'name' '')
            if (-not $name) { $name = $type }
            $label = "step $($i + 1) ($name)"
            Send-RmmProgress ([int](10 + 80 * $i / $steps.Count)) $label
            if (-not (Test-Conditions (Get-Prop $s 'when') $label)) {
                Send-RmmLog "${label}: conditions not met, skipped" 'info'
                [void]$results.Add(@{ name = $name; type = $type; status = 'skipped' })
                continue
            }
            Send-RmmLog "${label}: start" 'info'
            try {
                $r = Invoke-Step $s $ctx
                $res = @{ name = $name; type = $type; status = 'ok'; detail = [string]$r.detail }
                if ($r.ContainsKey('exit_code')) { $res.exit_code = $r.exit_code }
                [void]$results.Add($res)
                Send-RmmLog "${label}: done" 'info'
            }
            catch {
                $msg = $_.Exception.Message
                if (-not (Get-Prop $s 'continue_on_error' $false)) { throw "${label}: $msg" }
                Send-RmmLog "${label}: $msg (continuing)" 'warn'
                [void]$results.Add(@{ name = $name; type = $type; status = 'failed'; detail = (Limit-Text $msg 1000) })
            }
        }

        $verified = $false
        if ($hasDetection) {
            Send-RmmProgress 95 'detection'
            $verified = Test-Conditions $detection 'detection after the steps'
            if (-not $verified -and -not $ctx.reboot) { throw 'the steps ran but the detection rules do not hold' }
            if (-not $verified) { Send-RmmLog 'the detection rules do not hold yet: a reboot is required' 'warn' }
        }
        @{ compliant = $false; verified = $verified; steps = @($results); reboot_required = $ctx.reboot }
    }
}
