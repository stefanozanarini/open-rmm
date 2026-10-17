Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$MaxOutput = 1MB

Invoke-RmmModule @{
    run = {
        param($Params, $Request)
        if ($null -eq $Params -or [string]::IsNullOrWhiteSpace($Params.script)) { throw 'params.script is required' }
        $block = [scriptblock]::Create($Params.script)
        $errors = New-Object System.Collections.Generic.List[string]
        $items = New-Object System.Collections.Generic.List[object]
        $started = Get-Date
        # Run in a child scope with all streams merged, so the operator sees
        # output, warnings and errors in order. A terminating error stops the
        # script, but what it produced until then is kept.
        try {
            & {
                $ErrorActionPreference = 'Continue'
                & $block
            } *>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) { $errors.Add($_.ToString()) }
                $items.Add($_)
            }
        }
        catch {
            $errors.Add($_.Exception.Message)
            $items.Add("Terminating error: $($_.Exception.Message)")
        }
        $output = ($items | Out-String -Width 4096)
        $truncated = $false
        if ($output.Length -gt $MaxOutput) {
            $output = $output.Substring(0, $MaxOutput)
            $truncated = $true
        }
        @{
            output           = $output
            errors           = @($errors)
            had_errors       = ($errors.Count -gt 0)
            output_truncated = $truncated
            duration_ms      = [int64]((Get-Date) - $started).TotalMilliseconds
        }
    }
}
