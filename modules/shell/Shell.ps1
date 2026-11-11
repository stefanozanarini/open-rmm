# Tempra RMM interactive session: startup script, run by the agent before the
# prompt. The agent, not this script, enforces the time limit.
# UTF-8 in and out: with the OEM code page, accented letters and symbols of
# localized Windows (e.g. French service names) reach the console garbled.
[void](& "$env:SystemRoot\System32\chcp.com" 65001)
[Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$Host.UI.RawUI.WindowTitle = "Tempra RMM $env:COMPUTERNAME"
Set-Location -Path "$env:SystemDrive\"
function global:prompt { "PS tempra $env:COMPUTERNAME $($executionContext.SessionState.Path.CurrentLocation)> " }
Write-Host "Tempra RMM: interactive session on $env:COMPUTERNAME as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)."
Write-Host "Every command is recorded in the console's audit log. Type 'exit' to close."
