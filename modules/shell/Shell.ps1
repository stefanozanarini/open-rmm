# open-rmm interactive session: startup script, run by the agent before the
# prompt. The agent, not this script, enforces the time limit.
$Host.UI.RawUI.WindowTitle = "open-rmm $env:COMPUTERNAME"
Set-Location -Path "$env:SystemDrive\"
function global:prompt { "PS open-rmm $env:COMPUTERNAME $($executionContext.SessionState.Path.CurrentLocation)> " }
Write-Host "open-rmm: interactive session on $env:COMPUTERNAME as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)."
Write-Host "Every command is recorded in the console's audit log. Type 'exit' to close."
