# Tempra RMM message module: a message box in every active session of the
# computer, through WTSSendMessage (the agent runs as SYSTEM in session 0).
#
# send  { "title": "IT", "text": "...", "icon": "info|warning|error",
#         "timeout_seconds": 0, "wait": false }
Import-Module (Join-Path $PSScriptRoot '_sdk/OpenRmm.psm1')

$ErrorActionPreference = 'Stop'

function Get-Prop($Object, [string]$Name, $Default = $null) {
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return $p.Value }
    return $Default
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class TempraWts {
    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool WTSSendMessageW(IntPtr server, int session, string title, int titleLength,
        string message, int messageLength, int style, int timeout, out int response, bool wait);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr info, out int count);
    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool WTSQuerySessionInformationW(IntPtr server, int session, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr memory);

    [StructLayout(LayoutKind.Sequential)]
    struct SessionInfo { public int Id; public IntPtr Station; public int State; }

    const int Active = 0, UserName = 5, DomainName = 7;

    static string Query(int session, int infoClass) {
        IntPtr buf; int n;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, infoClass, out buf, out n)) return "";
        try { return Marshal.PtrToStringUni(buf) ?? ""; } finally { WTSFreeMemory(buf); }
    }

    // ActiveSessions returns "id|DOMAIN\user" of the active sessions with a user.
    public static List<string> ActiveSessions() {
        var list = new List<string>();
        IntPtr info; int count;
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out info, out count)) return list;
        try {
            int size = Marshal.SizeOf(typeof(SessionInfo));
            for (int i = 0; i < count; i++) {
                var s = (SessionInfo)Marshal.PtrToStructure(new IntPtr(info.ToInt64() + i * size), typeof(SessionInfo));
                if (s.State != Active) continue;
                string user = Query(s.Id, UserName);
                if (user == "") continue;
                string domain = Query(s.Id, DomainName);
                list.Add(s.Id + "|" + (domain == "" ? user : domain + "\\" + user));
            }
        } finally { WTSFreeMemory(info); }
        return list;
    }

    // Send shows the box; it returns the button (1 OK), 32000 for a
    // timeout, 32001 when not waiting, or -1 on failure.
    public static int Send(int session, string title, string message, int style, int timeout, bool wait) {
        int response;
        if (!WTSSendMessageW(IntPtr.Zero, session, title, title.Length * 2, message, message.Length * 2,
            style, timeout, out response, wait)) return -1;
        return response;
    }
}
'@

Invoke-RmmModule @{
    send = {
        param($Params, $Request)
        $text = [string](Get-Prop $Params 'text' '')
        $text = $text.Trim()
        if (-not $text) { throw 'the message is empty' }
        if ($text.Length -gt 1000) { throw 'the message is longer than 1000 characters' }
        $title = ([string](Get-Prop $Params 'title' 'IT')).Trim()
        if (-not $title) { $title = 'IT' }
        if ($title.Length -gt 100) { $title = $title.Substring(0, 100) }
        # MB_OK, icon, MB_SETFOREGROUND | MB_TOPMOST.
        $icon = switch ([string](Get-Prop $Params 'icon' 'info')) { 'warning' { 0x30 } 'error' { 0x10 } default { 0x40 } }
        $style = $icon -bor 0x10000 -bor 0x40000
        $timeout = [int](Get-Prop $Params 'timeout_seconds' 0)
        $timeout = [Math]::Max(0, [Math]::Min(3600, $timeout))
        $wait = [bool](Get-Prop $Params 'wait' $false)

        $sessions = @([TempraWts]::ActiveSessions())
        if ($sessions.Count -eq 0) {
            return @{ delivered = 0; sessions = @(); note = 'no user signed in' }
        }
        Send-RmmProgress 20 "$($sessions.Count) sessioni"
        $results = @()
        # With wait, each box blocks until answered: one thread per session
        # would be needed to wait for all at once; sessions are few, so they
        # are shown without waiting and only the first one is waited for.
        $first = $true
        foreach ($s in $sessions) {
            $id, $user = $s -split '\|', 2
            $w = $wait -and $first
            $r = [TempraWts]::Send([int]$id, $title, $text, $style, $timeout, $w)
            $first = $false
            $outcome = switch ($r) { 1 { 'ok' } 32000 { 'timeout' } 32001 { 'shown' } -1 { 'failed' } default { "button $r" } }
            $results += @{ session = [int]$id; user = $user; outcome = $outcome }
            Send-RmmLog "session $id ($user): $outcome"
        }
        @{ delivered = @($results | Where-Object { $_.outcome -ne 'failed' }).Count; sessions = $results }
    }
}
