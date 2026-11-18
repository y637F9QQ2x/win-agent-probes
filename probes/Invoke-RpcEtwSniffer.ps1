#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Record RPC calls with the Microsoft-Windows-RPC ETW provider and return, for each
    call, the interface UUID, opnum, process, protocol and endpoint, plus a per-interface
    summary. Can also parse an .etl file recorded earlier.

.DESCRIPTION
    Three modes. Without a mode switch the tool runs as -DryRun.

      -Capture           Create a file-mode ETW session (it writes an .etl file) for the
                         Microsoft-Windows-RPC provider
                         ({6AD52B32-D609-4BE9-AE07-CE8DAE937E39}) with logman, run
                         -TriggerCommand or wait -DurationSeconds, read the lost-buffer
                         count of the session, stop it, and parse the .etl file.
      -ParseEtl <file>   Parse an existing .etl file. Nothing is started.
      -DryRun            Report whether a capture could start. Nothing is started.

    Rows come from event 5 ("Client RPC call started", side = client) and event 6
    ("Server RPC call started", side = server). Both carry InterfaceUuid, ProcNum
    (the opnum), Protocol, NetworkAddress, Endpoint, Options, AuthenticationLevel,
    AuthenticationService and ImpersonationLevel. These IDs and field names were read
    from the provider manifest with "Get-WinEvent -ListProvider Microsoft-Windows-RPC"
    on Windows 11; check them on your build with the same command. All other event IDs
    are counted in summary.byEventId and not returned as rows.

    pid is the process that logged the event: the client process for event 5 and the
    server process for event 6. In capture mode, processName is looked up when the
    capture stops, so a process that exited earlier has no name and a reused process ID
    can show the wrong name. protocol is the number logged by the provider; this tool
    does not translate it to a protocol-sequence name. time is the event time in UTC,
    ISO 8601 with milliseconds.

    State changes in capture mode (-Capture only):
      - One ETW session is created and stopped again in a finally block. The default
        session name is unique to this run; an existing session with the same name is
        never stopped or reused (the tool refuses to start instead).
      - The .etl file is written to a new directory (under the Windows temporary
        directory, readable only by Administrators and SYSTEM, when elevated; under the
        temporary directory of the user otherwise) or to -EtlPath, and deleted at the
        end unless -KeepArtifacts is set. The session stops writing when the file
        reaches -MaxEtlMB.
      - -TriggerCommand runs through cmd.exe with the token of this tool.
    If this tool is killed during a capture, the session keeps running until it is
    stopped with "logman stop <session name> -ets" or the computer restarts.

    Elevation: capture mode needs Administrators or Performance Log Users membership.
    -ParseEtl and -DryRun need none.

    The provider is enabled with all keywords at level 0xFF, with 256 KB buffers (16 to
    64 of them). A busy system produces many events, and ETW drops events when its
    buffers fill. summary.buffersLost and summary.eventsLost report the counts that
    "logman query <session> -ets" prints before the session stops; they are null when
    the output does not contain them (for example in a language other than English).

.PARAMETER Capture
    Run a capture. Without -Capture, -ParseEtl or -DryRun, the tool runs as -DryRun.

.PARAMETER DurationSeconds
    Capture length when no -TriggerCommand is given. Default: 10.

.PARAMETER TriggerCommand
    A command line run with "cmd.exe /d /s /c" while the session runs. The capture
    continues for -SettleSeconds after it exits. Quote a program path or an argument that
    contains spaces inside the value.

.PARAMETER TriggerTimeoutSeconds
    Stop waiting for -TriggerCommand after this many seconds and stop the cmd.exe process
    that this tool started. Default: 120.

.PARAMETER SettleSeconds
    Seconds to keep capturing after -TriggerCommand exits. Default: 2.

.PARAMETER InterfaceFilter
    Keep only calls whose interface UUID contains one of these values (case-insensitive,
    braces ignored). With -File, pass several values as one comma-separated string.

.PARAMETER SessionName
    ETW session name. Default: a name unique to this run. Allowed characters: letters,
    digits, dot, underscore and hyphen.

.PARAMETER EtlPath
    Path of the .etl file to write, in a directory that exists. The file must not exist
    yet. Default: rpc.etl in a new directory (see State changes).

.PARAMETER MaxEtlMB
    Maximum size of the .etl file in megabytes (logman -max). Default: 256.

.PARAMETER ParseEtl
    Parse this existing .etl file instead of capturing. The file is never deleted.

.PARAMETER KeepArtifacts
    Keep the .etl file written in capture mode and report its path.

.PARAMETER IncludeRaw
    Add every event-data field of each row as "raw".

.PARAMETER MaxRows
    Maximum number of data rows; summary.byInterface counts every kept call. Default: 2000.

.PARAMETER DryRun
    Report readiness only.

.PARAMETER SummaryOnly
    Return the summary with an empty data array.

.PARAMETER Compress
    Print the JSON document on one line, without indentation.

.PARAMETER OutFile
    Also write the JSON document to this file (UTF-8 without BOM).

.PARAMETER Help
    Print this help text and exit with code 0.

.OUTPUTS
    One JSON document in the envelope described in CONVENTIONS.md.
    summary: mode, sessionName, totalEvents, callEvents, keptCalls, truncated,
             buffersLost, eventsLost, byEventId{}, byInterface[], triggerExitCode,
             artifacts{}, caveats[]
             byInterface[]: interfaceUuid, calls, opnums[], clientPids[], serverPids[],
                            endpoints[], endpointsTruncated
             (-DryRun: mode, sessionName, logman, elevatedNow, performanceLogUser, ready)
    data[]:  time, eventId, side, pid, processName, threadId, interfaceUuid, opnum,
             protocol, networkAddress, endpoint, authenticationLevel,
             authenticationService, impersonationLevel, raw

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-RpcEtwSniffer.ps1 -Capture -TriggerCommand "sc.exe query spooler" -OutFile .\rpc.json

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-RpcEtwSniffer.ps1 -ParseEtl .\rpc.etl -InterfaceFilter 367abb81
#>
[CmdletBinding()]
param(
    [switch]   $Capture,
    [int]      $DurationSeconds = 10,
    [string]   $TriggerCommand,
    [int]      $TriggerTimeoutSeconds = 120,
    [int]      $SettleSeconds = 2,
    [string[]] $InterfaceFilter,
    [string]   $SessionName,
    [string]   $EtlPath,
    [int]      $MaxEtlMB = 256,
    [string]   $ParseEtl,
    [switch]   $KeepArtifacts,
    [switch]   $IncludeRaw,
    [int]      $MaxRows = 2000,
    [switch]   $DryRun,
    [switch]   $SummaryOnly,
    [switch]   $Compress,
    [string]   $OutFile,
    [switch]   $Help
)

#region Common probe helpers. This block is identical in every probe (see CONVENTIONS.md).
$script:ProbeCaveats = New-Object 'System.Collections.Generic.List[string]'
$script:ProbeOutFileFailed = $false

function Add-Caveat {
    param([string]$Text)
    if (-not [string]::IsNullOrWhiteSpace($Text) -and -not $script:ProbeCaveats.Contains($Text)) {
        $script:ProbeCaveats.Add($Text)
    }
}

function Get-ProbeHelpText {
    param([string]$ScriptPath)
    $text = [System.IO.File]::ReadAllText($ScriptPath)
    $start = $text.IndexOf('<#')
    $end = $text.IndexOf('#>')
    if ($start -lt 0 -or $end -le $start) { return '' }
    return $text.Substring($start + 2, $end - $start - 2).Trim()
}

function Get-ProbeIdentity {
    $result = @{ Name = [string]$env:USERNAME; Elevated = $false }
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $result.Name = $id.Name
        $windowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($id)
        $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
        $result.Elevated = [bool]$windowsPrincipal.IsInRole($adminRole)
    } catch {
        Write-Verbose ('identity lookup failed: ' + $_.Exception.Message)
    }
    return $result
}

function ConvertTo-ProbeArray {
    param($Items)
    $list = New-Object 'System.Collections.Generic.List[object]'
    if ($null -ne $Items) {
        foreach ($item in $Items) {
            if ($null -ne $item) { $list.Add($item) }
        }
    }
    return ,($list.ToArray())
}

function Split-ProbeList {
    param([string[]]$Values)
    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        foreach ($part in ([string]$value).Split(',')) {
            $trimmed = $part.Trim()
            if ($trimmed) { $list.Add($trimmed) }
        }
    }
    return ,($list.ToArray())
}

function Get-ObjectProperty {
    param($InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    try { return $property.Value } catch { return $null }
}

function ConvertTo-ProbeEnvelope {
    param([string]$Tool, $Params, [bool]$Ok, [string]$ErrorMessage, $Summary, $Data, [bool]$SummaryOnly)
    $identity = Get-ProbeIdentity
    $errorText = $null
    $rows = ConvertTo-ProbeArray $Data
    if (-not $Ok) {
        $errorText = $ErrorMessage
        if ([string]::IsNullOrEmpty($errorText)) { $errorText = 'unspecified error' }
        $rows = ConvertTo-ProbeArray $null
    } elseif ($SummaryOnly) {
        Add-Caveat ('data[] is empty because -SummaryOnly was set; {0} row(s) were left out.' -f $rows.Count)
        $rows = ConvertTo-ProbeArray $null
    }
    if ($null -eq $Summary) { $Summary = [ordered]@{} }
    $Summary['caveats'] = $script:ProbeCaveats.ToArray()
    return [ordered]@{
        tool          = $Tool
        schemaVersion = 1
        generatedUtc  = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        host          = [string]$env:COMPUTERNAME
        principal     = $identity.Name
        elevated      = $identity.Elevated
        params        = $Params
        ok            = $Ok
        error         = $errorText
        summary       = $Summary
        data          = $rows
    }
}

function Write-ProbeEnvelope {
    param($Envelope, [string]$OutFile, [bool]$Compress)
    if ($Compress) {
        $json = $Envelope | ConvertTo-Json -Depth 12 -Compress
    } else {
        $json = $Envelope | ConvertTo-Json -Depth 12
    }
    if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
        try {
            $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
            $directory = [System.IO.Path]::GetDirectoryName($full)
            if ($directory -and -not [System.IO.Directory]::Exists($directory)) {
                $null = [System.IO.Directory]::CreateDirectory($directory)
            }
            [System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))
        } catch {
            $script:ProbeOutFileFailed = $true
            [Console]::Error.WriteLine(('could not write -OutFile {0}: {1}' -f $OutFile, $_.Exception.Message))
        }
    }
    Write-Output $json
}

function Get-ProbeExitCode {
    param([bool]$Ok)
    if (-not $Ok) { return 1 }
    if ($script:ProbeOutFileFailed) { return 2 }
    return 0
}
#endregion

$script:RpcProviderGuid = '{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}'
$script:CmdPath = Join-Path ([System.Environment]::SystemDirectory) 'cmd.exe'
$script:LogmanPath = Join-Path ([System.Environment]::SystemDirectory) 'logman.exe'
$script:MaxEndpoints = 10

function Get-TriggerArgumentLine {
    param([string]$Command)
    # With /s, cmd.exe removes only the outer pair of quotes that this tool adds, so the
    # command keeps its own quotes: a quoted program path and quoted arguments survive.
    return ('/d /s /c "' + $Command + '"')
}

function New-ProbeRunDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper. A probe calls it only in a run mode whose help names this directory under State changes.')]
    param([string]$Parent, [bool]$AdministratorsOnly)
    # A new directory with a random name. With -AdministratorsOnly, its DACL grants
    # access only to Administrators and SYSTEM and inherits nothing, so processes of the
    # same user at medium integrity cannot read or replace the files of an elevated run.
    $path = Join-Path $Parent ('win-agent-probes-' + [Guid]::NewGuid().ToString('N'))
    if (-not $AdministratorsOnly) {
        $null = [System.IO.Directory]::CreateDirectory($path)
        return $path
    }
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sidText in @('S-1-5-32-544', 'S-1-5-18')) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    if ($null -ne [System.IO.Directory].GetMethod('CreateDirectory', [type[]]@([string], [System.Security.AccessControl.DirectorySecurity]))) {
        $null = [System.IO.Directory]::CreateDirectory($path, $security)
    } else {
        $null = [System.IO.FileSystemAclExtensions]::Create((New-Object System.IO.DirectoryInfo($path)), $security)
    }
    return $path
}

function Test-PerformanceLogUser {
    try {
        $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
        return [bool]$principal.IsInRole((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-559')))
    } catch {
        return $false
    }
}

function Invoke-Logman {
    param([string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $output = & $script:LogmanPath @Arguments 2>&1
    $code = $LASTEXITCODE
    $lines = @($output | ForEach-Object { [string]$_ })
    return @{ ExitCode = $code; Output = (($lines -join ' ').Trim()); Text = ($lines -join "`n") }
}

function Get-LogmanCounter {
    param([string]$Text, [string]$Label)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $match = [regex]::Match($Text, ('(?im)^\s*{0}:\s*(\d+)\s*$' -f [regex]::Escape($Label)))
    if ($match.Success) { return [int64]$match.Groups[1].Value }
    return $null
}

function Get-EventDataMap {
    param([string]$EventXml)
    $map = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($EventXml)) { return $map }
    $document = New-Object System.Xml.XmlDocument
    $document.LoadXml($EventXml)
    $index = 0
    foreach ($node in $document.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = $null
        if ($null -ne $node.Attributes -and $null -ne $node.Attributes['Name']) { $name = $node.Attributes['Name'].Value }
        if ([string]::IsNullOrEmpty($name)) { $name = 'Data' + $index }
        if (-not $map.Contains($name)) { $map[$name] = $node.InnerText }
        $index++
    }
    return $map
}

function ConvertTo-NumberOrNull {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $value = $Text.Trim()
    $number = [int64]0
    if ($value -match '^0[xX][0-9A-Fa-f]+$') { return [Convert]::ToInt64($value.Substring(2), 16) }
    if ([int64]::TryParse($value, [ref]$number)) { return $number }
    return $null
}

function ConvertTo-InterfaceKey {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return $Text.Trim().Trim('{', '}').ToLowerInvariant()
}

function Test-InterfaceFilter {
    param([string]$InterfaceUuid, [string[]]$Filters)
    if ($Filters.Count -eq 0) { return $true }
    if (-not $InterfaceUuid) { return $false }
    foreach ($filter in $Filters) {
        $needle = ConvertTo-InterfaceKey $filter
        if ($needle -and $InterfaceUuid.Contains($needle)) { return $true }
    }
    return $false
}

function ConvertTo-RpcCallRow {
    param([int]$EventId, $ProcessId, $ThreadId, $TimeUtc, $Map, [bool]$WithRaw)
    if ($EventId -ne 5 -and $EventId -ne 6) { return $null }
    $interface = ConvertTo-InterfaceKey ([string](Get-ObjectProperty $Map 'InterfaceUuid'))
    if (-not $interface) { return $null }
    $side = 'client'
    if ($EventId -eq 6) { $side = 'server' }
    $raw = $null
    if ($WithRaw) { $raw = $Map }
    return [pscustomobject][ordered]@{
        time                  = $TimeUtc
        eventId               = $EventId
        side                  = $side
        pid                   = $ProcessId
        processName           = $null
        threadId              = $ThreadId
        interfaceUuid         = $interface
        opnum                 = (ConvertTo-NumberOrNull ([string](Get-ObjectProperty $Map 'ProcNum')))
        protocol              = (ConvertTo-NumberOrNull ([string](Get-ObjectProperty $Map 'Protocol')))
        networkAddress        = (Get-ObjectProperty $Map 'NetworkAddress')
        endpoint              = (Get-ObjectProperty $Map 'Endpoint')
        authenticationLevel   = (ConvertTo-NumberOrNull ([string](Get-ObjectProperty $Map 'AuthenticationLevel')))
        authenticationService = (ConvertTo-NumberOrNull ([string](Get-ObjectProperty $Map 'AuthenticationService')))
        impersonationLevel    = (ConvertTo-NumberOrNull ([string](Get-ObjectProperty $Map 'ImpersonationLevel')))
        raw                   = $raw
    }
}

function Measure-RpcByInterface {
    param($Rows, [int]$MaxEndpoints = 10)
    $groups = @{}
    foreach ($row in $Rows) {
        $key = $row.interfaceUuid
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = @{
                Calls = 0
                Opnums = New-Object 'System.Collections.Generic.SortedSet[int64]'
                Clients = New-Object 'System.Collections.Generic.SortedSet[int64]'
                Servers = New-Object 'System.Collections.Generic.SortedSet[int64]'
                Endpoints = New-Object 'System.Collections.Generic.List[string]'
                EndpointsTruncated = $false
            }
        }
        $group = $groups[$key]
        $group.Calls++
        if ($null -ne $row.opnum) { [void]$group.Opnums.Add([int64]$row.opnum) }
        if ($null -ne $row.pid) {
            if ($row.side -eq 'client') { [void]$group.Clients.Add([int64]$row.pid) } else { [void]$group.Servers.Add([int64]$row.pid) }
        }
        $endpoint = [string]$row.endpoint
        if ($endpoint -and -not $group.Endpoints.Contains($endpoint)) {
            if ($group.Endpoints.Count -lt $MaxEndpoints) { $group.Endpoints.Add($endpoint) } else { $group.EndpointsTruncated = $true }
        }
    }
    $result = New-Object 'System.Collections.Generic.List[object]'
    foreach ($key in ($groups.Keys | Sort-Object -Property @{ Expression = { $groups[$_].Calls }; Descending = $true }, @{ Expression = { $_ }; Descending = $false })) {
        $group = $groups[$key]
        $result.Add([pscustomobject][ordered]@{
            interfaceUuid      = $key
            calls              = $group.Calls
            opnums             = (ConvertTo-ProbeArray $group.Opnums)
            clientPids         = (ConvertTo-ProbeArray $group.Clients)
            serverPids         = (ConvertTo-ProbeArray $group.Servers)
            endpoints          = $group.Endpoints.ToArray()
            endpointsTruncated = $group.EndpointsTruncated
        })
    }
    return ,($result.ToArray())
}

function Read-RpcEtl {
    param([string]$FilePath, [string[]]$Filters, [bool]$WithRaw)
    $state = @{
        Total = 0; CallEvents = 0
        ByEventId = @{}
        Rows = New-Object 'System.Collections.Generic.List[object]'
    }
    try {
        Get-WinEvent -Path $FilePath -Oldest -ErrorAction Stop | ForEach-Object {
            $state.Total++
            $eventId = [int]$_.Id
            $key = [string]$eventId
            if ($state.ByEventId.ContainsKey($key)) { $state.ByEventId[$key] = [int]$state.ByEventId[$key] + 1 } else { $state.ByEventId[$key] = 1 }
            if ($eventId -ne 5 -and $eventId -ne 6) { return }
            $state.CallEvents++
            $time = $null
            if ($null -ne $_.TimeCreated) { $time = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
            $row = ConvertTo-RpcCallRow -EventId $eventId -ProcessId $_.ProcessId -ThreadId $_.ThreadId -TimeUtc $time -Map (Get-EventDataMap -EventXml $_.ToXml()) -WithRaw $WithRaw
            if ($null -eq $row) { return }
            if (-not (Test-InterfaceFilter -InterfaceUuid $row.interfaceUuid -Filters $Filters)) { return }
            $state.Rows.Add($row)
        }
    } catch {
        if ([string]$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }
    return $state
}

if ($MyInvocation.InvocationName -eq '.') { return }

if ($Help) {
    Write-Output (Get-ProbeHelpText -ScriptPath $PSCommandPath)
    exit 0
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$filters = Split-ProbeList $InterfaceFilter
if ([string]::IsNullOrWhiteSpace($SessionName)) {
    $SessionName = 'win-agent-probes-rpc-{0}-{1}' -f $PID, [DateTime]::UtcNow.ToString('yyyyMMddHHmmss')
}
$params = [ordered]@{
    Capture               = [bool]$Capture
    DurationSeconds       = $DurationSeconds
    TriggerCommand        = $TriggerCommand
    TriggerTimeoutSeconds = $TriggerTimeoutSeconds
    SettleSeconds         = $SettleSeconds
    InterfaceFilter       = $filters
    SessionName           = $SessionName
    EtlPath               = $EtlPath
    MaxEtlMB              = $MaxEtlMB
    ParseEtl              = $ParseEtl
    KeepArtifacts         = [bool]$KeepArtifacts
    IncludeRaw            = [bool]$IncludeRaw
    MaxRows               = $MaxRows
    DryRun                = [bool]$DryRun
    SummaryOnly           = [bool]$SummaryOnly
    Compress              = [bool]$Compress
    OutFile               = $OutFile
}
$ok = $true
$errorMessage = $null
$summary = $null
$dataRows = $null
$sessionCreated = $false
$etlFile = $null
$deleteEtl = $false
$runDirectory = $null

try {
    if ($MaxRows -lt 1) { throw '-MaxRows must be 1 or more.' }
    $modes = New-Object 'System.Collections.Generic.List[string]'
    if ($Capture) { $modes.Add('-Capture') }
    if (-not [string]::IsNullOrWhiteSpace($ParseEtl)) { $modes.Add('-ParseEtl') }
    if ($DryRun) { $modes.Add('-DryRun') }
    if ($modes.Count -gt 1) { throw ('Use only one of -Capture, -ParseEtl and -DryRun (got {0}).' -f ($modes -join ', ')) }
    if (-not $Capture) {
        $captureOnly = New-Object 'System.Collections.Generic.List[string]'
        foreach ($name in @('TriggerCommand', 'DurationSeconds', 'TriggerTimeoutSeconds', 'SettleSeconds', 'EtlPath', 'MaxEtlMB', 'KeepArtifacts')) {
            if ($PSBoundParameters.ContainsKey($name)) { $captureOnly.Add('-' + $name) }
        }
        if ($captureOnly.Count -gt 0) { throw ('These parameters apply only to -Capture: {0}. Add -Capture to run a capture.' -f ($captureOnly -join ', ')) }
    }
    $elevatedNow = (Get-ProbeIdentity).Elevated
    $mode = 'dry-run'
    if ($Capture) { $mode = 'capture' } elseif (-not [string]::IsNullOrWhiteSpace($ParseEtl)) { $mode = 'parse-etl' }

    if ($mode -eq 'dry-run') {
        if (-not $DryRun) { Add-Caveat 'No mode was given, so the tool ran as -DryRun. Pass -Capture to capture.' }
        $logmanFound = Test-Path -LiteralPath $script:LogmanPath -PathType Leaf
        $performanceLogUser = Test-PerformanceLogUser
        if (-not $logmanFound) { Add-Caveat ('logman.exe was not found at ' + $script:LogmanPath) }
        if (-not $elevatedNow -and -not $performanceLogUser) { Add-Caveat 'Creating the session needs an elevated prompt or Performance Log Users membership.' }
        $summary = [ordered]@{
            mode               = 'dry-run'
            sessionName        = $SessionName
            logman             = $(if ($logmanFound) { $script:LogmanPath } else { $null })
            elevatedNow        = $elevatedNow
            performanceLogUser = $performanceLogUser
            ready              = ($logmanFound -and ($elevatedNow -or $performanceLogUser))
        }
    } else {
        $triggerExit = $null
        $buffersLost = $null
        $eventsLost = $null
        if ($mode -eq 'parse-etl') {
            if (-not (Test-Path -LiteralPath $ParseEtl -PathType Leaf)) { throw ('-ParseEtl file not found: ' + $ParseEtl) }
            $etlFile = (Resolve-Path -LiteralPath $ParseEtl).ProviderPath
        } else {
            if ($SessionName -notmatch '^[A-Za-z0-9_.\-]{1,100}$') { throw '-SessionName may contain only letters, digits, dot, underscore and hyphen (at most 100 characters).' }
            if ($DurationSeconds -lt 1 -or $TriggerTimeoutSeconds -lt 1 -or $SettleSeconds -lt 0) {
                throw '-DurationSeconds and -TriggerTimeoutSeconds must be 1 or more; -SettleSeconds 0 or more.'
            }
            if ($MaxEtlMB -lt 1 -or $MaxEtlMB -gt 65536) { throw '-MaxEtlMB must be between 1 and 65536.' }
            if (-not [string]::IsNullOrWhiteSpace($EtlPath)) {
                $etlFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($EtlPath)
                if (Test-Path -LiteralPath $etlFile) { throw ('{0} already exists; choose another -EtlPath. This tool does not overwrite or delete files that it did not create.' -f $etlFile) }
                $etlDirectory = [System.IO.Path]::GetDirectoryName($etlFile)
                if (-not [System.IO.Directory]::Exists($etlDirectory)) { throw ('The directory of -EtlPath does not exist: {0}. Create it first; this tool does not create it, so that a capture leaves no directory behind.' -f $etlDirectory) }
            }
            if (-not (Test-Path -LiteralPath $script:LogmanPath -PathType Leaf)) { throw ('logman.exe was not found at ' + $script:LogmanPath) }
            $existing = Invoke-Logman -Arguments @('query', $SessionName, '-ets')
            if ($existing.ExitCode -eq 0) { throw ('An ETW session named "{0}" already exists; this tool never stops or reuses an existing session.' -f $SessionName) }
            if (-not $etlFile) {
                $parent = [System.IO.Path]::GetTempPath()
                if ($elevatedNow) { $parent = Join-Path ([System.Environment]::GetFolderPath('Windows')) 'Temp' }
                $runDirectory = New-ProbeRunDirectory -Parent $parent -AdministratorsOnly $elevatedNow
                $etlFile = Join-Path $runDirectory 'rpc.etl'
            }
            $created = Invoke-Logman -Arguments @('create', 'trace', $SessionName, '-p', $script:RpcProviderGuid, '0xffffffffffffffff', '0xff', '-o', $etlFile, '-bs', '256', '-nb', '16', '64', '-max', ([string]$MaxEtlMB), '-ets')
            if ($created.ExitCode -ne 0) {
                throw ('logman could not create the session (exit {0}): {1}. Creating an ETW session needs Administrators or Performance Log Users membership.' -f $created.ExitCode, $created.Output)
            }
            $sessionCreated = $true
            $deleteEtl = -not $KeepArtifacts

            if (-not [string]::IsNullOrWhiteSpace($TriggerCommand)) {
                $trigger = Start-Process -FilePath $script:CmdPath -ArgumentList (Get-TriggerArgumentLine -Command $TriggerCommand) -WindowStyle Hidden -PassThru
                if ($trigger.WaitForExit($TriggerTimeoutSeconds * 1000)) {
                    $triggerExit = $trigger.ExitCode
                } else {
                    Add-Caveat ('-TriggerCommand did not exit within {0} s; the cmd.exe process started by this tool was stopped. Processes it started may still run.' -f $TriggerTimeoutSeconds)
                    try { $trigger.Kill() } catch { Add-Caveat ('Stopping the trigger failed: ' + $_.Exception.Message) }
                }
                if ($null -ne $triggerExit -and $triggerExit -ne 0) {
                    Add-Caveat ('-TriggerCommand exited with code {0}. Check that the command ran as intended; the capture may hold no activity of it.' -f $triggerExit)
                }
                Start-Sleep -Seconds $SettleSeconds
            } else {
                Start-Sleep -Seconds $DurationSeconds
            }
            $queried = Invoke-Logman -Arguments @('query', $SessionName, '-ets')
            $buffersLost = Get-LogmanCounter -Text $queried.Text -Label 'Buffers Lost'
            $eventsLost = Get-LogmanCounter -Text $queried.Text -Label 'Events Lost'
            $stopped = Invoke-Logman -Arguments @('stop', $SessionName, '-ets')
            if ($stopped.ExitCode -ne 0) { Add-Caveat ('logman stop returned {0}: {1}' -f $stopped.ExitCode, $stopped.Output) } else { $sessionCreated = $false }
            if (-not (Test-Path -LiteralPath $etlFile -PathType Leaf)) { throw ('The session did not produce {0}.' -f $etlFile) }
            if ($null -eq $buffersLost -and $null -eq $eventsLost) {
                Add-Caveat 'The lost-buffer and lost-event counts were not found in the output of "logman query <session> -ets"; buffersLost and eventsLost are null.'
            } elseif (([int64]$buffersLost -gt 0) -or ([int64]$eventsLost -gt 0)) {
                Add-Caveat ('ETW reported lost buffers or events (buffersLost {0}, eventsLost {1}); the capture is incomplete.' -f $buffersLost, $eventsLost)
            }
        }

        $parsed = Read-RpcEtl -FilePath $etlFile -Filters $filters -WithRaw ([bool]$IncludeRaw)
        $callRows = $parsed.Rows
        if ($mode -eq 'capture' -and $callRows.Count -gt 0) {
            $names = @{}
            foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) { $names[[int64]$process.Id] = $process.ProcessName }
            foreach ($row in $callRows) {
                if ($null -ne $row.pid -and $names.ContainsKey([int64]$row.pid)) { $row.processName = $names[[int64]$row.pid] }
            }
            Add-Caveat 'processName was looked up when the capture stopped; processes that exited earlier have no name, and a reused process ID can show the wrong name.'
        }
        $truncated = $callRows.Count -gt $MaxRows
        $dataRows = New-Object 'System.Collections.Generic.List[object]'
        $limit = [Math]::Min($MaxRows, $callRows.Count)
        for ($i = 0; $i -lt $limit; $i++) { $dataRows.Add($callRows[$i]) }
        if ($truncated) { Add-Caveat ('data[] lists the first {0} of {1} calls (raise -MaxRows); summary.byInterface counts all of them.' -f $MaxRows, $callRows.Count) }
        if ($parsed.Total -eq 0) { Add-Caveat 'No events were recorded. Check the elevation, that RPC traffic happened during the capture, and that the provider exists on this build.' }
        $byEventId = [ordered]@{}
        foreach ($key in ($parsed.ByEventId.Keys | Sort-Object -Property { [int]$_ })) { $byEventId[$key] = $parsed.ByEventId[$key] }
        $byInterface = Measure-RpcByInterface -Rows $callRows -MaxEndpoints $script:MaxEndpoints
        $cutInterfaces = @($byInterface | Where-Object { $_.endpointsTruncated }).Count
        if ($cutInterfaces -gt 0) {
            Add-Caveat ('summary.byInterface lists at most {0} endpoints per interface; {1} interface(s) had more (endpointsTruncated is true for them).' -f $script:MaxEndpoints, $cutInterfaces)
        }
        $artifacts = $null
        if ($mode -eq 'capture' -and $KeepArtifacts) { $artifacts = [ordered]@{ etl = $etlFile } }
        $summary = [ordered]@{
            mode            = $mode
            sessionName     = $(if ($mode -eq 'capture') { $SessionName } else { $null })
            totalEvents     = $parsed.Total
            callEvents      = $parsed.CallEvents
            keptCalls       = $callRows.Count
            truncated       = $truncated
            buffersLost     = $buffersLost
            eventsLost      = $eventsLost
            byEventId       = $byEventId
            byInterface     = $byInterface
            triggerExitCode = $triggerExit
            artifacts       = $artifacts
        }
    }
} catch {
    $ok = $false
    $errorMessage = $_.Exception.Message
} finally {
    if ($sessionCreated) {
        $stopped = Invoke-Logman -Arguments @('stop', $SessionName, '-ets')
        if ($stopped.ExitCode -ne 0) { Add-Caveat ('logman stop in cleanup returned {0}: {1}' -f $stopped.ExitCode, $stopped.Output) }
    }
    if ($deleteEtl -and $etlFile -and (Test-Path -LiteralPath $etlFile)) {
        try { Remove-Item -LiteralPath $etlFile -Force -ErrorAction Stop } catch { Add-Caveat ('Could not delete ' + $etlFile) }
    }
    if ($runDirectory -and -not $KeepArtifacts -and (Test-Path -LiteralPath $runDirectory)) {
        try { Remove-Item -LiteralPath $runDirectory -Recurse -Force -ErrorAction Stop } catch { Add-Caveat ('Could not delete ' + $runDirectory) }
    }
}

$envelope = ConvertTo-ProbeEnvelope -Tool 'Invoke-RpcEtwSniffer' -Params $params -Ok $ok -ErrorMessage $errorMessage -Summary $summary -Data $dataRows -SummaryOnly ([bool]$SummaryOnly)
Write-ProbeEnvelope -Envelope $envelope -OutFile $OutFile -Compress ([bool]$Compress)
exit (Get-ProbeExitCode -Ok $ok)
