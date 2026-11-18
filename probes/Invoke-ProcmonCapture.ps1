#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Run a Process Monitor capture from the command line, optionally around a trigger
    command, and return the file, registry and process events as JSON rows. Can also
    parse a CSV that Process Monitor exported earlier.

.DESCRIPTION
    Three modes. Without a mode switch the tool runs as -DryRun.

      -Capture           Start Process Monitor minimized with a backing file, run
                         -TriggerCommand or wait -DurationSeconds, stop the capture with
                         "Procmon /Terminate", convert the .pml log to CSV with
                         "Procmon /OpenLog ... /SaveAs ...", and parse the CSV.
      -ParseCsv <file>   Parse an existing Process Monitor CSV export. Nothing is started.
      -DryRun            Report whether a capture could start (Process Monitor found,
                         elevated, no other instance running). Nothing is started.

    Rows are filtered while the CSV is read: -Operation (exact names), -ProcessName
    (substring of the process name) and -PathFilter (regular expression on the path).
    The filters apply to the parsed rows only; the capture itself records everything that
    Process Monitor records.

    Process Monitor is a GUI program. In capture mode it runs minimized in the desktop
    session of this tool, so a capture needs an interactive desktop session. Captures
    over SSH, WinRM or from a scheduled task have not been tested.

    State changes in capture mode (-Capture only):
      - Process Monitor loads its kernel filter driver. Process Monitor manages the driver
        and its service entry, and can leave both on the system after it exits; this tool
        installs and removes nothing itself.
      - Process Monitor is started with /AcceptEula, which records the acceptance of the
        Sysinternals license, and stores its settings in the registry of the current
        user. By running a capture you accept the Sysinternals Software License Terms:
        https://learn.microsoft.com/sysinternals/license-terms.
      - The .pml backing file and the .csv export are written to a new directory under
        the Windows temporary directory that only Administrators and SYSTEM can open, or
        next to each other at -BackingFile. They are deleted at the end unless
        -KeepArtifacts is set. An existing file is never overwritten or deleted.
      - -TriggerCommand runs through cmd.exe with the elevated token of this tool. Only
        pass commands that you would run in an elevated prompt yourself.
    The tool refuses to start while another Process Monitor instance runs, because
    "Procmon /Terminate" stops every instance. After a capture that was killed, stop
    Process Monitor with "Procmon64.exe /Terminate".

    Process Monitor uses the settings saved by its GUI for the current user (filter,
    columns, and the "Drop Filtered Events" option) unless -ConfigFile names a .pmc
    configuration; the configuration is passed to the capture and to the conversion. A
    saved filter with "Drop Filtered Events" turned on removes events from the capture.
    Add the User and Integrity columns in the configuration to get the user and
    integrity fields.

    In an elevated session, Process Monitor is started only from -ProcmonPath: PATH is
    not searched, because it can include folders that a standard user can write.

    Elevation: required for -Capture. Not required for -ParseCsv and -DryRun.

.PARAMETER Capture
    Run a capture. Without -Capture, -ParseCsv or -DryRun, the tool runs as -DryRun.

.PARAMETER DurationSeconds
    Capture length when no -TriggerCommand is given. Default: 10.

.PARAMETER TriggerCommand
    A command line run with "cmd.exe /d /s /c" while the capture runs. The capture
    continues for -SettleSeconds after the command exits. Quote a program path or an
    argument that contains spaces inside the value, for example
    '"C:\Program Files\Contoso\tool.exe" /run "Some Value"'.

.PARAMETER TriggerTimeoutSeconds
    Stop waiting for -TriggerCommand after this many seconds, stop the cmd.exe process
    that this tool started, and finish the capture. Default: 120.

.PARAMETER SettleSeconds
    Seconds to keep capturing after -TriggerCommand exits. Default: 2.

.PARAMETER ProcessName
    Keep rows whose process name contains one of these values (case-insensitive).
    With -File, pass several values as one comma-separated string.

.PARAMETER PathFilter
    Keep rows whose path matches this regular expression (case-insensitive).

.PARAMETER Operation
    Keep rows with these operation names (exact, case-insensitive). Pass * to keep every
    operation. Default: CreateFile, ReadFile, WriteFile, SetRenameInformationFile,
    SetRenameInformationEx, SetDispositionInformationFile, SetDispositionInformationEx,
    SetSecurityFile, RegOpenKey, RegCreateKey, RegQueryValue, RegSetValue, RegDeleteKey,
    RegDeleteValue, Process Create, Load Image.

.PARAMETER MaxRows
    Maximum number of data rows; the summary counts every kept row. Default: 5000.

.PARAMETER BackingFile
    Path of the .pml file, in a directory that exists. Neither it nor the .csv file next
    to it (same name, .csv extension) may exist yet. Default: capture.pml in a new
    directory that only Administrators and SYSTEM can open.

.PARAMETER ConfigFile
    A Process Monitor configuration file (.pmc) passed with /LoadConfig.

.PARAMETER ConvertTimeoutSeconds
    Maximum time for the .pml to .csv conversion. Default: 300.

.PARAMETER KeepArtifacts
    Keep the .pml and .csv files and report their paths.

.PARAMETER ParseCsv
    Parse this existing CSV export instead of capturing.

.PARAMETER DryRun
    Report readiness only.

.PARAMETER ProcmonPath
    Path to Procmon64.exe or Procmon.exe. Required for -Capture, which runs elevated.

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
    summary: mode, procmonPath, totalEvents, keptEvents, truncated, distinctPaths,
             distinctProcesses, byOperation{}, triggerExitCode, artifacts{}, caveats[]
             (-DryRun: mode, procmonPath, elevatedNow, otherInstanceRunning, ready)
    data[]:  time, processName, pid, operation, path, result, detail, user, integrity
    time is the "Time of Day" column as Process Monitor exports it: the local time of
    day, without a date.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-ProcmonCapture.ps1 -DryRun

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-ProcmonCapture.ps1 -Capture -ProcmonPath "C:\Program Files\Sysinternals\Procmon64.exe" -TriggerCommand "sc.exe query spooler" -ProcessName "spoolsv.exe,services.exe" -OutFile .\capture.json

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-ProcmonCapture.ps1 -ParseCsv .\Logfile.CSV -Operation * -PathFilter "\\ProgramData\\"
#>
[CmdletBinding()]
param(
    [switch]   $Capture,
    [int]      $DurationSeconds = 10,
    [string]   $TriggerCommand,
    [int]      $TriggerTimeoutSeconds = 120,
    [int]      $SettleSeconds = 2,
    [string[]] $ProcessName,
    [string]   $PathFilter,
    [string[]] $Operation = @('CreateFile', 'ReadFile', 'WriteFile', 'SetRenameInformationFile', 'SetRenameInformationEx', 'SetDispositionInformationFile', 'SetDispositionInformationEx', 'SetSecurityFile', 'RegOpenKey', 'RegCreateKey', 'RegQueryValue', 'RegSetValue', 'RegDeleteKey', 'RegDeleteValue', 'Process Create', 'Load Image'),
    [int]      $MaxRows = 5000,
    [string]   $BackingFile,
    [string]   $ConfigFile,
    [int]      $ConvertTimeoutSeconds = 300,
    [switch]   $KeepArtifacts,
    [string]   $ParseCsv,
    [switch]   $DryRun,
    [string]   $ProcmonPath,
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

$script:CmdPath = Join-Path ([System.Environment]::SystemDirectory) 'cmd.exe'

function ConvertTo-QuotedArgument {
    param([string]$Argument)
    if ($Argument -eq '') { return '""' }
    if ($Argument -notmatch '[\s"]') { return $Argument }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq [char]'\') { $backslashes++; continue }
        if ($character -eq [char]'"') {
            [void]$builder.Append(('\' * ($backslashes * 2 + 1)) + '"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) { [void]$builder.Append('\' * $backslashes); $backslashes = 0 }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) { [void]$builder.Append('\' * ($backslashes * 2)) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-ArgumentList {
    param([string[]]$Arguments)
    return (($Arguments | ForEach-Object { ConvertTo-QuotedArgument $_ }) -join ' ')
}

function Resolve-ExternalTool {
    param([string]$Explicit, [string[]]$Names, [string[]]$FixedPaths, [bool]$Elevated)
    # An explicit path wins. Otherwise PATH is searched, but only when the session is not
    # elevated: PATH can include folders that a standard user can write. $FixedPaths are
    # install locations under Program Files, which only administrators can change.
    $result = @{ Path = $null; Source = $null; PathSkipped = $false }
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        if (Test-Path -LiteralPath $Explicit -PathType Leaf) {
            $result.Path = (Resolve-Path -LiteralPath $Explicit).ProviderPath
            $result.Source = 'parameter'
        }
        return $result
    }
    if ($Elevated) {
        $result.PathSkipped = $true
    } else {
        foreach ($name in $Names) {
            $command = Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($command) {
                $result.Path = $command.Source
                $result.Source = 'PATH'
                return $result
            }
        }
    }
    foreach ($candidate in $FixedPaths) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $result.Path = $candidate
            $result.Source = 'install directory'
            return $result
        }
    }
    return $result
}

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

function Get-ProcmonArtifactPath {
    param([string]$BackingFile)
    $pml = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackingFile)
    if ([System.IO.Path]::GetExtension($pml) -ne '.pml') { $pml = $pml + '.pml' }
    return @{ Pml = $pml; Csv = [System.IO.Path]::ChangeExtension($pml, '.csv') }
}

function Get-OtherProcmonInstance {
    return @(Get-Process -Name 'Procmon', 'Procmon64', 'Procmon64a' -ErrorAction SilentlyContinue)
}

function Wait-FileStable {
    param([string]$FilePath, [int]$TimeoutSeconds)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastSize = -1
    $stableChecks = 0
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
            $size = (Get-Item -LiteralPath $FilePath -Force).Length
            if ($size -gt 0 -and $size -eq $lastSize) {
                $stableChecks++
                if ($stableChecks -ge 2) { return $true }
            } else {
                $stableChecks = 0
            }
            $lastSize = $size
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Invoke-ProcmonTerminate {
    param([string]$Exe, [int]$TimeoutSeconds)
    try {
        $stopper = Start-Process -FilePath $Exe -ArgumentList '/AcceptEula /Terminate' -WindowStyle Hidden -PassThru -ErrorAction Stop
        if (-not $stopper.WaitForExit($TimeoutSeconds * 1000)) {
            Add-Caveat ('Procmon /Terminate did not finish within {0} s.' -f $TimeoutSeconds)
        }
    } catch {
        Add-Caveat ('Procmon /Terminate could not be started: ' + $_.Exception.Message)
    }
}

function ConvertTo-ColumnKey {
    param([string]$Name)
    $clean = $Name.Replace([string][char]0xFEFF, '')
    return ($clean -replace '\s', '').ToLowerInvariant()
}

function Read-ProcmonCsv {
    param([string]$CsvPath, [string[]]$Operations, [string[]]$ProcessFilters, [string]$PathPattern, [int]$RowLimit)
    $state = @{
        Total = 0; Kept = 0; Truncated = $false
        Rows = New-Object 'System.Collections.Generic.List[object]'
        ByOperation = [ordered]@{}
        Paths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        Processes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    }
    $allOperations = ($Operations.Count -eq 1 -and $Operations[0] -eq '*')
    $operationSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $Operations) { [void]$operationSet.Add($name) }
    $pathRegex = $null
    if (-not [string]::IsNullOrEmpty($PathPattern)) {
        $pathRegex = New-Object System.Text.RegularExpressions.Regex($PathPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $columns = @{
        time = @('timeofday', 'time'); processName = @('processname'); pid = @('pid'); operation = @('operation')
        path = @('path'); result = @('result'); detail = @('detail'); user = @('user'); integrity = @('integrity')
    }
    Import-Csv -LiteralPath $CsvPath | ForEach-Object {
        $state.Total++
        $values = @{}
        foreach ($property in $_.PSObject.Properties) {
            $key = ConvertTo-ColumnKey -Name $property.Name
            if (-not $values.ContainsKey($key)) { $values[$key] = [string]$property.Value }
        }
        $cell = @{}
        foreach ($field in $columns.Keys) {
            $cell[$field] = $null
            foreach ($candidate in $columns[$field]) {
                if ($values.ContainsKey($candidate)) { $cell[$field] = $values[$candidate]; break }
            }
        }
        $operationName = [string]$cell.operation
        if (-not $allOperations -and -not $operationSet.Contains($operationName)) { return }
        $process = [string]$cell.processName
        if ($ProcessFilters.Count -gt 0) {
            $hit = $false
            foreach ($filter in $ProcessFilters) {
                if ($process.IndexOf($filter, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true; break }
            }
            if (-not $hit) { return }
        }
        $pathValue = [string]$cell.path
        if ($null -ne $pathRegex -and -not $pathRegex.IsMatch($pathValue)) { return }
        $state.Kept++
        if ($state.ByOperation.Contains($operationName)) { $state.ByOperation[$operationName] = [int]$state.ByOperation[$operationName] + 1 } else { $state.ByOperation[$operationName] = 1 }
        if ($pathValue) { [void]$state.Paths.Add($pathValue) }
        if ($process) { [void]$state.Processes.Add($process) }
        if ($state.Rows.Count -ge $RowLimit) { $state.Truncated = $true; return }
        $pidNumber = $null
        $parsed = 0
        if ([int]::TryParse([string]$cell.pid, [ref]$parsed)) { $pidNumber = $parsed }
        $state.Rows.Add([pscustomobject][ordered]@{
            time        = $cell.time
            processName = $cell.processName
            pid         = $pidNumber
            operation   = $operationName
            path        = $pathValue
            result      = $cell.result
            detail      = $cell.detail
            user        = $cell.user
            integrity   = $cell.integrity
        })
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

$operations = Split-ProbeList $Operation
$processFilters = Split-ProbeList $ProcessName
$params = [ordered]@{
    Capture               = [bool]$Capture
    DurationSeconds       = $DurationSeconds
    TriggerCommand        = $TriggerCommand
    TriggerTimeoutSeconds = $TriggerTimeoutSeconds
    SettleSeconds         = $SettleSeconds
    ProcessName           = $processFilters
    PathFilter            = $PathFilter
    Operation             = $operations
    MaxRows               = $MaxRows
    BackingFile           = $BackingFile
    ConfigFile            = $ConfigFile
    ConvertTimeoutSeconds = $ConvertTimeoutSeconds
    KeepArtifacts         = [bool]$KeepArtifacts
    ParseCsv              = $ParseCsv
    DryRun                = [bool]$DryRun
    ProcmonPath           = $ProcmonPath
    SummaryOnly           = [bool]$SummaryOnly
    Compress              = [bool]$Compress
    OutFile               = $OutFile
}
$ok = $true
$errorMessage = $null
$summary = $null
$rows = $null
$captureRunning = $false
$procmonExe = $null
$capturer = $null
$pmlPath = $null
$csvPath = $null
$artifactsOwned = $false
$runDirectory = $null
$procmonNames = @('Procmon64.exe', 'Procmon.exe')

try {
    if ($operations.Count -eq 0) { throw '-Operation must name at least one operation, or *.' }
    if ($MaxRows -lt 1) { throw '-MaxRows must be 1 or more.' }
    if (-not [string]::IsNullOrEmpty($PathFilter)) {
        try { $null = New-Object System.Text.RegularExpressions.Regex($PathFilter) } catch { throw ('-PathFilter is not a valid regular expression: ' + $_.Exception.Message) }
    }
    $modes = New-Object 'System.Collections.Generic.List[string]'
    if ($Capture) { $modes.Add('-Capture') }
    if (-not [string]::IsNullOrWhiteSpace($ParseCsv)) { $modes.Add('-ParseCsv') }
    if ($DryRun) { $modes.Add('-DryRun') }
    if ($modes.Count -gt 1) { throw ('Use only one of -Capture, -ParseCsv and -DryRun (got {0}).' -f ($modes -join ', ')) }
    if (-not $Capture) {
        $captureOnly = New-Object 'System.Collections.Generic.List[string]'
        foreach ($name in @('TriggerCommand', 'DurationSeconds', 'TriggerTimeoutSeconds', 'SettleSeconds', 'BackingFile', 'ConfigFile', 'ConvertTimeoutSeconds', 'KeepArtifacts')) {
            if ($PSBoundParameters.ContainsKey($name)) { $captureOnly.Add('-' + $name) }
        }
        if ($captureOnly.Count -gt 0) { throw ('These parameters apply only to -Capture: {0}. Add -Capture to run a capture.' -f ($captureOnly -join ', ')) }
    }
    $elevatedNow = (Get-ProbeIdentity).Elevated

    if (-not [string]::IsNullOrWhiteSpace($ParseCsv)) {
        if (-not (Test-Path -LiteralPath $ParseCsv -PathType Leaf)) { throw ('-ParseCsv file not found: ' + $ParseCsv) }
        $parsed = Read-ProcmonCsv -CsvPath (Resolve-Path -LiteralPath $ParseCsv).ProviderPath -Operations $operations -ProcessFilters $processFilters -PathPattern $PathFilter -RowLimit $MaxRows
        $rows = $parsed.Rows
        if ($parsed.Truncated) { Add-Caveat ('data[] stopped at -MaxRows {0}; the summary counts every kept row.' -f $MaxRows) }
        $summary = [ordered]@{
            mode              = 'parse-csv'
            procmonPath       = $null
            totalEvents       = $parsed.Total
            keptEvents        = $parsed.Kept
            truncated         = $parsed.Truncated
            distinctPaths     = $parsed.Paths.Count
            distinctProcesses = $parsed.Processes.Count
            byOperation       = $parsed.ByOperation
            triggerExitCode   = $null
            artifacts         = $null
        }
    } elseif ($Capture) {
        if ($DurationSeconds -lt 1 -or $TriggerTimeoutSeconds -lt 1 -or $SettleSeconds -lt 0 -or $ConvertTimeoutSeconds -lt 10) {
            throw '-DurationSeconds and -TriggerTimeoutSeconds must be 1 or more, -SettleSeconds 0 or more, -ConvertTimeoutSeconds 10 or more.'
        }
        if ($ConfigFile -and -not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) { throw ('-ConfigFile not found: ' + $ConfigFile) }
        if (-not [string]::IsNullOrWhiteSpace($BackingFile)) {
            $artifactPaths = Get-ProcmonArtifactPath -BackingFile $BackingFile
            foreach ($artifact in @($artifactPaths.Pml, $artifactPaths.Csv)) {
                if (Test-Path -LiteralPath $artifact) { throw ('{0} already exists; choose another -BackingFile. This tool does not overwrite or delete files that it did not create.' -f $artifact) }
            }
            $backingDirectory = [System.IO.Path]::GetDirectoryName($artifactPaths.Pml)
            if (-not [System.IO.Directory]::Exists($backingDirectory)) { throw ('The directory of -BackingFile does not exist: {0}. Create it first; this tool does not create it, so that a capture leaves no directory behind.' -f $backingDirectory) }
        }
        if (-not $elevatedNow) { throw 'Capture mode needs elevation (Process Monitor loads a kernel driver). Run from an elevated prompt, or use -ParseCsv / -DryRun.' }
        $tool = Resolve-ExternalTool -Explicit $ProcmonPath -Names $procmonNames -FixedPaths @() -Elevated $true
        $procmonExe = $tool.Path
        if (-not $procmonExe) {
            if ($ProcmonPath) { throw ('-ProcmonPath not found: ' + $ProcmonPath) }
            throw 'Pass -ProcmonPath with the full path of Procmon64.exe, in a folder that only administrators can change. A capture runs elevated, and in an elevated session this tool does not take a program from PATH, because PATH can include folders that a standard user can write.'
        }
        $others = @(Get-OtherProcmonInstance)
        if ($others.Count -gt 0) {
            throw ('Process Monitor is already running (PID {0}). This tool ends a capture with Procmon /Terminate, which stops every instance, so it does not start while another instance runs.' -f (($others | ForEach-Object { $_.Id }) -join ', '))
        }
        if ([string]::IsNullOrWhiteSpace($BackingFile)) {
            $runDirectory = New-ProbeRunDirectory -Parent (Join-Path ([System.Environment]::GetFolderPath('Windows')) 'Temp') -AdministratorsOnly $true
            $pmlPath = Join-Path $runDirectory 'capture.pml'
            $csvPath = Join-Path $runDirectory 'capture.csv'
        } else {
            $pmlPath = $artifactPaths.Pml
            $csvPath = $artifactPaths.Csv
        }

        $configArguments = @()
        if ($ConfigFile) { $configArguments = @('/LoadConfig', (Resolve-Path -LiteralPath $ConfigFile).ProviderPath) }
        $startArguments = @('/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', $pmlPath) + $configArguments
        $artifactsOwned = $true
        $capturer = Start-Process -FilePath $procmonExe -ArgumentList (Join-ArgumentList $startArguments) -WindowStyle Minimized -PassThru
        $captureRunning = $true
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $pmlPath) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 300 }
        if (-not (Test-Path -LiteralPath $pmlPath)) { throw 'The capture did not start: the backing file did not appear within 30 s.' }

        $triggerExit = $null
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

        Invoke-ProcmonTerminate -Exe $procmonExe -TimeoutSeconds 60
        if (-not $capturer.WaitForExit(60000)) {
            Add-Caveat 'The capturing Process Monitor process did not exit after /Terminate; it was stopped.'
            try { Stop-Process -Id $capturer.Id -Force -ErrorAction Stop } catch { Add-Caveat ('Stopping it failed: ' + $_.Exception.Message) }
        }
        $captureRunning = $false
        if (-not (Wait-FileStable -FilePath $pmlPath -TimeoutSeconds 60)) { Add-Caveat 'The .pml file did not stop growing within 60 s; the log may be incomplete.' }

        $convertArguments = @('/AcceptEula', '/Quiet', '/Minimized', '/OpenLog', $pmlPath, '/SaveAs', $csvPath) + $configArguments
        $converter = Start-Process -FilePath $procmonExe -ArgumentList (Join-ArgumentList $convertArguments) -WindowStyle Minimized -PassThru
        if (-not $converter.WaitForExit($ConvertTimeoutSeconds * 1000)) {
            try { Stop-Process -Id $converter.Id -Force -ErrorAction Stop } catch { Write-Verbose 'converter already gone' }
            throw ('The .pml to .csv conversion did not finish within {0} s.' -f $ConvertTimeoutSeconds)
        }
        if (-not (Wait-FileStable -FilePath $csvPath -TimeoutSeconds 60)) { throw 'The CSV export did not appear (or did not stop growing) within 60 s.' }

        $parsed = Read-ProcmonCsv -CsvPath $csvPath -Operations $operations -ProcessFilters $processFilters -PathPattern $PathFilter -RowLimit $MaxRows
        $rows = $parsed.Rows
        if ($parsed.Truncated) { Add-Caveat ('data[] stopped at -MaxRows {0}; the summary counts every kept row.' -f $MaxRows) }
        if ($ConfigFile) {
            Add-Caveat 'Process Monitor used -ConfigFile for the capture and the conversion. Whether it also saves that configuration as the settings of the current user was not checked.'
        } else {
            Add-Caveat 'Process Monitor applied the settings saved for the current user; a saved filter with Drop Filtered Events turned on removes events from the capture.'
        }
        $artifacts = $null
        if ($KeepArtifacts) { $artifacts = [ordered]@{ pml = $pmlPath; csv = $csvPath } }
        $summary = [ordered]@{
            mode              = 'capture'
            procmonPath       = $procmonExe
            totalEvents       = $parsed.Total
            keptEvents        = $parsed.Kept
            truncated         = $parsed.Truncated
            distinctPaths     = $parsed.Paths.Count
            distinctProcesses = $parsed.Processes.Count
            byOperation       = $parsed.ByOperation
            triggerExitCode   = $triggerExit
            artifacts         = $artifacts
        }
    } else {
        if (-not $DryRun) { Add-Caveat 'No mode was given, so the tool ran as -DryRun. Pass -Capture to capture.' }
        $tool = Resolve-ExternalTool -Explicit $ProcmonPath -Names $procmonNames -FixedPaths @() -Elevated $true
        $procmonExe = $tool.Path
        if (-not $procmonExe) {
            if ($ProcmonPath) {
                Add-Caveat ('-ProcmonPath not found: ' + $ProcmonPath)
            } else {
                $hint = ''
                if (-not $elevatedNow) {
                    $onPath = (Resolve-ExternalTool -Explicit '' -Names $procmonNames -FixedPaths @() -Elevated $false).Path
                    if ($onPath) { $hint = (' Process Monitor is on PATH at {0}.' -f $onPath) }
                }
                Add-Caveat ('A capture runs elevated and does not take Process Monitor from PATH: pass -ProcmonPath.' + $hint)
            }
        }
        $others = @(Get-OtherProcmonInstance)
        if (-not $elevatedNow) { Add-Caveat 'Not elevated: a capture needs an elevated prompt.' }
        if ($others.Count -gt 0) { Add-Caveat 'Another Process Monitor instance is running; a capture would refuse to start.' }
        $summary = [ordered]@{
            mode                 = 'dry-run'
            procmonPath          = $procmonExe
            elevatedNow          = $elevatedNow
            otherInstanceRunning = ($others.Count -gt 0)
            ready                = ([bool]$procmonExe -and $elevatedNow -and ($others.Count -eq 0))
        }
    }
} catch {
    $ok = $false
    $errorMessage = $_.Exception.Message
} finally {
    if ($captureRunning -and $procmonExe) {
        Invoke-ProcmonTerminate -Exe $procmonExe -TimeoutSeconds 60
        if ($capturer -and -not $capturer.HasExited) {
            try { Stop-Process -Id $capturer.Id -Force -ErrorAction Stop } catch { Write-Verbose 'capturer already gone' }
        }
    }
    if ($artifactsOwned -and -not $KeepArtifacts) {
        foreach ($artifact in @($pmlPath, $csvPath)) {
            if ($artifact -and (Test-Path -LiteralPath $artifact)) {
                try { Remove-Item -LiteralPath $artifact -Force -ErrorAction Stop } catch { Add-Caveat ('Could not delete ' + $artifact) }
            }
        }
    }
    if ($runDirectory -and -not $KeepArtifacts -and (Test-Path -LiteralPath $runDirectory)) {
        try { Remove-Item -LiteralPath $runDirectory -Recurse -Force -ErrorAction Stop } catch { Add-Caveat ('Could not delete ' + $runDirectory) }
    }
}

$envelope = ConvertTo-ProbeEnvelope -Tool 'Invoke-ProcmonCapture' -Params $params -Ok $ok -ErrorMessage $errorMessage -Summary $summary -Data $rows -SummaryOnly ([bool]$SummaryOnly)
Write-ProbeEnvelope -Envelope $envelope -OutFile $OutFile -Compress ([bool]$Compress)
exit (Get-ProbeExitCode -Ok $ok)
