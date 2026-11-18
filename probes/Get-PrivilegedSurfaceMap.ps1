#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Inventory the processes, services and scheduled tasks of this computer with the
    account each one runs as, as one JSON document.

.DESCRIPTION
    Three sources, each one optional and each one isolated, so that a failure in one does
    not stop the others:

      process   Win32_Process (pid, name, path, parent, session, command line). The account,
                integrity level, protection and two token privileges come from
                NtObjectManager when the module is installed. Without it, only the account
                is read, with Win32_Process.GetOwner and GetOwnerSid, which is slower.
      service   Win32_Service (name, account, state, start mode, pid, command line), plus the
                Parameters\ServiceDll and LaunchProtected registry values.
      task      Get-ScheduledTask (path, name, principal, run level, logon type, actions,
                trigger types). For the first executable action, the program file is
                resolved and its PE machine type (x86, x64, arm64) is read from the file
                header.

    -OnlyPrivileged keeps:
      processes that run as SYSTEM, LOCAL SERVICE or NETWORK SERVICE, run protected, or
                have SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege in their token
      services whose account is SYSTEM, LOCAL SERVICE or NETWORK SERVICE
      tasks whose account is one of those three, or whose run level is Highest
    Processes are compared by SID. Services and tasks are compared by account name: the
    English names, and the names that Windows gives the same three SIDs in the language
    of this system. Virtual service accounts (NT SERVICE\name) and user accounts are not
    counted as privileged, except in tasks with run level Highest.

    Task programs. A path that starts with \\ (UNC, WebDAV, \\?\ and \\.\ paths) or that
    is on a network drive is never opened, so that the tool does not connect to another
    computer with the token of the person who runs it. A program name without a path is
    looked up in System32, the Windows directory and the directories of the machine
    PATH. Environment variables are expanded with the environment of this tool, which can
    differ from the environment of the task account. executableExists is true when the
    file was found, false when a local path names no file, and null when the tool did not
    check (network or device path, or a name without a path that was not found).

    State changes: none. The tool reads WMI, the registry, the Task Scheduler and file
    headers.
    Elevation: recommended. Without it, the token of most processes that run as other
    accounts cannot be opened, so their user and token fields are null. In an elevated
    session, NtObjectManager is imported only from the PowerShell installation directory
    ($PSHOME) or from Program Files: processes of the same user at medium integrity can
    change files in the user profile and in other folders that the user adds to
    PSModulePath.

    The output contains command lines, task arguments, paths and account names from this
    computer. Review it before you share it. -OmitCommandLine leaves process and service
    command lines and task arguments out.

.PARAMETER SkipProcesses
    Do not list processes.

.PARAMETER SkipServices
    Do not list services.

.PARAMETER SkipTasks
    Do not list scheduled tasks.

.PARAMETER OnlyPrivileged
    Keep only the privileged rows defined above.

.PARAMETER OmitCommandLine
    Leave process and service command lines and scheduled-task arguments out of the
    output.

.PARAMETER MaxRows
    Maximum number of data rows, taken in this order: processes, services, tasks.
    summary.returned counts every row. Default: 5000.

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
    summary: tokenSource, counts{}, returned{}, truncated, protectedProcesses[],
             impersonationPrivilegeHolders[], caveats[]
    data[] (kind = process): kind, pid, name, path, parentPid, sessionId, commandLine,
             user, userSid, integrityLevel, protection, hasSeImpersonate,
             hasSeAssignPrimaryToken
    data[] (kind = service): kind, name, displayName, account, state, startMode, pid,
             serviceType, commandLine, serviceDll, launchProtected
    data[] (kind = task):    kind, taskPath, taskName, state, runAs, runLevel, logonType,
             executable, resolvedExecutable, executableExists, machine, arguments,
             comHandlers[], triggerTypes[]
    impersonationPrivilegeHolders lists the names of the returned processes whose token
    has SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-PrivilegedSurfaceMap.ps1 -OnlyPrivileged -OutFile .\surface.json

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-PrivilegedSurfaceMap.ps1 -SkipProcesses -OmitCommandLine -SummaryOnly
#>
[CmdletBinding()]
param(
    [switch] $SkipProcesses,
    [switch] $SkipServices,
    [switch] $SkipTasks,
    [switch] $OnlyPrivileged,
    [switch] $OmitCommandLine,
    [int]    $MaxRows = 5000,
    [switch] $SummaryOnly,
    [switch] $Compress,
    [string] $OutFile,
    [switch] $Help
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

function Test-TrustedModuleBase {
    param([string]$ModuleBase, [string[]]$TrustedRoots)
    # An elevated probe imports a module only from a folder under a trusted root: the
    # PowerShell installation directory ($PSHOME) or Program Files, which only
    # administrators can change. Other folders in PSModulePath, such as the Modules folder
    # in Documents or a folder that the user added, can be changed by processes of the
    # same user at medium integrity. The path is normalized first, so that ".." cannot
    # lead out of a trusted root.
    if ([string]::IsNullOrWhiteSpace($ModuleBase) -or $ModuleBase -notmatch '^[A-Za-z]:\\') { return $false }
    try {
        $base = [System.IO.Path]::GetFullPath($ModuleBase).TrimEnd('\') + '\'
    } catch {
        return $false
    }
    foreach ($root in $TrustedRoots) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $prefix = $root.TrimEnd('\') + '\'
        if ($base.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Import-ProbeModule {
    param([string]$Name, [bool]$Elevated)
    # Imports the highest installed version of the module and returns its version, or
    # returns $null. In an elevated session, only copies under $PSHOME or Program Files
    # are used.
    $available = @(Get-Module -ListAvailable -Name $Name | Sort-Object -Property Version -Descending)
    if ($available.Count -eq 0) { return $null }
    $candidates = $available
    if ($Elevated) {
        $roots = @(
            $PSHOME,
            [System.Environment]::GetFolderPath('ProgramFiles'),
            [System.Environment]::GetFolderPath('ProgramFilesX86'))
        $candidates = @($available | Where-Object { Test-TrustedModuleBase -ModuleBase $_.ModuleBase -TrustedRoots $roots })
        if ($candidates.Count -eq 0) {
            Add-Caveat ('{0} was not imported: this session is elevated, and the module was found only outside the PowerShell installation directory and Program Files ({1}). Other folders can be writable for processes of this user. Install it with: Install-Module {0} -Scope AllUsers' -f $Name, $available[0].ModuleBase)
            return $null
        }
    }
    try {
        Import-Module -Name $candidates[0].Path -DisableNameChecking -ErrorAction Stop
        return [string]$candidates[0].Version
    } catch {
        Add-Caveat ('{0} could not be imported: {1}' -f $Name, $_.Exception.Message)
        return $null
    }
}

function ConvertTo-AccountKey {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    return ($Name.Trim() -replace '\s', '').ToUpperInvariant()
}

function Get-LocalizedPrivilegedName {
    # The names that this system gives SYSTEM, LOCAL SERVICE and NETWORK SERVICE. Windows
    # resolves these well-known SIDs locally.
    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($sidText in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')) {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
            $names.Add($sid.Translate([System.Security.Principal.NTAccount]).Value)
        } catch {
            Write-Verbose ('no name for ' + $sidText)
        }
    }
    return ,($names.ToArray())
}

function Get-PrivilegedNameSet {
    param([string[]]$LocalizedNames)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'SYSTEM', 'LOCALSYSTEM', 'LOCALSERVICE', 'NETWORKSERVICE',
            'NTAUTHORITY\SYSTEM', 'NTAUTHORITY\LOCALSERVICE', 'NTAUTHORITY\NETWORKSERVICE')) {
        [void]$set.Add($name)
    }
    foreach ($name in $LocalizedNames) {
        $key = ConvertTo-AccountKey $name
        if (-not $key) { continue }
        [void]$set.Add($key)
        $slash = $key.LastIndexOf('\')
        if ($slash -ge 0 -and $slash -lt ($key.Length - 1)) { [void]$set.Add($key.Substring($slash + 1)) }
    }
    return ,$set
}

function Test-PrivilegedPrincipal {
    param([string]$Account, [string]$Sid, $NameSet)
    if ($Sid -and (@('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -contains $Sid.Trim())) { return $true }
    $key = ConvertTo-AccountKey $Account
    if (-not $key -or $null -eq $NameSet) { return $false }
    return $NameSet.Contains($key)
}

function Resolve-AccountName {
    param([string]$Sid, [hashtable]$Cache)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $null }
    if ($Cache.ContainsKey($Sid)) { return $Cache[$Sid] }
    $name = $null
    try {
        $name = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        Write-Verbose ('no account name for ' + $Sid)
    }
    $Cache[$Sid] = $name
    return $name
}

function Test-LocalFilePath {
    param([string]$Path)
    # False for a path that can reach another computer or a device: UNC paths
    # (\\server\share and the WebDAV forms), \\?\ and \\.\ paths, and paths on a mapped
    # network drive. The probe does not open a path for which this returns false.
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $text = $Path.Trim()
    if ($text.StartsWith('\\') -or $text.StartsWith('//')) { return $false }
    if ($text -match '^[A-Za-z]:') {
        try {
            $drive = New-Object System.IO.DriveInfo($text.Substring(0, 1))
            if ($drive.DriveType -eq [System.IO.DriveType]::Network) { return $false }
        } catch {
            return $false
        }
    }
    return $true
}

function Get-PeMachineName {
    param([string]$FilePath)
    if ([string]::IsNullOrWhiteSpace($FilePath) -or -not (Test-LocalFilePath $FilePath)) { return $null }
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $null }
    $stream = $null
    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $stream = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($stream.Length -lt 0x40 -or $reader.ReadUInt16() -ne 0x5A4D) { return $null }
        $null = $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin)
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or ($peOffset + 6) -gt $stream.Length) { return $null }
        $null = $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin)
        if ($reader.ReadUInt32() -ne 0x00004550) { return $null }
        $machine = [int]$reader.ReadUInt16()
        switch ($machine) {
            0x014C { return 'x86' }
            0x8664 { return 'x64' }
            0xAA64 { return 'arm64' }
            0x01C4 { return 'arm' }
            default { return ('0x{0:X4}' -f $machine) }
        }
    } catch {
        Write-Verbose ('cannot read PE header of {0}: {1}' -f $FilePath, $_.Exception.Message)
        return $null
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Get-TaskExecutableCandidate {
    param([string]$Execute)
    # Task Scheduler keeps the program in Execute and its arguments in Arguments, so an
    # unquoted Execute value with spaces is still one path. The whole value is tried
    # first; the text before the first space is the fallback.
    $list = New-Object 'System.Collections.Generic.List[string]'
    if ([string]::IsNullOrWhiteSpace($Execute)) { return ,($list.ToArray()) }
    $text = [System.Environment]::ExpandEnvironmentVariables($Execute.Trim())
    if ($text.StartsWith('"')) {
        $close = $text.IndexOf('"', 1)
        if ($close -gt 1) { $list.Add($text.Substring(1, $close - 1)) } else { $list.Add($text.Trim('"')) }
    } else {
        $list.Add($text)
        $space = $text.IndexOf(' ')
        if ($space -gt 0) { $list.Add($text.Substring(0, $space)) }
    }
    return ,($list.ToArray())
}

function Find-ExistingFile {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return $Path }
        if (-not [System.IO.Path]::HasExtension($Path) -and (Test-Path -LiteralPath ($Path + '.exe') -PathType Leaf)) { return $Path + '.exe' }
    } catch {
        Write-Verbose ('cannot test {0}: {1}' -f $Path, $_.Exception.Message)
    }
    return $null
}

function Get-TaskSearchDirectory {
    # System32, the Windows directory and the local directories of the machine PATH.
    $list = New-Object 'System.Collections.Generic.List[string]'
    $entries = New-Object 'System.Collections.Generic.List[string]'
    $entries.Add([System.Environment]::GetFolderPath('System'))
    $entries.Add([System.Environment]::GetFolderPath('Windows'))
    $machinePath = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)
    if ($machinePath) { foreach ($entry in $machinePath.Split(';')) { $entries.Add($entry) } }
    foreach ($entry in $entries) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        $expanded = [System.Environment]::ExpandEnvironmentVariables($entry.Trim().Trim('"'))
        if (-not [System.IO.Path]::IsPathRooted($expanded) -or -not (Test-LocalFilePath $expanded)) { continue }
        if (-not $list.Contains($expanded)) { $list.Add($expanded) }
    }
    return ,($list.ToArray())
}

function Resolve-TaskExecutable {
    param([string]$Execute, [string[]]$SearchDirectories)
    $result = @{ Path = $null; Exists = $null; NotOpened = $false; Unresolved = $false }
    $candidates = Get-TaskExecutableCandidate -Execute $Execute
    if ($candidates.Count -eq 0) { return $result }
    $result.Path = $candidates[0]
    if (-not (Test-LocalFilePath $candidates[0])) {
        $result.NotOpened = $true
        return $result
    }
    foreach ($candidate in $candidates) {
        if ([System.IO.Path]::IsPathRooted($candidate)) {
            $found = Find-ExistingFile -Path $candidate
            if ($found) { $result.Path = $found; $result.Exists = $true; return $result }
        } else {
            foreach ($directory in $SearchDirectories) {
                $found = Find-ExistingFile -Path (Join-Path $directory $candidate)
                if ($found) { $result.Path = $found; $result.Exists = $true; return $result }
            }
        }
    }
    if ([System.IO.Path]::IsPathRooted($candidates[0])) { $result.Exists = $false } else { $result.Unresolved = $true }
    return $result
}

function Get-ServiceRegistryValue {
    param([string]$ServiceName, [string]$SubKey, [string]$ValueName)
    $keyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $ServiceName
    if ($SubKey) { $keyPath = $keyPath + '\' + $SubKey }
    try {
        $item = Get-ItemProperty -LiteralPath $keyPath -Name $ValueName -ErrorAction Stop
        return (Get-ObjectProperty $item $ValueName)
    } catch {
        return $null
    }
}

function ConvertTo-LaunchProtectedName {
    param($Value)
    if ($null -eq $Value) { return $null }
    switch ([int]$Value) {
        0 { return 'none' }
        1 { return 'windows' }
        2 { return 'windows-light' }
        3 { return 'antimalware-light' }
        default { return ('unknown ({0})' -f $Value) }
    }
}

function Get-TokenDetail {
    param([int]$ProcessId)
    $detail = @{ User = $null; UserSid = $null; IntegrityLevel = $null; Protection = $null; HasSeImpersonate = $null; HasSeAssignPrimaryToken = $null; Failed = $false }
    $ntProcess = $null
    $token = $null
    try {
        try {
            $ntProcess = Get-NtProcess -ProcessId $ProcessId -Access QueryLimitedInformation -ErrorAction Stop
        } catch {
            $ntProcess = Get-NtProcess -ProcessId $ProcessId -ErrorAction Stop
        }
        $user = Get-ObjectProperty $ntProcess 'User'
        if ($user) {
            $text = [string]$user
            if ($text -match '^S-1-') { $detail.UserSid = $text } else { $detail.User = $text }
        }
        if ((Get-ObjectProperty $ntProcess 'Protected') -eq $true) {
            $protection = [string](Get-ObjectProperty $ntProcess 'Protection')
            if ([string]::IsNullOrWhiteSpace($protection)) { $protection = 'protected' }
            $detail.Protection = $protection
        }
        try {
            $token = Get-NtToken -Process $ntProcess -Access Query -Duplicate -ErrorAction Stop
        } catch {
            $token = Get-NtToken -Process $ntProcess -ErrorAction Stop
        }
        $integrity = Get-ObjectProperty $token 'IntegrityLevel'
        if ($null -ne $integrity) { $detail.IntegrityLevel = [string]$integrity }
        if (-not $detail.UserSid) {
            $sid = Get-ObjectProperty (Get-ObjectProperty $token 'User') 'Sid'
            if ($sid) { $detail.UserSid = [string]$sid }
        }
        $privileges = Get-ObjectProperty $token 'Privileges'
        if ($null -ne $privileges) {
            $names = @($privileges | ForEach-Object { [string](Get-ObjectProperty $_ 'Name') })
            $detail.HasSeImpersonate = ($names -contains 'SeImpersonatePrivilege')
            $detail.HasSeAssignPrimaryToken = ($names -contains 'SeAssignPrimaryTokenPrivilege')
        }
    } catch {
        $detail.Failed = $true
        Write-Verbose ('token detail unavailable for PID {0}: {1}' -f $ProcessId, $_.Exception.Message)
    } finally {
        if ($token) { try { $token.Dispose() } catch { Write-Verbose 'token dispose failed' } }
        if ($ntProcess) { try { $ntProcess.Dispose() } catch { Write-Verbose 'process dispose failed' } }
    }
    return $detail
}

function Get-ProcessRow {
    param([string]$TokenSource, [bool]$WithCommandLine)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $unreadable = 0
    $tokenFailures = 0
    $nameCache = @{}
    foreach ($process in $processes) {
        $processId = [int]$process.ProcessId
        $detail = @{ User = $null; UserSid = $null; IntegrityLevel = $null; Protection = $null; HasSeImpersonate = $null; HasSeAssignPrimaryToken = $null; Failed = $false }
        if ($processId -eq 4) {
            $detail.UserSid = 'S-1-5-18'
            $detail.User = Resolve-AccountName -Sid 'S-1-5-18' -Cache $nameCache
        } elseif ($processId -gt 4) {
            if ($TokenSource -eq 'NtObjectManager') {
                $detail = Get-TokenDetail -ProcessId $processId
                if ($detail.Failed) { $tokenFailures++ }
                if ($detail.UserSid -and -not $detail.User) { $detail.User = Resolve-AccountName -Sid $detail.UserSid -Cache $nameCache }
            } elseif ($TokenSource -eq 'Win32_Process.GetOwner') {
                try {
                    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
                    if ($owner.ReturnValue -eq 0 -and $owner.User) {
                        if ($owner.Domain) { $detail.User = $owner.Domain + '\' + $owner.User } else { $detail.User = $owner.User }
                    }
                    $ownerSid = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
                    if ($ownerSid.ReturnValue -eq 0 -and $ownerSid.Sid) { $detail.UserSid = [string]$ownerSid.Sid }
                } catch {
                    Write-Verbose ('GetOwner failed for PID {0}' -f $processId)
                }
            }
            if ($TokenSource -ne 'none' -and -not $detail.User -and -not $detail.UserSid) { $unreadable++ }
        }
        $commandLine = $null
        if ($WithCommandLine) { $commandLine = $process.CommandLine }
        $rows.Add([pscustomobject][ordered]@{
            kind                    = 'process'
            pid                     = $processId
            name                    = $process.Name
            path                    = $process.ExecutablePath
            parentPid               = [int]$process.ParentProcessId
            sessionId               = [int]$process.SessionId
            commandLine             = $commandLine
            user                    = $detail.User
            userSid                 = $detail.UserSid
            integrityLevel          = $detail.IntegrityLevel
            protection              = $detail.Protection
            hasSeImpersonate        = $detail.HasSeImpersonate
            hasSeAssignPrimaryToken = $detail.HasSeAssignPrimaryToken
        })
    }
    if ($unreadable -gt 0) {
        Add-Caveat ('The account of {0} process(es) could not be read; run elevated for a complete picture.' -f $unreadable)
    }
    if ($tokenFailures -gt 0) {
        Add-Caveat ('The token of {0} process(es) could not be read; their integrityLevel, protection and privilege fields are null. Protected processes stay unreadable even when elevated.' -f $tokenFailures)
    }
    return ,($rows.ToArray())
}

function Get-ServiceRow {
    param([bool]$WithCommandLine)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        $servicePid = $null
        if ($service.ProcessId -gt 0) { $servicePid = [int]$service.ProcessId }
        $commandLine = $null
        if ($WithCommandLine) { $commandLine = $service.PathName }
        $rows.Add([pscustomobject][ordered]@{
            kind            = 'service'
            name            = $service.Name
            displayName     = $service.DisplayName
            account         = $service.StartName
            state           = $service.State
            startMode       = $service.StartMode
            pid             = $servicePid
            serviceType     = $service.ServiceType
            commandLine     = $commandLine
            serviceDll      = (Get-ServiceRegistryValue -ServiceName $service.Name -SubKey 'Parameters' -ValueName 'ServiceDll')
            launchProtected = (ConvertTo-LaunchProtectedName (Get-ServiceRegistryValue -ServiceName $service.Name -SubKey '' -ValueName 'LaunchProtected'))
        })
    }
    return ,($rows.ToArray())
}

function ConvertTo-TaskRow {
    param($Task, [bool]$WithCommandLine, [string[]]$SearchDirectories, [hashtable]$Counters)
    $principal = Get-ObjectProperty $Task 'Principal'
    $runAs = Get-ObjectProperty $principal 'UserId'
    if (-not $runAs) { $runAs = Get-ObjectProperty $principal 'GroupId' }
    $executables = New-Object 'System.Collections.Generic.List[string]'
    $arguments = New-Object 'System.Collections.Generic.List[string]'
    $comHandlers = New-Object 'System.Collections.Generic.List[string]'
    foreach ($action in @(Get-ObjectProperty $Task 'Actions')) {
        if ($null -eq $action) { continue }
        $execute = Get-ObjectProperty $action 'Execute'
        if ($execute) {
            $executables.Add([string]$execute)
            $argumentText = Get-ObjectProperty $action 'Arguments'
            if ($argumentText) { $arguments.Add([string]$argumentText) }
        }
        $classId = Get-ObjectProperty $action 'ClassId'
        if ($classId) { $comHandlers.Add([string]$classId) }
    }
    $triggerTypes = New-Object 'System.Collections.Generic.List[string]'
    foreach ($trigger in @(Get-ObjectProperty $Task 'Triggers')) {
        if ($null -eq $trigger) { continue }
        $cimClass = Get-ObjectProperty $trigger 'CimClass'
        $typeName = [string](Get-ObjectProperty $cimClass 'CimClassName')
        if (-not $typeName) { $typeName = $trigger.GetType().Name }
        if (-not $triggerTypes.Contains($typeName)) { $triggerTypes.Add($typeName) }
    }
    $first = $null
    $resolved = $null
    $exists = $null
    $machine = $null
    if ($executables.Count -gt 0) {
        $first = $executables[0]
        if ($first.Contains('%')) { $Counters['Expanded'] = [int]$Counters['Expanded'] + 1 }
        $resolution = Resolve-TaskExecutable -Execute $first -SearchDirectories $SearchDirectories
        $resolved = $resolution.Path
        $exists = $resolution.Exists
        if ($resolution.NotOpened) { $Counters['NotOpened'] = [int]$Counters['NotOpened'] + 1 }
        if ($resolution.Unresolved) { $Counters['Unresolved'] = [int]$Counters['Unresolved'] + 1 }
        if ($exists -eq $true) { $machine = Get-PeMachineName -FilePath $resolved }
    }
    $argumentValue = $null
    if ($WithCommandLine -and $arguments.Count -gt 0) { $argumentValue = ($arguments -join ' | ') }
    $state = Get-ObjectProperty $Task 'State'
    $runLevel = Get-ObjectProperty $principal 'RunLevel'
    $logonType = Get-ObjectProperty $principal 'LogonType'
    return [pscustomobject][ordered]@{
        kind               = 'task'
        taskPath           = (Get-ObjectProperty $Task 'TaskPath')
        taskName           = (Get-ObjectProperty $Task 'TaskName')
        state              = $(if ($null -ne $state) { [string]$state } else { $null })
        runAs              = $runAs
        runLevel           = $(if ($null -ne $runLevel) { [string]$runLevel } else { $null })
        logonType          = $(if ($null -ne $logonType) { [string]$logonType } else { $null })
        executable         = $first
        resolvedExecutable = $resolved
        executableExists   = $exists
        machine            = $machine
        arguments          = $argumentValue
        comHandlers        = $comHandlers.ToArray()
        triggerTypes       = $triggerTypes.ToArray()
    }
}

function Get-TaskRow {
    param([bool]$WithCommandLine)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Add-Caveat 'Get-ScheduledTask is not available; tasks were not listed.'
        return ,($rows.ToArray())
    }
    $counters = @{ NotOpened = 0; Unresolved = 0; Expanded = 0; Failed = 0 }
    $directories = Get-TaskSearchDirectory
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
        try {
            $rows.Add((ConvertTo-TaskRow -Task $task -WithCommandLine $WithCommandLine -SearchDirectories $directories -Counters $counters))
        } catch {
            $counters['Failed'] = [int]$counters['Failed'] + 1
            Write-Verbose ('task could not be read: ' + $_.Exception.Message)
        }
    }
    if ($counters['NotOpened'] -gt 0) {
        Add-Caveat ('{0} task action(s) name a network or device path; those files were not opened, so executableExists and machine are null for them.' -f $counters['NotOpened'])
    }
    if ($counters['Unresolved'] -gt 0) {
        Add-Caveat ('{0} task action(s) name a program without a path that is not in System32, the Windows directory or the machine PATH; executableExists is null for them.' -f $counters['Unresolved'])
    }
    if ($counters['Expanded'] -gt 0) {
        Add-Caveat ('{0} task action(s) contain environment variables; they were expanded with the environment of this tool, which can differ from the environment of the task account.' -f $counters['Expanded'])
    }
    if ($counters['Failed'] -gt 0) {
        Add-Caveat ('{0} task(s) could not be read and are not listed.' -f $counters['Failed'])
    }
    return ,($rows.ToArray())
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

$params = [ordered]@{
    SkipProcesses   = [bool]$SkipProcesses
    SkipServices    = [bool]$SkipServices
    SkipTasks       = [bool]$SkipTasks
    OnlyPrivileged  = [bool]$OnlyPrivileged
    OmitCommandLine = [bool]$OmitCommandLine
    MaxRows         = $MaxRows
    SummaryOnly     = [bool]$SummaryOnly
    Compress        = [bool]$Compress
    OutFile         = $OutFile
}
$ok = $true
$errorMessage = $null
$summary = $null
$rows = New-Object 'System.Collections.Generic.List[object]'

try {
    if ($SkipProcesses -and $SkipServices -and $SkipTasks) { throw 'All three sources are skipped; nothing to list.' }
    if ($MaxRows -lt 1) { throw '-MaxRows must be 1 or more.' }
    $elevatedNow = (Get-ProbeIdentity).Elevated

    $tokenSource = 'none'
    if (-not $SkipProcesses) {
        $tokenSource = 'Win32_Process.GetOwner'
        $moduleVersion = Import-ProbeModule -Name 'NtObjectManager' -Elevated $elevatedNow
        if ($moduleVersion -and (Get-Command -Name Get-NtProcess -ErrorAction SilentlyContinue) -and (Get-Command -Name Get-NtToken -ErrorAction SilentlyContinue)) {
            $tokenSource = 'NtObjectManager'
        }
        if ($tokenSource -ne 'NtObjectManager') {
            Add-Caveat 'NtObjectManager is not available: process integrity level, protection and privileges are null; the account comes from Win32_Process.GetOwner and GetOwnerSid.'
        }
    }

    $processRows = @()
    $serviceRows = @()
    $taskRows = @()
    if (-not $SkipProcesses) {
        try { $processRows = Get-ProcessRow -TokenSource $tokenSource -WithCommandLine (-not $OmitCommandLine) }
        catch { Add-Caveat ('Process listing failed: ' + $_.Exception.Message) }
    }
    if (-not $SkipServices) {
        try { $serviceRows = Get-ServiceRow -WithCommandLine (-not $OmitCommandLine) }
        catch { Add-Caveat ('Service listing failed: ' + $_.Exception.Message) }
    }
    if (-not $SkipTasks) {
        try { $taskRows = Get-TaskRow -WithCommandLine (-not $OmitCommandLine) }
        catch { Add-Caveat ('Task listing failed: ' + $_.Exception.Message) }
    }

    $counts = [ordered]@{ processes = @($processRows).Count; services = @($serviceRows).Count; tasks = @($taskRows).Count }
    if ($OnlyPrivileged) {
        $nameSet = Get-PrivilegedNameSet -LocalizedNames (Get-LocalizedPrivilegedName)
        $processRows = @($processRows | Where-Object {
            (Test-PrivilegedPrincipal -Account $_.user -Sid $_.userSid -NameSet $nameSet) -or $_.protection -or ($_.hasSeImpersonate -eq $true) -or ($_.hasSeAssignPrimaryToken -eq $true)
        })
        $serviceRows = @($serviceRows | Where-Object { Test-PrivilegedPrincipal -Account $_.account -NameSet $nameSet })
        $taskRows = @($taskRows | Where-Object { (Test-PrivilegedPrincipal -Account $_.runAs -NameSet $nameSet) -or ($_.runLevel -eq 'Highest') })
    }
    $all = @($processRows) + @($serviceRows) + @($taskRows)
    $truncated = $all.Count -gt $MaxRows
    foreach ($row in $all) {
        if ($rows.Count -ge $MaxRows) { break }
        $rows.Add($row)
    }
    if ($truncated) {
        Add-Caveat ('data[] stopped at -MaxRows {0}; {1} row(s) were left out (rows are taken in the order processes, services, tasks). summary.returned counts every row.' -f $MaxRows, ($all.Count - $MaxRows))
    }

    $protectedNames = New-Object 'System.Collections.Generic.List[string]'
    $impersonationNames = New-Object 'System.Collections.Generic.List[string]'
    foreach ($row in $processRows) {
        if ($row.protection -and -not $protectedNames.Contains($row.name)) { $protectedNames.Add($row.name) }
        if ((($row.hasSeImpersonate -eq $true) -or ($row.hasSeAssignPrimaryToken -eq $true)) -and -not $impersonationNames.Contains($row.name)) {
            $impersonationNames.Add($row.name)
        }
    }
    $protectedNames.Sort()
    $impersonationNames.Sort()
    $summary = [ordered]@{
        tokenSource                   = $tokenSource
        counts                        = $counts
        returned                      = [ordered]@{ processes = @($processRows).Count; services = @($serviceRows).Count; tasks = @($taskRows).Count }
        truncated                     = $truncated
        protectedProcesses            = $protectedNames.ToArray()
        impersonationPrivilegeHolders = $impersonationNames.ToArray()
    }
} catch {
    $ok = $false
    $errorMessage = $_.Exception.Message
}

$envelope = ConvertTo-ProbeEnvelope -Tool 'Get-PrivilegedSurfaceMap' -Params $params -Ok $ok -ErrorMessage $errorMessage -Summary $summary -Data $rows -SummaryOnly ([bool]$SummaryOnly)
Write-ProbeEnvelope -Envelope $envelope -OutFile $OutFile -Compress ([bool]$Compress)
exit (Get-ProbeExitCode -Ok $ok)
