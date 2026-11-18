#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Report the effective access of an account to files, directories, registry keys,
    services and processes (Sysinternals AccessChk), and the named pipes, devices, ALPC
    ports and object-manager entries that a token can open (NtObjectManager).

.DESCRIPTION
    Two engines:

      accesschk       -FilePath, -RegistryKey, -Service, -Process. AccessChk computes the
                      effective access of the account named by -Principal from the
                      security descriptor of each object and the groups of that account.
                      The account does not have to be logged on, and its password is not
                      needed. Each row has access R, W or RW.
      NtObjectManager -NamedPipe, -Device, -AlpcPort, -ObjectDirectory. The Get-Accessible*
                      cmdlets of the NtObjectManager module check access for a token: the
                      token of the current process, or with -ProcessId the token of that
                      process. Each row has the granted access as the cmdlet names it
                      (GrantedAccessString).

    Write-type access: W or RW for accesschk rows. For NtObjectManager rows, the IsWrite
    or IsAll flag of the result, or a granted-access name that contains Write, Append,
    Delete, GenericAll, AllAccess, Full Access, CreateObject, CreateSubDirectory,
    MapWrite, AddFile, AddSubdirectory, SetValue, CreateSubKey or CreateLink. The
    generic names (GenericWrite and the others) match through "Write" and "GenericAll".

    Default filter: accesschk rows, named pipes and object-manager entries are returned
    only with write-type access; devices and ALPC ports are returned with any access,
    because opening a device can be enough to send it IOCTLs and connecting to an ALPC
    port needs only Connect access. -IncludeReadOnly returns every row. Without
    -IncludeReadOnly, AccessChk is started with -w, so it prints only objects with write
    access.

    When AccessChk reports an error for a named target (an unknown account, a missing
    path or service, access denied), the row for that target has access and writable set
    to null and the message in "error"; summary.errors counts these rows.

    Accuracy notes:
      - When AccessChk evaluates a named account, access that is granted only through
        logon-type groups (for example INTERACTIVE) can be missed. Treat "no write access"
        as a lower bound and confirm important results with a token of that account.
      - NtObjectManager rows are for the token named in the "subject" field, not for
        -Principal. An elevated token can open objects that a standard user cannot.
      - The NtObjectManager cmdlets, their parameters and the result fields are checked
        at run time. A missing cmdlet or parameter skips that category with a caveat; it
        never falls back to a different token. These categories have not been run
        against the module for this release.

    Programs and modules. In an elevated session, AccessChk is started only from
    -AccessChkPath (PATH is not searched, because it can include folders that a standard
    user can write), and NtObjectManager is imported only from the PowerShell
    installation directory ($PSHOME) or from Program Files.

    State changes: AccessChk is started with -accepteula, which records the acceptance of
    the Sysinternals license in the registry of the current user
    (HKCU\Software\Sysinternals). By running the AccessChk categories you accept the
    Sysinternals Software License Terms:
    https://learn.microsoft.com/sysinternals/license-terms. No other change is made.
    Elevation: not required for accesschk on objects that the current user can read the
    security descriptor of. Run elevated for a complete -Service or -Process listing.

.PARAMETER Principal
    The account to evaluate with AccessChk: "user", "DOMAIN\user" or a group name.
    Required with -FilePath, -RegistryKey, -Service and -Process.

.PARAMETER FilePath
    Files or directories. A directory is checked itself; add -Recurse to also check
    everything below it. With powershell.exe -File, pass one path, or use -Command to
    pass several.

.PARAMETER RegistryKey
    Registry keys, for example HKLM\SOFTWARE\Contoso or HKLM:\SOFTWARE\Contoso. The key
    is checked itself; add -Recurse to also check its subkeys.

.PARAMETER Service
    Service names, or * for all services. With -File, pass several names as one
    comma-separated string.

.PARAMETER Process
    Check every running process (accesschk -p *).

.PARAMETER NamedPipe
    List the named pipes the token can open (Get-AccessibleNamedPipe).

.PARAMETER Device
    List the objects under \Device that the token can open (Get-AccessibleDevice).

.PARAMETER AlpcPort
    List the ALPC ports the token can connect to (Get-AccessibleAlpcPort).

.PARAMETER ObjectDirectory
    Object-manager directories to check recursively, for example "\RPC Control" or
    "\BaseNamedObjects" (Get-AccessibleObject). Object-manager names can contain commas,
    so the value is not split on commas. With powershell.exe -File, pass one directory,
    or use -Command to pass several.

.PARAMETER ProcessId
    Use the token of this process for the NtObjectManager categories. Opening the token
    of a process that runs as another account usually needs elevation.

.PARAMETER Recurse
    Also check the contents of -FilePath directories and the subkeys of -RegistryKey.

.PARAMETER IncludeReadOnly
    Return rows without write-type access as well.

.PARAMETER IncludeSddl
    Add the SDDL of each returned file, directory and registry row (Get-Acl).

.PARAMETER MaxRows
    Maximum number of data rows. Default: 5000.

.PARAMETER AccessChkPath
    Path to accesschk64.exe or accesschk.exe. Default when not elevated: the first one
    found on PATH. Required in an elevated session.

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
    summary: principal, accessChk, ntObjectManager, objectsChecked, rowsReturned,
             writableRows, rowsFilteredReadOnly, rowsDropped, truncated, errors,
             accessChkMessages, byCategory{}, caveats[]
    data[]:  category, name, objectType, subject, access, writable, error, sddl, engine

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-EffectiveAccess.ps1 -Principal "<standard-user>" -FilePath C:\ProgramData -Recurse -OutFile .\programdata-access.json

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-EffectiveAccess.ps1 -Principal "<standard-user>" -Service * -AccessChkPath "C:\Program Files\Sysinternals\accesschk64.exe"

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-EffectiveAccess.ps1 -NamedPipe -AlpcPort -ProcessId 4321
#>
[CmdletBinding()]
param(
    [string]   $Principal,
    [string[]] $FilePath,
    [string[]] $RegistryKey,
    [string[]] $Service,
    [switch]   $Process,
    [switch]   $NamedPipe,
    [switch]   $Device,
    [switch]   $AlpcPort,
    [string[]] $ObjectDirectory,
    [int]      $ProcessId = 0,
    [switch]   $Recurse,
    [switch]   $IncludeReadOnly,
    [switch]   $IncludeSddl,
    [int]      $MaxRows = 5000,
    [string]   $AccessChkPath,
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

$script:AccessRows = New-Object 'System.Collections.Generic.List[object]'
$script:ObjectsChecked = 0
$script:RowsFiltered = 0
$script:RowsDropped = 0
$script:ErrorRows = 0
$script:AccessChkMessages = 0
$script:MaxMessageCaveats = 20

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

function ConvertFrom-AccessChkOutput {
    param([string[]]$Lines)
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $messages = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $Lines) {
        if ($null -eq $line) { continue }
        $text = $line.TrimEnd()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $match = [regex]::Match($text, '^\s*(RW|R|W)\s+(\S.*)$')
        if ($match.Success) {
            $entries.Add(@{ Access = $match.Groups[1].Value; Name = $match.Groups[2].Value.Trim() })
        } else {
            $messages.Add($text.Trim())
        }
    }
    return @{ Entries = $entries.ToArray(); Messages = $messages.ToArray() }
}

function ConvertTo-AccessChkKey {
    param([string]$Key)
    $text = $Key.Trim()
    if ($text -match '^(?i)Registry::') { $text = $text.Substring(10) }
    return ($text -replace '^(HK[A-Za-z_]+):\\?', '$1\')
}

function ConvertTo-RegistryProviderPath {
    param([string]$Key)
    $hives = @{
        'HKLM' = 'HKEY_LOCAL_MACHINE'; 'HKCU' = 'HKEY_CURRENT_USER'; 'HKCR' = 'HKEY_CLASSES_ROOT'
        'HKU' = 'HKEY_USERS'; 'HKCC' = 'HKEY_CURRENT_CONFIG'
    }
    $text = ConvertTo-AccessChkKey -Key $Key
    $slash = $text.IndexOf('\')
    $rest = ''
    if ($slash -lt 0) { $hive = $text } else { $hive = $text.Substring(0, $slash); $rest = $text.Substring($slash + 1) }
    $hive = $hive.ToUpperInvariant()
    if ($hives.ContainsKey($hive)) { $hive = $hives[$hive] }
    if ($rest) { return 'Registry::' + $hive + '\' + $rest }
    return 'Registry::' + $hive
}

function Test-WriteLikeAccess {
    param([string]$Access)
    if ([string]::IsNullOrWhiteSpace($Access)) { return $false }
    return [regex]::IsMatch($Access, '(?i)write|append|delete|genericall|generic_all|allaccess|all_access|full ?access|createobject|createsubdirectory|mapwrite|addfile|addsubdirectory|setvalue|createsubkey|createlink')
}

function Invoke-AccessChk {
    param([string]$Exe, [string[]]$Arguments)
    # The command line is built with the quoting rules of the C runtime, so a value such
    # as "C:\Program Files\" reaches AccessChk unchanged in Windows PowerShell 5.1 too.
    $commandLine = Join-ArgumentList $Arguments
    Write-Verbose ('accesschk ' + $commandLine)
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Exe
    $startInfo.Arguments = $commandLine
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $startInfo.StandardOutputEncoding = [Console]::OutputEncoding
    $startInfo.StandardErrorEncoding = [Console]::OutputEncoding
    $child = [System.Diagnostics.Process]::Start($startInfo)
    try {
        $stdoutTask = $child.StandardOutput.ReadToEndAsync()
        $stderrTask = $child.StandardError.ReadToEndAsync()
        $child.WaitForExit()
        $text = $stdoutTask.Result + "`n" + $stderrTask.Result
    } finally {
        $child.Dispose()
    }
    return ,($text -split "\r?\n")
}

function Get-SddlText {
    param([string]$Category, [string]$Name)
    try {
        if ($Category -eq 'registry') { return (Get-Acl -LiteralPath (ConvertTo-RegistryProviderPath -Key $Name)).Sddl }
        if ($Category -eq 'file' -or $Category -eq 'directory') { return (Get-Acl -LiteralPath $Name).Sddl }
    } catch {
        Write-Verbose ('Get-Acl failed for {0}: {1}' -f $Name, $_.Exception.Message)
    }
    return $null
}

function Add-AccessRow {
    param([string]$Category, [string]$Name, $ObjectType, [string]$Subject, $Access, $Writable, [bool]$Keep, $ErrorText, [string]$Engine)
    if ($null -eq $ErrorText) { $script:ObjectsChecked++ }
    if (-not $Keep) { $script:RowsFiltered++; return }
    if ($script:AccessRows.Count -ge $MaxRows) {
        $script:RowsDropped++
        Add-Caveat ('data[] stopped at -MaxRows {0}; narrow the scope or raise -MaxRows.' -f $MaxRows)
        return
    }
    $rowCategory = $Category
    if ($Category -eq 'filesystem') {
        $rowCategory = 'file'
        if (Test-Path -LiteralPath $Name -PathType Container) { $rowCategory = 'directory' }
    }
    $sddl = $null
    if ($IncludeSddl -and $null -eq $ErrorText) { $sddl = Get-SddlText -Category $rowCategory -Name $Name }
    $script:AccessRows.Add([pscustomobject][ordered]@{
        category   = $rowCategory
        name       = $Name
        objectType = $ObjectType
        subject    = $Subject
        access     = $Access
        writable   = $Writable
        error      = $ErrorText
        sddl       = $sddl
        engine     = $Engine
    })
}

function Add-AccessChkMessage {
    param([string]$Target, [string]$Message)
    $script:AccessChkMessages++
    if ($script:AccessChkMessages -le $script:MaxMessageCaveats) {
        $short = $Message
        if ($short.Length -gt 200) { $short = $short.Substring(0, 200) }
        Add-Caveat ('accesschk ({0}): {1}' -f $Target, $short)
    }
}

function Add-AccessChkResult {
    param([string]$Exe, [string[]]$Switches, [string]$Target, [string]$Category, [string]$Account, [bool]$ReportTarget)
    $arguments = @('-accepteula', '-nobanner') + $Switches + @($Account, $Target)
    $parsed = ConvertFrom-AccessChkOutput -Lines (Invoke-AccessChk -Exe $Exe -Arguments $arguments)
    $errors = New-Object 'System.Collections.Generic.List[string]'
    foreach ($message in $parsed.Messages) {
        if ($message -match '^(?i)No matching objects found') { continue }
        $errors.Add($message)
        Add-AccessChkMessage -Target $Target -Message $message
    }
    foreach ($entry in $parsed.Entries) {
        $writable = ($entry.Access -match 'W')
        Add-AccessRow -Category $Category -Name $entry.Name -ObjectType $null -Subject $Account -Access $entry.Access -Writable $writable -Keep ($writable -or [bool]$IncludeReadOnly) -ErrorText $null -Engine 'accesschk'
    }
    if (-not $ReportTarget -or $parsed.Entries.Count -gt 0) { return }
    if ($errors.Count -gt 0) {
        $text = ($errors -join ' ')
        if ($text.Length -gt 300) { $text = $text.Substring(0, 300) }
        $script:ErrorRows++
        Add-AccessRow -Category $Category -Name $Target -ObjectType $null -Subject $Account -Access $null -Writable $null -Keep $true -ErrorText $text -Engine 'accesschk'
    } else {
        Add-AccessRow -Category $Category -Name $Target -ObjectType $null -Subject $Account -Access '' -Writable $false -Keep ([bool]$IncludeReadOnly) -ErrorText $null -Engine 'accesschk'
    }
}

function Test-ParameterSetSatisfied {
    param($Command, [string[]]$Supplied)
    foreach ($set in $Command.ParameterSets) {
        $missing = @($set.Parameters | Where-Object { $_.IsMandatory -and ($Supplied -notcontains $_.Name) })
        if ($missing.Count -eq 0) { return $true }
    }
    return $false
}

function ConvertFrom-NtAccessResult {
    param($InputObject)
    # Reads the fields that NtObjectManager sets on an access-check result. Returns $null
    # when IsWrite, IsAll or GrantedAccessString is missing: GrantedAccess alone is an
    # access mask, and its text form is a number, not access names.
    if ($null -eq $InputObject) { return $null }
    $properties = $InputObject.PSObject.Properties
    foreach ($required in @('IsWrite', 'IsAll', 'GrantedAccessString')) {
        if ($null -eq $properties[$required]) { return $null }
    }
    $name = $null
    foreach ($propertyName in @('FullPath', 'Name', 'Path')) {
        $value = Get-ObjectProperty $InputObject $propertyName
        if ($value) { $name = [string]$value; break }
    }
    $access = [string](Get-ObjectProperty $InputObject 'GrantedAccessString')
    $writable = ((Get-ObjectProperty $InputObject 'IsWrite') -eq $true) -or ((Get-ObjectProperty $InputObject 'IsAll') -eq $true) -or (Test-WriteLikeAccess -Access $access)
    $typeName = Get-ObjectProperty $InputObject 'TypeName'
    if ($null -ne $typeName) { $typeName = [string]$typeName }
    return @{ Name = $name; TypeName = $typeName; Access = $access; Writable = [bool]$writable }
}

function Add-NtAccessibleResult {
    param([string]$CommandName, [string]$Category, [hashtable]$Required, [hashtable]$Optional, [string]$Subject)
    $command = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
    if (-not $command) {
        Add-Caveat ('{0} is not available; {1} rows were not collected.' -f $CommandName, $Category)
        return
    }
    $splat = @{}
    foreach ($key in $Required.Keys) {
        if (-not $command.Parameters.ContainsKey($key)) {
            Add-Caveat ('{0} has no -{1} parameter in this NtObjectManager version; {2} rows were not collected.' -f $CommandName, $key, $Category)
            return
        }
        $splat[$key] = $Required[$key]
    }
    foreach ($key in $Optional.Keys) {
        if ($command.Parameters.ContainsKey($key)) { $splat[$key] = $Optional[$key] }
    }
    if ($ProcessId -gt 0) {
        if (-not $command.Parameters.ContainsKey('ProcessIds')) {
            Add-Caveat ('{0} has no -ProcessIds parameter in this NtObjectManager version; {1} rows were not collected, so that no result is reported for the wrong token.' -f $CommandName, $Category)
            return
        }
        $splat['ProcessIds'] = @($ProcessId)
    }
    if (-not (Test-ParameterSetSatisfied -Command $command -Supplied @($splat.Keys))) {
        Add-Caveat ('{0} needs parameters this tool does not supply; {1} rows were not collected.' -f $CommandName, $Category)
        return
    }
    $objects = @()
    try {
        $objects = @(& $CommandName @splat -ErrorAction Stop)
    } catch {
        Add-Caveat ('{0} failed: {1}' -f $CommandName, $_.Exception.Message)
        return
    }
    $anyAccessCounts = ($Category -eq 'device') -or ($Category -eq 'alpcPort')
    $missingFields = 0
    $unnamed = 0
    foreach ($object in $objects) {
        $result = ConvertFrom-NtAccessResult -InputObject $object
        if ($null -eq $result) { $missingFields++; continue }
        if (-not $result.Name) { $unnamed++; continue }
        $keep = $result.Writable -or $anyAccessCounts -or [bool]$IncludeReadOnly
        Add-AccessRow -Category $Category -Name $result.Name -ObjectType $result.TypeName -Subject $Subject -Access $result.Access -Writable $result.Writable -Keep $keep -ErrorText $null -Engine 'NtObjectManager'
    }
    if ($missingFields -gt 0) {
        Add-Caveat ('{0} returned {1} result(s) without the IsWrite, IsAll or GrantedAccessString property; they were skipped, because this tool does not support that NtObjectManager version.' -f $CommandName, $missingFields)
    }
    if ($unnamed -gt 0) {
        Add-Caveat ('{0} returned {1} result(s) without a name; they were skipped.' -f $CommandName, $unnamed)
    }
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

$serviceNames = Split-ProbeList $Service
$objectDirectories = ConvertTo-ProbeArray $ObjectDirectory
$filePaths = ConvertTo-ProbeArray $FilePath
$registryKeys = ConvertTo-ProbeArray $RegistryKey
$params = [ordered]@{
    Principal       = $Principal
    FilePath        = $filePaths
    RegistryKey     = $registryKeys
    Service         = $serviceNames
    Process         = [bool]$Process
    NamedPipe       = [bool]$NamedPipe
    Device          = [bool]$Device
    AlpcPort        = [bool]$AlpcPort
    ObjectDirectory = $objectDirectories
    ProcessId       = $ProcessId
    Recurse         = [bool]$Recurse
    IncludeReadOnly = [bool]$IncludeReadOnly
    IncludeSddl     = [bool]$IncludeSddl
    MaxRows         = $MaxRows
    AccessChkPath   = $AccessChkPath
    SummaryOnly     = [bool]$SummaryOnly
    Compress        = [bool]$Compress
    OutFile         = $OutFile
}
$ok = $true
$errorMessage = $null
$summary = $null
$accessChk = $null
$ntObjectManager = $null

try {
    $useAccessChk = ($filePaths.Count -gt 0) -or ($registryKeys.Count -gt 0) -or ($serviceNames.Count -gt 0) -or [bool]$Process
    $useNt = [bool]$NamedPipe -or [bool]$Device -or [bool]$AlpcPort -or ($objectDirectories.Count -gt 0)
    if (-not $useAccessChk -and -not $useNt) {
        throw 'Select at least one category: -FilePath, -RegistryKey, -Service, -Process, -NamedPipe, -Device, -AlpcPort or -ObjectDirectory.'
    }
    if ($MaxRows -lt 1) { throw '-MaxRows must be 1 or more.' }
    if ($ProcessId -lt 0) { throw '-ProcessId must be a process ID.' }
    $elevatedNow = (Get-ProbeIdentity).Elevated

    if ($useAccessChk) {
        if ([string]::IsNullOrWhiteSpace($Principal)) {
            throw '-Principal is required with -FilePath, -RegistryKey, -Service and -Process.'
        }
        if ($Principal.Trim() -match '^[-/]') { throw '-Principal must not start with "-" or "/".' }
        foreach ($target in @($filePaths) + @($registryKeys) + @($serviceNames)) {
            if (([string]$target).Trim() -match '^[-/]') { throw ('Target "{0}" must not start with "-" or "/".' -f $target) }
        }
        $tool = Resolve-ExternalTool -Explicit $AccessChkPath -Names @('accesschk64.exe', 'accesschk.exe') -FixedPaths @() -Elevated $elevatedNow
        $accessChk = $tool.Path
        if (-not $accessChk) {
            if ($AccessChkPath) { throw ('-AccessChkPath not found: {0}' -f $AccessChkPath) }
            if ($tool.PathSkipped) { throw 'This session is elevated, so the probe does not take AccessChk from PATH (PATH can include folders that a standard user can write). Pass -AccessChkPath with the full path of accesschk64.exe, in a folder that only administrators can change.' }
            throw 'accesschk64.exe or accesschk.exe was not found on PATH. Install Sysinternals AccessChk or pass -AccessChkPath.'
        }
        Add-Caveat 'AccessChk evaluates the named account from its group memberships; access granted only through logon-type groups such as INTERACTIVE can be missed, so "no write access" is a lower bound.'
        $account = $Principal.Trim()
        $writeOnly = @()
        if (-not $IncludeReadOnly) { $writeOnly = @('-w') }

        foreach ($target in $filePaths) {
            if (-not (Test-Path -LiteralPath $target)) { Add-Caveat ('Path not found, skipped: ' + $target); continue }
            if (Test-Path -LiteralPath $target -PathType Container) {
                Add-AccessChkResult -Exe $accessChk -Switches (@('-d') + $writeOnly) -Target $target -Category 'directory' -Account $account -ReportTarget $true
                if ($Recurse) {
                    Add-AccessChkResult -Exe $accessChk -Switches (@('-s') + $writeOnly) -Target $target -Category 'filesystem' -Account $account -ReportTarget $false
                }
            } else {
                Add-AccessChkResult -Exe $accessChk -Switches $writeOnly -Target $target -Category 'file' -Account $account -ReportTarget $true
            }
        }
        foreach ($key in $registryKeys) {
            $accessChkKey = ConvertTo-AccessChkKey -Key $key
            Add-AccessChkResult -Exe $accessChk -Switches (@('-k', '-d') + $writeOnly) -Target $accessChkKey -Category 'registry' -Account $account -ReportTarget $true
            if ($Recurse) {
                Add-AccessChkResult -Exe $accessChk -Switches (@('-k', '-s') + $writeOnly) -Target $accessChkKey -Category 'registry' -Account $account -ReportTarget $false
            }
        }
        foreach ($name in $serviceNames) {
            Add-AccessChkResult -Exe $accessChk -Switches (@('-c') + $writeOnly) -Target $name -Category 'service' -Account $account -ReportTarget ($name -ne '*')
        }
        if ($Process) {
            Add-AccessChkResult -Exe $accessChk -Switches (@('-p') + $writeOnly) -Target '*' -Category 'process' -Account $account -ReportTarget $false
        }
        if ($script:AccessChkMessages -gt $script:MaxMessageCaveats) {
            Add-Caveat ('AccessChk printed {0} message(s); only the first {1} are listed in caveats.' -f $script:AccessChkMessages, $script:MaxMessageCaveats)
        }
    }

    if ($useNt) {
        $subject = 'token of the current process'
        if ($ProcessId -gt 0) { $subject = ('token of PID {0}' -f $ProcessId) }
        $ntObjectManager = $null
        if (Get-Module -ListAvailable -Name NtObjectManager) {
            $ntObjectManager = Import-ProbeModule -Name 'NtObjectManager' -Elevated $elevatedNow
            if (-not $ntObjectManager) { Add-Caveat 'NtObjectManager was not imported; -NamedPipe, -Device, -AlpcPort and -ObjectDirectory were skipped.' }
        } else {
            Add-Caveat 'The NtObjectManager module is not installed; -NamedPipe, -Device, -AlpcPort and -ObjectDirectory were skipped.'
        }
        if ($ntObjectManager) {
            Add-Caveat ('NtObjectManager rows are computed for the {0}, not for -Principal.' -f $subject)
            if ($NamedPipe) { Add-NtAccessibleResult -CommandName 'Get-AccessibleNamedPipe' -Category 'namedPipe' -Required @{} -Optional @{} -Subject $subject }
            if ($Device) { Add-NtAccessibleResult -CommandName 'Get-AccessibleDevice' -Category 'device' -Required @{ Path = '\Device' } -Optional @{} -Subject $subject }
            if ($AlpcPort) { Add-NtAccessibleResult -CommandName 'Get-AccessibleAlpcPort' -Category 'alpcPort' -Required @{} -Optional @{} -Subject $subject }
            foreach ($root in $objectDirectories) {
                Add-NtAccessibleResult -CommandName 'Get-AccessibleObject' -Category 'objectManager' -Required @{ Path = $root } -Optional @{ Recurse = $true } -Subject $subject
            }
        }
    }

    $byCategory = [ordered]@{}
    $writableRows = 0
    foreach ($row in $script:AccessRows) {
        if ($row.writable -eq $true) { $writableRows++ }
        if ($byCategory.Contains($row.category)) { $byCategory[$row.category] = [int]$byCategory[$row.category] + 1 } else { $byCategory[$row.category] = 1 }
    }
    $summary = [ordered]@{
        principal            = $Principal
        accessChk            = $accessChk
        ntObjectManager      = $ntObjectManager
        objectsChecked       = $script:ObjectsChecked
        rowsReturned         = $script:AccessRows.Count
        writableRows         = $writableRows
        rowsFilteredReadOnly = $script:RowsFiltered
        rowsDropped          = $script:RowsDropped
        truncated            = ($script:RowsDropped -gt 0)
        errors               = $script:ErrorRows
        accessChkMessages    = $script:AccessChkMessages
        byCategory           = $byCategory
    }
} catch {
    $ok = $false
    $errorMessage = $_.Exception.Message
}

$envelope = ConvertTo-ProbeEnvelope -Tool 'Get-EffectiveAccess' -Params $params -Ok $ok -ErrorMessage $errorMessage -Summary $summary -Data $script:AccessRows -SummaryOnly ([bool]$SummaryOnly)
Write-ProbeEnvelope -Envelope $envelope -OutFile $OutFile -Compress ([bool]$Compress)
exit (Get-ProbeExitCode -Ok $ok)
