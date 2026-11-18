#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Map the neighborhood of one Windows component: the services that host it, the
    processes that have it loaded, the other services and modules in those processes,
    and the DLLs it imports.

.DESCRIPTION
    Given one DLL, EXE or SYS file, Get-ComponentNeighborhood emits one row per edge:

      ownerService        a service whose program (Win32_Service.PathName), service DLL
                          (Parameters\ServiceDll) or, for a .sys file, driver file
                          (Win32_SystemDriver.PathName) is the file
      ownerServiceByName  a service that names a file with the same file name at another
                          path, or in a form that the tool did not resolve
      hostProcess         a running process whose module list contains the file
      hostProcessByName   a running process that has a module with the same file name
                          loaded from another path
      coHostedService     another service that runs in a host process
      coHostedModule      another module loaded in one or more host processes (common
                          system DLLs such as ntdll.dll and kernel32.dll are left out)
      import              a DLL named in the PE import table of the file
      delayImport         a DLL named in the PE delay-load import table of the file
      stringReference     (-IncludeStringReferences) a *.dll name found in the strings of
                          the file but not in its import tables
      dependent           (-ScanDependents) a file in -SearchRoot whose bytes contain the
                          file name as a whole name, as ASCII or UTF-16LE text

    Host processes are the processes of ownerService and hostProcess rows. stringReference
    and dependent rows come from text matches. They show that a name appears in a file,
    not that the file loads or calls the component.

    Reading the module list of a process opens it with PROCESS_VM_READ. lsass.exe is left
    out unless -IncludeLsass is set, because endpoint protection products report that
    access to lsass.exe as credential theft.

    State changes: none. The tool reads service configuration, the registry, the module
    lists of running processes and files.
    Elevation: recommended. Without it, the module lists of processes that run as other
    accounts cannot be read, so hostProcess and coHostedModule rows are missing for them.
    Protected processes cannot be read even when elevated. summary.processesNotReadable
    counts the processes that could not be read.

    The output contains service command lines. -OmitCommandLine leaves them out.

.PARAMETER Component
    A full path, a relative path that contains a directory separator, or a file name that
    is looked up in -SearchRoot ("spoolsv.exe"). A file name without an extension is tried
    with .dll, .exe and .sys. Required.

.PARAMETER SearchRoot
    Directory used to resolve a bare -Component name and to look for dependents.
    Default: the System32 directory.

.PARAMETER IncludeStringReferences
    Add stringReference rows.

.PARAMETER ScanDependents
    Add dependent rows. This reads every .dll, .exe and .sys file directly in
    -SearchRoot (no subdirectories), so it is slow on System32.

.PARAMETER IncludeLsass
    Also read the module list of lsass.exe.

.PARAMETER OmitCommandLine
    Leave service command lines out of the output.

.PARAMETER MaxDependents
    Maximum number of dependent rows. Default: 100.

.PARAMETER MaxFileMB
    Files larger than this are not read, the target file included. Default: 64.

.PARAMETER MaxRows
    Maximum number of data rows; summary.edgeCounts counts every edge. Default: 5000.

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
    summary: target, targetName, machine, edgeCounts{}, hostPids[], processesNotReadable,
             truncated, caveats[]
    data[]:  relation, name, path, commandLine, account, startMode, state, pids[],
             launchProtected, evidence
    For service rows, path is the program, driver or DLL file and commandLine is the full
    Win32_Service.PathName value.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-ComponentNeighborhood.ps1 -Component spoolsv.exe -OutFile .\spooler-neighborhood.json

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Get-ComponentNeighborhood.ps1 -Component w32time.dll -IncludeStringReferences -OmitCommandLine
#>
[CmdletBinding()]
param(
    [string] $Component,
    [string] $SearchRoot = [System.Environment]::GetFolderPath('System'),
    [switch] $IncludeStringReferences,
    [switch] $ScanDependents,
    [switch] $IncludeLsass,
    [switch] $OmitCommandLine,
    [int]    $MaxDependents = 100,
    [int]    $MaxFileMB = 64,
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

function Read-ProbeFileContent {
    param([string]$FilePath)
    $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    $stream = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
    try {
        $length = [int]$stream.Length
        $buffer = New-Object byte[] $length
        $read = 0
        while ($read -lt $length) {
            $count = $stream.Read($buffer, $read, $length - $read)
            if ($count -le 0) { break }
            $read += $count
        }
        if ($read -lt $length) { [Array]::Resize([ref]$buffer, $read) }
        return ,$buffer
    } finally {
        $stream.Dispose()
    }
}

function Get-PeImageInfo {
    param([byte[]]$Bytes)
    $info = @{ IsPe = $false; Machine = $null; Magic = $null; ImageBase = $null; Sections = @(); DataDirectories = @(); Error = $null }
    try {
        if ($Bytes.Length -lt 0x40 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { $info.Error = 'no MZ header'; return $info }
        $peOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
        if ($peOffset -lt 0 -or ($peOffset + 24) -gt $Bytes.Length) { $info.Error = 'e_lfanew points outside the file'; return $info }
        if ([BitConverter]::ToUInt32($Bytes, $peOffset) -ne 0x00004550) { $info.Error = 'no PE signature'; return $info }
        $info.Machine = [int][BitConverter]::ToUInt16($Bytes, $peOffset + 4)
        $sectionCount = [int][BitConverter]::ToUInt16($Bytes, $peOffset + 6)
        $optionalSize = [int][BitConverter]::ToUInt16($Bytes, $peOffset + 20)
        $optionalOffset = $peOffset + 24
        if ($optionalSize -lt 2 -or ($optionalOffset + $optionalSize) -gt $Bytes.Length) {
            $info.Error = 'optional header extends past the end of the file'
            return $info
        }
        $info.Magic = [int][BitConverter]::ToUInt16($Bytes, $optionalOffset)
        $countOffset = -1
        if ($info.Magic -eq 0x10B) {
            if ($optionalSize -ge 32) { $info.ImageBase = [UInt64][BitConverter]::ToUInt32($Bytes, $optionalOffset + 28) }
            $countOffset = 92
        } elseif ($info.Magic -eq 0x20B) {
            if ($optionalSize -ge 32) { $info.ImageBase = [BitConverter]::ToUInt64($Bytes, $optionalOffset + 24) }
            $countOffset = 108
        }
        $directories = New-Object 'System.Collections.Generic.List[object]'
        if ($countOffset -gt 0 -and ($countOffset + 4) -le $optionalSize) {
            $declared = [int64][BitConverter]::ToUInt32($Bytes, $optionalOffset + $countOffset)
            $available = [int64][Math]::Floor(($optionalSize - ($countOffset + 4)) / 8)
            $count = [int][Math]::Min([Math]::Min($declared, $available), 16)
            for ($i = 0; $i -lt $count; $i++) {
                $entry = $optionalOffset + $countOffset + 4 + (8 * $i)
                $directories.Add(@{
                    Rva  = [int64][BitConverter]::ToUInt32($Bytes, $entry)
                    Size = [int64][BitConverter]::ToUInt32($Bytes, $entry + 4)
                })
            }
        }
        $info.DataDirectories = $directories.ToArray()
        $tableOffset = $optionalOffset + $optionalSize
        $sections = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt $sectionCount; $i++) {
            $entry = $tableOffset + (40 * $i)
            if (($entry + 40) -gt $Bytes.Length) { break }
            $sections.Add(@{
                VirtualSize    = [int64][BitConverter]::ToUInt32($Bytes, $entry + 8)
                VirtualAddress = [int64][BitConverter]::ToUInt32($Bytes, $entry + 12)
                RawSize        = [int64][BitConverter]::ToUInt32($Bytes, $entry + 16)
                RawPointer     = [int64][BitConverter]::ToUInt32($Bytes, $entry + 20)
            })
        }
        $info.Sections = $sections.ToArray()
        $info.IsPe = $true
    } catch {
        $info.Error = $_.Exception.Message
    }
    return $info
}

function ConvertTo-FileOffset {
    param($Sections, [int64]$Rva)
    foreach ($section in $Sections) {
        $span = [Math]::Max($section.VirtualSize, $section.RawSize)
        if ($Rva -ge $section.VirtualAddress -and $Rva -lt ($section.VirtualAddress + $span)) {
            $delta = $Rva - $section.VirtualAddress
            if ($delta -ge $section.RawSize) { return [int64]-1 }
            return [int64]($section.RawPointer + $delta)
        }
    }
    return [int64]-1
}

function Read-AsciiZ {
    param([byte[]]$Bytes, [int64]$Offset, [int]$MaxLength = 260)
    if ($Offset -lt 0 -or $Offset -ge $Bytes.Length) { return $null }
    $end = $Offset
    while ($end -lt $Bytes.Length -and ($end - $Offset) -lt $MaxLength -and $Bytes[$end] -ne 0) { $end++ }
    if ($end -eq $Offset) { return $null }
    return [System.Text.Encoding]::ASCII.GetString($Bytes, [int]$Offset, [int]($end - $Offset))
}

function Get-PeImportList {
    param([byte[]]$Bytes)
    $result = @{ Machine = $null; Imports = @(); DelayImports = @(); Error = $null }
    $info = Get-PeImageInfo -Bytes $Bytes
    $result.Machine = $info.Machine
    if (-not $info.IsPe) { $result.Error = $info.Error; return $result }
    $imports = New-Object 'System.Collections.Generic.List[string]'
    $delayImports = New-Object 'System.Collections.Generic.List[string]'
    if ($info.DataDirectories.Count -gt 1 -and $info.DataDirectories[1].Rva -gt 0) {
        $offset = ConvertTo-FileOffset -Sections $info.Sections -Rva $info.DataDirectories[1].Rva
        $guard = 0
        while ($offset -ge 0 -and ($offset + 20) -le $Bytes.Length -and $guard -lt 4096) {
            $lookup = [BitConverter]::ToUInt32($Bytes, [int]$offset)
            $nameRva = [BitConverter]::ToUInt32($Bytes, [int]$offset + 12)
            $thunk = [BitConverter]::ToUInt32($Bytes, [int]$offset + 16)
            if ($lookup -eq 0 -and $nameRva -eq 0 -and $thunk -eq 0) { break }
            $name = Read-AsciiZ -Bytes $Bytes -Offset (ConvertTo-FileOffset -Sections $info.Sections -Rva $nameRva)
            if ($name -and -not $imports.Contains($name)) { $imports.Add($name) }
            $offset += 20
            $guard++
        }
    }
    if ($info.DataDirectories.Count -gt 13 -and $info.DataDirectories[13].Rva -gt 0) {
        $offset = ConvertTo-FileOffset -Sections $info.Sections -Rva $info.DataDirectories[13].Rva
        $guard = 0
        while ($offset -ge 0 -and ($offset + 32) -le $Bytes.Length -and $guard -lt 4096) {
            $attributes = [BitConverter]::ToUInt32($Bytes, [int]$offset)
            $nameField = [int64][BitConverter]::ToUInt32($Bytes, [int]$offset + 4)
            if ($nameField -eq 0) { break }
            $nameRva = $nameField
            if ((($attributes -band 1) -eq 0) -and ($null -ne $info.ImageBase) -and ($nameField -ge [int64]$info.ImageBase)) {
                $nameRva = $nameField - [int64]$info.ImageBase
            }
            $name = Read-AsciiZ -Bytes $Bytes -Offset (ConvertTo-FileOffset -Sections $info.Sections -Rva $nameRva)
            if ($name -and -not $delayImports.Contains($name)) { $delayImports.Add($name) }
            $offset += 32
            $guard++
        }
    }
    $result.Imports = $imports.ToArray()
    $result.DelayImports = $delayImports.ToArray()
    return $result
}

function Test-ReferencesBasename {
    param([string]$Text, [string]$Basename)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Basename)) { return $false }
    $pattern = '(?i)(^|[\\/"\s=])' + [regex]::Escape($Basename) + '($|["\s,;])'
    return [regex]::IsMatch($Text, $pattern)
}

function Get-ServiceProgramPath {
    param([string]$PathName)
    # The program, driver or DLL part of a service value, as a full path: \SystemRoot\,
    # \??\ and relative driver paths are resolved, and an unquoted path with spaces is cut
    # after the first ".exe", ".sys" or ".dll" that ends a word.
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $text = [System.Environment]::ExpandEnvironmentVariables($PathName.Trim())
    if ($text.StartsWith('"')) {
        $close = $text.IndexOf('"', 1)
        if ($close -gt 1) { $text = $text.Substring(1, $close - 1) } else { $text = $text.Trim('"') }
    } else {
        $match = [regex]::Match($text, '(?i)^(.+?\.(exe|sys|dll))(\s|$)')
        if ($match.Success) { $text = $match.Groups[1].Value }
    }
    $windows = [System.Environment]::GetFolderPath('Windows')
    if ($text.StartsWith('\SystemRoot\', [System.StringComparison]::OrdinalIgnoreCase)) { return $windows + '\' + $text.Substring(12) }
    if ($text.StartsWith('\??\')) { return $text.Substring(4) }
    if ($text -notmatch '^[A-Za-z]:\\' -and -not $text.StartsWith('\\')) { return $windows + '\' + $text }
    return $text
}

function Get-ServiceImageMatch {
    param([string]$PathName, [string]$TargetPath, [string]$TargetName)
    # 'path' when the value names the target file by its full path, 'name' when it names
    # only a file with the same file name, $null otherwise.
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $program = Get-ServiceProgramPath -PathName $PathName
    if ($program -and ($program -ieq $TargetPath)) { return 'path' }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($PathName)
    $pattern = '(?i)(^|[\s"=,])' + [regex]::Escape($TargetPath) + '($|[\s",;])'
    if ([regex]::IsMatch($expanded, $pattern)) { return 'path' }
    if (Test-ReferencesBasename -Text $expanded -Basename $TargetName) { return 'name' }
    return $null
}

function Resolve-ComponentPath {
    param([string]$Name, [string]$Root)
    # A rooted path, or a path with a directory separator, is used as given. A bare file
    # name is looked up in $Root only, never in the current directory.
    if ([System.IO.Path]::IsPathRooted($Name) -or $Name.Contains('\') -or $Name.Contains('/')) {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Name)
        if (Test-Path -LiteralPath $full -PathType Leaf) { return (Get-Item -LiteralPath $full -Force).FullName }
        return $null
    }
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    $candidates.Add($Name)
    if (-not [System.IO.Path]::HasExtension($Name)) {
        foreach ($extension in @('.dll', '.exe', '.sys')) { $candidates.Add($Name + $extension) }
    }
    foreach ($candidate in $candidates) {
        $full = Join-Path $Root $candidate
        if (Test-Path -LiteralPath $full -PathType Leaf) { return (Get-Item -LiteralPath $full -Force).FullName }
    }
    return $null
}

function Get-ProcessModuleList {
    param($Process)
    # get_Modules() is called as a method on purpose: PowerShell returns $null when a
    # property getter throws, so reading .Modules would hide an access-denied error.
    try {
        return @{ Modules = @($Process.get_Modules()); Readable = $true }
    } catch {
        return @{ Modules = @(); Readable = $false }
    }
}

function Get-NameNeedlePattern {
    param([string]$Name)
    # The file name as a whole name, as ASCII and as UTF-16LE text on a Latin-1 view of
    # the bytes: "svc.dll" matches "C:\x\svc.dll" and "svc.dll" but not "mysvc.dll".
    $ascii = '(?<![A-Za-z0-9_.\-])' + [regex]::Escape($Name) + '(?![A-Za-z0-9_])'
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('(?<![A-Za-z0-9_.\-]\x00)')
    foreach ($character in $Name.ToCharArray()) {
        [void]$builder.Append([regex]::Escape([string]$character))
        [void]$builder.Append('\x00')
    }
    [void]$builder.Append('(?![A-Za-z0-9_]\x00)')
    return @{ Ascii = $ascii; Wide = $builder.ToString() }
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

function ConvertTo-EdgeRow {
    param([string]$Relation, [string]$Name, $Path, $CommandLine, $Account, $StartMode, $State, $Pids, $LaunchProtected, [string]$Evidence)
    return [pscustomobject][ordered]@{
        relation        = $Relation
        name            = $Name
        path            = $Path
        commandLine     = $CommandLine
        account         = $Account
        startMode       = $StartMode
        state           = $State
        pids            = (ConvertTo-ProbeArray $Pids)
        launchProtected = $LaunchProtected
        evidence        = $Evidence
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

$params = [ordered]@{
    Component               = $Component
    SearchRoot              = $SearchRoot
    IncludeStringReferences = [bool]$IncludeStringReferences
    ScanDependents          = [bool]$ScanDependents
    IncludeLsass            = [bool]$IncludeLsass
    OmitCommandLine         = [bool]$OmitCommandLine
    MaxDependents           = $MaxDependents
    MaxFileMB               = $MaxFileMB
    MaxRows                 = $MaxRows
    SummaryOnly             = [bool]$SummaryOnly
    Compress                = [bool]$Compress
    OutFile                 = $OutFile
}
$ok = $true
$errorMessage = $null
$summary = $null
$rows = New-Object 'System.Collections.Generic.List[object]'
$baseModules = '^(ntdll|kernel32|kernelbase|user32|win32u|gdi32|gdi32full|advapi32|sechost|msvcrt|msvcp_win|ucrtbase|combase|ole32|oleaut32|rpcrt4|bcrypt|bcryptprimitives|crypt32|wintrust|shcore|shlwapi|imm32|clbcatq|cfgmgr32|ws2_32|cryptbase|sspicli|kernel\.appcore|powrprof|umpdc|profapi|msasn1|wldp)\.dll$'

try {
    if ([string]::IsNullOrWhiteSpace($Component)) { throw '-Component is required: a file path, or a file name in -SearchRoot.' }
    if ($MaxDependents -lt 1 -or $MaxFileMB -lt 1 -or $MaxRows -lt 1) { throw '-MaxDependents, -MaxFileMB and -MaxRows must be 1 or more.' }
    $targetPath = Resolve-ComponentPath -Name $Component -Root $SearchRoot
    if (-not $targetPath) { throw ('Could not resolve -Component "{0}" to a file (a bare name is looked up in "{1}"). Pass a full path.' -f $Component, $SearchRoot) }
    $targetName = [System.IO.Path]::GetFileName($targetPath)
    $maxBytes = [int64]$MaxFileMB * 1MB

    $services = @()
    try {
        $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    } catch {
        Add-Caveat ('Win32_Service query failed: ' + $_.Exception.Message)
    }

    $ownerNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $hostPids = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($service in $services) {
        $pathName = [string]$service.PathName
        $match = Get-ServiceImageMatch -PathName $pathName -TargetPath $targetPath -TargetName $targetName
        $source = 'Win32_Service.PathName'
        if ($match -ne 'path') {
            $serviceDll = [string](Get-ServiceRegistryValue -ServiceName $service.Name -SubKey 'Parameters' -ValueName 'ServiceDll')
            $dllMatch = Get-ServiceImageMatch -PathName $serviceDll -TargetPath $targetPath -TargetName $targetName
            if ($dllMatch -eq 'path' -or ($dllMatch -eq 'name' -and -not $match)) {
                $match = $dllMatch
                $source = 'Parameters\ServiceDll'
            }
        }
        if (-not $match) { continue }
        $servicePid = $null
        if ($service.ProcessId -gt 0) { $servicePid = [int]$service.ProcessId }
        $commandLine = $null
        if (-not $OmitCommandLine) { $commandLine = $pathName }
        $protected = ConvertTo-LaunchProtectedName (Get-ServiceRegistryValue -ServiceName $service.Name -SubKey '' -ValueName 'LaunchProtected')
        if ($match -eq 'path') {
            [void]$ownerNames.Add($service.Name)
            if ($null -ne $servicePid) { [void]$hostPids.Add($servicePid) }
            $rows.Add((ConvertTo-EdgeRow -Relation 'ownerService' -Name $service.Name -Path (Get-ServiceProgramPath -PathName $pathName) -CommandLine $commandLine -Account $service.StartName -StartMode $service.StartMode -State $service.State -Pids @($servicePid) -LaunchProtected $protected -Evidence ($source + ' names the file')))
        } else {
            $rows.Add((ConvertTo-EdgeRow -Relation 'ownerServiceByName' -Name $service.Name -Path (Get-ServiceProgramPath -PathName $pathName) -CommandLine $commandLine -Account $service.StartName -StartMode $service.StartMode -State $service.State -Pids @($servicePid) -LaunchProtected $protected -Evidence ($source + ' names a file with the same file name at another path, or in a form that was not resolved')))
        }
    }

    if ([System.IO.Path]::GetExtension($targetPath) -ieq '.sys') {
        $drivers = @()
        try {
            $drivers = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop)
        } catch {
            Add-Caveat ('Win32_SystemDriver query failed: ' + $_.Exception.Message)
        }
        foreach ($driver in $drivers) {
            $pathName = [string]$driver.PathName
            $match = Get-ServiceImageMatch -PathName $pathName -TargetPath $targetPath -TargetName $targetName
            if (-not $match) { continue }
            $commandLine = $null
            if (-not $OmitCommandLine) { $commandLine = $pathName }
            $relation = 'ownerService'
            $evidence = 'Win32_SystemDriver.PathName names the file'
            if ($match -eq 'name') {
                $relation = 'ownerServiceByName'
                $evidence = 'Win32_SystemDriver.PathName names a file with the same file name at another path, or in a form that was not resolved'
            } else {
                [void]$ownerNames.Add($driver.Name)
            }
            $rows.Add((ConvertTo-EdgeRow -Relation $relation -Name $driver.Name -Path (Get-ServiceProgramPath -PathName $pathName) -CommandLine $commandLine -Account $driver.StartName -StartMode $driver.StartMode -State $driver.State -Pids @() -LaunchProtected $null -Evidence $evidence))
        }
    }

    $processes = @(Get-Process -ErrorAction SilentlyContinue)
    $notReadable = 0
    $lsassSkipped = $false
    $moduleCache = @{}
    foreach ($process in $processes) {
        if ($process.Id -eq 0 -or $process.Id -eq 4) { continue }
        if (-not $IncludeLsass -and ($process.ProcessName -ieq 'lsass')) { $lsassSkipped = $true; continue }
        $list = Get-ProcessModuleList -Process $process
        if (-not $list.Readable) { $notReadable++; continue }
        $moduleCache[[int]$process.Id] = $list.Modules
        $pathMatch = $false
        $sameName = $null
        foreach ($module in $list.Modules) {
            if ($null -eq $module) { continue }
            $moduleName = [string]$module.ModuleName
            if (-not $moduleName -or ($moduleName -ine $targetName)) { continue }
            if ([string]$module.FileName -ieq $targetPath) { $pathMatch = $true; break }
            if (-not $sameName) { $sameName = [string]$module.FileName }
        }
        if (-not $pathMatch -and -not $sameName) { continue }
        $processPath = $null
        try { $processPath = $process.Path } catch { Write-Verbose ('no path for PID ' + $process.Id) }
        if ($pathMatch) {
            [void]$hostPids.Add([int]$process.Id)
            $rows.Add((ConvertTo-EdgeRow -Relation 'hostProcess' -Name $process.ProcessName -Path $processPath -CommandLine $null -Account $null -StartMode $null -State $null -Pids @([int]$process.Id) -LaunchProtected $null -Evidence 'the module list of the process contains the file'))
        } else {
            $rows.Add((ConvertTo-EdgeRow -Relation 'hostProcessByName' -Name $process.ProcessName -Path $processPath -CommandLine $null -Account $null -StartMode $null -State $null -Pids @([int]$process.Id) -LaunchProtected $null -Evidence ('the module list of the process contains {0}, which has the same file name' -f $sameName)))
        }
    }
    if ($notReadable -gt 0) {
        Add-Caveat ('The module lists of {0} process(es) could not be read. Without elevation, processes of other accounts cannot be read; protected processes cannot be read even when elevated.' -f $notReadable)
    }
    if ($lsassSkipped) {
        Add-Caveat 'lsass.exe was not read, because reading its module list opens it with PROCESS_VM_READ, which endpoint protection reports as credential theft. Pass -IncludeLsass to read it; a component loaded only in lsass.exe has no hostProcess row without it.'
    }
    Add-Caveat 'For 32-bit (WOW64) processes, a module list read from 64-bit PowerShell can omit 32-bit modules.'

    foreach ($service in $services) {
        if ($service.ProcessId -le 0) { continue }
        if (-not $hostPids.Contains([int]$service.ProcessId)) { continue }
        if ($ownerNames.Contains($service.Name)) { continue }
        $pathName = [string]$service.PathName
        $commandLine = $null
        if (-not $OmitCommandLine) { $commandLine = $pathName }
        $protected = ConvertTo-LaunchProtectedName (Get-ServiceRegistryValue -ServiceName $service.Name -SubKey '' -ValueName 'LaunchProtected')
        $rows.Add((ConvertTo-EdgeRow -Relation 'coHostedService' -Name $service.Name -Path (Get-ServiceProgramPath -PathName $pathName) -CommandLine $commandLine -Account $service.StartName -StartMode $service.StartMode -State $service.State -Pids @([int]$service.ProcessId) -LaunchProtected $protected -Evidence ('runs in host PID {0}' -f $service.ProcessId)))
    }

    $moduleRows = [ordered]@{}
    foreach ($hostPid in @($hostPids | Sort-Object)) {
        if (-not $moduleCache.ContainsKey($hostPid)) { continue }
        foreach ($module in $moduleCache[$hostPid]) {
            if ($null -eq $module) { continue }
            $moduleName = [string]$module.ModuleName
            if (-not $moduleName -or ($moduleName -ieq $targetName)) { continue }
            if ($moduleName -match $baseModules) { continue }
            $modulePath = [string]$module.FileName
            $key = $modulePath.ToLowerInvariant()
            if (-not $key) { $key = $moduleName.ToLowerInvariant() }
            if (-not $moduleRows.Contains($key)) {
                $moduleRows[$key] = @{ Name = $moduleName; Path = $modulePath; Pids = New-Object 'System.Collections.Generic.List[int]' }
            }
            if (-not $moduleRows[$key].Pids.Contains($hostPid)) { $moduleRows[$key].Pids.Add($hostPid) }
        }
    }
    foreach ($key in $moduleRows.Keys) {
        $entry = $moduleRows[$key]
        $rows.Add((ConvertTo-EdgeRow -Relation 'coHostedModule' -Name $entry.Name -Path $entry.Path -CommandLine $null -Account $null -StartMode $null -State $null -Pids $entry.Pids.ToArray() -LaunchProtected $null -Evidence ('loaded in {0} host process(es)' -f $entry.Pids.Count)))
    }

    $targetBytes = $null
    $importInfo = @{ Machine = $null; Imports = @(); DelayImports = @(); Error = $null }
    if ((Get-Item -LiteralPath $targetPath -Force).Length -gt $maxBytes) {
        Add-Caveat ('The target file is larger than -MaxFileMB {0}; its import tables and strings were not read.' -f $MaxFileMB)
    } else {
        $targetBytes = Read-ProbeFileContent -FilePath $targetPath
        $importInfo = Get-PeImportList -Bytes $targetBytes
        if ($importInfo.Error) { Add-Caveat ('Import tables not read: ' + $importInfo.Error) }
    }
    foreach ($name in $importInfo.Imports) {
        $rows.Add((ConvertTo-EdgeRow -Relation 'import' -Name $name -Path $null -CommandLine $null -Account $null -StartMode $null -State $null -Pids @() -LaunchProtected $null -Evidence 'PE import table'))
    }
    foreach ($name in $importInfo.DelayImports) {
        $rows.Add((ConvertTo-EdgeRow -Relation 'delayImport' -Name $name -Path $null -CommandLine $null -Account $null -StartMode $null -State $null -Pids @() -LaunchProtected $null -Evidence 'PE delay-load import table'))
    }

    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    if ($IncludeStringReferences -and $null -ne $targetBytes) {
        $text = $latin1.GetString($targetBytes)
        $known = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $importInfo.Imports) { [void]$known.Add($name) }
        foreach ($name in $importInfo.DelayImports) { [void]$known.Add($name) }
        [void]$known.Add($targetName)
        $ascii = New-Object System.Text.RegularExpressions.Regex('[A-Za-z0-9_.\-]{1,120}\.dll(?![A-Za-z0-9_])', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $wide = New-Object System.Text.RegularExpressions.Regex('(?:[A-Za-z0-9_.\-]\x00){1,120}\.\x00[dD]\x00[lL]\x00[lL]\x00', [System.Text.RegularExpressions.RegexOptions]::None)
        $found = New-Object 'System.Collections.Generic.List[string]'
        foreach ($match in $ascii.Matches($text)) { $found.Add($match.Value) }
        foreach ($match in $wide.Matches($text)) { $found.Add($match.Value.Replace([string][char]0, '')) }
        foreach ($name in $found) {
            if ($known.Add($name)) {
                $rows.Add((ConvertTo-EdgeRow -Relation 'stringReference' -Name $name -Path $null -CommandLine $null -Account $null -StartMode $null -State $null -Pids @() -LaunchProtected $null -Evidence 'name appears in the strings of the file'))
            }
        }
    }

    if ($ScanDependents) {
        if (-not (Test-Path -LiteralPath $SearchRoot -PathType Container)) {
            Add-Caveat ('-ScanDependents skipped: -SearchRoot is not a directory: ' + $SearchRoot)
        } else {
            $needles = Get-NameNeedlePattern -Name $targetName
            $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
            $asciiNeedle = New-Object System.Text.RegularExpressions.Regex($needles.Ascii, $options)
            $wideNeedle = New-Object System.Text.RegularExpressions.Regex($needles.Wide, $options)
            $dependents = 0
            $unreadable = 0
            $candidates = @(Get-ChildItem -LiteralPath $SearchRoot -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -match '^\.(dll|exe|sys)$' })
            foreach ($candidate in $candidates) {
                if ($candidate.FullName -ieq $targetPath) { continue }
                if ($candidate.Length -gt $maxBytes) { continue }
                try {
                    $candidateText = $latin1.GetString((Read-ProbeFileContent -FilePath $candidate.FullName))
                } catch {
                    $unreadable++
                    continue
                }
                $how = $null
                if ($asciiNeedle.IsMatch($candidateText)) { $how = 'ASCII' } elseif ($wideNeedle.IsMatch($candidateText)) { $how = 'UTF-16LE' }
                if ($null -eq $how) { continue }
                if ($dependents -ge $MaxDependents) {
                    Add-Caveat ('Dependent scan stopped at -MaxDependents {0}; more files name the component.' -f $MaxDependents)
                    break
                }
                $rows.Add((ConvertTo-EdgeRow -Relation 'dependent' -Name $candidate.Name -Path $candidate.FullName -CommandLine $null -Account $null -StartMode $null -State $null -Pids @() -LaunchProtected $null -Evidence ('file name found in the bytes of the file ({0})' -f $how)))
                $dependents++
            }
            if ($unreadable -gt 0) { Add-Caveat ('Dependent scan: {0} file(s) could not be read.' -f $unreadable) }
        }
    }

    $edgeCounts = [ordered]@{}
    foreach ($relation in @('ownerService', 'ownerServiceByName', 'hostProcess', 'hostProcessByName', 'coHostedService', 'coHostedModule', 'import', 'delayImport', 'stringReference', 'dependent')) {
        $edgeCounts[$relation] = @($rows | Where-Object { $_.relation -eq $relation }).Count
    }
    $truncated = $rows.Count -gt $MaxRows
    if ($truncated) {
        Add-Caveat ('data[] stopped at -MaxRows {0}; {1} row(s) were left out. summary.edgeCounts counts every edge.' -f $MaxRows, ($rows.Count - $MaxRows))
        $rows.RemoveRange($MaxRows, $rows.Count - $MaxRows)
    }
    $pidList = New-Object 'System.Collections.Generic.List[int]'
    foreach ($hostPid in $hostPids) { $pidList.Add($hostPid) }
    $pidList.Sort()
    $machineName = $null
    switch ($importInfo.Machine) {
        0x014C { $machineName = 'x86' }
        0x8664 { $machineName = 'x64' }
        0xAA64 { $machineName = 'arm64' }
        default { if ($null -ne $importInfo.Machine) { $machineName = ('0x{0:X4}' -f $importInfo.Machine) } }
    }
    $summary = [ordered]@{
        target               = $targetPath
        targetName           = $targetName
        machine              = $machineName
        edgeCounts           = $edgeCounts
        hostPids             = $pidList.ToArray()
        processesNotReadable = $notReadable
        truncated            = $truncated
    }
} catch {
    $ok = $false
    $errorMessage = $_.Exception.Message
}

$envelope = ConvertTo-ProbeEnvelope -Tool 'Get-ComponentNeighborhood' -Params $params -Ok $ok -ErrorMessage $errorMessage -Summary $summary -Data $rows -SummaryOnly ([bool]$SummaryOnly)
Write-ProbeEnvelope -Envelope $envelope -OutFile $OutFile -Compress ([bool]$Compress)
exit (Get-ProbeExitCode -Ok $ok)
