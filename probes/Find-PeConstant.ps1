#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Search PE files for a constant or a byte pattern. Report each hit with its file
    offset, RVA, virtual address and section.

.DESCRIPTION
    Find-PeConstant reads each file and searches its bytes for a needle:

      -Constant '0x1234ABCD'   the little-endian bytes of the value at -Width (2, 4 or 8)
      -Pattern '48 8B ?? 24'   literal hex bytes; "??" matches any one byte

    Each hit is mapped through the PE section table:

      rva = section.VirtualAddress + (fileOffset - section.PointerToRawData)
      va  = ImageBase (from the optional header) + rva

    A hit outside the raw data of every section (for example in the headers) has rva, va
    and section set to null. "mapped" is false when the hit is inside the raw data of a
    section but past its VirtualSize, so the loader does not map those bytes.

    The search runs the .NET regular expression engine on a Latin-1 view of the bytes
    (one character per byte), so it needs no compiler and no external tool. Hits do not
    overlap: after a hit, the search continues after the end of that hit.

    State changes: none. The tool only reads files.
    Elevation: not required. Files that the current user cannot read are counted in
    summary.filesUnreadable.

    A hit is a place to look in a disassembler. It does not show that the bytes are used
    as the value that you searched for.

.PARAMETER Path
    A file or a directory. Required.

.PARAMETER Filter
    File-name wildcards used when -Path is a directory. Default: *.dll, *.exe, *.sys.
    With powershell.exe -File, pass several values as one comma-separated string.

.PARAMETER Recurse
    Also search the subdirectories of -Path.

.PARAMETER Constant
    A hexadecimal value as text, with or without the 0x prefix. Use exactly one of
    -Constant and -Pattern. Quote the value when you call the probe from PowerShell
    (-Constant '0x1234ABCD'): PowerShell turns an unquoted 0x literal into a number, and
    the probe rejects a number because its digits would be read as decimal.

.PARAMETER Width
    Byte width of -Constant: 2, 4 or 8. Default: 4.

.PARAMETER Pattern
    Space-separated hex bytes. "??" (or "?") matches any byte. At least one byte must
    be fixed.

.PARAMETER Context
    Number of context bytes reported around each hit, split before and after it.
    Default: 16.

.PARAMETER MaxHitsPerFile
    Stop searching a file after this many hits. Default: 64.

.PARAMETER MaxRows
    Stop the whole run after this many hits (data rows). Default: 5000.

.PARAMETER MaxFiles
    Search at most this many files. Default: 2000.

.PARAMETER MaxFileMB
    Skip files larger than this many megabytes. Default: 64.

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
    summary: needle, needleLength, filesConsidered, filesScanned, filesSkippedTooLarge,
             filesUnreadable, filesNotPe, filesWithHits, hitFiles[], totalHits, truncated,
             caveats[]
    data[]:  file, fileOffset, rva, va, section, sectionExecutable, mapped, contextHex
    fileOffset, rva and va are hex strings such as "0x1A2B". truncated is true when
    -MaxRows or -MaxFiles cut the result.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Find-PeConstant.ps1 -Path C:\Windows\System32\ntdll.dll -Constant "0xC0000022"

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Find-PeConstant.ps1 -Path C:\Windows\System32 -Pattern "48 8B ?? 24" -MaxHitsPerFile 5 -OutFile .\hits.json
#>
[CmdletBinding()]
param(
    [string]   $Path,
    [string[]] $Filter = @('*.dll', '*.exe', '*.sys'),
    [switch]   $Recurse,
    [object]   $Constant,
    [int]      $Width = 4,
    [string]   $Pattern,
    [int]      $Context = 16,
    [int]      $MaxHitsPerFile = 64,
    [int]      $MaxRows = 5000,
    [int]      $MaxFiles = 2000,
    [int]      $MaxFileMB = 64,
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

function Get-ProbeFileList {
    param([string]$Root, [string[]]$Patterns, [bool]$Descend)
    $item = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) { return ,@($item) }
    $listErrors = $null
    $children = Get-ChildItem -LiteralPath $Root -File -Force -Recurse:$Descend -ErrorAction SilentlyContinue -ErrorVariable listErrors
    if ($listErrors -and @($listErrors).Count -gt 0) {
        Add-Caveat ('{0} item(s) under -Path could not be listed (access denied or removed during the scan).' -f @($listErrors).Count)
    }
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($child in $children) {
        foreach ($pattern in $Patterns) {
            if ($child.Name -like $pattern) { $list.Add($child); break }
        }
    }
    return ,($list.ToArray())
}

function Get-PeLayout {
    param([byte[]]$Bytes)
    $layout = @{ IsPe = $false; Machine = $null; Magic = $null; ImageBase = $null; Sections = @(); Error = $null }
    try {
        if ($Bytes.Length -lt 0x40 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) {
            $layout.Error = 'no MZ header'
            return $layout
        }
        $peOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
        if ($peOffset -lt 0 -or ($peOffset + 24) -gt $Bytes.Length) {
            $layout.Error = 'e_lfanew points outside the file'
            return $layout
        }
        if ([BitConverter]::ToUInt32($Bytes, $peOffset) -ne 0x00004550) {
            $layout.Error = 'no PE signature'
            return $layout
        }
        $layout.Machine = [int][BitConverter]::ToUInt16($Bytes, $peOffset + 4)
        $sectionCount = [int][BitConverter]::ToUInt16($Bytes, $peOffset + 6)
        $optionalSize = [int][BitConverter]::ToUInt16($Bytes, $peOffset + 20)
        $optionalOffset = $peOffset + 24
        if (($optionalOffset + $optionalSize) -gt $Bytes.Length) {
            $layout.Error = 'optional header extends past the end of the file'
            return $layout
        }
        if ($optionalSize -ge 32) {
            $layout.Magic = [int][BitConverter]::ToUInt16($Bytes, $optionalOffset)
            if ($layout.Magic -eq 0x10B) {
                $layout.ImageBase = [UInt64][BitConverter]::ToUInt32($Bytes, $optionalOffset + 28)
            } elseif ($layout.Magic -eq 0x20B) {
                $layout.ImageBase = [BitConverter]::ToUInt64($Bytes, $optionalOffset + 24)
            }
        }
        $tableOffset = $optionalOffset + $optionalSize
        $sections = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt $sectionCount; $i++) {
            $entry = $tableOffset + (40 * $i)
            if (($entry + 40) -gt $Bytes.Length) { break }
            $nameLength = 0
            while ($nameLength -lt 8 -and $Bytes[$entry + $nameLength] -ne 0) { $nameLength++ }
            $characteristics = [int64][BitConverter]::ToUInt32($Bytes, $entry + 36)
            $sections.Add([pscustomobject]@{
                Name            = [System.Text.Encoding]::ASCII.GetString($Bytes, $entry, $nameLength)
                VirtualSize     = [int64][BitConverter]::ToUInt32($Bytes, $entry + 8)
                VirtualAddress  = [int64][BitConverter]::ToUInt32($Bytes, $entry + 12)
                RawSize         = [int64][BitConverter]::ToUInt32($Bytes, $entry + 16)
                RawPointer      = [int64][BitConverter]::ToUInt32($Bytes, $entry + 20)
                Executable      = ((($characteristics -band 0x20000000) -ne 0) -or (($characteristics -band 0x20) -ne 0))
            })
        }
        $layout.Sections = $sections.ToArray()
        $layout.IsPe = $true
    } catch {
        $layout.Error = $_.Exception.Message
    }
    return $layout
}

function Get-HitLocation {
    param($Layout, [int64]$Offset)
    $location = @{ Rva = $null; Va = $null; Section = $null; Executable = $null; Mapped = $null }
    if (-not $Layout.IsPe) { return $location }
    foreach ($section in $Layout.Sections) {
        if ($section.RawSize -le 0) { continue }
        if ($Offset -ge $section.RawPointer -and $Offset -lt ($section.RawPointer + $section.RawSize)) {
            $delta = $Offset - $section.RawPointer
            $rva = $section.VirtualAddress + $delta
            $location.Rva = ('0x{0:X}' -f $rva)
            if ($null -ne $Layout.ImageBase) {
                $location.Va = ('0x{0:X}' -f ([UInt64]$Layout.ImageBase + [UInt64]$rva))
            }
            $location.Section = $section.Name
            $location.Executable = [bool]$section.Executable
            $location.Mapped = (($section.VirtualSize -eq 0) -or ($delta -lt $section.VirtualSize))
            break
        }
    }
    return $location
}

function ConvertTo-NeedleSpec {
    param([string]$ConstantText, [int]$ByteWidth, [string]$PatternText)
    $haveConstant = -not [string]::IsNullOrWhiteSpace($ConstantText)
    $havePattern = -not [string]::IsNullOrWhiteSpace($PatternText)
    if ($haveConstant -eq $havePattern) { throw 'Use exactly one of -Constant and -Pattern.' }
    $tokens = New-Object 'System.Collections.Generic.List[int]'
    if ($haveConstant) {
        if (@(2, 4, 8) -notcontains $ByteWidth) { throw ('-Width must be 2, 4 or 8 (got {0}).' -f $ByteWidth) }
        $hex = $ConstantText.Trim()
        if ($hex -match '^0[xX]') { $hex = $hex.Substring(2) }
        if ($hex -notmatch '^[0-9A-Fa-f]{1,16}$') {
            throw ('-Constant "{0}" is not a hexadecimal value of at most 16 digits.' -f $ConstantText)
        }
        if ($hex.TrimStart('0').Length -gt ($ByteWidth * 2)) {
            throw ('-Constant "{0}" does not fit in {1} bytes.' -f $ConstantText, $ByteWidth)
        }
        $allBytes = [BitConverter]::GetBytes([Convert]::ToUInt64($hex, 16))
        if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($allBytes) }
        for ($i = 0; $i -lt $ByteWidth; $i++) { $tokens.Add([int]$allBytes[$i]) }
    } else {
        foreach ($token in ($PatternText.Trim() -split '\s+')) {
            if ($token -eq '??' -or $token -eq '?') {
                $tokens.Add(-1)
            } elseif ($token -match '^[0-9A-Fa-f]{1,2}$') {
                $tokens.Add([Convert]::ToInt32($token, 16))
            } else {
                throw ('-Pattern token "{0}" is not a hex byte or ??.' -f $token)
            }
        }
    }
    $builder = New-Object System.Text.StringBuilder
    $display = New-Object 'System.Collections.Generic.List[string]'
    $fixedBytes = 0
    foreach ($token in $tokens) {
        if ($token -lt 0) {
            [void]$builder.Append('[\x00-\xFF]')
            $display.Add('??')
        } else {
            $fixedBytes++
            [void]$builder.Append('\x' + $token.ToString('X2'))
            $display.Add($token.ToString('X2'))
        }
    }
    if ($fixedBytes -eq 0) { throw 'The pattern must contain at least one fixed byte.' }
    $options = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    return @{
        Regex   = New-Object System.Text.RegularExpressions.Regex($builder.ToString(), $options)
        Length  = $tokens.Count
        Display = ($display -join ' ')
    }
}

function Format-HexString {
    param([byte[]]$Bytes, [int]$Start, [int]$Count)
    if ($Count -le 0) { return '' }
    return [BitConverter]::ToString($Bytes, $Start, $Count).Replace('-', ' ')
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

$filters = Split-ProbeList $Filter
$params = [ordered]@{
    Path           = $Path
    Filter         = $filters
    Recurse        = [bool]$Recurse
    Constant       = $Constant
    Width          = $Width
    Pattern        = $Pattern
    Context        = $Context
    MaxHitsPerFile = $MaxHitsPerFile
    MaxRows        = $MaxRows
    MaxFiles       = $MaxFiles
    MaxFileMB      = $MaxFileMB
    SummaryOnly    = [bool]$SummaryOnly
    Compress       = [bool]$Compress
    OutFile        = $OutFile
}
$ok = $true
$errorMessage = $null
$summary = $null
$rows = New-Object 'System.Collections.Generic.List[object]'

try {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw '-Path is required (a file or a directory).' }
    if (-not (Test-Path -LiteralPath $Path)) { throw ('-Path not found: {0}' -f $Path) }
    if ($Context -lt 0 -or $MaxHitsPerFile -lt 1 -or $MaxRows -lt 1 -or $MaxFiles -lt 1 -or $MaxFileMB -lt 1) {
        throw '-Context must be 0 or more; -MaxHitsPerFile, -MaxRows, -MaxFiles and -MaxFileMB must be 1 or more.'
    }
    if ($filters.Count -eq 0) { $filters = @('*') }
    if ($null -ne $Constant -and $Constant -isnot [string]) {
        throw ('-Constant must be text such as ''0x1234ABCD''. PowerShell passed the number {0}; quote the value.' -f $Constant)
    }
    $needle = ConvertTo-NeedleSpec -ConstantText ([string]$Constant) -ByteWidth $Width -PatternText $Pattern

    $files = Get-ProbeFileList -Root $Path -Patterns $filters -Descend ([bool]$Recurse)
    $filesConsidered = $files.Count
    if ($files.Count -gt $MaxFiles) {
        Add-Caveat ('{0} files matched; only the first {1} were searched (raise -MaxFiles).' -f $files.Count, $MaxFiles)
        $files = $files[0..($MaxFiles - 1)]
    }

    $maxBytes = [int64]$MaxFileMB * 1MB
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $filesScanned = 0
    $skippedLarge = 0
    $unreadable = 0
    $notPe = 0
    $perFileCapped = 0
    $totalHits = 0
    $truncated = $false
    $withHits = New-Object 'System.Collections.Generic.List[string]'
    $half = [int][Math]::Floor($Context / 2)

    foreach ($file in $files) {
        if ($file.Length -gt $maxBytes) { $skippedLarge++; continue }
        $bytes = $null
        try {
            $bytes = Read-ProbeFileContent -FilePath $file.FullName
        } catch {
            $unreadable++
            Write-Verbose ('cannot read {0}: {1}' -f $file.FullName, $_.Exception.Message)
            continue
        }
        $filesScanned++
        $layout = Get-PeLayout -Bytes $bytes
        if (-not $layout.IsPe) { $notPe++ }
        $text = $latin1.GetString($bytes)
        $fileHits = 0
        $match = $needle.Regex.Match($text)
        while ($match.Success) {
            $offset = [int64]$match.Index
            $location = Get-HitLocation -Layout $layout -Offset $offset
            $start = [int][Math]::Max(0, $offset - $half)
            $end = [int][Math]::Min($bytes.Length, $offset + $needle.Length + ($Context - $half))
            $rows.Add([pscustomobject][ordered]@{
                file              = $file.FullName
                fileOffset        = ('0x{0:X}' -f $offset)
                rva               = $location.Rva
                va                = $location.Va
                section           = $location.Section
                sectionExecutable = $location.Executable
                mapped            = $location.Mapped
                contextHex        = (Format-HexString -Bytes $bytes -Start $start -Count ($end - $start))
            })
            $fileHits++
            $totalHits++
            if ($totalHits -ge $MaxRows) { $truncated = $true; break }
            if ($fileHits -ge $MaxHitsPerFile) { $perFileCapped++; break }
            $match = $match.NextMatch()
        }
        if ($fileHits -gt 0) { $withHits.Add($file.FullName) }
        if ($truncated) {
            Add-Caveat ('Stopped at -MaxRows {0}; later hits and files were not searched.' -f $MaxRows)
            break
        }
    }

    if ($perFileCapped -gt 0) {
        Add-Caveat ('{0} file(s) reached -MaxHitsPerFile {1}; their later hits are not listed.' -f $perFileCapped, $MaxHitsPerFile)
    }
    if ($skippedLarge -gt 0) { Add-Caveat ('{0} file(s) larger than -MaxFileMB {1} were skipped.' -f $skippedLarge, $MaxFileMB) }
    if ($unreadable -gt 0) { Add-Caveat ('{0} file(s) could not be read (access denied or locked). Run with -Verbose for names.' -f $unreadable) }
    if ($notPe -gt 0) { Add-Caveat ('{0} searched file(s) are not PE images; their hits have rva, va and section set to null.' -f $notPe) }

    $summary = [ordered]@{
        needle               = $needle.Display
        needleLength         = $needle.Length
        filesConsidered      = $filesConsidered
        filesScanned         = $filesScanned
        filesSkippedTooLarge = $skippedLarge
        filesUnreadable      = $unreadable
        filesNotPe           = $notPe
        filesWithHits        = $withHits.Count
        hitFiles             = $withHits.ToArray()
        totalHits            = $totalHits
        truncated            = ($truncated -or ($filesConsidered -gt $MaxFiles))
    }
} catch {
    $ok = $false
    $errorMessage = $_.Exception.Message
}

$envelope = ConvertTo-ProbeEnvelope -Tool 'Find-PeConstant' -Params $params -Ok $ok -ErrorMessage $errorMessage -Summary $summary -Data $rows -SummaryOnly ([bool]$SummaryOnly)
Write-ProbeEnvelope -Envelope $envelope -OutFile $OutFile -Compress ([bool]$Compress)
exit (Get-ProbeExitCode -Ok $ok)
