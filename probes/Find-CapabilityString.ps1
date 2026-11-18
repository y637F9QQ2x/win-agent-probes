#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Extract the printable strings of files and match them against categories of
    capability-related names (API names, object paths, privilege names). Rank files by
    the number of categories they match.

.DESCRIPTION
    Find-CapabilityString reads each file and extracts printable strings the way the
    "strings" tools do: runs of at least -MinLength printable ASCII characters (0x20 to
    0x7E), and the same runs encoded as UTF-16LE. Each category is a set of regular
    expressions (case-insensitive). A data row is one (file, category, label) with the
    number of matches and one sample string.

    "Capability" here means a category of API, object and privilege names that point to
    what a binary can do. It is not an AppContainer capability SID.

    The built-in categories and their regular expressions are in the function
    Get-DefaultPatternSet in this script (docs/probes.md lists them too). -PatternFile
    replaces them with your own (format below). Each regular expression gets 5 seconds
    per match; a pattern that takes longer is skipped for that file, with a caveat.

    State changes: none. The tool only reads files.
    Elevation: not required. Files that the current user cannot read are counted in
    summary.filesUnreadable.

    A match shows that a string is present in the file. It does not show that the code
    that uses it is reachable, or that it runs with any particular privilege. Use the
    result to choose which binaries to open in a disassembler.

    -PatternFile format (JSON):
      { "categories": {
          "my_category": { "meaning": "free text",
                           "patterns": [ { "label": "Name", "regex": "Name(A|W)?" } ] } } }

.PARAMETER Path
    A file or a directory. Required.

.PARAMETER Filter
    File-name wildcards used when -Path is a directory. Default: *.dll, *.exe, *.sys.
    With powershell.exe -File, pass several values as one comma-separated string.

.PARAMETER Recurse
    Also read the subdirectories of -Path.

.PARAMETER Category
    Use only these categories (names from the built-in set or from -PatternFile).
    Default: all.

.PARAMETER PatternFile
    A JSON file with your own categories. It replaces the built-in set.

.PARAMETER MinLength
    Minimum string length in characters. Default: 4.

.PARAMETER MinCategories
    A file is listed in summary.topFiles only when it matches at least this many
    categories. Default: 1. data[] always lists every match.

.PARAMETER MaxTopFiles
    Maximum number of entries in summary.topFiles. Default: 100.

.PARAMETER MaxFiles
    Read at most this many files. Default: 500.

.PARAMETER MaxFileMB
    Skip files larger than this many megabytes. Default: 64.

.PARAMETER CheckSignature
    Add the Authenticode status and signer of each file that has a match
    (Get-AuthenticodeSignature). Windows signature verification can retrieve certificate
    data from the network.

.PARAMETER MaxRows
    Maximum number of data rows; rowsByCategory and topFiles count every row.
    Default: 5000.

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
    summary: patternSource, categories[], filesConsidered, filesScanned, filesWithHits,
             filesSkippedTooLarge, filesUnreadable, rowsByCategory{}, truncated,
             topFiles[], caveats[]
    data[]:  file, fileVersion, signatureStatus, signer, category, label, matches, sample
    truncated is true when -MaxRows or -MaxFiles cut the result.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Find-CapabilityString.ps1 -Path C:\Windows\System32\kernelbase.dll

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Find-CapabilityString.ps1 -Path "C:\Program Files\Contoso" -Recurse -Category "token_and_identity,rpc_alpc_com" -MinCategories 2 -OutFile .\strings.json
#>
[CmdletBinding()]
param(
    [string]   $Path,
    [string[]] $Filter = @('*.dll', '*.exe', '*.sys'),
    [switch]   $Recurse,
    [string[]] $Category,
    [string]   $PatternFile,
    [int]      $MinLength = 4,
    [int]      $MinCategories = 1,
    [int]      $MaxTopFiles = 100,
    [int]      $MaxFiles = 500,
    [int]      $MaxFileMB = 64,
    [switch]   $CheckSignature,
    [int]      $MaxRows = 5000,
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

function Get-DefaultPatternSet {
    return [ordered]@{
        cross_process = @{
            meaning  = 'references APIs that read or write the memory of another process or start threads in it'
            patterns = @(
                @{ label = 'WriteProcessMemory'; regex = 'WriteProcessMemory' },
                @{ label = 'ReadProcessMemory'; regex = 'ReadProcessMemory' },
                @{ label = 'VirtualAllocEx'; regex = 'VirtualAllocEx' },
                @{ label = 'CreateRemoteThread'; regex = 'CreateRemoteThread' },
                @{ label = 'NtCreateThreadEx'; regex = 'NtCreateThreadEx' },
                @{ label = 'QueueUserAPC'; regex = 'QueueUserAPC|NtQueueApcThread' },
                @{ label = 'SetThreadContext'; regex = 'SetThreadContext' },
                @{ label = 'NtMapViewOfSection'; regex = 'NtMapViewOfSection' }
            )
        }
        token_and_identity = @{
            meaning  = 'references token, privilege, logon or impersonation APIs and privilege names'
            patterns = @(
                @{ label = 'ImpersonateNamedPipeClient'; regex = 'ImpersonateNamedPipeClient' },
                @{ label = 'RpcImpersonateClient'; regex = 'RpcImpersonateClient' },
                @{ label = 'CoImpersonateClient'; regex = 'CoImpersonateClient' },
                @{ label = 'ImpersonateLoggedOnUser'; regex = 'ImpersonateLoggedOnUser' },
                @{ label = 'DuplicateToken'; regex = 'DuplicateToken' },
                @{ label = 'AdjustTokenPrivileges'; regex = 'AdjustTokenPrivileges|RtlAdjustPrivilege' },
                @{ label = 'LogonUser'; regex = 'LogonUser' },
                @{ label = 'CheckTokenMembership'; regex = 'CheckTokenMembership' },
                @{ label = 'privilege name'; regex = 'Se(Impersonate|AssignPrimaryToken|Debug|TakeOwnership|Backup|Restore|LoadDriver|Tcb)Privilege' }
            )
        }
        process_creation = @{
            meaning  = 'references APIs that start processes'
            patterns = @(
                @{ label = 'CreateProcess'; regex = 'CreateProcess' },
                @{ label = 'ShellExecute'; regex = 'ShellExecute' },
                @{ label = 'WinExec'; regex = 'WinExec' },
                @{ label = 'UpdateProcThreadAttribute'; regex = 'UpdateProcThreadAttribute' }
            )
        }
        links_and_paths = @{
            meaning  = 'references symbolic links, junctions, reparse points, DOS device mappings or object-manager paths'
            patterns = @(
                @{ label = 'DefineDosDevice'; regex = 'DefineDosDevice' },
                @{ label = 'CreateSymbolicLink'; regex = 'CreateSymbolicLink' },
                @{ label = 'reparse point'; regex = 'reparse' },
                @{ label = 'junction or mount point'; regex = 'junction|mount ?point' },
                @{ label = 'GetFinalPathNameByHandle'; regex = 'GetFinalPathNameByHandle' },
                @{ label = 'object-manager path'; regex = '\\RPC Control|\\GLOBAL\?\?|\\BaseNamedObjects' }
            )
        }
        rpc_alpc_com = @{
            meaning  = 'references RPC, ALPC or COM server and client APIs and protocol sequences'
            patterns = @(
                @{ label = 'RpcServerRegisterIf'; regex = 'RpcServerRegisterIf' },
                @{ label = 'RpcServerUseProtseq'; regex = 'RpcServerUseProtseq' },
                @{ label = 'NdrServerCall'; regex = 'NdrServerCall' },
                @{ label = 'NdrClientCall'; regex = 'NdrClientCall' },
                @{ label = 'protocol sequence'; regex = 'ncalrpc|ncacn_np|ncacn_ip_tcp' },
                @{ label = 'ALPC port API'; regex = 'NtAlpcCreatePort|NtAlpcConnectPort|NtAlpcSendWaitReceivePort' },
                @{ label = 'CoRegisterClassObject'; regex = 'CoRegisterClassObject' },
                @{ label = 'CoInitializeSecurity'; regex = 'CoInitializeSecurity' }
            )
        }
        security_and_configuration = @{
            meaning  = 'references APIs that change security descriptors, services, registry values or file locations'
            patterns = @(
                @{ label = 'SetSecurityInfo'; regex = 'Set(Named)?SecurityInfo' },
                @{ label = 'SetEntriesInAcl'; regex = 'SetEntriesInAcl' },
                @{ label = 'SetFileSecurity'; regex = 'SetFileSecurity|SetKernelObjectSecurity' },
                @{ label = 'service configuration'; regex = 'CreateService|ChangeServiceConfig' },
                @{ label = 'registry write'; regex = 'RegSetValue|RegSetKeyValue|RegCreateKey' },
                @{ label = 'MoveFileEx'; regex = 'MoveFileEx|MoveFileWithProgress' },
                @{ label = 'ReplaceFile'; regex = 'ReplaceFile' },
                @{ label = 'CreateHardLink'; regex = 'CreateHardLink' }
            )
        }
        trust_verification = @{
            meaning  = 'references signature, certificate or catalog verification APIs'
            patterns = @(
                @{ label = 'WinVerifyTrust'; regex = 'WinVerifyTrust' },
                @{ label = 'CryptCATAdmin'; regex = 'CryptCATAdmin' },
                @{ label = 'CertGetCertificateChain'; regex = 'CertGetCertificateChain' },
                @{ label = 'CertVerifyCertificateChainPolicy'; regex = 'CertVerifyCertificateChainPolicy' },
                @{ label = 'CryptQueryObject'; regex = 'CryptQueryObject' }
            )
        }
        module_loading = @{
            meaning  = 'references module loading or DLL search-path APIs'
            patterns = @(
                @{ label = 'LoadLibrary'; regex = 'LoadLibrary' },
                @{ label = 'LdrLoadDll'; regex = 'LdrLoadDll' },
                @{ label = 'SetDllDirectory'; regex = 'SetDllDirectory' },
                @{ label = 'SetDefaultDllDirectories'; regex = 'SetDefaultDllDirectories|AddDllDirectory' },
                @{ label = 'KnownDlls'; regex = '\\KnownDlls' }
            )
        }
        serialization = @{
            meaning  = 'references .NET serializers or deserialization routines'
            patterns = @(
                @{ label = 'BinaryFormatter'; regex = 'BinaryFormatter' },
                @{ label = 'NetDataContractSerializer'; regex = 'NetDataContractSerializer' },
                @{ label = 'SoapFormatter'; regex = 'SoapFormatter' },
                @{ label = 'LosFormatter'; regex = 'LosFormatter|ObjectStateFormatter' },
                @{ label = 'deserialize'; regex = 'deserializ' }
            )
        }
        file_locking = @{
            meaning  = 'references file locking, opportunistic lock or file-system control APIs'
            patterns = @(
                @{ label = 'LockFileEx'; regex = 'LockFileEx' },
                @{ label = 'oplock'; regex = 'oplock' },
                @{ label = 'NtFsControlFile'; regex = 'NtFsControlFile' },
                @{ label = 'FSCTL code name'; regex = 'FSCTL_[A-Z_]+' }
            )
        }
    }
}

function Read-PatternFile {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { throw ('-PatternFile not found: {0}' -f $FilePath) }
    $document = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $FilePath).ProviderPath) | ConvertFrom-Json
    $categories = Get-ObjectProperty $document 'categories'
    if ($null -eq $categories) { throw '-PatternFile has no "categories" object.' }
    $set = [ordered]@{}
    foreach ($property in $categories.PSObject.Properties) {
        $patterns = New-Object 'System.Collections.Generic.List[object]'
        foreach ($entry in @(Get-ObjectProperty $property.Value 'patterns')) {
            $label = [string](Get-ObjectProperty $entry 'label')
            $regex = [string](Get-ObjectProperty $entry 'regex')
            if ([string]::IsNullOrWhiteSpace($label) -or [string]::IsNullOrWhiteSpace($regex)) {
                throw ('-PatternFile category "{0}" has a pattern without "label" or "regex".' -f $property.Name)
            }
            $patterns.Add(@{ label = $label; regex = $regex })
        }
        if ($patterns.Count -eq 0) { throw ('-PatternFile category "{0}" has no patterns.' -f $property.Name) }
        $set[$property.Name] = @{ meaning = [string](Get-ObjectProperty $property.Value 'meaning'); patterns = $patterns.ToArray() }
    }
    if ($set.Count -eq 0) { throw '-PatternFile defines no categories.' }
    return $set
}

$script:RegexTimeout = [TimeSpan]::FromSeconds(5)

function Get-CompiledPatternList {
    param($PatternSet, [string[]]$Selected)
    $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in $PatternSet.Keys) {
        if ($Selected.Count -gt 0 -and $Selected -notcontains $name) { continue }
        foreach ($pattern in $PatternSet[$name].patterns) {
            try {
                $compiled = New-Object System.Text.RegularExpressions.Regex($pattern.regex, $options, $script:RegexTimeout)
            } catch {
                throw ('Category "{0}", label "{1}": invalid regular expression: {2}' -f $name, $pattern.label, $_.Exception.Message)
            }
            $list.Add([pscustomobject]@{ Category = $name; Label = $pattern.label; Regex = $compiled })
        }
    }
    return ,($list.ToArray())
}

function Test-RegexTimeout {
    param($Exception)
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [System.Text.RegularExpressions.RegexMatchTimeoutException]) { return $true }
        $current = $current.InnerException
    }
    return $false
}

function Measure-PatternMatch {
    param($Regex, [string]$Corpus)
    # Counts the matches with Match and NextMatch. MatchCollection.Count is not used:
    # PowerShell returns $null when a property getter throws, so a timeout would be lost.
    $result = @{ Total = 0; FirstIndex = -1; TimedOut = $false }
    try {
        $match = $Regex.Match($Corpus)
        while ($match.Success) {
            if ($result.Total -eq 0) { $result.FirstIndex = $match.Index }
            $result.Total++
            $match = $match.NextMatch()
        }
    } catch {
        if (-not (Test-RegexTimeout $_.Exception)) { throw }
        $result.TimedOut = $true
    }
    return $result
}

function Get-StringCorpus {
    param([byte[]]$Bytes, $Encoding, $AsciiRegex, $WideRegex)
    $text = $Encoding.GetString($Bytes)
    $builder = New-Object System.Text.StringBuilder
    $nul = [string][char]0
    foreach ($match in $AsciiRegex.Matches($text)) {
        [void]$builder.Append($match.Value)
        [void]$builder.Append("`n")
    }
    foreach ($match in $WideRegex.Matches($text)) {
        [void]$builder.Append($match.Value.Replace($nul, ''))
        [void]$builder.Append("`n")
    }
    return $builder.ToString()
}

function Get-SampleLine {
    param([string]$Corpus, [int]$Index, [int]$MaxLength = 200)
    $lineStart = $Corpus.LastIndexOf([char]10, [Math]::Max(0, $Index)) + 1
    if ($lineStart -gt $Index) { $lineStart = 0 }
    $lineEnd = $Corpus.IndexOf([char]10, $Index)
    if ($lineEnd -lt 0) { $lineEnd = $Corpus.Length }
    $line = $Corpus.Substring($lineStart, $lineEnd - $lineStart)
    if ($line.Length -gt $MaxLength) { $line = $line.Substring(0, $MaxLength) }
    return $line
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
$selected = Split-ProbeList $Category
$params = [ordered]@{
    Path           = $Path
    Filter         = $filters
    Recurse        = [bool]$Recurse
    Category       = $selected
    PatternFile    = $PatternFile
    MinLength      = $MinLength
    MinCategories  = $MinCategories
    MaxTopFiles    = $MaxTopFiles
    MaxFiles       = $MaxFiles
    MaxFileMB      = $MaxFileMB
    CheckSignature = [bool]$CheckSignature
    MaxRows        = $MaxRows
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
    if ($MinLength -lt 2 -or $MinLength -gt 1024) { throw '-MinLength must be between 2 and 1024.' }
    if ($MinCategories -lt 1 -or $MaxTopFiles -lt 0 -or $MaxFiles -lt 1 -or $MaxFileMB -lt 1 -or $MaxRows -lt 1) {
        throw '-MinCategories, -MaxFiles, -MaxFileMB and -MaxRows must be 1 or more; -MaxTopFiles must be 0 or more.'
    }
    if ($filters.Count -eq 0) { $filters = @('*') }

    $patternSource = 'built-in'
    if ([string]::IsNullOrWhiteSpace($PatternFile)) {
        $patternSet = Get-DefaultPatternSet
    } else {
        $patternSet = Read-PatternFile -FilePath $PatternFile
        $patternSource = $PatternFile
    }
    $unknown = @($selected | Where-Object { -not $patternSet.Contains($_) })
    if ($unknown.Count -gt 0) {
        throw ('Unknown -Category value(s): {0}. Valid: {1}' -f ($unknown -join ', '), (@($patternSet.Keys) -join ', '))
    }
    $compiled = Get-CompiledPatternList -PatternSet $patternSet -Selected $selected
    $activeCategories = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in $patternSet.Keys) {
        if ($selected.Count -eq 0 -or $selected -contains $name) { $activeCategories.Add($name) }
    }

    $files = Get-ProbeFileList -Root $Path -Patterns $filters -Descend ([bool]$Recurse)
    $filesConsidered = $files.Count
    if ($files.Count -gt $MaxFiles) {
        Add-Caveat ('{0} files matched; only the first {1} were read (raise -MaxFiles).' -f $files.Count, $MaxFiles)
        $files = $files[0..($MaxFiles - 1)]
    }

    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $asciiRegex = New-Object System.Text.RegularExpressions.Regex(('[\x20-\x7E]{' + $MinLength + ',}'))
    $wideRegex = New-Object System.Text.RegularExpressions.Regex(('(?:[\x20-\x7E]\x00){' + $MinLength + ',}'))
    $maxBytes = [int64]$MaxFileMB * 1MB
    $filesScanned = 0
    $filesWithHits = 0
    $skippedLarge = 0
    $unreadable = 0
    $rowsByCategory = [ordered]@{}
    foreach ($name in $activeCategories) { $rowsByCategory[$name] = 0 }
    $perFile = New-Object 'System.Collections.Generic.List[object]'
    $rowsDropped = 0
    $timeouts = [ordered]@{}

    foreach ($file in $files) {
        if ($file.Length -gt $maxBytes) { $skippedLarge++; continue }
        try {
            $bytes = Read-ProbeFileContent -FilePath $file.FullName
        } catch {
            $unreadable++
            Write-Verbose ('cannot read {0}: {1}' -f $file.FullName, $_.Exception.Message)
            continue
        }
        $filesScanned++
        $corpus = Get-StringCorpus -Bytes $bytes -Encoding $latin1 -AsciiRegex $asciiRegex -WideRegex $wideRegex
        $fileRows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($pattern in $compiled) {
            $measured = Measure-PatternMatch -Regex $pattern.Regex -Corpus $corpus
            if ($measured.TimedOut) {
                $key = 'Category "{0}", label "{1}"' -f $pattern.Category, $pattern.Label
                if ($timeouts.Contains($key)) { $timeouts[$key] = [int]$timeouts[$key] + 1 } else { $timeouts[$key] = 1 }
                continue
            }
            if ($measured.Total -eq 0) { continue }
            $fileRows.Add([pscustomobject][ordered]@{
                file            = $file.FullName
                fileVersion     = $null
                signatureStatus = $null
                signer          = $null
                category        = $pattern.Category
                label           = $pattern.Label
                matches         = $measured.Total
                sample          = (Get-SampleLine -Corpus $corpus -Index $measured.FirstIndex)
            })
        }
        if ($fileRows.Count -eq 0) { continue }
        $filesWithHits++
        $version = $null
        try { $version = $file.VersionInfo.FileVersion } catch { Write-Verbose ('no version info for ' + $file.FullName) }
        $status = $null
        $signer = $null
        if ($CheckSignature) {
            try {
                $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
                $status = [string]$signature.Status
                if ($null -ne $signature.SignerCertificate) { $signer = $signature.SignerCertificate.Subject }
            } catch {
                $status = 'check failed'
            }
        }
        $categoriesHit = New-Object 'System.Collections.Generic.List[string]'
        foreach ($row in $fileRows) {
            $row.fileVersion = $version
            $row.signatureStatus = $status
            $row.signer = $signer
            if ($rows.Count -lt $MaxRows) { $rows.Add($row) } else { $rowsDropped++ }
            $rowsByCategory[$row.category] = [int]$rowsByCategory[$row.category] + 1
            if (-not $categoriesHit.Contains($row.category)) { $categoriesHit.Add($row.category) }
        }
        $perFile.Add([pscustomobject][ordered]@{
            file          = $file.FullName
            categoryCount = $categoriesHit.Count
            categories    = $categoriesHit.ToArray()
        })
    }

    $ranked = @($perFile | Where-Object { $_.categoryCount -ge $MinCategories } |
        Sort-Object -Property @{ Expression = 'categoryCount'; Descending = $true }, @{ Expression = 'file'; Descending = $false })
    if ($ranked.Count -gt $MaxTopFiles) {
        Add-Caveat ('summary.topFiles lists the first {0} of {1} ranked files (raise -MaxTopFiles).' -f $MaxTopFiles, $ranked.Count)
        if ($MaxTopFiles -eq 0) { $ranked = @() } else { $ranked = $ranked[0..($MaxTopFiles - 1)] }
    }
    if ($skippedLarge -gt 0) { Add-Caveat ('{0} file(s) larger than -MaxFileMB {1} were skipped.' -f $skippedLarge, $MaxFileMB) }
    if ($unreadable -gt 0) { Add-Caveat ('{0} file(s) could not be read (access denied or locked). Run with -Verbose for names.' -f $unreadable) }
    if ($rowsDropped -gt 0) { Add-Caveat ('data[] stopped at -MaxRows {0}; {1} row(s) were left out. rowsByCategory and topFiles count every row.' -f $MaxRows, $rowsDropped) }
    foreach ($key in $timeouts.Keys) {
        Add-Caveat ('{0}: the regular expression did not finish within {1} s on {2} file(s); those files have no row for it.' -f $key, $script:RegexTimeout.TotalSeconds, $timeouts[$key])
    }
    Add-Caveat 'A matching string shows presence in the file only; it does not show that the code using it is reachable.'

    $summary = [ordered]@{
        patternSource        = $patternSource
        categories           = $activeCategories.ToArray()
        filesConsidered      = $filesConsidered
        filesScanned         = $filesScanned
        filesWithHits        = $filesWithHits
        filesSkippedTooLarge = $skippedLarge
        filesUnreadable      = $unreadable
        rowsByCategory       = $rowsByCategory
        truncated            = (($rowsDropped -gt 0) -or ($filesConsidered -gt $MaxFiles))
        topFiles             = (ConvertTo-ProbeArray $ranked)
    }
} catch {
    $ok = $false
    $errorMessage = $_.Exception.Message
}

$envelope = ConvertTo-ProbeEnvelope -Tool 'Find-CapabilityString' -Params $params -Ok $ok -ErrorMessage $errorMessage -Summary $summary -Data $rows -SummaryOnly ([bool]$SummaryOnly)
Write-ProbeEnvelope -Envelope $envelope -OutFile $OutFile -Compress ([bool]$Compress)
exit (Get-ProbeExitCode -Ok $ok)
