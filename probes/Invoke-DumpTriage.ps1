#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Triage a Windows crash dump from a dump file (no live target) with kd.exe and return
    the bug check code, its arguments, the faulting module and the key/value lines of
    !analyze -v as JSON.

.DESCRIPTION
    Invoke-DumpTriage runs the console debugger from the Debugging Tools for Windows
    on a dump file, under a time limit:

      kd.exe -z <dump> -y <symbol path> -logo <log> -c "!analyze -v; .bugcheck; kv; [lmv m <module>;] q"

    and parses the log. It does not connect to a live system. The dump is only read.

    The log file is kept (it is the evidence for the result) and its SHA-256 is reported.
    The kd.exe console output goes to two temporary files that are deleted afterwards, so
    stdout carries only the JSON document.

    Symbols, in this order:
      -SymbolPath                  used as given.
      -UseMicrosoftSymbolServer    srv*<LOCALAPPDATA>\win-agent-probes\symbols*https://msdl.microsoft.com/download/symbols
                                   kd.exe downloads symbol files from the Microsoft
                                   symbol server into that directory.
      _NT_SYMBOL_PATH              the environment variable, when it is set.
      none of these                srv*<LOCALAPPDATA>\win-agent-probes\symbols, a local
                                   symbol store only: nothing is downloaded, so names
                                   are missing unless that directory already has them.
    A caveat names the case when the symbol path can reach the network: a URL, a UNC
    path, or a srv* or symsrv* element without a local store.
    The symbol cache <LOCALAPPDATA>\win-agent-probes\symbols is kept between runs and is
    in the user profile, so processes of the same user at medium integrity can change
    its files, and changed symbol files can make names in the result wrong. An elevated
    run that uses this cache says so in a caveat. Pass -SymbolPath with a cache in a
    folder that only administrators can change.

    Bug check arguments are reported as hex strings such as "0xFFFFFFFFC0000005", without
    the backtick that kd.exe prints inside 64-bit values.

    In an elevated session, kd.exe is started only from -KdPath or from the Debugging
    Tools directories under Program Files; PATH is not searched, because it can include
    folders that a standard user can write.

    State changes: writes the log file to a new directory (under the Windows temporary
    directory, readable only by Administrators and SYSTEM, when elevated; under the
    temporary directory of the user otherwise) or to -LogPath. kd.exe also writes the
    symbol files that it downloads into the symbol cache.
    Elevation: not required, unless the dump file itself needs it (for example
    C:\Windows\MEMORY.DMP); copy the dump to your own directory first.

    -SelfTest checks the argument quoting, the symbol path check and the log parser on
    built-in samples. It starts no process and writes no file. When a check fails, ok is
    false, data is empty, and error names each failed check with its expected and actual
    value.

.PARAMETER Dump
    Path of the dump file (.dmp). Required unless -SelfTest is set.

.PARAMETER Module
    A module name for "lmv m <module>" (letters, digits, dot, underscore, hyphen).
    Optional.

.PARAMETER LogPath
    Path of the kd.exe log. It must not exist yet. Default: a new file in a new
    directory (see State changes).

.PARAMETER SymbolPath
    Symbol path passed to kd.exe with -y.

.PARAMETER UseMicrosoftSymbolServer
    Download symbols from the Microsoft symbol server into the local symbol cache.

.PARAMETER TimeoutSeconds
    Stop kd.exe after this many seconds (30 to 3600). Default: 600.

.PARAMETER KdPath
    Path of kd.exe. Default: kd.exe on PATH (not in an elevated session), then the x64
    and arm64 directories of the Windows 10 and 11 SDK debuggers under Program Files
    and Program Files (x86): Windows Kits\10\Debuggers.

.PARAMETER MaxRows
    Maximum number of key/value rows. Default: 5000.

.PARAMETER SelfTest
    Run the built-in checks only.

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
    summary: mode, dump, kdPath, symbolPath, logPath, logSha256, bugcheckCode,
             bugcheckArguments[], faultingModule, imageName, symbolName, failureBucket,
             processName, symbolWarnings, truncated, caveats[]
    data[]:  key, value   (each "KEY: value" line of the log, first occurrence)
    With -SelfTest: summary { mode, checks, failed }, data[] { check, expected, actual, pass }

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-DumpTriage.ps1 -Dump D:\dumps\MEMORY.DMP -Module sampledrv -UseMicrosoftSymbolServer -OutFile .\triage.json

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-DumpTriage.ps1 -SelfTest
#>
[CmdletBinding()]
param(
    [string] $Dump,
    [string] $Module,
    [string] $LogPath,
    [string] $SymbolPath,
    [switch] $UseMicrosoftSymbolServer,
    [int]    $TimeoutSeconds = 600,
    [string] $KdPath,
    [int]    $MaxRows = 5000,
    [switch] $SelfTest,
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

function Test-ModuleName {
    param([string]$Name)
    return ($Name -match '^[A-Za-z0-9_.\-]{1,64}$')
}

function Get-KdCommand {
    param([string]$ModuleName)
    $commands = '!analyze -v; .bugcheck; kv; '
    if ($ModuleName) { $commands += ('lmv m {0}; ' -f $ModuleName) }
    return ($commands + 'q')
}

function Get-KdInstallPath {
    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not $root) { continue }
        foreach ($architecture in @('x64', 'arm64')) {
            $candidate = Join-Path $root ('Windows Kits\10\Debuggers\{0}\kd.exe' -f $architecture)
            if (-not $list.Contains($candidate)) { $list.Add($candidate) }
        }
    }
    return ,($list.ToArray())
}

function Test-SymbolPathUsesNetwork {
    param([string]$SymbolPath)
    # True when an element of the symbol path can reach the network: a URL, a UNC path,
    # or a srv* or symsrv* element without any local store (the debugger then uses its
    # default server).
    if ([string]::IsNullOrWhiteSpace($SymbolPath)) { return $false }
    foreach ($element in $SymbolPath.Split(';')) {
        $text = $element.Trim()
        if (-not $text) { continue }
        if ($text -match '(?i)https?://' -or $text.StartsWith('\\')) { return $true }
        $parts = @($text.Split('*'))
        $head = $parts[0].Trim().ToLowerInvariant()
        $stores = @()
        if ($head -eq 'srv' -and $parts.Count -gt 1) { $stores = @($parts[1..($parts.Count - 1)]) }
        elseif ($head -eq 'symsrv' -and $parts.Count -gt 2) { $stores = @($parts[2..($parts.Count - 1)]) }
        elseif ($head -ne 'srv' -and $head -ne 'symsrv') { continue }
        $localStores = 0
        foreach ($store in $stores) {
            $value = $store.Trim()
            if (-not $value) { continue }
            if ($value -match '(?i)https?://' -or $value.StartsWith('\\')) { return $true }
            $localStores++
        }
        if ($localStores -eq 0) { return $true }
    }
    return $false
}

function Format-BugcheckCode {
    param([string]$Hex)
    $digits = $Hex.Trim().TrimStart('0').ToUpperInvariant()
    if (-not $digits) { $digits = '0' }
    return '0x' + $digits
}

function Format-HexValue {
    param([string]$Text)
    # "ffffffff`c0000005" and "0xffffffffc0000005" become "0xFFFFFFFFC0000005". Text
    # that is not a hex number is returned unchanged.
    if ($null -eq $Text) { return $null }
    $value = $Text.Trim().Replace('`', '')
    if ($value -match '^0[xX]') { $value = $value.Substring(2) }
    if ($value -notmatch '^[0-9A-Fa-f]{1,16}$') { return $Text.Trim() }
    return (Format-BugcheckCode $value)
}

function Get-DumpTriageFromLog {
    param([string]$Text)
    $result = [ordered]@{
        bugcheckCode      = $null
        bugcheckArguments = @()
        faultingModule    = $null
        imageName         = $null
        symbolName        = $null
        failureBucket     = $null
        processName       = $null
        symbolWarnings    = 0
    }
    if ([string]::IsNullOrEmpty($Text)) { return $result }
    $match = [regex]::Match($Text, '(?im)^\s*Bugcheck code\s+([0-9A-F]+)\s*$')
    if ($match.Success) { $result.bugcheckCode = Format-BugcheckCode $match.Groups[1].Value }
    $match = [regex]::Match($Text, '(?im)^\s*Arguments\s+(\S.*)$')
    if ($match.Success) { $result.bugcheckArguments = @($match.Groups[1].Value.Trim() -split '\s+') }
    if (-not $result.bugcheckCode) {
        $match = [regex]::Match($Text, '(?im)^\s*BUGCHECK_CODE:\s*([0-9A-F]+)\s*$')
        if ($match.Success) { $result.bugcheckCode = Format-BugcheckCode $match.Groups[1].Value }
    }
    if (-not $result.bugcheckCode) {
        $match = [regex]::Match($Text, '(?im)^\s*BugCheck\s+([0-9A-F]+)\s*,\s*\{([^}]*)\}')
        if ($match.Success) {
            $result.bugcheckCode = Format-BugcheckCode $match.Groups[1].Value
            if ($result.bugcheckArguments.Count -eq 0) {
                $result.bugcheckArguments = @($match.Groups[2].Value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }
        }
    }
    if ($result.bugcheckArguments.Count -eq 0) {
        $parameters = New-Object 'System.Collections.Generic.List[string]'
        foreach ($index in 1..4) {
            $match = [regex]::Match($Text, ('(?im)^\s*BUGCHECK_P{0}:\s*(\S+)' -f $index))
            if ($match.Success) { $parameters.Add($match.Groups[1].Value) }
        }
        $result.bugcheckArguments = $parameters.ToArray()
    }
    $result.bugcheckArguments = @($result.bugcheckArguments | ForEach-Object { Format-HexValue $_ })
    $keys = [ordered]@{ faultingModule = 'MODULE_NAME'; imageName = 'IMAGE_NAME'; symbolName = 'SYMBOL_NAME'; failureBucket = 'FAILURE_BUCKET_ID'; processName = 'PROCESS_NAME' }
    foreach ($field in $keys.Keys) {
        $match = [regex]::Match($Text, ('(?im)^\s*{0}:\s*(\S.*?)\s*$' -f $keys[$field]))
        if ($match.Success) { $result[$field] = $match.Groups[1].Value }
    }
    $result.symbolWarnings = [regex]::Matches($Text, '(?im)symbol file could not be found|symbols could not be loaded|unable to load image|unable to verify checksum').Count
    return $result
}

function Get-KeyValueLine {
    param([string]$Text, [int]$Limit = 5000)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $truncated = $false
    foreach ($match in [regex]::Matches($Text, '(?m)^([A-Z][A-Z0-9_]{2,}):[ \t]+(\S[^\r\n]*?)[ \t]*\r?$')) {
        $key = $match.Groups[1].Value
        if (-not $seen.Add($key)) { continue }
        if ($rows.Count -ge $Limit) { $truncated = $true; break }
        $rows.Add([pscustomobject][ordered]@{ key = $key; value = $match.Groups[2].Value })
    }
    return @{ Rows = $rows.ToArray(); Truncated = $truncated }
}

function Invoke-SelfTestCheck {
    $checks = New-Object 'System.Collections.Generic.List[object]'
    $add = {
        param([string]$Name, $Expected, $Actual)
        $checks.Add([pscustomobject][ordered]@{ check = $Name; expected = $Expected; actual = $Actual; pass = ($Expected -ceq $Actual) })
    }
    & $add 'quote.plain' 'plain' (ConvertTo-QuotedArgument 'plain')
    & $add 'quote.space' '"C:\Dump Dir\MEMORY.DMP"' (ConvertTo-QuotedArgument 'C:\Dump Dir\MEMORY.DMP')
    & $add 'quote.embeddedQuote' '"a\"b"' (ConvertTo-QuotedArgument 'a"b')
    & $add 'quote.trailingBackslash' '"C:\a b\\"' (ConvertTo-QuotedArgument 'C:\a b\')
    & $add 'quote.empty' '""' (ConvertTo-QuotedArgument '')
    $command = Get-KdCommand -ModuleName 'sampledrv'
    $joined = Join-ArgumentList @('-z', 'C:\Dump Dir\MEMORY.DMP', '-y', 'srv*C:\Sym*https://example.invalid/symbols', '-logo', 'C:\Log Dir\kd.log', '-c', $command)
    & $add 'kd.commandIsOneToken' $true ($joined.Contains('-c "' + $command + '"'))
    & $add 'kd.dumpIsOneToken' $true ($joined.Contains('-z "C:\Dump Dir\MEMORY.DMP"'))
    & $add 'kd.commandText' '!analyze -v; .bugcheck; kv; lmv m sampledrv; q' $command
    & $add 'kd.noModule' '!analyze -v; .bugcheck; kv; q' (Get-KdCommand -ModuleName '')
    & $add 'module.valid' $true (Test-ModuleName 'sampledrv.sys')
    & $add 'module.rejectsCommandSeparator' $false (Test-ModuleName 'x; .shell')
    & $add 'symbols.localStoreIsOffline' $false (Test-SymbolPathUsesNetwork 'srv*C:\Symbols')
    & $add 'symbols.plainDirectoryIsOffline' $false (Test-SymbolPathUsesNetwork 'C:\Symbols;cache*C:\Cache')
    & $add 'symbols.serverUrlIsNetwork' $true (Test-SymbolPathUsesNetwork 'srv*C:\Symbols*https://msdl.microsoft.com/download/symbols')
    & $add 'symbols.uncIsNetwork' $true (Test-SymbolPathUsesNetwork 'C:\Local;\\server\symbols')
    & $add 'symbols.bareSrvIsNetwork' $true (Test-SymbolPathUsesNetwork 'srv*')
    & $add 'symbols.symsrvWithoutStoreIsNetwork' $true (Test-SymbolPathUsesNetwork 'symsrv*symsrv.dll')
    $sample = @(
        'Bugcheck code 0000001E',
        'Arguments ffffffff`c0000005 fffff801`23456789 00000000`00000000 00000000`00000000',
        'BUGCHECK_CODE:  1e',
        'MODULE_NAME: sampledrv',
        'IMAGE_NAME:  sampledrv.sys',
        'SYMBOL_NAME:  sampledrv!SampleDispatch+42',
        'FAILURE_BUCKET_ID:  AV_sampledrv!SampleDispatch',
        'PROCESS_NAME:  System'
    ) -join "`r`n"
    $parsed = Get-DumpTriageFromLog -Text $sample
    & $add 'parse.bugcheckCode' '0x1E' $parsed.bugcheckCode
    & $add 'parse.argumentCount' 4 @($parsed.bugcheckArguments).Count
    & $add 'parse.argumentFormat' '0xFFFFFFFFC0000005' @($parsed.bugcheckArguments)[0]
    & $add 'parse.zeroArgument' '0x0' @($parsed.bugcheckArguments)[2]
    & $add 'parse.faultingModule' 'sampledrv' $parsed.faultingModule
    & $add 'parse.symbolName' 'sampledrv!SampleDispatch+42' $parsed.symbolName
    & $add 'parse.noSymbolWarnings' 0 $parsed.symbolWarnings
    $legacy = Get-DumpTriageFromLog -Text ("BugCheck 50, {ffffd00000001000, 0, fffff80012345678, 2}`r`n*** ERROR: Module load completed but symbols could not be loaded for sampledrv.sys")
    & $add 'parse.legacyBugcheckCode' '0x50' $legacy.bugcheckCode
    & $add 'parse.legacyArgumentCount' 4 @($legacy.bugcheckArguments).Count
    & $add 'parse.legacyArgumentFormat' '0xFFFFD00000001000' @($legacy.bugcheckArguments)[0]
    & $add 'parse.symbolWarning' 1 $legacy.symbolWarnings
    $keyRows = Get-KeyValueLine -Text $sample
    & $add 'keys.count' 6 @($keyRows.Rows).Count
    & $add 'keys.firstKey' 'BUGCHECK_CODE' @($keyRows.Rows)[0].key
    & $add 'keys.notTruncated' $false $keyRows.Truncated
    $capped = Get-KeyValueLine -Text $sample -Limit 2
    & $add 'keys.capRows' 2 @($capped.Rows).Count
    & $add 'keys.capTruncated' $true $capped.Truncated
    return ,($checks.ToArray())
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
    Dump                     = $Dump
    Module                   = $Module
    LogPath                  = $LogPath
    SymbolPath               = $SymbolPath
    UseMicrosoftSymbolServer = [bool]$UseMicrosoftSymbolServer
    TimeoutSeconds           = $TimeoutSeconds
    KdPath                   = $KdPath
    MaxRows                  = $MaxRows
    SelfTest                 = [bool]$SelfTest
    SummaryOnly              = [bool]$SummaryOnly
    Compress                 = [bool]$Compress
    OutFile                  = $OutFile
}
$ok = $true
$errorMessage = $null
$summary = $null
$rows = $null

try {
    if ($SelfTest) {
        $checks = Invoke-SelfTestCheck
        $failed = @($checks | Where-Object { -not $_.pass }).Count
        $rows = $checks
        $summary = [ordered]@{ mode = 'self-test'; checks = $checks.Count; failed = $failed }
        if ($failed -gt 0) {
            $ok = $false
            $failures = @($checks | Where-Object { -not $_.pass } | ForEach-Object { '{0} (expected <{1}>, got <{2}>)' -f $_.check, $_.expected, $_.actual })
            $errorMessage = ('{0} of {1} self-test checks failed: {2}' -f $failed, $checks.Count, ($failures -join '; '))
        }
    } else {
        if ([string]::IsNullOrWhiteSpace($Dump)) { throw '-Dump is required (or use -SelfTest).' }
        if (-not (Test-Path -LiteralPath $Dump -PathType Leaf)) { throw ('Dump file not found: ' + $Dump) }
        if ($TimeoutSeconds -lt 30 -or $TimeoutSeconds -gt 3600) { throw '-TimeoutSeconds must be between 30 and 3600.' }
        if ($MaxRows -lt 1) { throw '-MaxRows must be 1 or more.' }
        if ($Module -and -not (Test-ModuleName $Module)) { throw '-Module may contain only letters, digits, dot, underscore and hyphen (at most 64 characters).' }
        if ($SymbolPath -and $UseMicrosoftSymbolServer) { throw 'Use only one of -SymbolPath and -UseMicrosoftSymbolServer.' }
        $dumpFull = (Resolve-Path -LiteralPath $Dump).ProviderPath
        $elevatedNow = (Get-ProbeIdentity).Elevated
        $tool = Resolve-ExternalTool -Explicit $KdPath -Names @('kd.exe') -FixedPaths (Get-KdInstallPath) -Elevated $elevatedNow
        $kd = $tool.Path
        if (-not $kd) {
            if ($KdPath) { throw ('-KdPath not found: ' + $KdPath) }
            if ($tool.PathSkipped) { throw 'kd.exe was not found in the Debugging Tools directories under Program Files, and this session is elevated, so PATH was not searched (it can include folders that a standard user can write). Pass -KdPath.' }
            throw 'kd.exe was not found. Install the Debugging Tools for Windows (Windows SDK) or pass -KdPath.'
        }

        $runDirectory = $null
        if ([string]::IsNullOrWhiteSpace($LogPath)) {
            $parent = [System.IO.Path]::GetTempPath()
            if ($elevatedNow) { $parent = Join-Path ([System.Environment]::GetFolderPath('Windows')) 'Temp' }
            $runDirectory = New-ProbeRunDirectory -Parent $parent -AdministratorsOnly $elevatedNow
            $base = ([System.IO.Path]::GetFileNameWithoutExtension($dumpFull) -replace '[^A-Za-z0-9._-]', '-')
            if ($base.Length -gt 48) { $base = $base.Substring(0, 48) }
            $logFull = Join-Path $runDirectory ($base + '.log')
        } else {
            $logFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
            if (Test-Path -LiteralPath $logFull) { throw ('{0} already exists; choose another -LogPath.' -f $logFull) }
            $logDirectory = [System.IO.Path]::GetDirectoryName($logFull)
            if (-not [System.IO.Directory]::Exists($logDirectory)) { $null = [System.IO.Directory]::CreateDirectory($logDirectory) }
        }
        $consoleDirectory = $runDirectory
        if (-not $consoleDirectory) { $consoleDirectory = [System.IO.Path]::GetDirectoryName($logFull) }

        $cache = Join-Path ([System.Environment]::GetFolderPath('LocalApplicationData')) 'win-agent-probes\symbols'
        $usesUserCache = $false
        if ($SymbolPath) {
            $symbols = $SymbolPath
        } elseif ($UseMicrosoftSymbolServer) {
            $symbols = 'srv*{0}*https://msdl.microsoft.com/download/symbols' -f $cache
            $usesUserCache = $true
        } elseif (-not [string]::IsNullOrWhiteSpace($env:_NT_SYMBOL_PATH)) {
            $symbols = $env:_NT_SYMBOL_PATH
            Add-Caveat 'The symbol path came from the _NT_SYMBOL_PATH environment variable.'
        } else {
            $symbols = 'srv*{0}' -f $cache
            $usesUserCache = $true
            Add-Caveat ('No symbol path was given, so kd.exe used only the local symbol store {0} and downloaded nothing; names can be missing. Pass -UseMicrosoftSymbolServer or -SymbolPath for complete symbols.' -f $cache)
        }
        if ($usesUserCache -and $elevatedNow) {
            Add-Caveat ('This session is elevated, but the symbol cache {0} is in the user profile, where processes of this user at medium integrity can change files. Changed symbol files can make names in the result wrong. Pass -SymbolPath with a cache in a folder that only administrators can change.' -f $cache)
        }
        if (Test-SymbolPathUsesNetwork $symbols) { Add-Caveat 'The symbol path can reach the network (a URL, a UNC path, or a symbol server without a local store); kd.exe may download symbol files.' }

        $arguments = Join-ArgumentList @('-z', $dumpFull, '-y', $symbols, '-logo', $logFull, '-c', (Get-KdCommand -ModuleName $Module))
        $tag = 'kd-console-' + [Guid]::NewGuid().ToString('N')
        $stdoutFile = Join-Path $consoleDirectory ($tag + '.out.txt')
        $stderrFile = Join-Path $consoleDirectory ($tag + '.err.txt')
        $consoleTail = ''
        $timedOut = $false
        try {
            $debugger = Start-Process -FilePath $kd -ArgumentList $arguments -NoNewWindow -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
            if (-not $debugger.WaitForExit($TimeoutSeconds * 1000)) {
                $timedOut = $true
                try { $debugger.Kill() } catch { Write-Verbose 'kd.exe already exited' }
                $null = $debugger.WaitForExit(10000)
            }
            foreach ($file in @($stdoutFile, $stderrFile)) {
                if (Test-Path -LiteralPath $file) { $consoleTail += [System.IO.File]::ReadAllText($file) }
            }
        } finally {
            foreach ($file in @($stdoutFile, $stderrFile)) {
                if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
            }
        }
        $consoleTail = ($consoleTail -replace '\s+', ' ').Trim()
        if ($consoleTail.Length -gt 400) { $consoleTail = $consoleTail.Substring($consoleTail.Length - 400) }

        $logText = ''
        $logHash = $null
        if (Test-Path -LiteralPath $logFull) {
            $logText = [System.IO.File]::ReadAllText($logFull)
            $logHash = (Get-FileHash -LiteralPath $logFull -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        if ($timedOut) { throw ('kd.exe did not finish within {0} s and was stopped. Log: {1}. Console tail: {2}' -f $TimeoutSeconds, $logFull, $consoleTail) }
        if (-not $logText) { throw ('kd.exe wrote no log. Console tail: ' + $consoleTail) }

        $triage = Get-DumpTriageFromLog -Text $logText
        if (-not $triage.bugcheckCode) { Add-Caveat 'No bug check code was found in the log; the dump may not be a kernel dump, or kd.exe stopped early.' }
        if ($triage.symbolWarnings -gt 0) { Add-Caveat ('The log has {0} symbol warning line(s); names in the result can be wrong or missing.' -f $triage.symbolWarnings) }
        $keyValues = Get-KeyValueLine -Text $logText -Limit $MaxRows
        $rows = $keyValues.Rows
        if ($keyValues.Truncated) { Add-Caveat ('data[] stopped at -MaxRows {0}; the log has more KEY: value lines.' -f $MaxRows) }
        if ($runDirectory -and $elevatedNow) { Add-Caveat ('The log is in {0}, which only Administrators and SYSTEM can open.' -f $runDirectory) }
        $summary = [ordered]@{
            mode              = 'triage'
            dump              = $dumpFull
            kdPath            = $kd
            symbolPath        = $symbols
            logPath           = $logFull
            logSha256         = $logHash
            bugcheckCode      = $triage.bugcheckCode
            bugcheckArguments = $triage.bugcheckArguments
            faultingModule    = $triage.faultingModule
            imageName         = $triage.imageName
            symbolName        = $triage.symbolName
            failureBucket     = $triage.failureBucket
            processName       = $triage.processName
            symbolWarnings    = $triage.symbolWarnings
            truncated         = $keyValues.Truncated
        }
    }
} catch {
    $ok = $false
    $errorMessage = $_.Exception.Message
}

$envelope = ConvertTo-ProbeEnvelope -Tool 'Invoke-DumpTriage' -Params $params -Ok $ok -ErrorMessage $errorMessage -Summary $summary -Data $rows -SummaryOnly ([bool]$SummaryOnly)
Write-ProbeEnvelope -Envelope $envelope -OutFile $OutFile -Compress ([bool]$Compress)
exit (Get-ProbeExitCode -Ok $ok)
