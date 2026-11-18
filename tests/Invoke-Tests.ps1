#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Offline tests for win-agent-probes. They use no test framework, so they do not depend
    on a Pester version: Windows ships Pester 3.4, and Pester 5 uses a different syntax.

.DESCRIPTION
    What the tests do:
      - parse every .ps1 file of the repository with the PowerShell parser (no execution)
      - check repository hygiene: ASCII-only text files, no trailing whitespace or tab
        characters in scripts, the copyright and SPDX lines in every script, an identical
        common helper block in every probe, identical copies of every function that more
        than one probe defines, help text for every parameter, the "State changes" and
        "Elevation:" lines in the help, comment-based help that Get-Help can read, and
        parameter names in the examples of the help, README.md and docs that exist in
        the probe
      - run every probe with -Help in a child process
      - run probes in child processes on code paths that need no elevation, no external
        tool and no network, and that do not open other processes: input validation
        errors, the refusal to replace or delete existing files or to write capture
        files into a directory that does not exist, the -DryRun modes,
        -SummaryOnly and -Compress, Find-PeConstant and Find-CapabilityString on
        generated fixture files, Invoke-ProcmonCapture -ParseCsv on a generated CSV, and
        Invoke-DumpTriage -SelfTest
      - dot-source probes to unit-test their helper functions, with stand-in functions
        in place of AccessChk and of the NtObjectManager cmdlets
      - start cmd.exe once, to check that a quoted trigger command line reaches the
        program unchanged

    The child processes run with -NoProfile -NonInteractive -ExecutionPolicy Bypass.
    Generated files go to a new directory under the temporary directory, which is
    deleted at the end unless -KeepWorkDirectory is set.

    The exit code is the number of failed tests.

.PARAMETER PowerShellPath
    The PowerShell executable used for the child processes. Default: the executable
    that runs this script.

.PARAMETER KeepWorkDirectory
    Keep the directory with the generated fixtures.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-Tests.ps1

.EXAMPLE
    pwsh -NoProfile -File .\tests\Invoke-Tests.ps1
#>
[CmdletBinding()]
param(
    [string] $PowerShellPath,
    [switch] $KeepWorkDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$probeDirectory = Join-Path $repoRoot 'probes'
if ([string]::IsNullOrWhiteSpace($PowerShellPath)) {
    $PowerShellPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
}
$workDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('win-agent-probes-tests-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $workDirectory
$probeNames = @(Get-ChildItem -LiteralPath $probeDirectory -Filter '*.ps1' | Sort-Object -Property Name | ForEach-Object { $_.BaseName })
$scriptFiles = @(Get-ChildItem -LiteralPath $repoRoot -Recurse -File | Where-Object { $_.Extension -eq '.ps1' -and $_.FullName -notmatch '\\\.git\\' })
$script:Results = New-Object 'System.Collections.Generic.List[object]'
$utf8 = New-Object System.Text.UTF8Encoding($false)

#region Test helpers
function Invoke-TestCase {
    param([string]$Title, [scriptblock]$Body)
    $started = [DateTime]::UtcNow
    try {
        & $Body
        $script:Results.Add([pscustomobject]@{ Test = $Title; Result = 'pass'; Seconds = [Math]::Round(([DateTime]::UtcNow - $started).TotalSeconds, 1); Message = '' })
    } catch {
        $script:Results.Add([pscustomobject]@{ Test = $Title; Result = 'FAIL'; Seconds = [Math]::Round(([DateTime]::UtcNow - $started).TotalSeconds, 1); Message = $_.Exception.Message })
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if (-not ($Expected -ceq $Actual)) { throw ('{0}: expected <{1}>, got <{2}>' -f $Message, $Expected, $Actual) }
}

function Assert-True {
    param($Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function ConvertTo-TestArgument {
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

function Invoke-ChildProcess {
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutSeconds = 180)
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $startInfo.WorkingDirectory = $workDirectory
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill()
        throw ('{0} did not exit within {1} s' -f [System.IO.Path]::GetFileName($FilePath), $TimeoutSeconds)
    }
    $process.WaitForExit()
    return @{ ExitCode = $process.ExitCode; StdOut = $stdoutTask.Result; StdErr = $stderrTask.Result }
}

function Invoke-Probe {
    param([string]$Name, [string[]]$Arguments, [int]$TimeoutSeconds = 180)
    $scriptPath = Join-Path $probeDirectory ($Name + '.ps1')
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath) + @($Arguments)
    return (Invoke-ChildProcess -FilePath $PowerShellPath -Arguments (($all | ForEach-Object { ConvertTo-TestArgument $_ }) -join ' ') -TimeoutSeconds $TimeoutSeconds)
}

function Assert-Envelope {
    param($Result, [string]$Tool, [bool]$ExpectOk)
    $text = ([string]$Result.StdOut).Trim()
    Assert-True ($text.StartsWith('{') -and $text.EndsWith('}')) ('stdout is not one JSON object: ' + $text.Substring(0, [Math]::Min(300, $text.Length)))
    Assert-True ($text -match '"generatedUtc":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"') 'generatedUtc is not an ISO 8601 UTC time'
    Assert-True ($text -match '"data":\s*\[') 'data is not a JSON array'
    $document = $text | ConvertFrom-Json
    $names = @($document.PSObject.Properties | ForEach-Object { $_.Name }) -join ','
    Assert-Equal 'tool,schemaVersion,generatedUtc,host,principal,elevated,params,ok,error,summary,data' $names 'envelope keys'
    Assert-Equal $Tool $document.tool 'tool'
    Assert-Equal 1 ([int]$document.schemaVersion) 'schemaVersion'
    if ($ExpectOk) {
        Assert-Equal $true $document.ok ('ok (error: {0})' -f $document.error)
        Assert-Equal 0 $Result.ExitCode 'exit code'
        Assert-True ($null -eq $document.error) 'error must be null when ok is true'
    } else {
        Assert-Equal $false $document.ok 'ok'
        Assert-Equal 1 $Result.ExitCode 'exit code'
        Assert-True ([bool]$document.error) 'error must be set when ok is false'
        Assert-Equal 0 @($document.data).Count 'data must be empty when ok is false'
    }
    Assert-True (@($document.summary.PSObject.Properties | ForEach-Object { $_.Name }) -contains 'caveats') 'summary.caveats is missing'
    return $document
}

function Get-ScriptAst {
    param([string]$Path)
    $tokens = $null
    $errors = $null
    return [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
}

function Write-UInt16 { param([byte[]]$Buffer, [int]$Offset, [int]$Value) [Array]::Copy([BitConverter]::GetBytes([UInt16]$Value), 0, $Buffer, $Offset, 2) }
function Write-UInt32 { param([byte[]]$Buffer, [int]$Offset, [int64]$Value) [Array]::Copy([BitConverter]::GetBytes([UInt32]$Value), 0, $Buffer, $Offset, 4) }
function Write-UInt64 { param([byte[]]$Buffer, [int]$Offset, [UInt64]$Value) [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Buffer, $Offset, 8) }
function Write-AsciiText {
    param([byte[]]$Buffer, [int]$Offset, [string]$Text)
    $encoded = [System.Text.Encoding]::ASCII.GetBytes($Text)
    [Array]::Copy($encoded, 0, $Buffer, $Offset, $encoded.Length)
}

function Get-TestPeByte {
    # A minimal PE32+ image: two sections (.text executable, .rdata with VirtualSize
    # smaller than its raw data), one import, one delay import, and the bytes
    # CD AB 34 12 at file offsets 0x300 (headers), 0x410 (.text), 0x740 (.rdata,
    # mapped) and 0x790 (.rdata, past VirtualSize).
    $buffer = New-Object byte[] 0x800
    $buffer[0] = 0x4D
    $buffer[1] = 0x5A
    Write-UInt32 $buffer 0x3C 0x80
    Write-UInt32 $buffer 0x80 0x00004550
    Write-UInt16 $buffer 0x84 0x8664
    Write-UInt16 $buffer 0x86 2
    Write-UInt16 $buffer 0x94 0xF0
    Write-UInt16 $buffer 0x96 0x22
    $optional = 0x98
    Write-UInt16 $buffer $optional 0x20B
    Write-UInt64 $buffer ($optional + 24) ([UInt64]0x180000000)
    Write-UInt32 $buffer ($optional + 108) 16
    Write-UInt32 $buffer ($optional + 112 + 8) 0x2000
    Write-UInt32 $buffer ($optional + 112 + 12) 40
    Write-UInt32 $buffer ($optional + 112 + 104) 0x2040
    Write-UInt32 $buffer ($optional + 112 + 108) 64
    $section = $optional + 0xF0
    Write-AsciiText $buffer $section '.text'
    Write-UInt32 $buffer ($section + 8) 0x200
    Write-UInt32 $buffer ($section + 12) 0x1000
    Write-UInt32 $buffer ($section + 16) 0x200
    Write-UInt32 $buffer ($section + 20) 0x400
    Write-UInt32 $buffer ($section + 36) 0x60000020
    $section += 40
    Write-AsciiText $buffer $section '.rdata'
    Write-UInt32 $buffer ($section + 8) 0x180
    Write-UInt32 $buffer ($section + 12) 0x2000
    Write-UInt32 $buffer ($section + 16) 0x200
    Write-UInt32 $buffer ($section + 20) 0x600
    Write-UInt32 $buffer ($section + 36) 0x40000040
    Write-UInt32 $buffer (0x600 + 12) 0x2100
    Write-UInt32 $buffer (0x600 + 16) 0x2080
    Write-UInt32 $buffer 0x640 1
    Write-UInt32 $buffer (0x640 + 4) 0x2120
    Write-AsciiText $buffer 0x700 'sample-import.dll'
    Write-AsciiText $buffer 0x720 'sample-delay.dll'
    foreach ($offset in @(0x300, 0x410, 0x740, 0x790)) {
        $buffer[$offset] = 0xCD
        $buffer[$offset + 1] = 0xAB
        $buffer[$offset + 2] = 0x34
        $buffer[$offset + 3] = 0x12
    }
    return ,$buffer
}
#endregion

#region Fixtures
$peFixture = Join-Path $workDirectory 'fixture.dll'
[System.IO.File]::WriteAllBytes($peFixture, (Get-TestPeByte))
$textFixture = Join-Path $workDirectory 'notes.txt'
[System.IO.File]::WriteAllText($textFixture, 'plain text, no PE header', $utf8)

$stringsFixture = Join-Path $workDirectory 'strings.bin'
$stream = New-Object System.IO.MemoryStream
foreach ($chunk in @(
        [byte[]](0x01, 0x02, 0x03),
        [System.Text.Encoding]::ASCII.GetBytes('xx CreateRemoteThread yy'), [byte[]](0x00, 0x07),
        [System.Text.Encoding]::Unicode.GetBytes('ImpersonateNamedPipeClient'), [byte[]](0x00, 0x00, 0x05),
        [System.Text.Encoding]::ASCII.GetBytes('ncalrpc'), [byte[]](0x00),
        [System.Text.Encoding]::ASCII.GetBytes('UNIQUE_MARKER_42'), [byte[]](0x00, 0x09))) {
    $stream.Write($chunk, 0, $chunk.Length)
}
[System.IO.File]::WriteAllBytes($stringsFixture, $stream.ToArray())
$stream.Dispose()

$patternFile = Join-Path $workDirectory 'patterns.json'
[System.IO.File]::WriteAllText($patternFile, '{ "categories": { "custom": { "meaning": "test", "patterns": [ { "label": "Marker", "regex": "UNIQUE_MARKER_\\d+" } ] } } }', $utf8)

$csvFixture = Join-Path $workDirectory 'procmon.csv'
$csvLines = @(
    '"Time of Day","Process Name","PID","Operation","Path","Result","Detail","User","Integrity"',
    '"10:00:00.0000000 AM","svchost.exe","1234","CreateFile","C:\ProgramData\Sample\a.txt","NAME NOT FOUND","Desired Access: Read","NT AUTHORITY\SYSTEM","System"',
    '"10:00:00.1000000 AM","notepad.exe","4321","ReadFile","C:\Temp\b.txt","SUCCESS","Offset: 0","CONTOSO\user","Medium"',
    '"10:00:00.2000000 AM","svchost.exe","1234","RegOpenKey","HKLM\Software\Sample","SUCCESS","","NT AUTHORITY\SYSTEM","System"',
    '"10:00:00.3000000 AM","svchost.exe","1234","QueryDirectory","C:\ProgramData\Sample","SUCCESS","","NT AUTHORITY\SYSTEM","System"',
    '"10:00:00.4000000 AM","explorer.exe","2222","Load Image","C:\Windows\System32\sample.dll","SUCCESS","Image Base: 0x7ff800000000","CONTOSO\user","Medium"'
)
[System.IO.File]::WriteAllText($csvFixture, (($csvLines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($true)))

$spacedDirectory = Join-Path $workDirectory 'Program Files (x86)\Vendor'
$null = New-Item -ItemType Directory -Path $spacedDirectory
$spacedProgram = Join-Path $spacedDirectory 'app.exe'
[System.IO.File]::WriteAllBytes($spacedProgram, (Get-TestPeByte))
#endregion

#region Static checks
Invoke-TestCase 'every .ps1 parses without errors' {
    foreach ($file in $scriptFiles) {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        Assert-Equal 0 @($errors).Count ('parse errors in ' + $file.Name + ': ' + (@($errors) -join '; '))
    }
}

Invoke-TestCase 'text files are ASCII only' {
    foreach ($file in @(Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Force | Where-Object { $_.FullName -notmatch '\\\.git\\' })) {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i] -gt 0x7E -or ($bytes[$i] -lt 0x20 -and $bytes[$i] -ne 0x0A -and $bytes[$i] -ne 0x0D -and $bytes[$i] -ne 0x09)) {
                throw ('{0} has a non-ASCII or control byte 0x{1:X2} at offset {2}' -f $file.Name, $bytes[$i], $i)
            }
        }
    }
}

Invoke-TestCase 'scripts have no trailing whitespace and no tab characters' {
    foreach ($file in @(Get-ChildItem -LiteralPath $repoRoot -Recurse -File | Where-Object { @('.ps1', '.psd1') -contains $_.Extension })) {
        $number = 0
        foreach ($line in [System.IO.File]::ReadAllLines($file.FullName)) {
            $number++
            Assert-True ($line -notmatch '[ \t]+$') ('{0} line {1} has trailing whitespace' -f $file.Name, $number)
            Assert-True ($line -notmatch "`t") ('{0} line {1} has a tab character' -f $file.Name, $number)
        }
    }
}

Invoke-TestCase 'every script starts with #Requires, the copyright line and the SPDX line' {
    foreach ($file in $scriptFiles) {
        $lines = [System.IO.File]::ReadAllLines($file.FullName)
        Assert-Equal '#Requires -Version 5.1' $lines[0] ($file.Name + ' line 1')
        Assert-Equal '# Copyright (c) 2026 Kazuma Matsumoto' $lines[1] ($file.Name + ' line 2')
        Assert-Equal '# SPDX-License-Identifier: MIT' $lines[2] ($file.Name + ' line 3')
        Assert-Equal '' $lines[3] ($file.Name + ' line 4 must be empty, so that Get-Help finds the help block')
    }
}

Invoke-TestCase 'probes avoid Write-Host, Invoke-Expression and mandatory parameters' {
    foreach ($name in $probeNames) {
        $text = [System.IO.File]::ReadAllText((Join-Path $probeDirectory ($name + '.ps1')))
        Assert-True ($text -notmatch '(?i)\bWrite-Host\b') ($name + ' uses Write-Host')
        Assert-True ($text -notmatch '(?i)\bWrite-Warning\b') ($name + ' uses Write-Warning')
        Assert-True ($text -notmatch '(?i)\bInvoke-Expression\b|\biex\b') ($name + ' uses Invoke-Expression')
        Assert-True ($text -notmatch '(?i)Mandatory\s*=') ($name + ' declares a mandatory parameter')
    }
}

Invoke-TestCase 'the common helper block is identical in every probe' {
    $reference = $null
    foreach ($name in $probeNames) {
        $text = [System.IO.File]::ReadAllText((Join-Path $probeDirectory ($name + '.ps1')))
        $start = $text.IndexOf('#region Common probe helpers')
        $end = $text.IndexOf('#endregion', [Math]::Max(0, $start))
        Assert-True ($start -ge 0 -and $end -gt $start) ($name + ' has no common helper block')
        $block = $text.Substring($start, $end - $start)
        if ($null -eq $reference) { $reference = $block } else { Assert-True ($block -ceq $reference) ($name + ' has a different common helper block') }
    }
}

Invoke-TestCase 'a function that several probes define is identical in each of them' {
    $definitions = @{}
    foreach ($name in $probeNames) {
        $ast = Get-ScriptAst -Path (Join-Path $probeDirectory ($name + '.ps1'))
        foreach ($function in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
            if (-not $definitions.ContainsKey($function.Name)) { $definitions[$function.Name] = New-Object 'System.Collections.Generic.List[object]' }
            $definitions[$function.Name].Add(@{ Probe = $name; Text = $function.Extent.Text })
        }
    }
    $shared = 0
    foreach ($functionName in $definitions.Keys) {
        $copies = $definitions[$functionName]
        if ($copies.Count -lt 2) { continue }
        $shared++
        foreach ($copy in $copies) {
            Assert-True ($copy.Text -ceq $copies[0].Text) ('{0} in {1} differs from the copy in {2}' -f $functionName, $copy.Probe, $copies[0].Probe)
        }
    }
    Assert-True ($shared -gt 10) ('only {0} shared functions found' -f $shared)
}

Invoke-TestCase 'the quoting helper of the tests is the same code as ConvertTo-QuotedArgument' {
    $probeAst = Get-ScriptAst -Path (Join-Path $probeDirectory 'Invoke-DumpTriage.ps1')
    $testAst = Get-ScriptAst -Path $PSCommandPath
    $probeFunction = $probeAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertTo-QuotedArgument' }, $false)
    $testFunction = $testAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertTo-TestArgument' }, $false)
    Assert-True ($null -ne $probeFunction -and $null -ne $testFunction) 'quoting functions not found'
    Assert-True ($probeFunction.Body.Extent.Text -ceq $testFunction.Body.Extent.Text) 'ConvertTo-TestArgument differs from ConvertTo-QuotedArgument'
}

Invoke-TestCase 'help documents every parameter, and only real ones' {
    foreach ($name in $probeNames) {
        $path = Join-Path $probeDirectory ($name + '.ps1')
        $ast = Get-ScriptAst -Path $path
        $declared = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $text = [System.IO.File]::ReadAllText($path)
        $documented = @([regex]::Matches($text, '(?m)^\.PARAMETER\s+(\S+)') | ForEach-Object { $_.Groups[1].Value })
        foreach ($parameter in $declared) { Assert-True ($documented -contains $parameter) ('{0}: -{1} has no .PARAMETER help' -f $name, $parameter) }
        foreach ($parameter in $documented) { Assert-True ($declared -contains $parameter) ('{0}: .PARAMETER {1} is not a parameter' -f $name, $parameter) }
        foreach ($section in @('.SYNOPSIS', '.DESCRIPTION', '.OUTPUTS', '.EXAMPLE')) {
            Assert-True ($text -match ('(?m)^' + [regex]::Escape($section) + '\s*$')) ('{0}: help has no {1} section' -f $name, $section)
        }
        Assert-True ($text -match '(?m)^\s+State changes\b') ('{0}: help has no "State changes" line' -f $name)
        Assert-True ($text -match '(?m)^\s+Elevation:') ('{0}: help has no "Elevation:" line' -f $name)
    }
}

Invoke-TestCase 'Get-Help reads the comment-based help of every probe' {
    foreach ($name in $probeNames) {
        $path = Join-Path $probeDirectory ($name + '.ps1')
        $text = [System.IO.File]::ReadAllText($path)
        $expected = [regex]::Match($text, '(?m)^\.SYNOPSIS\s*\r?\n\s*(\S[^\r\n]*)').Groups[1].Value.Trim()
        $synopsis = ([string](Get-Help -Name $path -ErrorAction Stop).Synopsis).Trim()
        Assert-True ($expected.Length -gt 20 -and $synopsis.StartsWith($expected.Substring(0, 20))) ('{0}: Get-Help shows "{1}"' -f $name, $synopsis.Substring(0, [Math]::Min(80, $synopsis.Length)))
    }
}

Invoke-TestCase 'examples in help and docs use existing parameter names' {
    $sources = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in @(Get-ChildItem -LiteralPath $repoRoot -Recurse -File | Where-Object { @('.md', '.ps1') -contains $_.Extension })) { $sources.Add($file.FullName) }
    foreach ($name in $probeNames) {
        $ast = Get-ScriptAst -Path (Join-Path $probeDirectory ($name + '.ps1'))
        $declared = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) + @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'ErrorVariable', 'WarningVariable', 'InformationVariable')
        foreach ($source in $sources) {
            foreach ($line in [System.IO.File]::ReadAllLines($source)) {
                $index = $line.IndexOf($name + '.ps1')
                if ($index -lt 0) { continue }
                $rest = $line.Substring($index + $name.Length + 4)
                $rest = [regex]::Replace($rest, '"[^"]*"|''[^'']*''|`[^`]*`', ' ')
                foreach ($match in [regex]::Matches($rest, '(?<![\w-])-([A-Za-z][A-Za-z0-9]*)')) {
                    Assert-True ($declared -contains $match.Groups[1].Value) ('{0}: "-{1}" in {2} is not a parameter of {3}' -f [System.IO.Path]::GetFileName($source), $match.Groups[1].Value, $line.Trim(), $name)
                }
            }
        }
    }
}

Invoke-TestCase 'README and docs cover every probe' {
    $readme = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'README.md'))
    $reference = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'docs\probes.md'))
    foreach ($name in $probeNames) {
        Assert-True ($readme.Contains($name)) ('README.md does not mention ' + $name)
        Assert-True ($reference -match ('(?m)^## ' + [regex]::Escape($name) + '\s*$')) ('docs/probes.md has no section for ' + $name)
    }
}
#endregion

#region Help and envelope contract
foreach ($helpProbe in $probeNames) {
    Invoke-TestCase ($helpProbe + ' -Help prints help and exits 0') {
        $result = Invoke-Probe -Name $helpProbe -Arguments @('-Help')
        Assert-Equal 0 $result.ExitCode 'exit code'
        Assert-True ($result.StdOut -match '\.SYNOPSIS') 'help text has no .SYNOPSIS'
        Assert-True (-not $result.StdOut.TrimStart().StartsWith('{')) 'help printed JSON'
    }
}

Invoke-TestCase '-SummaryOnly empties data and -Compress prints one line' {
    $result = Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture, '-Constant', '0x1234ABCD', '-SummaryOnly', '-Compress')
    $text = ([string]$result.StdOut).Trim()
    Assert-True (-not $text.Contains("`n")) 'compressed JSON must be one line'
    $document = Assert-Envelope $result 'Find-PeConstant' $true
    Assert-Equal 0 @($document.data).Count 'data with -SummaryOnly'
    Assert-Equal 4 ([int]$document.summary.totalHits) 'totalHits with -SummaryOnly'
    Assert-True (@($document.summary.caveats | Where-Object { $_ -match 'SummaryOnly' -and $_ -match '4 row' }).Count -eq 1) 'SummaryOnly caveat'
}
#endregion

#region Find-PeConstant
Invoke-TestCase 'Find-PeConstant maps hits to sections, RVAs and VAs' {
    $document = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture, '-Constant', '0x1234ABCD')) 'Find-PeConstant' $true
    Assert-Equal 4 ([int]$document.summary.totalHits) 'totalHits'
    Assert-Equal 'CD AB 34 12' $document.summary.needle 'needle'
    $hits = @($document.data)
    Assert-Equal '0x300' $hits[0].fileOffset 'header hit offset'
    Assert-True ($null -eq $hits[0].rva -and $null -eq $hits[0].section) 'header hit must have no RVA or section'
    Assert-Equal '0x1010' $hits[1].rva '.text hit rva'
    Assert-Equal '0x180001010' $hits[1].va '.text hit va'
    Assert-Equal '.text' $hits[1].section '.text hit section'
    Assert-Equal $true $hits[1].sectionExecutable '.text executable'
    Assert-Equal '0x2140' $hits[2].rva '.rdata hit rva'
    Assert-Equal $false $hits[2].sectionExecutable '.rdata executable'
    Assert-Equal $true $hits[2].mapped '.rdata hit mapped'
    Assert-Equal $false $hits[3].mapped 'hit past VirtualSize must be unmapped'
    Assert-True ($hits[1].contextHex -match '^([0-9A-F]{2} ){19}[0-9A-F]{2}$') ('contextHex format: ' + $hits[1].contextHex)
}

Invoke-TestCase 'Find-PeConstant -Pattern wildcards, -Width 2, -MaxHitsPerFile and -MaxRows' {
    $document = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture, '-Pattern', 'CD AB ?? 12')) 'Find-PeConstant' $true
    Assert-Equal 4 ([int]$document.summary.totalHits) 'pattern hits'
    $document = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture, '-Constant', 'ABCD', '-Width', '2')) 'Find-PeConstant' $true
    Assert-Equal 4 ([int]$document.summary.totalHits) 'width 2 hits'
    $document = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture, '-Constant', '0x1234ABCD', '-MaxHitsPerFile', '2')) 'Find-PeConstant' $true
    Assert-Equal 2 @($document.data).Count 'capped hits'
    Assert-True (@($document.summary.caveats | Where-Object { $_ -match 'MaxHitsPerFile' }).Count -eq 1) 'cap caveat'
    $document = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture, '-Constant', '0x1234ABCD', '-MaxRows', '3')) 'Find-PeConstant' $true
    Assert-Equal 3 @($document.data).Count 'rows with -MaxRows 3'
    Assert-Equal $true $document.summary.truncated 'truncated with -MaxRows'
}

Invoke-TestCase 'Find-PeConstant scans a directory with -Filter and reports non-PE files' {
    $document = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', $workDirectory, '-Filter', '*.dll,*.txt', '-Constant', '0x1234ABCD')) 'Find-PeConstant' $true
    Assert-Equal 2 ([int]$document.summary.filesScanned) 'files scanned'
    Assert-Equal 1 ([int]$document.summary.filesNotPe) 'non-PE files'
    Assert-Equal 1 ([int]$document.summary.filesWithHits) 'filesWithHits is a count'
    Assert-Equal $peFixture (@($document.summary.hitFiles)[0]) 'hitFiles lists the file'
}

Invoke-TestCase 'Find-PeConstant rejects bad input' {
    $null = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture)) 'Find-PeConstant' $false
    $null = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture, '-Constant', '0x123456789', '-Width', '4')) 'Find-PeConstant' $false
    $null = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture, '-Pattern', '?? ??')) 'Find-PeConstant' $false
    $null = Assert-Envelope (Invoke-Probe 'Find-PeConstant' @('-Path', (Join-Path $workDirectory 'missing.dll'), '-Constant', '1')) 'Find-PeConstant' $false
}

Invoke-TestCase 'Find-PeConstant -OutFile writes the same JSON without a BOM' {
    $outFile = Join-Path $workDirectory 'out\pe.json'
    $result = Invoke-Probe 'Find-PeConstant' @('-Path', $peFixture, '-Constant', '0x1234ABCD', '-OutFile', $outFile)
    $null = Assert-Envelope $result 'Find-PeConstant' $true
    $bytes = [System.IO.File]::ReadAllBytes($outFile)
    Assert-True ($bytes[0] -eq 0x7B) 'file must start with "{" (no BOM)'
    Assert-Equal ($result.StdOut.Trim()) ([System.Text.Encoding]::UTF8.GetString($bytes).Trim()) 'file content equals stdout'
}
#endregion

#region Find-CapabilityString
Invoke-TestCase 'Find-CapabilityString finds ASCII and UTF-16LE strings by category' {
    $document = Assert-Envelope (Invoke-Probe 'Find-CapabilityString' @('-Path', $stringsFixture, '-MinCategories', '3')) 'Find-CapabilityString' $true
    $categories = @($document.data | ForEach-Object { $_.category } | Sort-Object -Unique)
    Assert-Equal 'cross_process,rpc_alpc_com,token_and_identity' ($categories -join ',') 'categories'
    $wide = @($document.data | Where-Object { $_.label -eq 'ImpersonateNamedPipeClient' })
    Assert-Equal 1 $wide.Count 'UTF-16LE string found'
    Assert-Equal 'ImpersonateNamedPipeClient' $wide[0].sample 'UTF-16LE sample'
    Assert-Equal 1 @($document.summary.topFiles).Count 'topFiles with 3 categories'
    Assert-Equal 3 ([int]@($document.summary.topFiles)[0].categoryCount) 'category count'
    Assert-Equal $false $document.summary.truncated 'not truncated'
}

Invoke-TestCase 'Find-CapabilityString -Category, -PatternFile and -MaxRows' {
    $document = Assert-Envelope (Invoke-Probe 'Find-CapabilityString' @('-Path', $stringsFixture, '-Category', 'rpc_alpc_com')) 'Find-CapabilityString' $true
    Assert-Equal 'rpc_alpc_com' ((@($document.data | ForEach-Object { $_.category } | Sort-Object -Unique)) -join ',') 'filtered category'
    $document = Assert-Envelope (Invoke-Probe 'Find-CapabilityString' @('-Path', $stringsFixture, '-PatternFile', $patternFile)) 'Find-CapabilityString' $true
    Assert-Equal 1 @($document.data).Count 'custom pattern rows'
    Assert-Equal 'UNIQUE_MARKER_42' @($document.data)[0].sample 'custom pattern sample'
    $null = Assert-Envelope (Invoke-Probe 'Find-CapabilityString' @('-Path', $stringsFixture, '-Category', 'no_such_category')) 'Find-CapabilityString' $false
    $document = Assert-Envelope (Invoke-Probe 'Find-CapabilityString' @('-Path', $stringsFixture, '-MaxRows', '1')) 'Find-CapabilityString' $true
    Assert-Equal 1 @($document.data).Count 'rows with -MaxRows 1'
    Assert-Equal $true $document.summary.truncated 'truncated with -MaxRows 1'
    $counted = 0
    foreach ($property in $document.summary.rowsByCategory.PSObject.Properties) { $counted += [int]$property.Value }
    Assert-Equal 3 $counted 'rowsByCategory counts every row'
}

Invoke-TestCase 'Find-CapabilityString -MaxFiles sets truncated and names the cap' {
    $document = Assert-Envelope (Invoke-Probe 'Find-CapabilityString' @('-Path', $workDirectory, '-Filter', '*', '-MaxFiles', '1')) 'Find-CapabilityString' $true
    Assert-True ([int]$document.summary.filesConsidered -gt 1) ('filesConsidered: ' + $document.summary.filesConsidered)
    Assert-Equal $true $document.summary.truncated 'truncated with -MaxFiles 1'
    Assert-True (@($document.summary.caveats | Where-Object { $_ -match 'MaxFiles' }).Count -eq 1) 'MaxFiles caveat'
}

Invoke-TestCase 'Find-CapabilityString reports a regular expression that times out' {
    & {
        . (Join-Path $probeDirectory 'Find-CapabilityString.ps1')
        $options = [System.Text.RegularExpressions.RegexOptions]::None
        $slow = New-Object System.Text.RegularExpressions.Regex('(x+x+)+y', $options, [TimeSpan]::FromMilliseconds(100))
        $result = Measure-PatternMatch -Regex $slow -Corpus ('x' * 40)
        Assert-Equal $true $result.TimedOut 'timeout reported'
        $fast = New-Object System.Text.RegularExpressions.Regex('ab', $options, [TimeSpan]::FromSeconds(5))
        $result = Measure-PatternMatch -Regex $fast -Corpus 'xxabyyab'
        Assert-Equal $false $result.TimedOut 'no timeout'
        Assert-Equal 2 $result.Total 'match count'
        Assert-Equal 2 $result.FirstIndex 'first index'
    }
}
#endregion

#region Invoke-ProcmonCapture
Invoke-TestCase 'Invoke-ProcmonCapture -ParseCsv applies the default operations' {
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-ParseCsv', $csvFixture)) 'Invoke-ProcmonCapture' $true
    Assert-Equal 'parse-csv' $document.summary.mode 'mode'
    Assert-Equal 5 ([int]$document.summary.totalEvents) 'total events'
    Assert-Equal 4 ([int]$document.summary.keptEvents) 'kept events'
    $first = @($document.data)[0]
    Assert-Equal 'svchost.exe' $first.processName 'processName'
    Assert-Equal 1234 ([int]$first.pid) 'pid'
    Assert-Equal 'NT AUTHORITY\SYSTEM' $first.user 'user column'
}

Invoke-TestCase 'Invoke-ProcmonCapture -ParseCsv filters and -MaxRows' {
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-ParseCsv', $csvFixture, '-ProcessName', 'svchost')) 'Invoke-ProcmonCapture' $true
    Assert-Equal 2 ([int]$document.summary.keptEvents) 'process filter'
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-ParseCsv', $csvFixture, '-Operation', '*', '-PathFilter', '\\ProgramData\\')) 'Invoke-ProcmonCapture' $true
    Assert-Equal 2 ([int]$document.summary.keptEvents) 'path filter with all operations'
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-ParseCsv', $csvFixture, '-MaxRows', '1')) 'Invoke-ProcmonCapture' $true
    Assert-Equal 1 @($document.data).Count 'rows after -MaxRows'
    Assert-Equal $true $document.summary.truncated 'truncated'
    $null = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-ParseCsv', $csvFixture, '-PathFilter', '([')) 'Invoke-ProcmonCapture' $false
}

Invoke-TestCase 'Invoke-ProcmonCapture -DryRun starts nothing and reports readiness' {
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-DryRun')) 'Invoke-ProcmonCapture' $true
    Assert-Equal 'dry-run' $document.summary.mode 'mode'
    Assert-True ($document.summary.PSObject.Properties.Name -contains 'ready') 'ready field'
}

Invoke-TestCase 'Invoke-ProcmonCapture runs as -DryRun without a mode and needs -Capture to capture' {
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @()) 'Invoke-ProcmonCapture' $true
    Assert-Equal 'dry-run' $document.summary.mode 'mode without arguments'
    Assert-True (@($document.summary.caveats | Where-Object { $_ -match 'No mode was given' }).Count -eq 1) 'no-mode caveat'
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-TriggerCommand', 'sc.exe query spooler')) 'Invoke-ProcmonCapture' $false
    Assert-True ($document.error -match '-Capture') ('error without -Capture: ' + $document.error)
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-Capture', '-DryRun')) 'Invoke-ProcmonCapture' $false
    Assert-True ($document.error -match 'only one of') ('error with two modes: ' + $document.error)
}

Invoke-TestCase 'Invoke-ProcmonCapture -Capture refuses an existing CSV next to -BackingFile and leaves it alone' {
    $pml = Join-Path $workDirectory 'run.pml'
    $csv = Join-Path $workDirectory 'run.csv'
    [System.IO.File]::WriteAllText($csv, 'keep me', $utf8)
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-Capture', '-BackingFile', $pml)) 'Invoke-ProcmonCapture' $false
    Assert-True ($document.error -match 'already exists') ('error: ' + $document.error)
    Assert-Equal 'keep me' ([System.IO.File]::ReadAllText($csv)) 'content of the existing run.csv'
    Assert-True (-not (Test-Path -LiteralPath $pml)) 'no .pml file was created'
}

Invoke-TestCase 'Invoke-ProcmonCapture -Capture refuses a -BackingFile in a missing directory and creates nothing' {
    $missing = Join-Path $workDirectory 'missing-capture-dir'
    $document = Assert-Envelope (Invoke-Probe 'Invoke-ProcmonCapture' @('-Capture', '-BackingFile', (Join-Path $missing 'run.pml'))) 'Invoke-ProcmonCapture' $false
    Assert-True ($document.error -match 'does not exist') ('error: ' + $document.error)
    Assert-True (-not (Test-Path -LiteralPath $missing)) 'the directory was not created'
}

Invoke-TestCase 'a quoted trigger command line reaches the program unchanged through cmd.exe' {
    $echoDirectory = Join-Path $workDirectory 'echo dir'
    $null = New-Item -ItemType Directory -Path $echoDirectory
    $echoScript = Join-Path $echoDirectory 'echo args.ps1'
    [System.IO.File]::WriteAllText($echoScript, 'foreach ($a in $args) { [Console]::Out.WriteLine(''<'' + $a + ''>'') }', $utf8)
    $command = '"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{1}" "a b" c' -f $PowerShellPath, $echoScript
    & {
        . (Join-Path $probeDirectory 'Invoke-ProcmonCapture.ps1')
        $line = Get-TriggerArgumentLine -Command $command
        Assert-Equal ('/d /s /c "' + $command + '"') $line 'trigger argument line'
        $result = Invoke-ChildProcess -FilePath (Join-Path ([System.Environment]::SystemDirectory) 'cmd.exe') -Arguments $line -TimeoutSeconds 120
        Assert-Equal 0 $result.ExitCode ('exit code (stderr: {0})' -f $result.StdErr)
        $lines = @(([string]$result.StdOut).Trim() -split '\r?\n')
        Assert-Equal '<a b>|<c>' ($lines -join '|') 'arguments received by the program'
    }
}
#endregion

#region Invoke-RpcEtwSniffer
Invoke-TestCase 'Invoke-RpcEtwSniffer -DryRun starts nothing' {
    $document = Assert-Envelope (Invoke-Probe 'Invoke-RpcEtwSniffer' @('-DryRun')) 'Invoke-RpcEtwSniffer' $true
    Assert-Equal 'dry-run' $document.summary.mode 'mode'
    Assert-True ($document.summary.sessionName -match '^win-agent-probes-rpc-\d+-\d{14}$') ('default session name: ' + $document.summary.sessionName)
    foreach ($field in @('logman', 'elevatedNow', 'performanceLogUser', 'ready')) {
        Assert-True ($document.summary.PSObject.Properties.Name -contains $field) ('dry-run field ' + $field)
    }
}

Invoke-TestCase 'Invoke-RpcEtwSniffer runs as -DryRun without a mode and needs -Capture to capture' {
    $document = Assert-Envelope (Invoke-Probe 'Invoke-RpcEtwSniffer' @()) 'Invoke-RpcEtwSniffer' $true
    Assert-Equal 'dry-run' $document.summary.mode 'mode without arguments'
    Assert-True (@($document.summary.caveats | Where-Object { $_ -match 'No mode was given' }).Count -eq 1) 'no-mode caveat'
    $document = Assert-Envelope (Invoke-Probe 'Invoke-RpcEtwSniffer' @('-TriggerCommand', 'sc.exe query spooler')) 'Invoke-RpcEtwSniffer' $false
    Assert-True ($document.error -match '-Capture') ('error without -Capture: ' + $document.error)
}

Invoke-TestCase 'Invoke-RpcEtwSniffer -Capture refuses an existing -EtlPath and leaves it alone' {
    $etl = Join-Path $workDirectory 'existing.etl'
    [System.IO.File]::WriteAllText($etl, 'keep me', $utf8)
    $document = Assert-Envelope (Invoke-Probe 'Invoke-RpcEtwSniffer' @('-Capture', '-EtlPath', $etl)) 'Invoke-RpcEtwSniffer' $false
    Assert-True ($document.error -match 'already exists') ('error: ' + $document.error)
    Assert-Equal 'keep me' ([System.IO.File]::ReadAllText($etl)) 'content of the existing file'
}

Invoke-TestCase 'Invoke-RpcEtwSniffer -Capture refuses an -EtlPath in a missing directory and creates nothing' {
    $missing = Join-Path $workDirectory 'missing-etl-dir'
    $document = Assert-Envelope (Invoke-Probe 'Invoke-RpcEtwSniffer' @('-Capture', '-EtlPath', (Join-Path $missing 'rpc.etl'))) 'Invoke-RpcEtwSniffer' $false
    Assert-True ($document.error -match 'does not exist') ('error: ' + $document.error)
    Assert-True (-not (Test-Path -LiteralPath $missing)) 'the directory was not created'
}

Invoke-TestCase 'Invoke-RpcEtwSniffer parses event data and aggregates calls' {
    & {
        . (Join-Path $probeDirectory 'Invoke-RpcEtwSniffer.ps1')
        $xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>5</EventID></System><EventData>" +
            "<Data Name='InterfaceUuid'>{367ABB81-9844-35F1-AD32-98F038001003}</Data><Data Name='ProcNum'>0x1B</Data>" +
            "<Data Name='Protocol'>3</Data><Data Name='NetworkAddress'>NULL</Data><Data Name='Endpoint'>ntsvcs</Data>" +
            "<Data Name='Options'>NULL</Data><Data Name='AuthenticationLevel'>6</Data><Data Name='AuthenticationService'>10</Data>" +
            "<Data Name='ImpersonationLevel'>2</Data></EventData></Event>"
        $map = Get-EventDataMap -EventXml $xml
        Assert-Equal 9 $map.Count 'field count'
        $row = ConvertTo-RpcCallRow -EventId 5 -ProcessId 100 -ThreadId 7 -TimeUtc 't' -Map $map -WithRaw $false
        Assert-Equal '367abb81-9844-35f1-ad32-98f038001003' $row.interfaceUuid 'interface key'
        Assert-Equal ([int64]27) $row.opnum 'hex opnum'
        Assert-Equal ([int64]3) $row.protocol 'protocol'
        Assert-Equal 'client' $row.side 'side'
        Assert-Equal 100 $row.pid 'pid field'
        Assert-True ($null -eq (ConvertTo-RpcCallRow -EventId 7 -ProcessId 1 -ThreadId 1 -TimeUtc 't' -Map $map -WithRaw $false)) 'event 7 is not a call row'
        $second = ConvertTo-RpcCallRow -EventId 5 -ProcessId 100 -ThreadId 7 -TimeUtc 't' -Map $map -WithRaw $false
        $second.opnum = [int64]15
        $server = ConvertTo-RpcCallRow -EventId 6 -ProcessId 200 -ThreadId 9 -TimeUtc 't' -Map $map -WithRaw $false
        $groups = @(Measure-RpcByInterface -Rows @($row, $second, $server))
        Assert-Equal 1 $groups.Count 'one interface'
        Assert-Equal 3 $groups[0].calls 'calls'
        Assert-Equal '15,27' ((@($groups[0].opnums)) -join ',') 'opnums'
        Assert-Equal '100' ((@($groups[0].clientPids)) -join ',') 'client pids'
        Assert-Equal '200' ((@($groups[0].serverPids)) -join ',') 'server pids'
        Assert-Equal $false $groups[0].endpointsTruncated 'endpoints not truncated'
        Assert-True (Test-InterfaceFilter -InterfaceUuid $row.interfaceUuid -Filters @('{367ABB81')) 'filter match'
        Assert-True (-not (Test-InterfaceFilter -InterfaceUuid $row.interfaceUuid -Filters @('deadbeef'))) 'filter mismatch'
        $many = New-Object 'System.Collections.Generic.List[object]'
        foreach ($index in 1..12) {
            $copy = ConvertTo-RpcCallRow -EventId 5 -ProcessId 100 -ThreadId 7 -TimeUtc 't' -Map $map -WithRaw $false
            $copy.endpoint = 'endpoint-' + $index
            $many.Add($copy)
        }
        $groups = @(Measure-RpcByInterface -Rows $many.ToArray() -MaxEndpoints 10)
        Assert-Equal 10 @($groups[0].endpoints).Count 'endpoint list is capped'
        Assert-Equal $true $groups[0].endpointsTruncated 'endpointsTruncated'
        Assert-Equal ([int64]3) (Get-LogmanCounter -Text "Buffer Size:          256`nBuffers Lost:         3`nBuffers Written:      9" -Label 'Buffers Lost') 'Buffers Lost value'
        Assert-True ($null -eq (Get-LogmanCounter -Text 'Name: x' -Label 'Events Lost')) 'missing counter is null'
    }
}
#endregion

#region Get-EffectiveAccess
Invoke-TestCase 'Get-EffectiveAccess input validation' {
    $null = Assert-Envelope (Invoke-Probe 'Get-EffectiveAccess' @()) 'Get-EffectiveAccess' $false
    $document = Assert-Envelope (Invoke-Probe 'Get-EffectiveAccess' @('-FilePath', $workDirectory)) 'Get-EffectiveAccess' $false
    Assert-True ($document.error -match 'Principal') 'missing -Principal error'
    $document = Assert-Envelope (Invoke-Probe 'Get-EffectiveAccess' @('-Principal', 'someone', '-FilePath', $workDirectory, '-AccessChkPath', (Join-Path $workDirectory 'missing.exe'))) 'Get-EffectiveAccess' $false
    Assert-True ($document.error -match 'not found') 'missing accesschk error'
    $document = Assert-Envelope (Invoke-Probe 'Get-EffectiveAccess' @('-Principal', '/x', '-Service', '*')) 'Get-EffectiveAccess' $false
    Assert-True ($document.error -match 'must not start') 'principal that looks like a switch'
    # -MaxRows 0 stops the probe before it looks for NtObjectManager; params shows how the
    # value was read.
    $document = Assert-Envelope (Invoke-Probe 'Get-EffectiveAccess' @('-ObjectDirectory', '\RPC Control,x', '-MaxRows', '0')) 'Get-EffectiveAccess' $false
    Assert-Equal '\RPC Control,x' (@($document.params.ObjectDirectory) -join '|') 'an object-manager path is not split on commas'
}

Invoke-TestCase 'Get-EffectiveAccess parsers and argument quoting' {
    & {
        . (Join-Path $probeDirectory 'Get-EffectiveAccess.ps1')
        $parsed = ConvertFrom-AccessChkOutput -Lines @('RW C:\Data\a.txt', 'R  C:\Data\b.txt', '  W C:\Data\c', 'Error opening C:\x: Access is denied.', '', 'No matching objects found.')
        Assert-Equal 3 @($parsed.Entries).Count 'entries'
        Assert-Equal 'RW' $parsed.Entries[0].Access 'first access'
        Assert-Equal 'C:\Data\b.txt' $parsed.Entries[1].Name 'second name'
        Assert-Equal 'W' $parsed.Entries[2].Access 'third access'
        Assert-Equal 2 @($parsed.Messages).Count 'messages'
        Assert-Equal 'HKLM\SOFTWARE\Contoso' (ConvertTo-AccessChkKey -Key 'HKLM:\SOFTWARE\Contoso') 'accesschk key'
        Assert-Equal 'HKLM\SOFTWARE' (ConvertTo-AccessChkKey -Key 'Registry::HKLM\SOFTWARE') 'provider prefix removed'
        Assert-Equal 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Contoso' (ConvertTo-RegistryProviderPath -Key 'HKLM:\SOFTWARE\Contoso') 'provider path'
        Assert-Equal 'Registry::HKEY_USERS' (ConvertTo-RegistryProviderPath -Key 'HKU') 'hive only'
        Assert-True (Test-WriteLikeAccess 'ReadData, WriteData, Synchronize') 'WriteData is write-like'
        Assert-True (Test-WriteLikeAccess 'GenericAll') 'GenericAll is write-like'
        Assert-True (Test-WriteLikeAccess 'Full Access') 'Full Access is write-like'
        Assert-True (-not (Test-WriteLikeAccess 'ReadData, ReadAttributes, Synchronize')) 'read rights are not write-like'
        Assert-True (-not (Test-WriteLikeAccess '')) 'empty is not write-like'
        Assert-True (-not (Test-WriteLikeAccess '1180063')) 'a numeric access mask is not read as names'
        Assert-Equal '-accepteula -nobanner -w -d someone "C:\Program Files\\"' (Join-ArgumentList @('-accepteula', '-nobanner', '-w', '-d', 'someone', 'C:\Program Files\')) 'trailing backslash is kept'
    }
}

Invoke-TestCase 'Get-EffectiveAccess turns AccessChk output into rows, with a stand-in for AccessChk' {
    & {
        . (Join-Path $probeDirectory 'Get-EffectiveAccess.ps1')
        $script:StandInExe = $null
        $script:StandInArguments = $null
        $script:StandInOutput = @('Error opening C:\Missing\x.txt:', 'The system cannot find the path specified.')
        function Invoke-AccessChk {
            param([string]$Exe, [string[]]$Arguments)
            $script:StandInExe = $Exe
            $script:StandInArguments = $Arguments
            return $script:StandInOutput
        }
        Add-AccessChkResult -Exe 'stand-in' -Switches @('-w') -Target 'C:\Missing\x.txt' -Category 'file' -Account 'someone' -ReportTarget $true
        Assert-Equal 'stand-in' $script:StandInExe 'AccessChk path'
        Assert-Equal '-accepteula|-nobanner|-w|someone|C:\Missing\x.txt' ($script:StandInArguments -join '|') 'AccessChk arguments'
        $rows = $script:AccessRows.ToArray()
        Assert-Equal 1 $rows.Count 'error row'
        Assert-True ($null -eq $rows[0].access -and $null -eq $rows[0].writable) 'an error row has access and writable null'
        Assert-True ($rows[0].error -match 'cannot find the path') ('error text: ' + $rows[0].error)
        Assert-Equal 1 $script:ErrorRows 'error rows counted'
        Assert-Equal 0 $script:ObjectsChecked 'an error row is not a checked object'
        $script:StandInOutput = @('RW C:\Data\a.txt', 'R  C:\Data\b.txt')
        Add-AccessChkResult -Exe 'stand-in' -Switches @('-s', '-w') -Target 'C:\Data' -Category 'filesystem' -Account 'someone' -ReportTarget $false
        $rows = $script:AccessRows.ToArray()
        Assert-Equal 2 $rows.Count 'one writable row added'
        Assert-Equal 'C:\Data\a.txt' $rows[1].name 'writable row'
        Assert-Equal $true $rows[1].writable 'writable flag'
        Assert-Equal 1 $script:RowsFiltered 'read-only row filtered'
        $script:StandInOutput = @()
        Add-AccessChkResult -Exe 'stand-in' -Switches @('-d', '-w') -Target 'C:\NoWrite' -Category 'directory' -Account 'someone' -ReportTarget $true
        Assert-Equal 2 $script:AccessRows.ToArray().Count 'a target without output is not a row by default'
        Assert-Equal 3 $script:ObjectsChecked 'objects checked'
    }
}

Invoke-TestCase 'Get-EffectiveAccess reads NtObjectManager results, with stand-in cmdlets' {
    & {
        . (Join-Path $probeDirectory 'Get-EffectiveAccess.ps1')
        $script:StandInProcessIds = 'not called'
        function Get-AccessibleAlpcPort {
            [CmdletBinding()]
            param([int[]]$ProcessIds)
            $script:StandInProcessIds = $ProcessIds
            [pscustomobject]@{ Name = '\RPC Control\SamplePort'; TypeName = 'ALPC Port'; GrantedAccess = 1; GrantedAccessString = 'Connect'; IsWrite = $false; IsAll = $false }
            [pscustomobject]@{ Name = '\RPC Control\OtherPort'; TypeName = 'ALPC Port'; GrantedAccess = 1 }
        }
        function Get-AccessibleNamedPipe {
            [CmdletBinding()]
            param([int[]]$ProcessIds)
            $script:StandInProcessIds = $ProcessIds
            [pscustomobject]@{ Name = '\Device\NamedPipe\readonly'; TypeName = 'File'; GrantedAccessString = 'ReadData, Synchronize'; IsWrite = $false; IsAll = $false }
            [pscustomobject]@{ Name = '\Device\NamedPipe\writable'; TypeName = 'File'; GrantedAccessString = 'ReadData, WriteData'; IsWrite = $true; IsAll = $false }
            [pscustomobject]@{ Name = '\Device\NamedPipe\dac'; TypeName = 'File'; GrantedAccessString = 'ReadControl, WriteDac'; IsWrite = $false; IsAll = $false }
        }
        Add-NtAccessibleResult -CommandName 'Get-AccessibleAlpcPort' -Category 'alpcPort' -Required @{} -Optional @{} -Subject 'token of the current process'
        Add-NtAccessibleResult -CommandName 'Get-AccessibleNamedPipe' -Category 'namedPipe' -Required @{} -Optional @{} -Subject 'token of the current process'
        Assert-True ($null -eq $script:StandInProcessIds) 'without -ProcessId, the cmdlets get no -ProcessIds value'
        $rows = $script:AccessRows.ToArray()
        Assert-Equal '\RPC Control\SamplePort|\Device\NamedPipe\writable|\Device\NamedPipe\dac' (($rows | ForEach-Object { $_.name }) -join '|') 'kept rows'
        Assert-Equal 'Connect' $rows[0].access 'ALPC access names'
        Assert-Equal $false $rows[0].writable 'an ALPC port with Connect only is kept but not writable'
        Assert-Equal $true $rows[2].writable 'WriteDac is write-type access'
        Assert-Equal 1 $script:RowsFiltered 'read-only pipe filtered'
        Assert-True (@($script:ProbeCaveats | Where-Object { $_ -match 'without the IsWrite' }).Count -eq 1) 'caveat for a result without the expected fields'
    }
}

Invoke-TestCase 'external tools are not taken from PATH in an elevated session' {
    & {
        . (Join-Path $probeDirectory 'Get-EffectiveAccess.ps1')
        $refused = Resolve-ExternalTool -Explicit '' -Names @('cmd.exe') -FixedPaths @() -Elevated $true
        Assert-True ($null -eq $refused.Path -and $refused.PathSkipped) 'PATH is not searched when elevated'
        $fixed = Resolve-ExternalTool -Explicit '' -Names @('cmd.exe') -FixedPaths @($peFixture) -Elevated $true
        Assert-Equal $peFixture $fixed.Path 'install directory used when elevated'
        $onPath = Resolve-ExternalTool -Explicit '' -Names @('cmd.exe') -FixedPaths @() -Elevated $false
        Assert-True ($onPath.Path -match '\\cmd\.exe$' -and $onPath.Source -eq 'PATH') 'PATH is searched when not elevated'
        $explicit = Resolve-ExternalTool -Explicit $peFixture -Names @() -FixedPaths @() -Elevated $true
        Assert-Equal $peFixture $explicit.Path 'explicit path'
        $missing = Resolve-ExternalTool -Explicit (Join-Path $workDirectory 'missing.exe') -Names @('cmd.exe') -FixedPaths @() -Elevated $false
        Assert-True ($null -eq $missing.Path) 'a missing explicit path is not replaced by a PATH result'
        $roots = @('C:\Windows\System32\WindowsPowerShell\v1.0', 'C:\Program Files', 'C:\Program Files (x86)')
        Assert-True (Test-TrustedModuleBase -ModuleBase 'C:\Program Files\WindowsPowerShell\Modules\NtObjectManager\2.0.1' -TrustedRoots $roots) 'module under Program Files'
        Assert-True (Test-TrustedModuleBase -ModuleBase 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\X' -TrustedRoots $roots) 'module under the PowerShell installation directory'
        Assert-True (-not (Test-TrustedModuleBase -ModuleBase 'C:\Users\analyst\Documents\WindowsPowerShell\Modules\NtObjectManager\2.0.1' -TrustedRoots $roots)) 'module under the profile'
        Assert-True (-not (Test-TrustedModuleBase -ModuleBase 'C:\Users\Public\Modules\X' -TrustedRoots $roots)) 'module in a folder that a user added to PSModulePath'
        Assert-True (-not (Test-TrustedModuleBase -ModuleBase 'C:\Program Files\..\Users\Public\Modules\X' -TrustedRoots $roots)) 'a path that leads out of Program Files with ..'
        Assert-True (-not (Test-TrustedModuleBase -ModuleBase 'C:\Program Files Extra\Modules\X' -TrustedRoots $roots)) 'a folder whose name only starts like Program Files'
        Assert-True (-not (Test-TrustedModuleBase -ModuleBase '\\server\share\Modules\X' -TrustedRoots $roots)) 'module on a share'
        Assert-True (-not (Test-TrustedModuleBase -ModuleBase 'Modules\X' -TrustedRoots $roots)) 'a relative path'
    }
}
#endregion

#region Get-PrivilegedSurfaceMap and Get-ComponentNeighborhood
Invoke-TestCase 'Get-PrivilegedSurfaceMap rejects an empty selection' {
    $null = Assert-Envelope (Invoke-Probe 'Get-PrivilegedSurfaceMap' @('-SkipProcesses', '-SkipServices', '-SkipTasks')) 'Get-PrivilegedSurfaceMap' $false
}

Invoke-TestCase 'Get-PrivilegedSurfaceMap helpers' {
    & {
        . (Join-Path $probeDirectory 'Get-PrivilegedSurfaceMap.ps1')
        $german = 'NT-AUTORIT' + [char]0x00C4 + 'T'
        $set = Get-PrivilegedNameSet -LocalizedNames @(($german + '\SYSTEM'), ($german + '\LOKALER DIENST'), ($german + '\NETZWERKDIENST'))
        foreach ($account in @('NT AUTHORITY\SYSTEM', 'LocalSystem', 'NT AUTHORITY\Local Service', 'NT AUTHORITY\NetworkService', 'S-1-5-18', 'system', ($german + '\LOKALER DIENST'), 'LOKALER DIENST', ($german + '\NETZWERKDIENST'))) {
            Assert-True (Test-PrivilegedPrincipal -Account $account -NameSet $set) ($account + ' must count as privileged')
        }
        foreach ($account in @('S-1-5-180', 'NT SERVICE\TrustedInstaller', 'CONTOSO\user', '', 'Users', 'CONTOSO\SYSTEM')) {
            Assert-True (-not (Test-PrivilegedPrincipal -Account $account -NameSet $set)) ($account + ' must not count as privileged')
        }
        Assert-True (Test-PrivilegedPrincipal -Account 'any name' -Sid 'S-1-5-19' -NameSet $set) 'the SID decides'
        Assert-True (-not (Test-PrivilegedPrincipal -Account 'any name' -Sid 'S-1-5-21-1-2-3-1001' -NameSet $set)) 'a user SID is not privileged'
        Assert-Equal 3 (Get-LocalizedPrivilegedName).Count 'names of the three SIDs on this system'
        Assert-Equal 'x64' (Get-PeMachineName -FilePath $peFixture) 'machine of the fixture'
        Assert-True ($null -eq (Get-PeMachineName -FilePath $textFixture)) 'text file has no machine'
        Assert-Equal 'C:\Program Files\A\b.exe' ((Get-TaskExecutableCandidate '"C:\Program Files\A\b.exe"') -join '|') 'quoted Execute value'
        Assert-Equal 'C:\Program Files\A\b.exe|C:\Program' ((Get-TaskExecutableCandidate 'C:\Program Files\A\b.exe') -join '|') 'unquoted Execute value: the whole value first'
        Assert-Equal 'windows-light' (ConvertTo-LaunchProtectedName 2) 'launch protected name'
    }
}

Invoke-TestCase 'Get-PrivilegedSurfaceMap does not open network or device paths' {
    & {
        . (Join-Path $probeDirectory 'Get-PrivilegedSurfaceMap.ps1')
        # 192.0.2.1 is in the documentation range of RFC 5737. These checks and the two
        # tests below must not touch the network: Test-LocalFilePath rejects the path
        # before any file access.
        foreach ($path in @('\\192.0.2.1\share\a.exe', '\\?\UNC\host\share\a.exe', '\\.\pipe\sample', '\\host@SSL\DavWWWRoot\a.exe', '//host/share/a.exe', '')) {
            Assert-True (-not (Test-LocalFilePath $path)) ($path + ' must not count as local')
        }
        Assert-True (Test-LocalFilePath (Join-Path ([System.Environment]::SystemDirectory) 'cmd.exe')) 'System32 path is local'
        Assert-True (Test-LocalFilePath 'cmd.exe') 'a bare name is local'
    }
}

Invoke-TestCase 'Get-PrivilegedSurfaceMap resolves task programs, with spaces and without a path' {
    & {
        . (Join-Path $probeDirectory 'Get-PrivilegedSurfaceMap.ps1')
        $resolved = Resolve-TaskExecutable -Execute $spacedProgram -SearchDirectories @()
        Assert-Equal $spacedProgram $resolved.Path 'unquoted path with spaces'
        Assert-Equal $true $resolved.Exists 'unquoted path with spaces exists'
        $missing = Resolve-TaskExecutable -Execute (Join-Path $workDirectory 'No Such Dir\app.exe') -SearchDirectories @()
        Assert-Equal (Join-Path $workDirectory 'No Such Dir\app.exe') $missing.Path 'a missing file keeps the whole value'
        Assert-Equal $false $missing.Exists 'a missing local file'
        $remote = Resolve-TaskExecutable -Execute '\\192.0.2.1\share\a.exe' -SearchDirectories @()
        Assert-True ($remote.NotOpened -and $null -eq $remote.Exists) 'a network path is not opened'
        $bare = Resolve-TaskExecutable -Execute 'cmd.exe' -SearchDirectories @([System.Environment]::SystemDirectory)
        Assert-Equal (Join-Path ([System.Environment]::SystemDirectory) 'cmd.exe') $bare.Path 'a bare name in a search directory'
        $unknown = Resolve-TaskExecutable -Execute 'no-such-program-name' -SearchDirectories @($workDirectory)
        Assert-True ($unknown.Unresolved -and $null -eq $unknown.Exists) 'an unknown bare name is not reported as missing'
    }
}

Invoke-TestCase 'Get-PrivilegedSurfaceMap builds task rows and leaves arguments out with -OmitCommandLine' {
    & {
        . (Join-Path $probeDirectory 'Get-PrivilegedSurfaceMap.ps1')
        $task = [pscustomobject]@{
            TaskPath  = '\Sample\'
            TaskName  = 'Sample task'
            State     = 'Ready'
            Principal = [pscustomobject]@{ UserId = 'SYSTEM'; GroupId = $null; RunLevel = 'Highest'; LogonType = 'ServiceAccount' }
            Actions   = @(
                [pscustomobject]@{ Execute = $spacedProgram; Arguments = '/token sample-value'; ClassId = $null },
                [pscustomobject]@{ Execute = $null; Arguments = $null; ClassId = '{00000000-0000-0000-0000-000000000001}' })
            Triggers  = @([pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskBootTrigger' } })
        }
        $counters = @{ NotOpened = 0; Unresolved = 0; Expanded = 0; Failed = 0 }
        $row = ConvertTo-TaskRow -Task $task -WithCommandLine $false -SearchDirectories @() -Counters $counters
        Assert-True ($null -eq $row.arguments) 'arguments are left out'
        Assert-Equal $true $row.executableExists 'executableExists'
        Assert-Equal 'x64' $row.machine 'machine'
        Assert-Equal 'Highest' $row.runLevel 'runLevel'
        Assert-Equal 'MSFT_TaskBootTrigger' (@($row.triggerTypes) -join ',') 'trigger types'
        Assert-Equal 1 @($row.comHandlers).Count 'COM handler'
        $row = ConvertTo-TaskRow -Task $task -WithCommandLine $true -SearchDirectories @() -Counters $counters
        Assert-Equal '/token sample-value' $row.arguments 'arguments are kept'
        $task.Actions[0].Execute = '\\192.0.2.1\share\a.exe'
        $row = ConvertTo-TaskRow -Task $task -WithCommandLine $true -SearchDirectories @() -Counters $counters
        Assert-True ($null -eq $row.executableExists -and $null -eq $row.machine) 'a network program is not opened'
        Assert-Equal 1 $counters['NotOpened'] 'counted for the caveat'
    }
}

Invoke-TestCase 'Get-ComponentNeighborhood rejects a missing component' {
    $null = Assert-Envelope (Invoke-Probe 'Get-ComponentNeighborhood' @()) 'Get-ComponentNeighborhood' $false
    $null = Assert-Envelope (Invoke-Probe 'Get-ComponentNeighborhood' @('-Component', 'no-such-component-name', '-SearchRoot', $workDirectory)) 'Get-ComponentNeighborhood' $false
}

Invoke-TestCase 'Get-ComponentNeighborhood import parser and name matching' {
    & {
        . (Join-Path $probeDirectory 'Get-ComponentNeighborhood.ps1')
        $imports = Get-PeImportList -Bytes ([System.IO.File]::ReadAllBytes($peFixture))
        Assert-True ($null -eq $imports.Error) ('import parse error: ' + $imports.Error)
        Assert-Equal 'sample-import.dll' ((@($imports.Imports)) -join ',') 'imports'
        Assert-Equal 'sample-delay.dll' ((@($imports.DelayImports)) -join ',') 'delay imports'
        Assert-Equal 0x8664 $imports.Machine 'machine'
        Assert-True (Test-ReferencesBasename -Text 'C:\Windows\system32\svchost.exe -k netsvcs' -Basename 'svchost.exe') 'path with arguments'
        Assert-True (Test-ReferencesBasename -Text '"C:\Program Files\A\svc.dll"' -Basename 'svc.dll') 'quoted path'
        Assert-True (-not (Test-ReferencesBasename -Text '%SystemRoot%\System32\mysvc.dll' -Basename 'svc.dll')) 'suffix of another name'
        Assert-Equal $peFixture (Resolve-ComponentPath -Name 'fixture' -Root $workDirectory) 'name without extension resolves to .dll'
        $emptyRoot = Join-Path $workDirectory 'empty-root'
        $null = New-Item -ItemType Directory -Path $emptyRoot
        Push-Location -LiteralPath $workDirectory
        try {
            Assert-True ($null -eq (Resolve-ComponentPath -Name 'fixture.dll' -Root $emptyRoot)) 'a bare name is not taken from the current directory'
            Assert-Equal $peFixture (Resolve-ComponentPath -Name '.\fixture.dll' -Root $emptyRoot) 'a relative path with a separator is used as given'
        } finally {
            Pop-Location
        }
    }
}

Invoke-TestCase 'Get-ComponentNeighborhood matches service files by full path' {
    & {
        . (Join-Path $probeDirectory 'Get-ComponentNeighborhood.ps1')
        $windows = [System.Environment]::GetFolderPath('Windows')
        $svchost = Join-Path $windows 'System32\svchost.exe'
        $driver = Join-Path $windows 'System32\drivers\sample.sys'
        Assert-Equal 'path' (Get-ServiceImageMatch -PathName ($svchost + ' -k netsvcs -p') -TargetPath $svchost -TargetName 'svchost.exe') 'program with arguments'
        Assert-Equal 'path' (Get-ServiceImageMatch -PathName ('"' + $svchost + '" -k sample') -TargetPath $svchost -TargetName 'svchost.exe') 'quoted program'
        Assert-Equal 'path' (Get-ServiceImageMatch -PathName '\SystemRoot\System32\drivers\sample.sys' -TargetPath $driver -TargetName 'sample.sys') '\SystemRoot\ driver path'
        Assert-Equal 'path' (Get-ServiceImageMatch -PathName 'System32\drivers\sample.sys' -TargetPath $driver -TargetName 'sample.sys') 'relative driver path'
        Assert-Equal 'path' (Get-ServiceImageMatch -PathName 'C:\Program Files\Contoso\svc.exe -k x' -TargetPath 'C:\Program Files\Contoso\svc.exe' -TargetName 'svc.exe') 'unquoted program path with spaces'
        Assert-Equal 'path' (Get-ServiceImageMatch -PathName ((Join-Path $windows 'System32\rundll32.exe') + ' C:\Contoso\x.dll,Entry') -TargetPath 'C:\Contoso\x.dll' -TargetName 'x.dll') 'file named in the arguments'
        Assert-Equal 'name' (Get-ServiceImageMatch -PathName 'C:\Other\version.dll' -TargetPath 'C:\Vendor\version.dll' -TargetName 'version.dll') 'same name at another path'
        Assert-True ($null -eq (Get-ServiceImageMatch -PathName '%SystemRoot%\System32\mysvc.dll' -TargetPath 'C:\Contoso\svc.dll' -TargetName 'svc.dll')) 'another file name'
        Assert-Equal 'C:\Program Files\Contoso\svc.exe' (Get-ServiceProgramPath -PathName 'C:\Program Files\Contoso\svc.exe -k x') 'program part of an unquoted command line'
        $needles = Get-NameNeedlePattern -Name 'svc.dll'
        $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        $ascii = New-Object System.Text.RegularExpressions.Regex($needles.Ascii, $options)
        $wide = New-Object System.Text.RegularExpressions.Regex($needles.Wide, $options)
        $latin1 = [System.Text.Encoding]::GetEncoding(28591)
        Assert-True ($ascii.IsMatch('load C:\x\SVC.DLL now')) 'ASCII whole name'
        Assert-True (-not $ascii.IsMatch('mysvc.dll')) 'ASCII suffix of another name'
        Assert-True (-not $ascii.IsMatch('svc.dll2')) 'ASCII prefix of another name'
        Assert-True ($wide.IsMatch($latin1.GetString([System.Text.Encoding]::Unicode.GetBytes('C:\x\svc.dll')))) 'UTF-16LE whole name'
        Assert-True (-not $wide.IsMatch($latin1.GetString([System.Text.Encoding]::Unicode.GetBytes('mysvc.dll')))) 'UTF-16LE suffix of another name'
    }
}

Invoke-TestCase 'Get-ComponentNeighborhood counts a process whose module list cannot be read' {
    & {
        . (Join-Path $probeDirectory 'Get-ComponentNeighborhood.ps1')
        $denied = New-Object psobject
        $denied | Add-Member -MemberType ScriptMethod -Name get_Modules -Value { throw 'Access is denied' }
        $list = Get-ProcessModuleList -Process $denied
        Assert-True (-not $list.Readable -and @($list.Modules).Count -eq 0) 'an access error is reported'
        $own = Get-ProcessModuleList -Process ([System.Diagnostics.Process]::GetCurrentProcess())
        Assert-True ($own.Readable -and @($own.Modules).Count -gt 0) 'the module list of this process'
    }
}
#endregion

#region Invoke-DumpTriage
Invoke-TestCase 'Invoke-DumpTriage -SelfTest passes and writes nothing' {
    $before = @(Get-ChildItem -LiteralPath $workDirectory -Recurse -Force).Count
    $document = Assert-Envelope (Invoke-Probe 'Invoke-DumpTriage' @('-SelfTest')) 'Invoke-DumpTriage' $true
    Assert-Equal 0 ([int]$document.summary.failed) 'failed self-test checks'
    Assert-True ([int]$document.summary.checks -ge 30) 'number of self-test checks'
    Assert-Equal $before @(Get-ChildItem -LiteralPath $workDirectory -Recurse -Force).Count 'files in the working directory'
}

Invoke-TestCase 'Invoke-DumpTriage input validation' {
    $null = Assert-Envelope (Invoke-Probe 'Invoke-DumpTriage' @()) 'Invoke-DumpTriage' $false
    $null = Assert-Envelope (Invoke-Probe 'Invoke-DumpTriage' @('-Dump', (Join-Path $workDirectory 'missing.dmp'))) 'Invoke-DumpTriage' $false
    $null = Assert-Envelope (Invoke-Probe 'Invoke-DumpTriage' @('-Dump', $peFixture, '-Module', 'x; .shell')) 'Invoke-DumpTriage' $false
    $document = Assert-Envelope (Invoke-Probe 'Invoke-DumpTriage' @('-Dump', $peFixture, '-SymbolPath', 'C:\Symbols', '-UseMicrosoftSymbolServer')) 'Invoke-DumpTriage' $false
    Assert-True ($document.error -match 'only one of') ('error: ' + $document.error)
}
#endregion

#region In-process use
Invoke-TestCase 'a probe called with & returns one JSON string and leaves the caller running' {
    $output = @(& (Join-Path $probeDirectory 'Find-PeConstant.ps1') -Path $peFixture -Constant '0x1234ABCD' -Filter @('*.dll'))
    $code = $LASTEXITCODE
    Assert-Equal 1 $output.Count 'number of output objects'
    $document = $output[0] | ConvertFrom-Json
    Assert-Equal 4 ([int]$document.summary.totalHits) 'totalHits'
    Assert-Equal 0 $code 'LASTEXITCODE'
    $rejected = & (Join-Path $probeDirectory 'Find-PeConstant.ps1') -Path $peFixture -Constant 0x1234ABCD | ConvertFrom-Json
    Assert-Equal 1 $LASTEXITCODE 'LASTEXITCODE after a handled error'
    Assert-True ($rejected.error -match 'quote the value') 'an unquoted number for -Constant is rejected'
}
#endregion

#region Common helpers
Invoke-TestCase 'common helpers' {
    & {
        . (Join-Path $probeDirectory 'Find-PeConstant.ps1')
        Assert-Equal 'a,b,c' ((Split-ProbeList @('a,b', ' c ', '')) -join ',') 'Split-ProbeList'
        $empty = ConvertTo-ProbeArray $null
        Assert-True ($empty -is [array]) 'ConvertTo-ProbeArray returns an array'
        Assert-Equal 0 $empty.Count 'empty array'
        Assert-Equal 2 (ConvertTo-ProbeArray @(1, $null, 2)).Count 'nulls removed'
        Assert-Equal 'x' (Get-ObjectProperty ([pscustomobject]@{ a = 'x' }) 'a') 'property'
        Assert-True ($null -eq (Get-ObjectProperty ([pscustomobject]@{ a = 'x' }) 'b')) 'missing property'
        Assert-Equal 'y' (Get-ObjectProperty @{ b = 'y' } 'b') 'dictionary key'
    }
}
#endregion

if (-not $KeepWorkDirectory) {
    Remove-Item -LiteralPath $workDirectory -Recurse -Force
} else {
    Write-Output ('Fixtures kept in ' + $workDirectory)
}

$failed = @($script:Results | Where-Object { $_.Result -ne 'pass' })
Write-Output ($script:Results | Format-Table -AutoSize -Wrap | Out-String -Width 200)
Write-Output ('PowerShell {0} ({1}), child processes: {2}: {3} passed, {4} failed' -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, [System.IO.Path]::GetFileName($PowerShellPath), ($script:Results.Count - $failed.Count), $failed.Count)
exit $failed.Count
