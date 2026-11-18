# win-agent-probes

Command-line PowerShell probes for Windows security research. Each probe prints one JSON
document, so a script, an agent or a person can read the result as data. An agent here
is any program that runs a command and reads JSON from its output, such as a CI job or
an AI assistant; the probes themselves contain no AI code. Several of them do from a
command line what is usually done in a GUI tool: a Process Monitor capture, an RPC
trace, a check of who can write a folder, a crash dump triage.

The probes observe. They do not exploit anything or change permissions, and they install
nothing themselves. With no arguments, no probe changes the system; the two capture
probes change state only with `-Capture`, and the table below lists every change. Use
the probes on systems that you own or are authorized to test. A lab virtual machine is
the intended place.

## Contents

- [Probes](#probes)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Output](#output)
- [Security and trust model](#security-and-trust-model)
- [Limitations](#limitations)
- [Tests](#tests)
- [Related projects](#related-projects)
- [Credits and license](#credits-and-license)

## Probes

| Probe | Reports | Elevation | Needs | Changes on the system |
|---|---|---|---|---|
| [Get-EffectiveAccess](docs/probes.md#get-effectiveaccess) | Effective access of an account to files, directories, registry keys, services and processes. Named pipes, devices, ALPC ports and object-manager entries that a token can open. | Not required for most objects | Sysinternals AccessChk; NtObjectManager (optional) | AccessChk records its license acceptance under HKCU |
| [Get-PrivilegedSurfaceMap](docs/probes.md#get-privilegedsurfacemap) | Processes, services and scheduled tasks with the account each runs as; token details of processes | Recommended | NtObjectManager (optional) | None |
| [Get-ComponentNeighborhood](docs/probes.md#get-componentneighborhood) | For one DLL, EXE or SYS: the services and drivers that name it, the processes that load it, their other services and modules, its imports | Recommended | None | None |
| [Invoke-ProcmonCapture](docs/probes.md#invoke-procmoncapture) | File, registry and process events of a Process Monitor capture, optionally around a trigger command; or a parsed CSV export | Required for `-Capture` | Sysinternals Process Monitor | With `-Capture` only: the Process Monitor driver and its service entry, Process Monitor settings and license acceptance under HKCU, temporary files, the trigger command |
| [Invoke-RpcEtwSniffer](docs/probes.md#invoke-rpcetwsniffer) | RPC calls (interface UUID, opnum, client or server process, endpoint) from the Microsoft-Windows-RPC ETW provider | `-Capture`: Administrators or Performance Log Users | logman.exe (part of Windows) | With `-Capture` only: one temporary ETW session, a temporary .etl file, the trigger command |
| [Find-CapabilityString](docs/probes.md#find-capabilitystring) | Strings in binaries that point to what they can do (API names, object paths, privilege names), by category | No | None | None |
| [Find-PeConstant](docs/probes.md#find-peconstant) | Hits of a constant or byte pattern with file offset, RVA, virtual address and section | No | None | None |
| [Invoke-DumpTriage](docs/probes.md#invoke-dumptriage) | Bug check code, arguments, faulting module and `!analyze -v` fields of a crash dump file | No | kd.exe (Debugging Tools for Windows) | The log file; downloaded symbol files when the symbol path names a server |

"Capability" in Find-CapabilityString means a category of names, not an AppContainer
capability SID. [docs/probes.md](docs/probes.md) has the parameters and output fields of
each probe. Every probe also prints its help with `-Help`, and `Get-Help` shows the same
help.

## Requirements

- Windows with Windows PowerShell 5.1 or PowerShell 7. The probes were written for
  Windows 11 x64; see [Tests](#tests) for what was run there. Windows
  10, Windows Server and ARM64 were not tested.
- Optional external tools, installed by you:
  - [Sysinternals AccessChk](https://learn.microsoft.com/sysinternals/downloads/accesschk)
    for Get-EffectiveAccess (`-AccessChkPath`)
  - [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
    for Invoke-ProcmonCapture (`-ProcmonPath`)
  - the [NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager)
    module for token details in Get-PrivilegedSurfaceMap and the token categories of
    Get-EffectiveAccess
  - kd.exe from the
    [Debugging Tools for Windows](https://learn.microsoft.com/windows-hardware/drivers/debugger/)
    for Invoke-DumpTriage (`-KdPath`)
- Get-EffectiveAccess starts AccessChk with `-accepteula`, and
  `Invoke-ProcmonCapture -Capture` starts Process Monitor with `/AcceptEula`. By running
  them you accept the
  [Sysinternals Software License Terms](https://learn.microsoft.com/sysinternals/license-terms).

## Install

There is nothing to install. Copy the `probes` directory to the machine. Each probe is a
single file with no dependency on the other files, so you can also copy only the probes
that you need. Code that several probes need (the envelope helpers, argument quoting,
file reading, the lookup of external tools) is therefore copied into each of them; the
tests check that every copy of a shared function is identical.

The scripts are not signed. If the execution policy blocks them, start PowerShell with
`-ExecutionPolicy Bypass`, or run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy
Bypass` in an open prompt. Both change the policy for that one process only. You can
also sign the scripts with your own certificate. If you downloaded a ZIP file, read the
scripts first, then remove the downloaded-file mark with `Unblock-File`.

Install NtObjectManager from an elevated prompt for all users:

```powershell
Install-Module NtObjectManager -Scope AllUsers
```

An elevated probe imports a module only from the PowerShell installation directory
(`$PSHOME`) or from Program Files, because processes of the same user at medium
integrity can change files in the user profile and in other folders that the user adds
to PSModulePath. A copy installed with `-Scope CurrentUser` is used only by probes that
run without elevation.

## Usage

From PowerShell, call a probe like a script. Array parameters work as usual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$result = & .\probes\Find-PeConstant.ps1 -Path C:\Windows\System32\ntdll.dll -Constant '0xC0000022' | ConvertFrom-Json
$result.summary.totalHits
$result.data | Select-Object -First 3
```

From another program (an agent, a CI job, a remote shell), start a new process and read
stdout or the `-OutFile` file:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\probes\Get-PrivilegedSurfaceMap.ps1 -OnlyPrivileged -SummaryOnly -OutFile C:\lab\out\surface.json
```

With `powershell.exe -File`, a list parameter receives one string. The probes split name
lists on commas (`-Filter "*.dll,*.exe"`, `-Service "Spooler,Schedule"`). Path lists are
not split, because paths can contain commas; call the probe from PowerShell to pass
several paths.

More examples:

```powershell
.\probes\Get-EffectiveAccess.ps1 -Principal "<standard-user>" -FilePath C:\ProgramData -Recurse
.\probes\Get-ComponentNeighborhood.ps1 -Component spoolsv.exe
.\probes\Invoke-ProcmonCapture.ps1 -Capture -ProcmonPath "C:\Program Files\Sysinternals\Procmon64.exe" -TriggerCommand "sc.exe query spooler" -ProcessName "spoolsv.exe,services.exe"
.\probes\Invoke-RpcEtwSniffer.ps1 -Capture -TriggerCommand "sc.exe query spooler"
.\probes\Find-CapabilityString.ps1 -Path C:\Windows\System32\kernelbase.dll
.\probes\Invoke-DumpTriage.ps1 -Dump D:\dumps\MEMORY.DMP -SymbolPath D:\symbols
```

## Output

Every probe prints the same envelope:

```json
{
  "tool": "Find-PeConstant",
  "schemaVersion": 1,
  "generatedUtc": "2026-01-01T12:00:00Z",
  "host": "LAB-VM",
  "principal": "LAB-VM\\analyst",
  "elevated": false,
  "params": { },
  "ok": true,
  "error": null,
  "summary": { "caveats": [] },
  "data": [ ]
}
```

- `ok` is `false` on a handled error, and `error` says why. The exit code is 0 when `ok`
  is `true`, 1 when it is `false`, 2 when `-OutFile` could not be written.
- `summary` holds counts and headline fields, so a consumer can read it first and look at
  `data` only when needed. Every probe has `-MaxRows`; when the cap is reached,
  `summary.truncated` is `true` and a caveat says so.
- `summary.caveats` lists the limits of this run: missing optional tools, skipped objects,
  caps, accuracy notes.

[CONVENTIONS.md](CONVENTIONS.md) defines the contract and the rules that every probe
follows.

### Output size

The size of a result depends on the machine and the input. `-SummaryOnly` returns the
summary with an empty `data` array, `-Compress` prints the JSON on one line, and
`-MaxRows` caps the rows. Measured on 2026-11-18 on Windows 11 x64, as the number of
bytes (UTF-8) of the JSON document that the probe wrote to stdout, without the line
break after it:

| Command | Rows | Windows PowerShell 5.1 | PowerShell 7.7 | With `-Compress` | With `-SummaryOnly` (5.1 / 7.7) |
|---|---|---|---|---|---|
| `Find-PeConstant -Path C:\Windows\System32\ntdll.dll -Constant '0xC0000022'` | 18 | 10,237 | 6,760 | 4,952 | 1,843 / 1,110 |
| `Find-CapabilityString -Path C:\Windows\System32\kernelbase.dll` | 52 | 29,513 | 19,286 | 14,255 | 4,487 / 2,232 |
| `Invoke-DumpTriage -SelfTest` | 33 | 8,403 | 5,066 | 3,300 | 1,128 / 733 |

Windows PowerShell 5.1 indents JSON with more spaces, so its default output is larger;
the `-Compress` output was the same in both. The row counts depend on the file versions.
Get-PrivilegedSurfaceMap and Get-ComponentNeighborhood return one row per process,
service, task or edge that they find, so their output grows with the machine; their size
was not measured for this release. A consumer with a size budget can ask for
`-SummaryOnly` first and then narrow the query, for example with `-OnlyPrivileged`,
`-SkipProcesses` or `-MaxRows`.

## Security and trust model

- **Run model.** A probe runs once with the token of whoever starts it, prints its result
  and exits. No probe installs a service, a scheduled task, a driver of its own or a
  background process, opens a listening socket, or asks for credentials. With no
  arguments, no probe changes the system. Apart from the files that you ask for
  (`-OutFile`, kept capture files), the only changes are the ones in the table above.
- **Network.** The code of the probes opens no network connection. Get-PrivilegedSurfaceMap
  does not open a task program on a UNC, WebDAV, device or network-drive path, because
  that would connect to another computer with your token, and any user can create such a
  task. Three components that the probes use can connect: kd.exe downloads symbol files
  when the symbol path names a server (`-UseMicrosoftSymbolServer`, or a server in
  `-SymbolPath` or `_NT_SYMBOL_PATH`); `Find-CapabilityString -CheckSignature` calls
  Get-AuthenticodeSignature, whose signature verification can retrieve certificate data;
  and Windows account-name lookups (`Win32_Process.GetOwner`, SID translation) can query a
  domain controller on a domain-joined machine.
- **Elevation.** No probe elevates itself. `Invoke-ProcmonCapture -Capture` needs an
  elevated token; `Invoke-RpcEtwSniffer -Capture` needs Administrators or Performance
  Log Users membership. Get-PrivilegedSurfaceMap and Get-ComponentNeighborhood give
  partial results without elevation, and say so in `caveats`.
- **Programs and modules.** In an elevated session the probes do not start a program that
  they find through PATH, because PATH can include folders that a standard user can
  write, such as the WindowsApps and WinGet Links folders in the user profile. Pass
  `-AccessChkPath` or `-ProcmonPath`, with a file in a folder that only administrators
  can change; kd.exe is also taken from the Debugging Tools directories under Program
  Files. cmd.exe and logman.exe are started from System32 by full path. An elevated probe
  imports NtObjectManager only from `$PSHOME` or Program Files. The probes do not
  change how PowerShell loads its own modules (CimCmdlets, ScheduledTasks): in an
  elevated session, PSModulePath still includes the Modules folder in your Documents.
- **Commands that you pass.** `-TriggerCommand` (Invoke-ProcmonCapture,
  Invoke-RpcEtwSniffer) is run by `cmd.exe /d /s /c` with the token of the probe, which
  is elevated for a Process Monitor capture. Treat it like a command typed into an
  elevated prompt and never build it from untrusted input. No other parameter is
  executed. AccessChk and kd.exe receive one command line that is quoted with the rules
  of the C runtime, so each value arrives as one argument in Windows PowerShell 5.1 and
  in PowerShell 7, and the `-Module` value of Invoke-DumpTriage is limited to letters,
  digits, dot, underscore and hyphen, so it cannot add debugger commands.
- **Existing state is left alone.** The probes refuse to overwrite or delete an existing
  capture or log file (`-BackingFile` and the .csv file next to it, `-EtlPath`,
  `-LogPath`), to reuse an existing ETW session name, or to start while another Process
  Monitor instance runs (its `/Terminate` switch would stop that instance too). They
  delete only files that they created. `-OutFile` is the exception: like a shell
  redirect, it replaces the JSON file that it names.
- **Temporary files.** Unless you name the file (`-BackingFile`, `-EtlPath`,
  `-LogPath`), an elevated capture or dump triage writes its files to a new directory
  under the Windows temporary directory that only Administrators and SYSTEM can open, so
  processes of the same user at medium integrity cannot read or replace them. A capture
  refuses a `-BackingFile` or `-EtlPath` in a directory that does not exist, so that it
  leaves no directory behind. The symbol cache of Invoke-DumpTriage
  (`%LOCALAPPDATA%\win-agent-probes\symbols`) is the exception: it is kept between runs
  in your profile, where such processes can change symbol files and so make names in
  the result wrong. An elevated run that uses it says so in a caveat; pass
  `-SymbolPath` with a cache in a folder that only administrators can change.
- **External tools.** AccessChk, Process Monitor and kd.exe are Microsoft tools, and
  NtObjectManager is a third-party module. You install them; the probes start or import
  the copy that you point them to. Nothing is downloaded or bundled.
- **Output can be sensitive.** Results contain paths, command lines, account names, SIDs
  and security descriptors of the machine. Every result keeps `host`, `principal`, the
  paths in `data`, and `params`, which repeats every parameter, `-TriggerCommand`
  included. `-OmitCommandLine` leaves out process and service command lines and
  scheduled-task arguments (Get-PrivilegedSurfaceMap) and service command lines
  (Get-ComponentNeighborhood). The `detail` field of Invoke-ProcmonCapture holds what
  Process Monitor shows, such as the command lines of new processes and the registry
  data that a process reads or writes. Review a result before you share it.
- **Results are leads.** A writable path, a string match or an RPC call is an observation.
  Whether it matters for security has to be checked by hand.
- **Modeling a standard user.** Analysis usually runs elevated, so that the probe can see
  the whole system. `Get-EffectiveAccess -Principal` evaluates a named account without
  using its token; its NtObjectManager categories use a real token (`-ProcessId`).
  Confirm an important result by repeating the action as that user.

To report a security problem in the probes, see [SECURITY.md](SECURITY.md).

## Limitations

- The offline tests do not run code paths that need elevation, an external tool, or
  access to other processes: Process Monitor and ETW captures, AccessChk and
  NtObjectManager calls, the process, service, task and module listings, and kd.exe
  runs. They test the functions behind those paths with generated fixtures and stand-in
  functions, for example ConvertFrom-AccessChkOutput, Add-AccessChkResult,
  Add-NtAccessibleResult, Read-ProcmonCsv (through `-ParseCsv`), Get-EventDataMap,
  ConvertTo-RpcCallRow, Measure-RpcByInterface, ConvertTo-TaskRow,
  Resolve-TaskExecutable, Get-ServiceImageMatch, Get-PeImportList and
  Get-DumpTriageFromLog. Run a probe in a lab before you rely on it.
- The NtObjectManager parts (the token categories of Get-EffectiveAccess and the token
  fields of Get-PrivilegedSurfaceMap) have not been run against the module for this
  release. The fields that they read are checked at run time, and missing fields are
  reported in `caveats`.
- AccessChk can miss access that a named account has only through logon-type groups
  such as INTERACTIVE, so "no write access" from Get-EffectiveAccess is a lower bound.
- Process Monitor is a GUI program: a capture needs an interactive desktop session and
  has not been tested over SSH, WinRM or from a scheduled task. It applies the settings
  saved by its GUI unless `-ConfigFile` is given; a saved filter with "Drop Filtered
  Events" removes events from the capture.
- ETW can drop events on a busy system. Invoke-RpcEtwSniffer reports the lost-buffer
  count that `logman query` prints, and only when that output is in English. Process
  names of RPC calls are looked up when the capture stops.
- String and name matches (Find-CapabilityString, the `stringReference` and `dependent`
  edges of Get-ComponentNeighborhood) show that text is present in a file, not that code
  using it runs.
- Under `-File`, `-Verbose` lines are written to stdout before the JSON document. Use
  `-OutFile` when you need `-Verbose` and clean JSON together.

## Tests

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-Tests.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-Tests.ps1
```

The tests do not depend on a Pester version: Windows ships Pester 3.4, and Pester 5 uses
a different syntax, so the tests are plain PowerShell. They parse every script, check
repository hygiene (ASCII-only files, the license lines, an identical helper block in
every probe, identical copies of shared functions, help for every parameter, help that
Get-Help can read, valid parameter names in all examples), run each probe with `-Help`,
run the probes on generated fixtures and on their input-validation paths, and test the
helper functions with stand-ins for AccessChk and the NtObjectManager cmdlets. They need
no elevation and no network. Apart from the PowerShell child processes that run the
probes, they start cmd.exe once (to check how a quoted trigger command arrives), and the
only process whose module list they read is their own. The exit code is the number of
failed tests.

On 2026-11-18, on Windows 11 x64, all 60 tests passed under Windows PowerShell
5.1.26100.9818 and under PowerShell 7.7.0, in a session without elevation.

[tools/Invoke-Lint.ps1](tools/Invoke-Lint.ps1) runs PSScriptAnalyzer with
[PSScriptAnalyzerSettings.psd1](PSScriptAnalyzerSettings.psd1) when the module is
installed (`Install-Module PSScriptAnalyzer -Scope CurrentUser`); `-RequiredVersion`
selects one installed version. On 2026-11-18, with PSScriptAnalyzer 1.25.0, it reported
no Error or Warning finding under both shells. It lists 236 Information findings
(PSAvoidUsingPositionalParameters, all in tests/Invoke-Tests.ps1), which do not make it
fail.

[.github/workflows/tests.yml](.github/workflows/tests.yml) runs the same tests under both
shells, and the lint with PSScriptAnalyzer 1.25.0, on the windows-latest runner of GitHub
Actions.

## Related projects

Other repositories by the same author:

- [binja-agent-mcp](https://github.com/y637F9QQ2x/binja-agent-mcp): an MCP server for
  Binary Ninja, built for LLM agents.
- [windbg-hyperv-mcp](https://github.com/y637F9QQ2x/windbg-hyperv-mcp): an MCP server for
  Windows kernel and user-mode debugging of one Hyper-V guest.
- [hyperv-lpe-lab](https://github.com/y637F9QQ2x/hyperv-lpe-lab): PowerShell scripts for
  a headless Hyper-V lab, with VM control that needs no elevation and guest commands over
  SSH as an administrator or as a standard user.
- [winremote-session-ext](https://github.com/y637F9QQ2x/winremote-session-ext): an
  extension for winremote-mcp that reports the Windows logon session the server runs in
  and restricts how its HTTP endpoint can be exposed.

The author's blog: [y637f9qq2x.com](https://y637f9qq2x.com).

## Credits and license

Written by Kazuma Matsumoto ([y637F9QQ2x](https://github.com/y637F9QQ2x)). No third-party
code is included. All code is original to this repository and released under the MIT
license. The probes start or import these tools, which you install separately under their
own licenses:

- AccessChk and Process Monitor, Sysinternals (Microsoft)
- NtObjectManager, by James Forshaw, from
  [sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)
  (Apache License 2.0)
- kd.exe, Debugging Tools for Windows (Microsoft)

Reading RPC calls from the Microsoft-Windows-RPC ETW provider is a known technique; for
example, [RPC Investigator](https://github.com/trailofbits/RpcInvestigator) by Trail of
Bits shows them in a GUI. Invoke-RpcEtwSniffer shares no code with it.

License: MIT, Copyright (c) 2026 Kazuma Matsumoto. See [LICENSE](LICENSE). Every script
also starts with a copyright line and an `SPDX-License-Identifier: MIT` line, so a probe
that is copied alone still names its license.

This project is not affiliated with or endorsed by Microsoft or by the authors of the
tools above.
