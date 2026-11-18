# Probe reference

Each section lists what the probe reports, what it needs, what it changes, its
parameters and its output fields. The envelope around `summary` and `data`, and the
parameters that every probe has (`-MaxRows`, `-SummaryOnly`, `-Compress`, `-OutFile`,
`-Help`), are described in [CONVENTIONS.md](../CONVENTIONS.md). The help of each probe
(`-Help`, or `Get-Help` on the script) has the same information in plain text.

Paths in the examples are relative to the `probes` directory.

- [Get-EffectiveAccess](#get-effectiveaccess)
- [Get-PrivilegedSurfaceMap](#get-privilegedsurfacemap)
- [Get-ComponentNeighborhood](#get-componentneighborhood)
- [Invoke-ProcmonCapture](#invoke-procmoncapture)
- [Invoke-RpcEtwSniffer](#invoke-rpcetwsniffer)
- [Find-CapabilityString](#find-capabilitystring)
- [Find-PeConstant](#find-peconstant)
- [Invoke-DumpTriage](#invoke-dumptriage)

---

## Get-EffectiveAccess

Reports which objects an account or a token can write (or, with `-IncludeReadOnly`,
access at all). It is a scriptable front end for two existing access-check tools.

| Engine | Categories | Whose access |
|---|---|---|
| Sysinternals AccessChk | `-FilePath`, `-RegistryKey`, `-Service`, `-Process` | the account named by `-Principal`, computed from the security descriptor and the groups of that account. The account does not need to be logged on. |
| NtObjectManager `Get-Accessible*` cmdlets | `-NamedPipe`, `-Device`, `-AlpcPort`, `-ObjectDirectory` | the token of the current process, or of `-ProcessId` |

**Requirements.** `accesschk64.exe` or `accesschk.exe` for the AccessChk categories:
on PATH when the session is not elevated, otherwise `-AccessChkPath`. The NtObjectManager
module for the others; in an elevated session it is imported only from the PowerShell
installation directory (`$PSHOME`) or from Program Files. Elevation is not required for
objects whose security descriptor the current user can read; run elevated for complete
`-Service` and `-Process` results.

**State changes.** AccessChk is started with `-accepteula`, which records the acceptance
of the Sysinternals license under `HKCU\Software\Sysinternals`. By running the AccessChk
categories you accept the
[Sysinternals Software License Terms](https://learn.microsoft.com/sysinternals/license-terms).
Nothing else changes.

**Write-type access and the default filter.**

- AccessChk rows: `W` or `RW`. Without `-IncludeReadOnly`, AccessChk runs with `-w`, so
  it prints only objects with write access.
- NtObjectManager rows: the `IsWrite` or `IsAll` flag of the result, or a granted-access
  name (`GrantedAccessString`) that contains Write, Append, Delete, GenericAll,
  AllAccess, Full Access, CreateObject, CreateSubDirectory, MapWrite, AddFile,
  AddSubdirectory, SetValue, CreateSubKey or CreateLink. GenericWrite and WriteDac match
  through "Write".
- Without `-IncludeReadOnly`, AccessChk rows, named pipes and object-manager entries are
  returned only with write-type access. Devices and ALPC ports are returned with any
  access: opening a device can be enough to send it IOCTLs, and connecting to an ALPC
  port needs only Connect access. `writable` keeps its meaning in every row.

**Errors.** When AccessChk prints only messages for a named target (an unknown account,
a missing path or service, access denied), that target gets a row with `access` and
`writable` set to null and the messages in `error`. `summary.errors` counts these rows.
Messages from recursive scans go to `caveats` (the first 20; `accessChkMessages` counts
all of them).

**Accuracy.**

- When AccessChk evaluates a named account, access that is granted only through
  logon-type groups (for example `INTERACTIVE`) can be missed. Treat "no write access"
  as a lower bound.
- NtObjectManager rows are for the token named in the row's `subject`. An elevated token
  can open objects that a standard user cannot. Use `-ProcessId` with a process of the
  account that you want to model.
- The NtObjectManager cmdlets, their parameters and the result fields `IsWrite`, `IsAll`
  and `GrantedAccessString` are checked at run time. A missing cmdlet or parameter skips
  that category with a caveat, and a result without those fields is skipped with a
  caveat. The probe never falls back to another token. These categories have not been
  run against the module for this release; the offline tests use stand-in cmdlets.
- Names that contain characters outside the console code page can be garbled when they
  are read from AccessChk output.

| Parameter | Meaning |
|---|---|
| `-Principal` | Account for AccessChk (`user`, `DOMAIN\user` or a group). Required with the AccessChk categories. |
| `-FilePath` | Files or directories. A directory is checked itself; `-Recurse` adds its contents. |
| `-RegistryKey` | Keys such as `HKLM\SOFTWARE\Contoso` or `HKLM:\SOFTWARE\Contoso`. |
| `-Service` | Service names, or `*` for all. |
| `-Process` | All running processes. |
| `-NamedPipe`, `-Device`, `-AlpcPort` | NtObjectManager categories. `-Device` lists objects under `\Device`. |
| `-ObjectDirectory` | Object-manager directories, checked recursively when the cmdlet supports it. Not split on commas, because object-manager names can contain them. |
| `-ProcessId` | Use the token of this process for the NtObjectManager categories. |
| `-Recurse` | Contents of directories, subkeys of keys. |
| `-IncludeReadOnly` | Also return rows without write-type access. |
| `-IncludeSddl` | Add the SDDL of file, directory and registry rows (`Get-Acl`). |
| `-MaxRows` | Row cap, default 5000. |
| `-AccessChkPath` | Path of AccessChk. Required in an elevated session. |

**summary:** `principal`, `accessChk`, `ntObjectManager` (module version),
`objectsChecked`, `rowsReturned`, `writableRows`, `rowsFilteredReadOnly`, `rowsDropped`,
`truncated`, `errors`, `accessChkMessages`, `byCategory`. With `-w`, AccessChk prints
only objects with write access, so `objectsChecked` counts those objects plus each named
target (a `-FilePath`, `-RegistryKey` or `-Service` value) for which AccessChk printed
nothing. Objects of a `-Recurse` scan without write access, and error rows, are not
counted.

**data[]:** `category` (`file`, `directory`, `registry`, `service`, `process`,
`namedPipe`, `device`, `alpcPort`, `objectManager`), `name`, `objectType`
(NtObjectManager type name), `subject`, `access`, `writable`, `error`, `sddl`, `engine`.

```powershell
.\Get-EffectiveAccess.ps1 -Principal "<standard-user>" -FilePath C:\ProgramData -Recurse -OutFile .\programdata.json
.\Get-EffectiveAccess.ps1 -Principal "<standard-user>" -RegistryKey HKLM\SOFTWARE\Contoso -Recurse -IncludeSddl
.\Get-EffectiveAccess.ps1 -NamedPipe -AlpcPort -ProcessId 4321
```

---

## Get-PrivilegedSurfaceMap

Lists processes, services and scheduled tasks with the account each one runs as.

| Kind | Source | Fields |
|---|---|---|
| `process` | `Win32_Process`; token fields from NtObjectManager when installed, otherwise only the account from `Win32_Process.GetOwner` and `GetOwnerSid` | `pid`, `name`, `path`, `parentPid`, `sessionId`, `commandLine`, `user`, `userSid`, `integrityLevel`, `protection`, `hasSeImpersonate`, `hasSeAssignPrimaryToken` |
| `service` | `Win32_Service`, plus `Parameters\ServiceDll` and `LaunchProtected` from the registry | `name`, `displayName`, `account`, `state`, `startMode`, `pid`, `serviceType`, `commandLine`, `serviceDll`, `launchProtected` |
| `task` | `Get-ScheduledTask`; the program of the first executable action is resolved and its PE machine type read from the file header | `taskPath`, `taskName`, `state`, `runAs`, `runLevel`, `logonType`, `executable`, `resolvedExecutable`, `executableExists`, `machine`, `arguments`, `comHandlers`, `triggerTypes` |

`user` is the account name (`DOMAIN\name`) and `userSid` its SID. PID 4 (System) is
reported as `S-1-5-18`.

`-OnlyPrivileged` keeps processes that run as SYSTEM, LOCAL SERVICE or NETWORK SERVICE,
run protected, or have `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`;
services whose account is one of those three; and tasks whose account is one of those
three or whose run level is Highest. Processes are compared by SID. Services and tasks
are compared by account name, with the English names and with the names that Windows
gives the same three SIDs in the language of the system. Virtual service accounts
(`NT SERVICE\name`) and user accounts are not counted, except in tasks with run level
Highest.

`hasSeImpersonate` and `hasSeAssignPrimaryToken` mean that the privilege is present in
the token, enabled or not. `summary.impersonationPrivilegeHolders` lists the names of the
returned processes that have either of the two.

**Task programs.** Task Scheduler keeps the program in `Execute` and its arguments in
`Arguments`, so an unquoted `Execute` value with spaces is tried as one path first.
`executableExists` is `true` when the file was found, `false` when a local path names no
file, and `null` when the probe did not check: the path starts with `\\` (UNC, WebDAV,
`\\?\` and `\\.\` paths) or is on a network drive, so it was not opened, or a program
name without a path is not in System32, the Windows directory or the machine PATH.
Opening a network path would connect to that computer with the token of the person who
runs the probe, and any user can create a task whose program is on a network path.
Environment variables are expanded with the environment of the probe, which can differ
from the environment of the task account; a caveat says when this happened.

**Requirements.** None. NtObjectManager adds the token fields; in an elevated session it
is imported only from `$PSHOME` or from Program Files. Run elevated: without elevation
the tokens of most processes of other accounts cannot be opened.

**State changes.** None.

**Sensitive output.** Command lines and task arguments can contain secrets.
`-OmitCommandLine` leaves process and service command lines and task arguments out.

| Parameter | Meaning |
|---|---|
| `-SkipProcesses`, `-SkipServices`, `-SkipTasks` | Leave a source out. |
| `-OnlyPrivileged` | Keep only the privileged rows defined above. |
| `-OmitCommandLine` | Leave command lines and task arguments out. |
| `-MaxRows` | Row cap, default 5000. Rows are taken in the order processes, services, tasks. |

**summary:** `tokenSource` (`NtObjectManager`, `Win32_Process.GetOwner` or `none`),
`counts` (all rows) and `returned` (after `-OnlyPrivileged`) for processes, services and
tasks, `truncated`, `protectedProcesses`, `impersonationPrivilegeHolders`.

```powershell
.\Get-PrivilegedSurfaceMap.ps1 -OnlyPrivileged -OutFile .\surface.json
.\Get-PrivilegedSurfaceMap.ps1 -SkipProcesses -OmitCommandLine -SummaryOnly
```

---

## Get-ComponentNeighborhood

Lists the edges around one DLL, EXE or SYS file.

| relation | Evidence |
|---|---|
| `ownerService` | the program of `Win32_Service.PathName`, the `Parameters\ServiceDll` value, or for a `.sys` file the driver file of `Win32_SystemDriver.PathName`, is the file (full path) |
| `ownerServiceByName` | one of those values names a file with the same file name at another path, or in a form that the probe did not resolve |
| `hostProcess` | the module list of a running process contains the file (full path) |
| `hostProcessByName` | a running process has a module with the same file name from another path |
| `coHostedService` | another service runs in a host process |
| `coHostedModule` | another module is loaded in one or more host processes (one row per module, with every host PID in `pids`); common system DLLs (ntdll.dll, kernel32.dll, kernelbase.dll and others listed in the script) are left out |
| `import`, `delayImport` | the PE import table or delay-load import table of the file |
| `stringReference` | `-IncludeStringReferences`: a `*.dll` name in the strings of the file that is not in its import tables |
| `dependent` | `-ScanDependents`: a `.dll`, `.exe` or `.sys` file directly in `-SearchRoot` whose bytes contain the file name as a whole name, as ASCII or UTF-16LE text |

Host processes are the processes of `ownerService` and `hostProcess` rows. File names
are matched as whole names: `svc.dll` does not match `mysvc.dll`. `stringReference` and
`dependent` are text matches. They show that a name appears in a file, not that the file
loads or calls the component.

A bare `-Component` name is looked up in `-SearchRoot` only, never in the current
directory. A full path, or a relative path with a directory separator, is used as given.

**Process access.** Reading the module list of a process opens it with
`PROCESS_VM_READ`. lsass.exe is left out unless `-IncludeLsass` is set, because endpoint
protection products report that access to lsass.exe as credential theft.

**Requirements.** None. Run elevated: without elevation, the module lists of processes of
other accounts cannot be read. Protected processes cannot be read even when elevated.
`summary.processesNotReadable` counts both. Module lists of 32-bit (WOW64) processes read
from a 64-bit PowerShell can omit 32-bit modules.

**State changes.** None.

| Parameter | Meaning |
|---|---|
| `-Component` | Full path, relative path with a separator, or a file name looked up in `-SearchRoot` (tried with .dll, .exe, .sys when it has no extension). |
| `-SearchRoot` | Default: the System32 directory. |
| `-IncludeStringReferences` | Add `stringReference` rows. |
| `-ScanDependents` | Add `dependent` rows. Reads every .dll, .exe and .sys file directly in `-SearchRoot`. |
| `-IncludeLsass` | Also read the module list of lsass.exe. |
| `-OmitCommandLine` | Leave service command lines out. |
| `-MaxDependents` | Default 100. |
| `-MaxFileMB` | Files larger than this are not read, the target file included. Default 64. |
| `-MaxRows` | Row cap, default 5000. `summary.edgeCounts` counts every edge. |

**summary:** `target`, `targetName`, `machine`, `edgeCounts`, `hostPids`,
`processesNotReadable`, `truncated`.

**data[]:** `relation`, `name`, `path`, `commandLine`, `account`, `startMode`, `state`,
`pids`, `launchProtected`, `evidence`. For service rows, `path` is the program, driver or
DLL file and `commandLine` is the full `PathName` value.

```powershell
.\Get-ComponentNeighborhood.ps1 -Component spoolsv.exe -OutFile .\spooler.json
.\Get-ComponentNeighborhood.ps1 -Component w32time.dll -IncludeStringReferences -OmitCommandLine
```

---

## Invoke-ProcmonCapture

Runs a Process Monitor capture from the command line and returns its events as rows.
Process Monitor is a GUI program; the probe starts it minimized.

| Mode | What happens | Elevation |
|---|---|---|
| `-Capture` | `Procmon /AcceptEula /Quiet /Minimized /BackingFile <pml> [/LoadConfig <pmc>]`, then `-TriggerCommand` or a wait of `-DurationSeconds`, then `Procmon /Terminate`, then `Procmon /OpenLog <pml> /SaveAs <csv> [/LoadConfig <pmc>]`, then the CSV is parsed | required |
| `-ParseCsv <file>` | parse a CSV that Process Monitor exported earlier | not required |
| `-DryRun`, or no mode | report whether a capture could start | not required |

Without `-Capture` the probe changes nothing. Parameters that apply only to a capture
(`-TriggerCommand`, `-DurationSeconds`, `-BackingFile` and others) are rejected without
`-Capture`.

**Requirements.** Sysinternals Process Monitor (`Procmon64.exe` or `Procmon.exe`), passed
with `-ProcmonPath`. A capture runs elevated, and in an elevated session the probe does
not take a program from PATH. A capture needs an interactive desktop session; captures
over SSH, WinRM or from a scheduled task have not been tested.

**State changes (`-Capture` only).**

- Process Monitor loads its kernel filter driver and manages the driver and its service
  entry; both can stay on the system after Process Monitor exits. This probe installs
  and removes nothing itself.
- Process Monitor stores its license acceptance and settings in the registry of the
  current user. By running a capture you accept the
  [Sysinternals Software License Terms](https://learn.microsoft.com/sysinternals/license-terms).
- The `.pml` and `.csv` files go to a new directory under the Windows temporary directory
  that only Administrators and SYSTEM can open (`capture.pml`, `capture.csv`), or next
  to each other at `-BackingFile`. They are deleted at the end unless `-KeepArtifacts`
  is set; the probe deletes only files that it created. An existing `.pml` or `.csv`
  file is never overwritten or deleted: the probe refuses to start instead.
- `-TriggerCommand` runs through `cmd.exe /d /s /c "<command>"` with the elevated token
  of the probe. cmd.exe is started from System32 by full path.

The probe refuses to start while another Process Monitor instance runs, because
`Procmon /Terminate` stops every instance. After a capture that was killed, stop
Process Monitor with `Procmon64.exe /Terminate`.

**Process Monitor settings.** Without `-ConfigFile`, Process Monitor uses the filter,
columns and "Drop Filtered Events" option saved by its GUI for the current user. A saved
filter with "Drop Filtered Events" turned on removes events from the capture. Save a
configuration (`.pmc`) with the columns that you need, including User and Integrity for
the `user` and `integrity` fields, and pass it with `-ConfigFile`; it is passed to the
capture and to the conversion. Whether Process Monitor also saves that configuration as
the settings of the current user was not checked.

**Filters.** `-Operation` (exact names, `*` for all), `-ProcessName` (substring),
`-PathFilter` (regular expression) apply while the CSV is read. The default operations
are CreateFile, ReadFile, WriteFile, SetRenameInformationFile, SetRenameInformationEx,
SetDispositionInformationFile, SetDispositionInformationEx, SetSecurityFile, RegOpenKey,
RegCreateKey, RegQueryValue, RegSetValue, RegDeleteKey, RegDeleteValue, Process Create
and Load Image.

**Sensitive output.** `detail` holds what Process Monitor shows for the event, such as
the command line of a new process and the registry data that a process reads or writes.

| Parameter | Meaning |
|---|---|
| `-Capture` | Run a capture. |
| `-DurationSeconds` | Capture length without a trigger. Default 10. Not used with `-TriggerCommand`. |
| `-TriggerCommand` | Command line run during the capture. |
| `-TriggerTimeoutSeconds` | Default 120. After it, the cmd.exe process started by the probe is stopped. |
| `-SettleSeconds` | Capture time after the trigger exits. Default 2. |
| `-ProcessName`, `-PathFilter`, `-Operation` | Row filters. |
| `-MaxRows` | Row cap, default 5000. The summary counts every kept row. |
| `-BackingFile` | Path of the `.pml` file, in a directory that exists. Neither it nor the `.csv` file next to it may exist. |
| `-ConfigFile` | `.pmc` file passed with `/LoadConfig`. |
| `-ConvertTimeoutSeconds` | Time limit of the conversion. Default 300. |
| `-KeepArtifacts` | Keep the `.pml` and `.csv` files. |
| `-ParseCsv` | Parse this CSV instead of capturing. |
| `-DryRun` | Report readiness only. |
| `-ProcmonPath` | Path of Process Monitor. Required for `-Capture`. |

**summary:** `mode`, `procmonPath`, `totalEvents`, `keptEvents`, `truncated`,
`distinctPaths`, `distinctProcesses`, `byOperation`, `triggerExitCode`, `artifacts`.
A caveat names a nonzero `triggerExitCode`. With `-DryRun`: `mode`, `procmonPath`,
`elevatedNow`, `otherInstanceRunning`, `ready`.

**data[]:** `time`, `processName`, `pid`, `operation`, `path`, `result`, `detail`,
`user`, `integrity` (the last two are null unless the CSV has those columns). `time` is
the "Time of Day" column as Process Monitor exports it: local time of day, without a
date.

```powershell
.\Invoke-ProcmonCapture.ps1 -DryRun
.\Invoke-ProcmonCapture.ps1 -Capture -ProcmonPath "C:\Program Files\Sysinternals\Procmon64.exe" -TriggerCommand "sc.exe query spooler" -ProcessName "spoolsv.exe,services.exe" -OutFile .\capture.json
.\Invoke-ProcmonCapture.ps1 -ParseCsv .\Logfile.CSV -Operation * -PathFilter "\\ProgramData\\"
```

---

## Invoke-RpcEtwSniffer

Records RPC calls with the Microsoft-Windows-RPC ETW provider
(`{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}`) and returns one row per call.

| Mode | What happens | Elevation |
|---|---|---|
| `-Capture` | `logman create trace <session> -p {provider} 0xffffffffffffffff 0xff -o <etl> -bs 256 -nb 16 64 -max <MaxEtlMB> -ets` (a file-mode session), then `-TriggerCommand` or a wait, then `logman query <session> -ets` for the lost-buffer count, then `logman stop <session> -ets`, then the `.etl` file is parsed with `Get-WinEvent` | Administrators or Performance Log Users |
| `-ParseEtl <file>` | parse an existing `.etl` file | not required |
| `-DryRun`, or no mode | report whether a capture could start | not required |

Without `-Capture` the probe changes nothing, and capture-only parameters are rejected.
logman.exe and cmd.exe are started from System32 by full path.

Rows come from event 5 (client call start, `side` = `client`) and event 6 (server call
start, `side` = `server`). The event IDs and field names were read from the provider
manifest on Windows 11 with:

```powershell
(Get-WinEvent -ListProvider Microsoft-Windows-RPC).Events | Where-Object Id -in 5, 6
```

Run the same command on your build before you rely on them. Other event IDs are counted
in `summary.byEventId`.

`pid` is the process that logged the event: the client for event 5, the server for event
6. `processName` is looked up when the capture stops, so a process that exited has no
name, and a reused process ID can show the wrong name. `protocol` is the number that the
provider logs; the probe does not translate it. `time` is the event time in UTC, ISO 8601
with milliseconds.

**State changes (`-Capture` only).** One ETW session, stopped in a `finally` block. The
default session name is unique to the run; the probe refuses to start when a session
with the given name exists and never stops a session it did not create. The `.etl` file
goes to a new directory (under the Windows temporary directory, readable only by
Administrators and SYSTEM, when elevated; under the temporary directory of the user
otherwise) or to `-EtlPath`, and is deleted at the end unless `-KeepArtifacts` is set.
The session stops writing when the file reaches `-MaxEtlMB`. `-TriggerCommand` runs
through `cmd.exe /d /s /c "<command>"`. If the probe is killed during a capture, the
session keeps running until `logman stop <session name> -ets` or a restart.

**Limits.** The provider is enabled with all keywords at level 0xFF. On a busy system ETW
drops events when its buffers fill. `buffersLost` and `eventsLost` are read from the
output of `logman query`, which is in the language of the system; they are null when
that output does not contain the English labels "Buffers Lost" and "Events Lost".

| Parameter | Meaning |
|---|---|
| `-Capture` | Run a capture. |
| `-DurationSeconds` | Capture length without a trigger. Default 10. Not used with `-TriggerCommand`. |
| `-TriggerCommand`, `-TriggerTimeoutSeconds`, `-SettleSeconds` | As in Invoke-ProcmonCapture. |
| `-InterfaceFilter` | Keep calls whose interface UUID contains one of these values. |
| `-SessionName` | Session name (letters, digits, `.`, `_`, `-`). |
| `-EtlPath` | Path of the `.etl` file to write, in a directory that exists. The file must not exist. |
| `-MaxEtlMB` | Maximum size of the `.etl` file. Default 256. |
| `-ParseEtl` | Parse this file instead of capturing. It is never deleted. |
| `-KeepArtifacts` | Keep the `.etl` file of a capture. |
| `-IncludeRaw` | Add all event-data fields as `raw`. |
| `-MaxRows` | Row cap, default 2000. `summary.byInterface` counts every kept call. |
| `-DryRun` | Report readiness only. |

**summary:** `mode`, `sessionName`, `totalEvents`, `callEvents`, `keptCalls`,
`truncated`, `buffersLost`, `eventsLost`, `byEventId`, `byInterface[]` (`interfaceUuid`,
`calls`, `opnums`, `clientPids`, `serverPids`, `endpoints` (at most 10),
`endpointsTruncated`), `triggerExitCode`, `artifacts`. With `-DryRun`: `mode`,
`sessionName`, `logman` (its path, or null), `elevatedNow`, `performanceLogUser`,
`ready` (logman.exe exists and the token is elevated or in Performance Log Users).

**data[]:** `time`, `eventId`, `side`, `pid`, `processName`, `threadId`,
`interfaceUuid`, `opnum`, `protocol`, `networkAddress`, `endpoint`,
`authenticationLevel`, `authenticationService`, `impersonationLevel`, `raw`.

```powershell
.\Invoke-RpcEtwSniffer.ps1 -Capture -TriggerCommand "sc.exe query spooler" -OutFile .\rpc.json
.\Invoke-RpcEtwSniffer.ps1 -ParseEtl .\rpc.etl -InterfaceFilter 367abb81
```

---

## Find-CapabilityString

Extracts printable strings from files and matches them against categories of names
that point to what a binary can do: API names, object paths and privilege names.
"Capability" here does not mean an AppContainer capability SID.

Strings are runs of at least `-MinLength` printable ASCII characters (0x20 to 0x7E), and
the same runs encoded as UTF-16LE. Matching is case-insensitive. Each regular expression
gets 5 seconds per match; one that takes longer is skipped for that file, and a caveat
names its category and label.

Built-in categories (the regular expressions are in the script, function
`Get-DefaultPatternSet`):

| Category | Matches |
|---|---|
| `cross_process` | WriteProcessMemory, ReadProcessMemory, VirtualAllocEx, CreateRemoteThread, NtCreateThreadEx, QueueUserAPC / NtQueueApcThread, SetThreadContext, NtMapViewOfSection |
| `token_and_identity` | ImpersonateNamedPipeClient, RpcImpersonateClient, CoImpersonateClient, ImpersonateLoggedOnUser, DuplicateToken, AdjustTokenPrivileges / RtlAdjustPrivilege, LogonUser, CheckTokenMembership, privilege names (SeImpersonate, SeAssignPrimaryToken, SeDebug, SeTakeOwnership, SeBackup, SeRestore, SeLoadDriver, SeTcb) |
| `process_creation` | CreateProcess, ShellExecute, WinExec, UpdateProcThreadAttribute |
| `links_and_paths` | DefineDosDevice, CreateSymbolicLink, reparse, junction / mount point, GetFinalPathNameByHandle, `\RPC Control`, `\GLOBAL??`, `\BaseNamedObjects` |
| `rpc_alpc_com` | RpcServerRegisterIf, RpcServerUseProtseq, NdrServerCall, NdrClientCall, ncalrpc / ncacn_np / ncacn_ip_tcp, NtAlpcCreatePort / NtAlpcConnectPort / NtAlpcSendWaitReceivePort, CoRegisterClassObject, CoInitializeSecurity |
| `security_and_configuration` | SetSecurityInfo / SetNamedSecurityInfo, SetEntriesInAcl, SetFileSecurity / SetKernelObjectSecurity, CreateService / ChangeServiceConfig, RegSetValue / RegSetKeyValue / RegCreateKey, MoveFileEx / MoveFileWithProgress, ReplaceFile, CreateHardLink |
| `trust_verification` | WinVerifyTrust, CryptCATAdmin, CertGetCertificateChain, CertVerifyCertificateChainPolicy, CryptQueryObject |
| `module_loading` | LoadLibrary, LdrLoadDll, SetDllDirectory, SetDefaultDllDirectories / AddDllDirectory, `\KnownDlls` |
| `serialization` | BinaryFormatter, NetDataContractSerializer, SoapFormatter, LosFormatter / ObjectStateFormatter, deserializ |
| `file_locking` | LockFileEx, oplock, NtFsControlFile, FSCTL_ code names |

A match shows that a string is in the file. It does not show that the code that uses it
is reachable or runs with any privilege.

`-PatternFile` replaces the built-in set:

```json
{ "categories": {
    "my_category": { "meaning": "free text",
                     "patterns": [ { "label": "Name", "regex": "Name(A|W)?" } ] } } }
```

**Requirements.** None. **State changes.** None.

| Parameter | Meaning |
|---|---|
| `-Path`, `-Filter`, `-Recurse` | Files to read. Default filter: `*.dll`, `*.exe`, `*.sys`. |
| `-Category` | Use only these categories. |
| `-PatternFile` | JSON file with your own categories. |
| `-MinLength` | Minimum string length. Default 4. |
| `-MinCategories` | A file is listed in `summary.topFiles` only with at least this many categories. |
| `-MaxTopFiles` | Default 100. |
| `-MaxFiles`, `-MaxFileMB` | Default 500 files, 64 MB per file. |
| `-MaxRows` | Row cap, default 5000. `rowsByCategory` and `topFiles` count every row. |
| `-CheckSignature` | Add `signatureStatus` and `signer` (`Get-AuthenticodeSignature`). |

**summary:** `patternSource`, `categories`, `filesConsidered`, `filesScanned`,
`filesWithHits`, `filesSkippedTooLarge`, `filesUnreadable`, `rowsByCategory`,
`truncated` (true when `-MaxRows` or `-MaxFiles` cut the result), `topFiles[]` (`file`,
`categoryCount`, `categories`).

**data[]:** `file`, `fileVersion`, `signatureStatus`, `signer`, `category`, `label`,
`matches` (number of matching strings), `sample` (the first matching string, at most 200
characters).

```powershell
.\Find-CapabilityString.ps1 -Path C:\Windows\System32\kernelbase.dll
.\Find-CapabilityString.ps1 -Path "C:\Program Files\Contoso" -Recurse -Category "token_and_identity,rpc_alpc_com" -MinCategories 2 -OutFile .\strings.json
```

---

## Find-PeConstant

Searches files for a constant or a byte pattern and maps each hit to the PE layout.

- `-Constant '0x1234ABCD' -Width 4` searches the little-endian bytes `CD AB 34 12`.
  Quote the value in PowerShell: an unquoted `0x` literal becomes a number, which the
  probe rejects.
- `-Pattern "48 8B ?? 24"` searches literal bytes; `??` matches any byte.
- `rva = section.VirtualAddress + (fileOffset - section.PointerToRawData)`;
  `va = ImageBase + rva`, with ImageBase from the optional header.
- A hit outside the raw data of every section has `rva`, `va` and `section` set to null.
- `mapped` is false for a hit past the `VirtualSize` of its section.
- `sectionExecutable` is true when the section has `IMAGE_SCN_MEM_EXECUTE` or
  `IMAGE_SCN_CNT_CODE`.
- Hits do not overlap.

The search uses the .NET regular expression engine on a Latin-1 view of the bytes, so it
needs no compiler or external tool.

**Requirements.** None. **State changes.** None.

| Parameter | Meaning |
|---|---|
| `-Path`, `-Filter`, `-Recurse` | Files to search. Default filter: `*.dll`, `*.exe`, `*.sys`. |
| `-Constant`, `-Width` | Hex value and its width (2, 4 or 8 bytes). |
| `-Pattern` | Hex bytes with `??` wildcards. |
| `-Context` | Context bytes around each hit. Default 16. |
| `-MaxHitsPerFile`, `-MaxRows`, `-MaxFiles`, `-MaxFileMB` | Caps. Defaults 64, 5000, 2000, 64. `-MaxRows` stops the whole run. |

**summary:** `needle`, `needleLength`, `filesConsidered`, `filesScanned`,
`filesSkippedTooLarge`, `filesUnreadable`, `filesNotPe`, `filesWithHits` (a count),
`hitFiles` (their paths), `totalHits`, `truncated` (true when `-MaxRows` or `-MaxFiles`
cut the result).

**data[]:** `file`, `fileOffset`, `rva`, `va`, `section`, `sectionExecutable`, `mapped`,
`contextHex`.

```powershell
.\Find-PeConstant.ps1 -Path C:\Windows\System32\ntdll.dll -Constant '0xC0000022'
.\Find-PeConstant.ps1 -Path C:\Windows\System32 -Pattern "48 8B ?? 24" -MaxHitsPerFile 5 -OutFile .\hits.json
```

---

## Invoke-DumpTriage

Runs `kd.exe` on a dump file (no live target) under a time limit and parses the log:

```text
kd.exe -z <dump> -y <symbol path> -logo <log> -c "!analyze -v; .bugcheck; kv; [lmv m <module>;] q"
```

The dump is only read.

**Requirements.** `kd.exe` from the Debugging Tools for Windows (Windows SDK):
`-KdPath` when it is given; otherwise PATH, only when the session is not elevated, and
then `Windows Kits\10\Debuggers\x64` and `arm64` under Program Files (x86) and Program
Files.

**Symbols.** In this order: `-SymbolPath`; `-UseMicrosoftSymbolServer`, which uses
`srv*<LOCALAPPDATA>\win-agent-probes\symbols*https://msdl.microsoft.com/download/symbols`;
the `_NT_SYMBOL_PATH` environment variable; otherwise
`srv*<LOCALAPPDATA>\win-agent-probes\symbols`, a local symbol store only, so nothing is
downloaded and names are missing unless that directory already has them. A caveat says
when the symbol path can reach the network: a URL, a UNC path, or a `srv*` or `symsrv*`
element without a local store. The symbol cache in `LOCALAPPDATA` is kept between runs
and is in the user profile, so processes of the same user at medium integrity can change
its files, and changed symbol files can make names in the result wrong. An elevated run
that uses this cache says so in a caveat; pass `-SymbolPath` with a cache in a folder
that only administrators can change.

**State changes.** Writes the log (kept, with its SHA-256 in the summary) to a new
directory (under the Windows temporary directory, readable only by Administrators and
SYSTEM, when elevated; under the temporary directory of the user otherwise) or to
`-LogPath`. kd.exe writes the symbol files that it downloads into the symbol cache.

**Parsing.** The bug check code and arguments come from the `.bugcheck` output, with
`BUGCHECK_CODE` / `BUGCHECK_P1..P4` and the `BugCheck X, {...}` line as fallbacks. Bug
check arguments are hex strings such as `0xFFFFFFFFC0000005`, without the backtick that
kd.exe prints inside 64-bit values. `symbolWarnings` counts lines that report missing or
unverified symbols. `data` holds the `KEY: value` lines of the log (first occurrence of
each key), up to `-MaxRows`.

`-Module` is checked against `^[A-Za-z0-9_.-]{1,64}$`, so it cannot add debugger commands.

`-SelfTest` checks the argument quoting, the symbol path check and the parser on built-in
samples. It starts no process and writes no file. When a check fails, `ok` is false,
`data` is empty as for every handled error, and `error` names each failed check with
its expected and actual value.

| Parameter | Meaning |
|---|---|
| `-Dump` | Dump file. |
| `-Module` | Module for `lmv m`. |
| `-LogPath` | Log path. Must not exist. Default: a new file in a new directory. |
| `-SymbolPath` | Symbol path for `-y`. |
| `-UseMicrosoftSymbolServer` | Download symbols from the Microsoft symbol server into the local cache. |
| `-TimeoutSeconds` | 30 to 3600, default 600. |
| `-KdPath` | Path of kd.exe. |
| `-MaxRows` | Row cap, default 5000. |
| `-SelfTest` | Built-in checks only. |

**summary:** `mode`, `dump`, `kdPath`, `symbolPath`, `logPath`, `logSha256`,
`bugcheckCode`, `bugcheckArguments`, `faultingModule`, `imageName`, `symbolName`,
`failureBucket`, `processName`, `symbolWarnings`, `truncated`.

**data[]:** `key`, `value`. With `-SelfTest`: `check`, `expected`, `actual`, `pass`.

```powershell
.\Invoke-DumpTriage.ps1 -Dump D:\dumps\MEMORY.DMP -Module sampledrv -UseMicrosoftSymbolServer -OutFile .\triage.json
.\Invoke-DumpTriage.ps1 -SelfTest
```
