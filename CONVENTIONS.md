# Conventions

These rules apply to every probe in `probes/`. The tests in `tests/Invoke-Tests.ps1`
check the parts that can be checked mechanically.

## Output contract

A probe writes exactly one JSON document to stdout:

```json
{
  "tool": "Find-PeConstant",
  "schemaVersion": 1,
  "generatedUtc": "2026-01-01T12:00:00Z",
  "host": "LAB-VM",
  "principal": "LAB-VM\\analyst",
  "elevated": false,
  "params": { "Path": "C:\\Windows\\System32\\ntdll.dll" },
  "ok": true,
  "error": null,
  "summary": { "caveats": [] },
  "data": []
}
```

| Key | Meaning |
|---|---|
| `tool` | The probe name (the script file name without `.ps1`). |
| `schemaVersion` | Version of this envelope and of the probe's field names. A change that removes or renames a field increases it. |
| `generatedUtc` | UTC time when the document was built, ISO 8601. |
| `host` | `COMPUTERNAME` of the machine that ran the probe. |
| `principal` | The account that ran the probe (`DOMAIN\user`). |
| `elevated` | `true` when the token of the probe is in the Administrators group (UAC elevated). |
| `params` | The parameters after defaults were applied, under their PowerShell names. |
| `ok` | `true` when the probe finished. `false` on a handled error. |
| `error` | `null` when `ok` is `true`, otherwise a message. |
| `summary` | Counts and headline fields of the probe. Always has `caveats`. |
| `data` | The result rows. Always an array. Empty when `ok` is `false` or with `-SummaryOnly`. |

`summary.caveats` lists the limits that apply to this run: skipped objects, caps that were
reached, missing optional modules, accuracy notes. A gap that is not in `caveats` is a bug.

Field names inside `summary` and `data` are camelCase. Identifiers (GUIDs, SIDs, paths,
offsets) are copied as the source reports them. Hex values are strings such as `"0x1A2B"`.
A process ID is `pid`, a list of them `pids` or `<role>Pids` (`hostPids`, `clientPids`).
`file` is the file that a row was read from; `path` is a path that belongs to the object
of the row. A time with a date is UTC in ISO 8601; Invoke-ProcmonCapture keeps the local
time of day that Process Monitor exports, because the CSV has no date.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `ok` is `true`. |
| 1 | `ok` is `false` (the JSON document is still printed). |
| 2 | `ok` is `true`, but the file named by `-OutFile` could not be written. A message goes to stderr. |

PowerShell itself reports parameter binding errors (for example a text value for an
integer parameter) before the probe runs. Those produce no JSON document.

## Streams

- stdout carries only the JSON document, or the help text with `-Help`.
- The probes do not use `Write-Host` or `Write-Warning`. Under `-File`, both Windows
  PowerShell 5.1 and PowerShell 7.7 write those streams to stdout (checked by running a
  test script with redirected output), so they would break the JSON.
- `-Verbose` prints diagnostic lines. Under `-File` they also go to stdout, so use
  `-OutFile` when you combine `-Verbose` with a JSON consumer.

## Common parameters

| Parameter | Meaning |
|---|---|
| `-MaxRows <n>` | Maximum number of data rows. When the cap is reached, `summary.truncated` is `true` and a caveat says so; the summary counts still cover every row. |
| `-SummaryOnly` | Return the summary with an empty `data` array, and a caveat with the number of rows left out. |
| `-Compress` | Print the JSON document on one line, without indentation. |
| `-OutFile <path>` | Also write the JSON document to this file, UTF-8 without BOM. The directory is created when it does not exist. |
| `-Help` | Print the comment-based help of the probe and exit 0. The help is read from the script file directly, so it works in sessions without a console. `Get-Help` on the script shows the same help. |

## Rules for probes

1. One file per probe. A probe does not depend on other files of this repository, so it
   can be copied alone. The common helper block (`#region Common probe helpers`) is
   identical in every probe, and a function that several probes need is copied into each
   of them unchanged; the tests compare every copy.
2. Windows PowerShell 5.1 and PowerShell 7 are both supported. Source files are ASCII.
   Windows PowerShell 5.1 reads a UTF-8 file without a BOM as ANSI, so a non-ASCII
   character can break a script there that parses on PowerShell 7.
3. No mandatory parameters. A missing mandatory parameter makes PowerShell prompt for a
   value, which can block a session that has no console. Required values are
   checked in the script body and reported as `ok: false`.
4. Every state change is named in the help (`State changes:`) and in README.md. Anything
   created for a run (a capture session, a temporary file) is removed in a `finally`
   block unless the user asked to keep it. The one exception is the kd.exe log of
   Invoke-DumpTriage: it is the evidence for the result, so it is kept, and its path and
   SHA-256 are in the summary.
5. Read-only by default. With no arguments, no probe changes the system. A probe that
   changes system state does so only with an explicit switch (`-Capture`), and a probe
   that runs a command for the user (`-TriggerCommand`) says so and runs it only when
   asked.
6. A probe never stops, reuses, overwrites or deletes something it did not create: an
   existing ETW session name, a running Process Monitor instance, an existing capture or
   log file. `-OutFile` is the one exception: like a shell redirect, it replaces the
   JSON file.
7. The code of a probe opens no network connection. A probe does not open a path that it
   read from the configuration of the system (a task action, a service entry) when that
   path can reach another computer: UNC, WebDAV, `\\?\`, `\\.\` and network-drive paths.
   When a tool or API that it uses can connect (kd.exe with a symbol server path,
   Windows signature verification), the help says so.
8. Large results are capped (`-MaxRows`, `-MaxFiles` and similar). When a cap is reached,
   `summary` says so and `caveats` names the parameter to raise.
9. When `powershell.exe -File` is used, a `string[]` parameter receives one string. Probes
   split name lists (filters, categories, service names) on commas. Path lists are not
   split, because paths can contain commas; use `-Command` or call the probe from
   PowerShell to pass several paths.
10. The script can be dot-sourced for tests. It then defines its functions and returns
    without running.
11. In an elevated session, a probe does not start a program found through PATH, and it
    imports a module only from the PowerShell installation directory (`$PSHOME`) or from
    Program Files. Programs that are part of Windows (cmd.exe, logman.exe) are started
    from System32 by full path. Files that an elevated run creates go to a new directory
    that only Administrators and SYSTEM can open, unless the user names the file. The one
    exception is the symbol cache of Invoke-DumpTriage
    (`%LOCALAPPDATA%\win-agent-probes\symbols`), which kd.exe keeps between runs: an
    elevated run that uses it says so in a caveat, and `-SymbolPath` selects another
    cache.

## Adding a probe

1. Start the file with `#Requires -Version 5.1`, `# Copyright (c) 2026 Kazuma Matsumoto`,
   `# SPDX-License-Identifier: MIT` and an empty line. Without the empty line, Get-Help
   does not find the help block.
2. Copy the common helper block from an existing probe without changes.
3. Write the help first: `.SYNOPSIS`, `.DESCRIPTION` with `State changes:` and
   `Elevation:`, one `.PARAMETER` per parameter, `.OUTPUTS` with the summary and row
   fields, and at least one `.EXAMPLE`.
4. Add a section to `docs/probes.md` and a row to the table in `README.md`.
5. Add tests for every code path that runs without elevation, external tools or network.
6. Run `tests/Invoke-Tests.ps1` under both `powershell.exe` and `pwsh`.
