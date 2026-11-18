#Requires -Version 5.1
# Copyright (c) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
    Run PSScriptAnalyzer on every script of the repository with the repository settings.

.DESCRIPTION
    Uses PSScriptAnalyzerSettings.psd1 from the repository root. Prints the version of
    PSScriptAnalyzer and every finding.
    Exit codes: 0 when there is no Error or Warning finding, 1 when there is at least one,
    3 when the PSScriptAnalyzer module (or the version given with -RequiredVersion) is
    not installed.

    Install the module for the current user with:
      Install-Module PSScriptAnalyzer -Scope CurrentUser

.PARAMETER RequiredVersion
    Use exactly this version of PSScriptAnalyzer, for example 1.25.0. The workflow in
    .github/workflows/tests.yml installs that version and passes it here, so that a new
    PSScriptAnalyzer release does not change the result. Default: the highest installed
    version.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Invoke-Lint.ps1

.EXAMPLE
    pwsh -NoProfile -File .\tools\Invoke-Lint.ps1 -RequiredVersion 1.25.0
#>
[CmdletBinding()]
param(
    [string] $RequiredVersion
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$available = @(Get-Module -ListAvailable -Name PSScriptAnalyzer)
if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
    $available = @($available | Where-Object { [string]$_.Version -eq $RequiredVersion })
}
if ($available.Count -eq 0) {
    if ([string]::IsNullOrWhiteSpace($RequiredVersion)) {
        Write-Output 'PSScriptAnalyzer is not installed. Install it with: Install-Module PSScriptAnalyzer -Scope CurrentUser'
    } else {
        Write-Output ('PSScriptAnalyzer {0} is not installed. Install it with: Install-Module PSScriptAnalyzer -RequiredVersion {0} -Scope CurrentUser' -f $RequiredVersion)
    }
    exit 3
}
if ([string]::IsNullOrWhiteSpace($RequiredVersion)) {
    Import-Module PSScriptAnalyzer
} else {
    Import-Module PSScriptAnalyzer -RequiredVersion $RequiredVersion
}
Write-Output ('PSScriptAnalyzer {0}' -f (Get-Module -Name PSScriptAnalyzer | Select-Object -First 1).Version)
$settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'
# Windows PowerShell 5.1 ignores -Include together with -LiteralPath, so the extension
# filter is applied with Where-Object.
$files = @(Get-ChildItem -LiteralPath $repoRoot -Recurse -File | Where-Object { @('.ps1', '.psd1') -contains $_.Extension })
$findings = @($files | ForEach-Object { Invoke-ScriptAnalyzer -Path $_.FullName -Settings $settings })
if ($findings.Count -gt 0) {
    Write-Output ($findings | Sort-Object -Property ScriptName, Line |
        Format-Table -Property Severity, RuleName, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 220)
}
$blocking = @($findings | Where-Object { [string]$_.Severity -in @('Error', 'Warning', 'ParseError') })
Write-Output ('{0} file(s), {1} finding(s), {2} of them Error or Warning.' -f $files.Count, $findings.Count, $blocking.Count)
if ($blocking.Count -gt 0) { exit 1 }
exit 0
