@{
    # Report every default rule. tools/Invoke-Lint.ps1 fails on Error and Warning
    # findings and lists Information findings without failing.
    Severity     = @('Error', 'Warning', 'Information')
    ExcludeRules = @()
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
