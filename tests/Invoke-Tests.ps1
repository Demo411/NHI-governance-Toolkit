#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0'; MaximumVersion='5.99.99' }
<#
.SYNOPSIS
    Runs every *.Tests.ps1 in this folder with Pester 5.x.
    Exit code 0 = all passed, 1 = any failure. No tenant, no network.

.NOTES
    Pester 5 is required (the tests use `Should -Be` and BeforeAll). The Windows built-in
    Pester 3.4 cannot run them. Install with:
      Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck -MaximumVersion 5.99.99
#>
$pester = Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -eq 5 } | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) { Write-Error 'Pester 5.x is not installed (see the .NOTES in this script).'; exit 1 }
Import-Module $pester -Force
Write-Host "Using Pester $($pester.Version)"

$result = Invoke-Pester -Path $PSScriptRoot -PassThru -Output Detailed
if ($result.FailedCount -gt 0) { exit 1 }
exit 0
