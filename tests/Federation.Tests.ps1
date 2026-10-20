# Phase 5: seed-02 moves from a client secret to GitHub Actions OIDC federation (Pester 5).
# Synthetic inventories only: no tenant, no network.

Describe 'seed-02: state-dependent expectation (engine -> validator)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $script:scan = '2026-10-19T23:17:44Z'
        $script:key02 = New-SynAnswerKey -Directory (Join-Path $TestDrive 'key02') -Apps (Get-Seed02Expectation)
        # 730-day secret, live at the scan time: the real seed-02.
        $script:live = New-SynSecretForDays -Start '2026-10-01T00:00:00Z' -Days 730
        # Ended before the scan: an expired secret.
        $script:dead = New-SynCredential -Start '2024-01-01T00:00:00Z' -End '2025-01-01T00:00:00Z'

        # Build an inventory, score it with the real engine, validate with the real validator.
        function script:Invoke-S02 {
            param([string]$Name, [hashtable]$Identity)
            $seed = New-SynIdentity -Name 'seed-02-longsecret' -Tags @('nhi-lab-seed') @Identity
            $inv = Write-SynInventory -Identities @($seed) -ScanStartUtc $script:scan -Directory (Join-Path $TestDrive "s02-$Name")
            $run = Invoke-SynEngine -InventoryPath $inv -OutputDirectory (Join-Path $TestDrive "s02-$Name-out")
            $val = Invoke-SynValidator -FindingsPath $run.Path -InventoryPath $inv -AnswerKeyPath $script:key02
            [pscustomobject]@{ Run = $run; Val = $val; Result = (Get-SynResult $run $seed.appId) }
        }
    }

    It 'secret only, inventory from before scanner v0.3.0 (no FIC property): NHI-002 + NHI-007, validator passes' {
        $c = Invoke-S02 'old' @{ AppSecrets = @($script:live) }
        Format-Set (Get-SynRuleIds $c.Result) | Should -Be 'NHI-002,NHI-007'
        $c.Val.ExitCode | Should -Be 0 -Because $c.Val.Output
        $c.Val.Output | Should -Match 'with secret'
    }

    It 'secret AND a matching FIC (the mixed state between checkpoints C and E): still with_secret' {
        $c = Invoke-S02 'mixed' @{ AppSecrets = @($script:live); Fics = @(New-SynFic) }
        Format-Set (Get-SynRuleIds $c.Result) | Should -Be 'NHI-002,NHI-007'
        $c.Val.ExitCode | Should -Be 0 -Because $c.Val.Output
        $c.Val.Output | Should -Match 'with secret'
    }

    It 'no secret and the matching FIC: no findings, score 0, validator passes as federated' {
        $c = Invoke-S02 'federated' @{ Fics = @(New-SynFic) }
        @(Get-SynRuleIds $c.Result).Count | Should -Be 0
        $c.Result.score.total | Should -Be 0
        $c.Val.ExitCode | Should -Be 0 -Because $c.Val.Output
        $c.Val.Output | Should -Match 'federated'
    }

    It 'no secret and a FIC with a DIFFERENT SUBJECT does not count as federated (validator fails)' {
        $c = Invoke-S02 'othersubject' @{ Fics = @(New-SynFic -Subject 'repo:Demo411/some-other-repo:environment:lab') }
        $c.Val.ExitCode | Should -Be 1 -Because $c.Val.Output
        $c.Val.Output | Should -Match 'undefined'
    }

    It 'a near-miss FIC does not count: <Case>' -ForEach @(
        @{ Case = 'subject differs only by case';   Fic = { New-SynFic -Subject 'repo:demo411/NHI-governance-Toolkit:environment:lab' } }
        @{ Case = 'wildcard-ish branch subject';    Fic = { New-SynFic -Subject 'repo:Demo411/NHI-governance-Toolkit:ref:refs/heads/main' } }
        @{ Case = 'wrong issuer';                   Fic = { New-SynFic -Issuer 'https://sts.windows.net/00000000-0000-0000-0000-000000000000/' } }
        @{ Case = 'wrong audience';                 Fic = { New-SynFic -Audiences @('api://SomethingElse') } }
        @{ Case = 'extra audience on top of the right one'; Fic = { New-SynFic -Audiences @('api://AzureADTokenExchange', 'api://SomethingElse') } }
    ) {
        $c = Invoke-S02 ('near-' + ($Case -replace '\W', '')) @{ Fics = @(& $Fic) }
        $c.Val.ExitCode | Should -Be 1 -Because $c.Val.Output
    }

    It 'the right FIC counts even when a stray FIC sits beside it' {
        $c = Invoke-S02 'stray' @{ Fics = @((New-SynFic -Name 'stray' -Subject 'repo:x/y:environment:z'), (New-SynFic)) }
        $c.Val.ExitCode | Should -Be 0 -Because $c.Val.Output
    }

    It 'a secret on the SERVICE PRINCIPAL only still counts as a secret (seed-11 lesson): with_secret, not federated' {
        # If the validator looked only at application.passwordCredentials it would call this
        # "federated" and expect no findings, while the engine (correctly) reports NHI-002 + NHI-007.
        $c = Invoke-S02 'spsecret' @{ SpSecrets = @($script:live); Fics = @(New-SynFic) }
        Format-Set (Get-SynRuleIds $c.Result) | Should -Be 'NHI-002,NHI-007'
        $c.Val.ExitCode | Should -Be 0 -Because $c.Val.Output
        $c.Val.Output | Should -Match 'with secret'
    }

    It 'no secret and no FIC at all: validator fails (undefined state)' {
        $c = Invoke-S02 'none' @{ Fics = @() }
        $c.Val.ExitCode | Should -Be 1 -Because $c.Val.Output
    }

    It 'no secret and no FIC property (old inventory, secret already gone): validator fails, no guessing' {
        $c = Invoke-S02 'nofic-nosecret' @{}
        $c.Val.ExitCode | Should -Be 1 -Because $c.Val.Output
    }

    It 'only an EXPIRED secret remains, with the matching FIC: validator fails (state not defined)' {
        $c = Invoke-S02 'expiredonly' @{ AppSecrets = @($script:dead); Fics = @(New-SynFic) }
        Format-Set (Get-SynRuleIds $c.Result) | Should -Be 'NHI-002,NHI-003'   # 366-day lifetime still trips NHI-002
        $c.Val.ExitCode | Should -Be 1 -Because $c.Val.Output
    }

    It 'the validator FAILS if the federated state is expected to carry findings' {
        $wrong = Get-Seed02Expectation
        $wrong['seed-02-longsecret'].state_dependent.federated.expected_rules = @('NHI-007')
        $key = New-SynAnswerKey -Directory (Join-Path $TestDrive 'key02-wrong') -Apps $wrong
        $seed = New-SynIdentity -Name 'seed-02-longsecret' -Tags @('nhi-lab-seed') -Fics @(New-SynFic)
        $inv = Write-SynInventory -Identities @($seed) -ScanStartUtc $script:scan -Directory (Join-Path $TestDrive 's02-wrongkey')
        $run = Invoke-SynEngine -InventoryPath $inv -OutputDirectory (Join-Path $TestDrive 's02-wrongkey-out')
        (Invoke-SynValidator -FindingsPath $run.Path -InventoryPath $inv -AnswerKeyPath $key).ExitCode | Should -Be 1
    }
}

Describe 'Real answer key: seed-02 block' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $script:real = Get-Content -LiteralPath (Join-Path (Get-RepoRoot) 'seed/expected-findings.json') -Raw | ConvertFrom-Json
    }
    It 'carries exactly the design-decision values (exact subject, no wildcards)' {
        $f = $script:real.apps.'seed-02-longsecret'.state_dependent.expected_federation
        $f.issuer | Should -BeExactly 'https://token.actions.githubusercontent.com'
        $f.subject | Should -BeExactly 'repo:Demo411/NHI-governance-Toolkit:environment:lab'
        @($f.audiences) | Should -Be @('api://AzureADTokenExchange')
        $f.subject | Should -Not -Match '[*?]'
    }
    It 'matches the synthetic helper block' {
        $real = $script:real.apps.'seed-02-longsecret'.state_dependent
        $syn = (Get-Seed02Expectation)['seed-02-longsecret'].state_dependent
        Format-Set $real.with_secret.expected_rules | Should -Be (Format-Set $syn.with_secret.expected_rules)
        @($real.federated.expected_rules).Count | Should -Be 0
        $real.expected_federation.subject | Should -BeExactly $syn.expected_federation.subject
    }
}

# The scanner script signs in and walks the tenant when run, so it cannot be dot-sourced. These two
# functions are lifted out of its source with the PowerShell parser and run against stand-ins for
# the Graph helpers.
Describe 'Scanner FIC collection (functions extracted from Invoke-NhiInventory.ps1)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $path = Join-Path (Get-RepoRoot) 'scanner/Invoke-NhiInventory.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -in 'ConvertTo-SafeFederatedCredential', 'Get-FederatedCredentials' }, $true)
        $script:found = @($defs | ForEach-Object Name)
        foreach ($d in $defs) { Invoke-Expression ($d.Extent.Text -replace '^function ', 'function script:') }

        $script:warnings = [System.Collections.Generic.List[string]]::new()
        function script:Add-ScanWarning { param([string]$Message) $script:warnings.Add($Message) }
        $script:graphMode = 'ok'
        function script:Get-GraphPaged {
            param([string]$Uri)
            $script:lastUri = $Uri
            if ($script:graphMode -eq 'throw') { throw 'Forbidden' }
            , @(
                @{ id = 'fic-id-1'; name = 'github'; description = 'free text'; issuer = 'https://token.actions.githubusercontent.com'
                   subject = 'repo:Demo411/NHI-governance-Toolkit:environment:lab'; audiences = @('api://AzureADTokenExchange') }
            )
        }
    }

    It 'found both functions in the scanner source' {
        $script:found | Should -Contain 'ConvertTo-SafeFederatedCredential'
        $script:found | Should -Contain 'Get-FederatedCredentials'
    }
    It 'projects only name, issuer, subject and audiences (id and description are dropped)' {
        $r = Get-FederatedCredentials -ObjectId 'obj-1' -Label 'application x'
        @($r).Count | Should -Be 1
        (@($r[0].Keys) -join ',') | Should -Be 'name,issuer,subject,audiences'
        $r[0].subject | Should -Be 'repo:Demo411/NHI-governance-Toolkit:environment:lab'
        $script:lastUri | Should -Be 'https://graph.microsoft.com/v1.0/applications/obj-1/federatedIdentityCredentials'
    }
    It 'a failed lookup returns $null (unknown) and records a warning, it does not throw' {
        $script:graphMode = 'throw'
        $r = Get-FederatedCredentials -ObjectId 'obj-2' -Label 'application y'
        $null -eq $r | Should -BeTrue
        $script:warnings.Count | Should -Be 1
        $script:warnings[0] | Should -Match 'application y'
    }
}
