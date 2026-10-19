# seed-03 time handling end to end (engine -> validator) plus validator guard rails (Pester 5).
# Synthetic inventories only: no tenant, no network.

Describe 'seed-03: before, at and after expiry' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        # Secret: 2026-10-11T13:02:51.150Z -> 2026-10-12T13:02:51.150Z (1 day), as in the real seed.
        $secret = New-SynCredential -Start '2026-10-11T13:02:51.150Z' -End '2026-10-12T13:02:51.150Z'
        $script:key03 = New-SynAnswerKey -Directory (Join-Path $TestDrive 'key03') -Apps (Get-Seed03Expectation)

        $script:s03 = @{}
        foreach ($state in @(
            @{ Name = 'before'; Scan = '2026-10-12T13:02:50.150Z'; Stamp = '20261012-130250Z' },   # 1 second before the end
            @{ Name = 'at';     Scan = '2026-10-12T13:02:51.150Z'; Stamp = '20261012-130251Z' },   # exactly the end
            @{ Name = 'after';  Scan = '2026-10-12T13:02:52.150Z'; Stamp = '20261012-130252Z' }    # 1 second after
        )) {
            $seed = New-SynIdentity -Name 'seed-03-expiring' -Tags @('nhi-lab-seed') -AppSecrets @($secret)
            $inv = Write-SynInventory -Identities @($seed) -ScanStartUtc $state.Scan -Stamp $state.Stamp -Directory (Join-Path $TestDrive "s03-$($state.Name)")
            $run = Invoke-SynEngine -InventoryPath $inv -OutputDirectory (Join-Path $TestDrive "s03-$($state.Name)-out")
            $val = Invoke-SynValidator -FindingsPath $run.Path -InventoryPath $inv -AnswerKeyPath $script:key03
            $script:s03[$state.Name] = @{ Inv = $inv; Run = $run; Val = $val; AppId = $seed.appId }
        }
    }

    It 'one second BEFORE expiry: NHI-007 only, score 10, validator passes' {
        $s = $script:s03['before']
        $s.Run.ExitCode | Should -Be 0 -Because $s.Run.Output
        $r = Get-SynResult $s.Run $s.AppId
        Format-Set (Get-SynRuleIds $r) | Should -Be 'NHI-007'
        $r.score.total | Should -Be 10
        $s.Val.ExitCode | Should -Be 0 -Because $s.Val.Output
    }
    It 'exactly AT expiry (end == scanStart counts as expired): NHI-003 only, score 3, validator passes' {
        $s = $script:s03['at']
        $r = Get-SynResult $s.Run $s.AppId
        Format-Set (Get-SynRuleIds $r) | Should -Be 'NHI-003'
        $r.score.total | Should -Be 3
        $s.Val.ExitCode | Should -Be 0 -Because $s.Val.Output
    }
    It 'one second AFTER expiry: NHI-003 only, score 3, validator passes' {
        $s = $script:s03['after']
        $r = Get-SynResult $s.Run $s.AppId
        Format-Set (Get-SynRuleIds $r) | Should -Be 'NHI-003'
        $r.score.total | Should -Be 3
        $s.Val.ExitCode | Should -Be 0 -Because $s.Val.Output
    }
    It 'the validator FAILS (exit 1) if the answer key expects the wrong state' {
        $wrong = Get-Seed03Expectation
        $wrong['seed-03-expiring'].time_dependent.before_expiry.expected_rules = @('NHI-003')   # engine says NHI-007 before expiry
        $key = New-SynAnswerKey -Directory (Join-Path $TestDrive 'key03-wrong') -Apps $wrong
        $s = $script:s03['before']
        $v = Invoke-SynValidator -FindingsPath $s.Run.Path -InventoryPath $s.Inv -AnswerKeyPath $key
        $v.ExitCode | Should -Be 1 -Because $v.Output
    }
}

Describe 'Validator guard rails' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $script:secretG = New-SynCredential -Start '2026-10-11T13:02:51.150Z' -End '2026-10-12T13:02:51.150Z'
        $script:scan = '2026-10-11T14:34:29Z'
        $script:keyG = New-SynAnswerKey -Directory (Join-Path $TestDrive 'keyG') -Apps (Get-Seed03Expectation)

        # Build an inventory, score it, validate it; return all three results.
        function script:Invoke-Case {
            param([string]$Name, [object[]]$Identities, [string]$Key)
            $inv = Write-SynInventory -Identities $Identities -ScanStartUtc $script:scan -Directory (Join-Path $TestDrive "g-$Name")
            $run = Invoke-SynEngine -InventoryPath $inv -OutputDirectory (Join-Path $TestDrive "g-$Name-out")
            $val = Invoke-SynValidator -FindingsPath $run.Path -InventoryPath $inv -AnswerKeyPath $Key
            [pscustomobject]@{ Inv = $inv; Run = $run; Val = $val }
        }
    }

    It 'passes when the seed is tagged and an untagged "seed-99" look-alike is present (names are ignored)' {
        $seed = New-SynIdentity -Name 'seed-03-expiring' -Tags @('nhi-lab-seed') -AppSecrets @($script:secretG)
        $decoy = New-SynIdentity -Name 'seed-99-not-a-seed' -Owners 0
        $c = Invoke-Case -Name 'decoy' -Identities @($seed, $decoy) -Key $script:keyG
        $c.Val.ExitCode | Should -Be 0 -Because $c.Val.Output
    }
    It 'FAILS when an identity is NAMED like the seed but carries no tag' {
        $untagged = New-SynIdentity -Name 'seed-03-expiring' -AppSecrets @($script:secretG)
        $c = Invoke-Case -Name 'untagged' -Identities @($untagged) -Key $script:keyG
        $c.Val.ExitCode | Should -Be 1 -Because $c.Val.Output
        $c.Val.Output | Should -Match 'no identity tagged'
    }
    It 'FAILS when a tagged seed has no answer-key entry (for example after a rename)' {
        $renamed = New-SynIdentity -Name 'renamed-seed' -Tags @('nhi-lab-seed') -AppSecrets @($script:secretG)
        $c = Invoke-Case -Name 'renamed' -Identities @($renamed) -Key $script:keyG
        $c.Val.ExitCode | Should -Be 1 -Because $c.Val.Output
        $c.Val.Output | Should -Match 'no entry in the answer key'
    }
    It 'accepts the tag on the service principal alone' {
        $seed = New-SynIdentity -Name 'seed-03-expiring' -AppSecrets @($script:secretG)
        $seed.servicePrincipal.tags = @('nhi-lab-seed')
        $c = Invoke-Case -Name 'sptag' -Identities @($seed) -Key $script:keyG
        $c.Val.ExitCode | Should -Be 0 -Because $c.Val.Output
    }
    It 'refuses to validate when the inventory was changed after scoring (hash mismatch)' {
        $seed = New-SynIdentity -Name 'seed-03-expiring' -Tags @('nhi-lab-seed') -AppSecrets @($script:secretG)
        $c = Invoke-Case -Name 'tamper' -Identities @($seed) -Key $script:keyG
        $c.Val.ExitCode | Should -Be 0 -Because $c.Val.Output
        Add-Content -LiteralPath $c.Inv -Value ' '
        $v = Invoke-SynValidator -FindingsPath $c.Run.Path -InventoryPath $c.Inv -AnswerKeyPath $script:keyG
        $v.ExitCode | Should -Be 1 -Because $v.Output
        $v.Output | Should -Match 'INTEGRITY'
    }
    It 'Phase 4: an untagged agent counts as a seed through its tagged blueprint (parent link, not name)' {
        $bp = New-SynBlueprint -Name 'bp-seed' -Tags @('nhi-lab-seed')
        $agent = New-SynAgent -Name 'agent-seed' -ParentAppId $bp.appId
        $key = New-SynAnswerKey -Directory (Join-Path $TestDrive 'keyAg') -Apps @{ 'bp-seed' = @{ expected_rules = @() }; 'agent-seed' = @{ expected_rules = @() } }
        $c = Invoke-Case -Name 'agentInherit' -Identities @($bp, $agent) -Key $key
        $c.Val.ExitCode | Should -Be 0 -Because $c.Val.Output
        $c.Val.Output | Should -Match '1 agent\(s\) through their tagged blueprint'
    }
    It 'Phase 4: an agent under an UNTAGGED blueprint is not a seed, even when named like one' {
        $bp = New-SynBlueprint -Name 'bp-not-seed'
        $agent = New-SynAgent -Name 'agent-seed' -ParentAppId $bp.appId
        $key = New-SynAnswerKey -Directory (Join-Path $TestDrive 'keyAgNo') -Apps @{ 'agent-seed' = @{ expected_rules = @() } }
        $c = Invoke-Case -Name 'agentNoInherit' -Identities @($bp, $agent) -Key $key
        $c.Val.ExitCode | Should -Be 1 -Because $c.Val.Output
        $c.Val.Output | Should -Match 'no identity tagged'
    }
    It 'FAILS a score constraint that does not hold' {
        $seed = New-SynIdentity -Name 'seed-03-expiring' -Tags @('nhi-lab-seed') -AppSecrets @($script:secretG)
        $constraint = [ordered]@{ id = 'CX'; text = 'score(seed-03-expiring) > 50'; type = 'greater_than'; subject = 'seed-03-expiring'; value = 50 }
        $key = New-SynAnswerKey -Directory (Join-Path $TestDrive 'keyCX') -Apps (Get-Seed03Expectation) -Constraints @($constraint)
        $c = Invoke-Case -Name 'constraint' -Identities @($seed) -Key $key
        $c.Val.ExitCode | Should -Be 1 -Because $c.Val.Output
        $c.Val.Output | Should -Match 'Constraint CX failed'
    }
}
