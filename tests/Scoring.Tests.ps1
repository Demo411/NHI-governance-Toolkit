# Engine tests (Pester 5). Synthetic inventories only: no tenant, no network.
# Run with tests/Invoke-Tests.ps1.

Describe 'NHI-002 lifetime boundary (179 / 180 / 181 days)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $start = '2026-01-01T00:00:00.000Z'
        $script:b002 = @{}
        $identities = @()
        # name, days, extra minutes. 180d + 1439 min = 180 days 23:59: floor() must still say 180.
        foreach ($case in @(@('d179', 179, 0), @('d180', 180, 0), @('d180_2359', 180, 1439), @('d181', 181, 0))) {
            $id = New-SynIdentity -Name $case[0] -AppSecrets @(New-SynSecretForDays -Start $start -Days $case[1] -ExtraMinutes $case[2])
            $script:b002[$case[0]] = $id.appId
            $identities += $id
        }
        # 400-day secret that ENDED before the scan: NHI-002 still fires (issuance), NHI-007 must not.
        $expired = New-SynIdentity -Name 'expired400' -AppSecrets @(New-SynSecretForDays -Start '2024-01-01T00:00:00.000Z' -Days 400)
        $script:b002['expired400'] = $expired.appId
        $identities += $expired

        $inv = Write-SynInventory -Identities $identities -ScanStartUtc '2026-06-01T00:00:00Z' -Directory (Join-Path $TestDrive 'nhi002')
        $script:r002 = Invoke-SynEngine -InventoryPath $inv -OutputDirectory (Join-Path $TestDrive 'nhi002-out')
    }

    It 'the engine ran' { $script:r002.ExitCode | Should -Be 0 -Because $script:r002.Output }
    It '179 days does not fire NHI-002' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:r002 $script:b002['d179'])) | Should -Not -Match 'NHI-002'
    }
    It 'exactly 180 days does not fire NHI-002' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:r002 $script:b002['d180'])) | Should -Not -Match 'NHI-002'
    }
    It '180 days 23:59 does not fire NHI-002 (whole-day floor)' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:r002 $script:b002['d180_2359'])) | Should -Not -Match 'NHI-002'
    }
    It '181 days fires NHI-002 with the credential as evidence' {
        $res = Get-SynResult $script:r002 $script:b002['d181']
        Format-Set (Get-SynRuleIds $res) | Should -Match 'NHI-002'
        $f = Get-SynFinding $res 'NHI-002'
        $f.evidence[0].lifetimeDays | Should -Be 181
        $f.evidence[0].onObject | Should -Be 'application'
        $f.evidence[0].credentialType | Should -Be 'secret'
    }
    It 'an expired 400-day secret fires NHI-002 and NHI-003 but not NHI-007' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:r002 $script:b002['expired400'])) | Should -Be 'NHI-002,NHI-003'
    }
}

Describe 'Resource resolution by appId (never by display name)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $otherApi = New-SynIdentity -Name 'Other API' -AppId '11111111-1111-1111-1111-111111111111' -SpId 'sp-other-0001' -OwnerType 'ThirdParty' -NoApplication
        # Same display name as Graph, different appId: the spoof case.
        $spoof = New-SynIdentity -Name 'Microsoft Graph' -AppId '22222222-2222-2222-2222-222222222222' -SpId 'sp-spoof-0001' -OwnerType 'ThirdParty' -NoApplication

        $cases = [ordered]@{
            appGraph   = @{ Perm = (New-SynAppRole 'Mail.Read');                                                              Grant = (New-SynGrant -Scopes 'Mail.Read') }
            appOther   = @{ Perm = (New-SynAppRole 'Mail.Read' -ResourceId 'sp-other-0001' -ResourceDisplayName 'Other API'); Grant = (New-SynGrant -Scopes 'Mail.Read' -ResourceId 'sp-other-0001' -ResourceDisplayName 'Other API') }
            appSpoof   = @{ Perm = (New-SynAppRole 'Mail.Read' -ResourceId 'sp-spoof-0001');                                  Grant = (New-SynGrant -Scopes 'Mail.Read' -ResourceId 'sp-spoof-0001') }
            appMissing = @{ Perm = (New-SynAppRole 'Mail.Read' -ResourceId 'sp-missing-0001');                                Grant = (New-SynGrant -Scopes 'Mail.Read' -ResourceId 'sp-missing-0001') }
        }
        $script:b004 = @{}
        $identities = @($otherApi, $spoof)
        foreach ($k in $cases.Keys) {
            $perm  = New-SynIdentity -Name "perm-$k"  -AppRoleAssignments @($cases[$k].Perm)
            $grant = New-SynIdentity -Name "grant-$k" -Grants @($cases[$k].Grant)
            $script:b004["perm-$k"]  = $perm.appId
            $script:b004["grant-$k"] = $grant.appId
            $identities += $perm
            $identities += $grant
        }
        $inv = Write-SynInventory -Identities $identities -ScanStartUtc '2026-06-01T00:00:00Z' -Directory (Join-Path $TestDrive 'res')
        $script:r004 = Invoke-SynEngine -InventoryPath $inv -OutputDirectory (Join-Path $TestDrive 'res-out')
    }

    It 'the engine ran' { $script:r004.ExitCode | Should -Be 0 -Because $script:r004.Output }

    It '(a) permission from the real Graph SP fires NHI-004 (High, 25) with resolved appId as evidence' {
        $res = Get-SynResult $script:r004 $script:b004['perm-appGraph']
        Format-Set (Get-SynRuleIds $res) | Should -Be 'NHI-004'
        $f = Get-SynFinding $res 'NHI-004'
        $f.points | Should -Be 25
        $f.evidence[0].permission | Should -Be 'Mail.Read'
        $f.evidence[0].resolvedResourceAppId | Should -Be (Get-GraphAppId)
    }
    It '(b) same permission name from another API does not fire NHI-004' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:r004 $script:b004['perm-appOther'])) | Should -Be ''
    }
    It '(c) a service principal NAMED "Microsoft Graph" with a different appId does not fire NHI-004' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:r004 $script:b004['perm-appSpoof'])) | Should -Be ''
    }
    It '(d) a resourceId missing from the inventory does not fire NHI-004 and warns' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:r004 $script:b004['perm-appMissing'])) | Should -Be ''
        $w = @($script:r004.Findings.warnings | Where-Object { $_.code -eq 'unresolvedResource' -and $_.appId -eq $script:b004['perm-appMissing'] })
        $w.Count | Should -Be 1
        $w[0].detail.resourceId | Should -Be 'sp-missing-0001'
    }

    It '(a) NHI-008: AllPrincipals grant on the real Graph SP fires (Low, 3)' {
        $res = Get-SynResult $script:r004 $script:b004['grant-appGraph']
        Format-Set (Get-SynRuleIds $res) | Should -Be 'NHI-008'
        (Get-SynFinding $res 'NHI-008').points | Should -Be 3
    }
    It '(b)(c)(d) NHI-008: other API, spoofed name and missing resource do not fire' {
        foreach ($k in 'grant-appOther', 'grant-appSpoof', 'grant-appMissing') {
            Format-Set (Get-SynRuleIds (Get-SynResult $script:r004 $script:b004[$k])) | Should -Be '' -Because $k
        }
    }
    It 'records exactly two unresolvedResource warnings (one per missing reference), none for the others' {
        $w = @($script:r004.Findings.warnings | Where-Object { $_.code -eq 'unresolvedResource' })
        $w.Count | Should -Be 2
        Format-Set ($w | ForEach-Object { $_.appId }) | Should -Be (Format-Set @($script:b004['perm-appMissing'], $script:b004['grant-appMissing']))
    }
}

Describe 'Service-principal-only credential (seed-11 regression)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $start = '2026-05-20T00:00:00.000Z'
        $keyId = 'aaaaaaaa-0000-0000-0000-000000000011'
        # Application has NO credentials; the only secret lives on the service principal.
        $hidden = New-SynIdentity -Name 'sp-secret' -SpSecrets @(New-SynSecretForDays -Start $start -Days 90 -KeyId $keyId)
        # SP-only identity (no application object at all) holding an expired secret.
        $spOnly = New-SynIdentity -Name 'sp-only-expired' -NoApplication -SpSecrets @(New-SynSecretForDays -Start '2025-01-01T00:00:00.000Z' -Days 30)
        # Expired certificate on the application: NHI-003 only; certificates never count for 002/007.
        $cert = New-SynIdentity -Name 'expired-cert' -AppCerts @(New-SynSecretForDays -Start '2025-01-01T00:00:00.000Z' -Days 400)
        $script:b011 = @{ hidden = $hidden.appId; spOnly = $spOnly.appId; cert = $cert.appId }
        $script:keyId011 = $keyId
        $inv = Write-SynInventory -Identities @($hidden, $spOnly, $cert) -ScanStartUtc '2026-06-01T00:00:00Z' -Directory (Join-Path $TestDrive 'sp')
        $script:r011 = Invoke-SynEngine -InventoryPath $inv -OutputDirectory (Join-Path $TestDrive 'sp-out')
    }

    It 'the engine ran' { $script:r011.ExitCode | Should -Be 0 -Because $script:r011.Output }
    It 'a secret only on the service principal fires NHI-007 and nothing else' {
        $res = Get-SynResult $script:r011 $script:b011['hidden']
        Format-Set (Get-SynRuleIds $res) | Should -Be 'NHI-007'
        $res.score.total | Should -Be 10
        $res.score.uplift | Should -Be 0
    }
    It 'the evidence names the credential keyId and the object it is on' {
        $e = (Get-SynFinding (Get-SynResult $script:r011 $script:b011['hidden']) 'NHI-007').evidence[0]
        $e.keyId | Should -Be $script:keyId011
        $e.onObject | Should -Be 'servicePrincipal'
    }
    It 'an identity with no application object is still evaluated (expired SP secret fires NHI-003 only)' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:r011 $script:b011['spOnly'])) | Should -Be 'NHI-003'
    }
    It 'an expired certificate fires NHI-003 but not NHI-002 or NHI-007' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:r011 $script:b011['cert'])) | Should -Be 'NHI-003'
    }
}

Describe 'Scoring design (tiers, COMBO-U1, ownerType scope, role matching)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $gaId = '62e90394-69f5-4237-9190-012177145e10'
        $active90 = New-SynSecretForDays -Start '2026-05-20T00:00:00.000Z' -Days 90
        $expired400 = New-SynSecretForDays -Start '2024-01-01T00:00:00.000Z' -Days 400

        $defs = [ordered]@{
            armed        = New-SynIdentity -Name 'armed'        -AppRoleAssignments @(New-SynAppRole 'RoleManagement.ReadWrite.Directory') -SpSecrets @($active90)
            notArmed     = New-SynIdentity -Name 'notArmed'     -AppRoleAssignments @(New-SynAppRole 'RoleManagement.ReadWrite.Directory') -AppSecrets @($expired400)
            twoHigh      = New-SynIdentity -Name 'twoHigh'      -AppRoleAssignments @((New-SynAppRole 'Mail.Read'), (New-SynAppRole 'Mail.Send'))
            critAndHigh  = New-SynIdentity -Name 'critAndHigh'  -AppRoleAssignments @((New-SynAppRole 'Mail.Read'), (New-SynAppRole 'Application.ReadWrite.All'))
            dirRW        = New-SynIdentity -Name 'dirRW'        -AppRoleAssignments @(New-SynAppRole 'Directory.ReadWrite.All')
            roleActive   = New-SynIdentity -Name 'roleActive'   -Roles @(New-SynRole -RoleDefinitionId $gaId -RoleName 'totally different name')
            roleEligible = New-SynIdentity -Name 'roleEligible' -Roles @(New-SynRole -RoleDefinitionId $gaId -AssignmentType 'Eligible')
            roleWrongId  = New-SynIdentity -Name 'roleWrongId'  -Roles @(New-SynRole -RoleDefinitionId ([guid]::NewGuid().ToString()) -RoleName 'Global Administrator')
            roleArmed    = New-SynIdentity -Name 'roleArmed'    -Roles @(New-SynRole -RoleDefinitionId $gaId) -SpSecrets @($active90)
            thirdNoOwner = New-SynIdentity -Name 'thirdNoOwner' -OwnerType 'ThirdParty' -Owners 0
            msNoOwner    = New-SynIdentity -Name 'msNoOwner'    -OwnerType 'Microsoft' -Owners 0
            miNoOwner    = New-SynIdentity -Name 'miNoOwner'    -OwnerType 'ManagedIdentity' -Owners 0
            miPriv       = New-SynIdentity -Name 'miPriv'       -OwnerType 'ManagedIdentity' -Owners 0 -AppRoleAssignments @(New-SynAppRole 'Mail.Read')
            unknownOwner = New-SynIdentity -Name 'unknownOwner' -OwnerType 'Unknown' -Owners 0
            clean        = New-SynIdentity -Name 'clean'
        }
        $script:bd = @{}
        foreach ($k in $defs.Keys) { $script:bd[$k] = $defs[$k].appId }
        $inv = Write-SynInventory -Identities @($defs.Values) -ScanStartUtc '2026-06-01T00:00:00Z' -Directory (Join-Path $TestDrive 'design')
        $script:rd = Invoke-SynEngine -InventoryPath $inv -OutputDirectory (Join-Path $TestDrive 'design-out')
    }

    It 'the engine ran' { $script:rd.ExitCode | Should -Be 0 -Because $script:rd.Output }

    It 'COMBO-U1: privilege + ACTIVE secret adds 15 (40 + 10 + 15 = 65), shown separately' {
        $r = Get-SynResult $script:rd $script:bd['armed']
        Format-Set (Get-SynRuleIds $r) | Should -Be 'NHI-004,NHI-007'
        $r.score.base | Should -Be 50
        $r.score.uplift | Should -Be 15
        $r.score.total | Should -Be 65
        $r.uplifts[0].id | Should -Be 'COMBO-U1'
    }
    It 'COMBO-U1 does not fire on privilege + an EXPIRED long secret (NHI-002 is not in the condition)' {
        $r = Get-SynResult $script:rd $script:bd['notArmed']
        Format-Set (Get-SynRuleIds $r) | Should -Be 'NHI-002,NHI-003,NHI-004'
        $r.score.uplift | Should -Be 0
        $r.score.total | Should -Be 53
    }
    It 'COMBO-U1 also fires for NHI-005 + active secret (40 + 10 + 15 = 65)' {
        $r = Get-SynResult $script:rd $script:bd['roleArmed']
        Format-Set (Get-SynRuleIds $r) | Should -Be 'NHI-005,NHI-007'
        $r.score.total | Should -Be 65
    }
    It 'NHI-004 fires once: two High permissions score 25, not 50, and both are in the evidence' {
        $r = Get-SynResult $script:rd $script:bd['twoHigh']
        @($r.findings).Count | Should -Be 1
        $r.score.total | Should -Be 25
        @($r.findings[0].evidence).Count | Should -Be 2
    }
    It 'NHI-004 takes the highest tier: Critical + High scores 40' {
        $r = Get-SynResult $script:rd $script:bd['critAndHigh']
        $r.findings[0].severity | Should -Be 'Critical'
        $r.score.total | Should -Be 40
    }
    It 'Directory.ReadWrite.All is High (25)' {
        (Get-SynResult $script:rd $script:bd['dirRW']).score.total | Should -Be 25
    }
    It 'NHI-005 matches on role template ID, ignoring the display name (Active assignment fires)' {
        $r = Get-SynResult $script:rd $script:bd['roleActive']
        Format-Set (Get-SynRuleIds $r) | Should -Be 'NHI-005'
        $e = (Get-SynFinding $r 'NHI-005').evidence[0]
        $e.roleDefinitionId | Should -Be '62e90394-69f5-4237-9190-012177145e10'
        $e.label | Should -Be 'Global Administrator'
    }
    It 'NHI-005 ignores Eligible assignments' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:rd $script:bd['roleEligible'])) | Should -Be ''
    }
    It 'NHI-005 is not fooled by a role NAMED "Global Administrator" with a different template ID' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:rd $script:bd['roleWrongId'])) | Should -Be ''
    }
    It 'NHI-001 covers ThirdParty and Unknown, but not Microsoft or ManagedIdentity' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:rd $script:bd['thirdNoOwner'])) | Should -Be 'NHI-001'
        Format-Set (Get-SynRuleIds (Get-SynResult $script:rd $script:bd['unknownOwner'])) | Should -Be 'NHI-001'
        Format-Set (Get-SynRuleIds (Get-SynResult $script:rd $script:bd['msNoOwner'])) | Should -Be ''
        Format-Set (Get-SynRuleIds (Get-SynResult $script:rd $script:bd['miNoOwner'])) | Should -Be ''
    }
    It 'NHI-004 covers ManagedIdentity (privilege on a managed identity is caught)' {
        Format-Set (Get-SynRuleIds (Get-SynResult $script:rd $script:bd['miPriv'])) | Should -Be 'NHI-004'
    }
    It 'a clean owned identity scores 0' {
        (Get-SynResult $script:rd $script:bd['clean']).score.total | Should -Be 0
    }
    It 'the deferred rule NHI-006 never fires and is listed as skipped' {
        $fired = @($script:rd.Findings.identities | ForEach-Object { $_.findings } | ForEach-Object { $_.ruleId })
        $fired | Should -Not -Contain 'NHI-006'
        @($script:rd.Findings.skippedRules | Where-Object { $_.id -eq 'NHI-006' -and $_.status -eq 'deferred' }).Count | Should -Be 1
    }
    It 'results are ranked highest score first' {
        $totals = @($script:rd.Findings.identities | ForEach-Object { $_.score.total })
        $sorted = @($totals | Sort-Object -Descending)
        ($totals -join ',') | Should -Be ($sorted -join ',')
    }
}

Describe 'Engine properties (offline, deterministic, traceable)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $id = New-SynIdentity -Name 'one' -AppSecrets @(New-SynSecretForDays -Start '2026-05-20T00:00:00.000Z' -Days 90)
        $script:invPath = Write-SynInventory -Identities @($id) -ScanStartUtc '2026-06-01T00:00:00Z' -Directory (Join-Path $TestDrive 'props')
        $script:runA = Invoke-SynEngine -InventoryPath $script:invPath -OutputDirectory (Join-Path $TestDrive 'props-a')
        $script:runB = Invoke-SynEngine -InventoryPath $script:invPath -OutputDirectory (Join-Path $TestDrive 'props-b')
    }

    It 'the same inputs give byte-identical output (no wall clock anywhere)' {
        $script:runA.ExitCode | Should -Be 0 -Because $script:runA.Output
        (Get-FileHash -LiteralPath $script:runA.Path).Hash | Should -Be (Get-FileHash -LiteralPath $script:runB.Path).Hash
    }
    It 'records the inventory file name, both SHA-256 hashes, engine version and scan clock' {
        $i = $script:runA.Findings.inputs
        $i.inventoryFile | Should -Be ([System.IO.Path]::GetFileName($script:invPath))
        $i.inventorySha256 | Should -Be (Get-FileHash -LiteralPath $script:invPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $i.rulesSha256 | Should -Be (Get-FileHash -LiteralPath (Join-Path (Get-RepoRoot) 'scanner/risk-rules.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:runA.Findings.engine.version | Should -Not -BeNullOrEmpty
        $i.scanStartUtc | Should -Be '2026-06-01T00:00:00.000Z'
    }
    It 'names the findings file after the inventory timestamp' {
        [System.IO.Path]::GetFileName($script:runA.Path) | Should -Be 'findings-20260101-000000Z.json'
    }
    It 'refuses to run (exit 1) when the inventory has no scanStartUtc, instead of using the clock' {
        $bad = Join-Path $TestDrive 'nostart'
        New-Item -ItemType Directory -Path $bad -Force | Out-Null
        $p = Join-Path $bad 'inventory-20260101-000000Z.json'
        '{ "scanMetadata": { }, "identities": [] }' | Set-Content -LiteralPath $p -Encoding utf8
        $r = Invoke-SynEngine -InventoryPath $p -OutputDirectory (Join-Path $TestDrive 'nostart-out')
        $r.ExitCode | Should -Be 1
    }
    It 'both scripts contain no sign-in, module import, network or wall-clock calls' {
        $forbidden = 'Connect-MgGraph', 'Import-Module', 'Invoke-RestMethod', 'Invoke-WebRequest', 'Invoke-MgGraphRequest', 'Get-Mg', 'Get-Date',
                     '\[datetime\]::(Utc)?Now', '\[datetimeoffset\]::(Utc)?Now', 'System\.Net\.'
        foreach ($name in 'Invoke-NhiScoring.ps1', 'Test-NhiFindings.ps1') {
            $text = Get-Content -LiteralPath (Join-Path (Get-RepoRoot) "scanner/$name") -Raw
            foreach ($f in $forbidden) { $text | Should -Not -Match $f -Because "$name must not contain '$f'" }
        }
    }
}

Describe 'Output order is ordinal, not culture-sensitive' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        # Under a culture-sensitive, case-insensitive comparison 'a-app' sorts before 'B-app'; under
        # ordinal comparison 'B' (U+0042) sorts before 'a' (U+0061). The engine must use ordinal.
        $ids = @(
            (New-SynIdentity -Name 'a-app' -AppId 'bbbbbbbb-0000-0000-0000-000000000001'),
            (New-SynIdentity -Name 'B-app' -AppId 'bbbbbbbb-0000-0000-0000-000000000002'),
            (New-SynIdentity -Name 'same'  -AppId 'ffffffff-0000-0000-0000-000000000003'),
            (New-SynIdentity -Name 'same'  -AppId '00000000-0000-0000-0000-000000000004'),
            (New-SynIdentity -Name 'low-score-first-in-input' -Owners 0)   # NHI-001 -> 10 points
        )
        $inv = Write-SynInventory -Identities $ids -ScanStartUtc '2026-06-01T00:00:00Z' -Directory (Join-Path $TestDrive 'ord')
        $script:ordRun = Invoke-SynEngine -InventoryPath $inv -OutputDirectory (Join-Path $TestDrive 'ord-out')
    }
    It 'runs' { $script:ordRun.ExitCode | Should -Be 0 -Because $script:ordRun.Output }
    It 'sorts higher scores first, then displayName by ordinal comparison ("B-app" before "a-app")' {
        $names = @($script:ordRun.Findings.identities | ForEach-Object displayName)
        $names[0] | Should -Be 'low-score-first-in-input'
        ([array]::IndexOf($names, 'B-app')) | Should -BeLessThan ([array]::IndexOf($names, 'a-app'))
        # confirm the premise: the culture-sensitive order really is the opposite on this machine
        ([string]::Compare('a-app', 'B-app', [System.StringComparison]::InvariantCultureIgnoreCase)) | Should -BeLessThan 0
    }
    It 'breaks displayName ties by appId, ordinal ascending' {
        $same = @($script:ordRun.Findings.identities | Where-Object displayName -eq 'same' | ForEach-Object appId)
        $same[0] | Should -Be '00000000-0000-0000-0000-000000000004'
        $same[1] | Should -Be 'ffffffff-0000-0000-0000-000000000003'
    }
}
