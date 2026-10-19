#Requires -Version 7.0
<#
.SYNOPSIS
    Phase 3 scoring engine: applies scanner/risk-rules.json to an inventory file.

.DESCRIPTION
    OFFLINE ONLY. This script reads two local JSON files (an inventory written by
    Invoke-NhiInventory.ps1, and risk-rules.json) and writes one local JSON file. It signs in
    to nothing, loads no Graph module and makes no network calls.

    Design is fixed in risk-rules.json and docs/risk-model.md; this script only executes it:
      - The clock is scanMetadata.scanStartUtc from the inventory. The machine's wall clock is
        never read, so the same inputs always produce the same findings file.
      - A rule runs on an identity only if the identity's ownerType is in the rule's appliesTo.
      - Rules whose status is not "active" (NHI-006 is "deferred") are skipped and listed.
      - Graph resources are matched by the resolved appId of the resource service principal
        (inventory index: servicePrincipal.id -> appId), never by display name.
      - Credential rules read BOTH application.* and servicePrincipal.* credentials.
      - A rule with appliesTo.identityType runs only on those identity types (Phase 4: Agent ID).
        Inventories older than scanner v0.2.0 have no identityType; it is read as 'application'.
      - score = base (sum of finding points) + uplift (combinations such as COMBO-U1).
      - Cross-identity combinations (COMBO-U3) run in a second pass, after every identity has its
        own findings, because they need a blueprint's findings AND its child agents' findings.

.PARAMETER InventoryPath
    Inventory JSON produced by Invoke-NhiInventory.ps1.

.PARAMETER RulesPath
    Rules file. Defaults to risk-rules.json next to this script.

.PARAMETER OutputDirectory
    Where findings-<inventory timestamp>.json is written. Defaults to <repo>/output (gitignored).

.PARAMETER Top
    How many ranked identities to print in the console summary.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InventoryPath,

    [string]$RulesPath = (Join-Path $PSScriptRoot 'risk-rules.json'),

    [string]$OutputDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'output'),

    [int]$Top = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:EngineVersion = '0.2.0'
$script:Warnings      = [System.Collections.Generic.List[object]]::new()
$script:WarningKeys   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:ScanStart     = $null   # DateTimeOffset, set once from the inventory
$script:SpIndex       = $null   # servicePrincipal.id -> appId
$script:Rules         = $null

# ---------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------

# Strict mode throws when a property is absent. Inventory objects legitimately omit things
# (an app-only identity has no servicePrincipal), so every read goes through this.
function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# Dates are read as strings (ConvertFrom-Json -DateKind String) and parsed here as UTC, so
# there is no hidden local-time conversion. Comparisons are on exact instants.
function ConvertTo-UtcDateTimeOffset {
    param($Value, [string]$What)
    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $parsed = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        throw "Cannot parse '$Value' as a date ($What)."
    }
    return $parsed
}

function Format-Utc {
    param([datetimeoffset]$Value)
    return $Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-FileSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-JsonFile {
    param([string]$Path)
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -DateKind String)
}

function Add-ScanWarning {
    param(
        [string]$Code,
        [string]$Message,
        $Identity,
        [hashtable]$Detail = @{}
    )
    $appId = Get-Prop $Identity 'appId'
    # One warning per distinct problem, however many rules trip over it.
    $key = "$Code|$appId|" + (($Detail.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';')
    if (-not $script:WarningKeys.Add($key)) { return }
    # A plain hashtable's key order is randomised per process in .NET, so copy the detail into
    # an ordered dictionary sorted by key (ordinal). Otherwise two runs on the same inputs could
    # write the detail fields in a different order and break byte-identical output.
    $names = [string[]]@($Detail.Keys)
    [System.Array]::Sort($names, [System.StringComparer]::Ordinal)
    $sortedDetail = [ordered]@{}
    foreach ($name in $names) { $sortedDetail[$name] = $Detail[$name] }
    $script:Warnings.Add([ordered]@{
        code        = $Code
        message     = $Message
        appId       = $appId
        displayName = Get-Prop $Identity 'displayName'
        detail      = $sortedDetail
    })
}

# Every credential on BOTH objects. seed-11 keeps its only credential on the service
# principal, so reading only the application would miss it (regression test).
function Get-IdentityCredentials {
    param($Identity)
    foreach ($objectName in 'application', 'servicePrincipal') {
        $obj = Get-Prop $Identity $objectName
        if ($null -eq $obj) { continue }
        foreach ($source in @(@('passwordCredentials', 'secret'), @('keyCredentials', 'certificate'))) {
            foreach ($c in @(Get-Prop $obj $source[0])) {
                if ($null -eq $c) { continue }
                $start = ConvertTo-UtcDateTimeOffset (Get-Prop $c 'startDateTime') 'startDateTime'
                $end   = ConvertTo-UtcDateTimeOffset (Get-Prop $c 'endDateTime') 'endDateTime'
                if ($null -eq $end) {
                    Add-ScanWarning -Code 'credentialMissingEndDate' -Identity $Identity `
                        -Message "A $($source[1]) has no endDateTime, so it cannot be evaluated." `
                        -Detail @{ onObject = $objectName; keyId = [string](Get-Prop $c 'keyId') }
                    continue
                }
                [pscustomobject]@{
                    Kind        = $source[1]
                    OnObject    = $objectName
                    KeyId       = [string](Get-Prop $c 'keyId')
                    DisplayName = [string](Get-Prop $c 'displayName')
                    Start       = $start
                    End         = $end
                }
            }
        }
    }
}

function New-CredentialEvidence {
    param($Credential)
    $item = [ordered]@{
        credentialType = $Credential.Kind
        onObject       = $Credential.OnObject
        keyId          = $Credential.KeyId
        displayName    = $Credential.DisplayName
        startDateTime  = if ($null -ne $Credential.Start) { Format-Utc $Credential.Start } else { $null }
        endDateTime    = Format-Utc $Credential.End
        expiredAtScan  = ($Credential.End -le $script:ScanStart)
    }
    if ($null -ne $Credential.Start) {
        $item['lifetimeDays'] = [int][math]::Floor(($Credential.End - $Credential.Start).TotalDays)
    }
    return $item
}

# resourceId is the object id of the resource's service principal IN THIS TENANT. Look it up
# in the inventory and return that service principal's appId. Display names are never used.
function Resolve-ResourceAppId {
    param($Identity, $ResourceId, [string]$Source)
    if ($null -ne $ResourceId -and $script:SpIndex.ContainsKey([string]$ResourceId)) {
        return $script:SpIndex[[string]$ResourceId]
    }
    Add-ScanWarning -Code 'unresolvedResource' -Identity $Identity `
        -Message "resourceId is not a service principal in the inventory, so this entry cannot match any rule." `
        -Detail @{ source = $Source; resourceId = [string]$ResourceId }
    return $null
}

# Grants can store scopes as an array or a space-separated string; accept both.
function Get-FlatScopes {
    param($Scopes)
    foreach ($s in @($Scopes)) {
        if ($null -eq $s) { continue }
        foreach ($piece in ([string]$s -split '\s+')) { if ($piece) { $piece } }
    }
}

# ---------------------------------------------------------------------------------------
# Rule evaluators. Each returns $null (no finding) or @{ Severity; Evidence } for ONE
# identity. They hold the logic; risk-rules.json holds the lists, tiers and thresholds.
# ---------------------------------------------------------------------------------------

function Test-Nhi001 {
    param($Identity, $Rule)
    $app = Get-Prop $Identity 'application'
    $sp  = Get-Prop $Identity 'servicePrincipal'
    if ($null -eq $app -and $null -eq $sp) { return $null }
    $appOwners = if ($null -ne $app) { @(Get-Prop $app 'owners' | Where-Object { $null -ne $_ }).Count } else { $null }
    $spOwners  = if ($null -ne $sp)  { @(Get-Prop $sp  'owners' | Where-Object { $null -ne $_ }).Count } else { $null }
    # "Both empty (or absent)": an owner on either object means someone is accountable.
    if (($appOwners -gt 0) -or ($spOwners -gt 0)) { return $null }
    return @{
        Severity = $Rule.severity
        Evidence = @([ordered]@{ applicationOwners = $appOwners; servicePrincipalOwners = $spOwners })
    }
}

function Test-Nhi002 {
    param($Identity, $Rule)
    $max = Get-Prop (Get-Prop $Rule 'parameters') 'maxLifetimeDays'
    if ($null -eq $max) { throw "Rule NHI-002 has no parameters.maxLifetimeDays in the rules file." }
    $evidence = foreach ($c in Get-IdentityCredentials $Identity) {
        if ($c.Kind -ne 'secret' -or $null -eq $c.Start) { continue }
        # Whole days (floor) so sub-day client/server timestamp skew cannot flip the boundary.
        $days = [int][math]::Floor(($c.End - $c.Start).TotalDays)
        # Strictly greater: exactly 180 does not fire. Expired secrets count too.
        if ($days -gt $max) { New-CredentialEvidence $c }
    }
    if (@($evidence).Count -eq 0) { return $null }
    return @{ Severity = $Rule.severity; Evidence = @($evidence) }
}

function Test-Nhi003 {
    param($Identity, $Rule)
    $evidence = foreach ($c in Get-IdentityCredentials $Identity) {
        # end == scanStart counts as expired.
        if ($c.End -le $script:ScanStart) { New-CredentialEvidence $c }
    }
    if (@($evidence).Count -eq 0) { return $null }
    return @{ Severity = $Rule.severity; Evidence = @($evidence) }
}

function Test-Nhi004 {
    param($Identity, $Rule)
    $sp = Get-Prop $Identity 'servicePrincipal'
    if ($null -eq $sp) { return $null }
    $points = $script:Rules.scoring.tierPoints
    $evidence = @()
    $best = $null
    foreach ($a in @(Get-Prop $sp 'appRoleAssignments')) {
        if ($null -eq $a) { continue }
        $resolved = Resolve-ResourceAppId $Identity (Get-Prop $a 'resourceId') 'appRoleAssignments'
        if ($resolved -ne $Rule.resourceAppId) { continue }
        $permission = [string](Get-Prop $a 'permission')
        foreach ($tier in $Rule.tiers) {
            if ($permission -in @($tier.permissions)) {
                $evidence += [ordered]@{
                    permission            = $permission
                    tier                  = $tier.severity
                    resourceId            = [string](Get-Prop $a 'resourceId')
                    resolvedResourceAppId = $resolved
                    appRoleId             = [string](Get-Prop $a 'appRoleId')
                }
                if ($null -eq $best -or $points.($tier.severity) -gt $points.$best) { $best = $tier.severity }
            }
        }
    }
    if ($evidence.Count -eq 0) { return $null }
    # One finding at the HIGHEST matching tier; extra permissions do not stack points.
    return @{ Severity = $best; Evidence = $evidence }
}

function Test-Nhi005 {
    param($Identity, $Rule)
    $sp = Get-Prop $Identity 'servicePrincipal'
    if ($null -eq $sp) { return $null }
    $evidence = @()
    foreach ($r in @(Get-Prop $sp 'directoryRoles')) {
        if ($null -eq $r) { continue }
        # Template ID decides; roleName from the inventory is shown but never matched on.
        $roleId = [string](Get-Prop $r 'roleDefinitionId')
        $listed = @($Rule.privilegedRoles | Where-Object { $_.roleDefinitionId -eq $roleId })
        if ($listed.Count -eq 0) { continue }
        if ((Get-Prop $r 'assignmentType') -notin @($Rule.assignmentTypes)) { continue }
        $evidence += [ordered]@{
            roleDefinitionId = $roleId
            label            = $listed[0].label
            assignmentType   = [string](Get-Prop $r 'assignmentType')
            directoryScopeId = [string](Get-Prop $r 'directoryScopeId')
            inventoryRoleName = [string](Get-Prop $r 'roleName')
        }
    }
    if ($evidence.Count -eq 0) { return $null }
    return @{ Severity = $Rule.severity; Evidence = $evidence }
}

function Test-Nhi007 {
    param($Identity, $Rule)
    $evidence = foreach ($c in Get-IdentityCredentials $Identity) {
        if ($c.Kind -ne 'secret') { continue }
        if ($c.End -gt $script:ScanStart) { New-CredentialEvidence $c }
    }
    if (@($evidence).Count -eq 0) { return $null }
    return @{ Severity = $Rule.severity; Evidence = @($evidence) }
}

function Test-Nhi008 {
    param($Identity, $Rule)
    $sp = Get-Prop $Identity 'servicePrincipal'
    if ($null -eq $sp) { return $null }
    $evidence = @()
    foreach ($g in @(Get-Prop $sp 'oauth2PermissionGrants')) {
        if ($null -eq $g) { continue }
        if ((Get-Prop $g 'consentType') -ne 'AllPrincipals') { continue }
        $resolved = Resolve-ResourceAppId $Identity (Get-Prop $g 'resourceId') 'oauth2PermissionGrants'
        if ($resolved -ne $Rule.resourceAppId) { continue }
        $all = @(Get-FlatScopes (Get-Prop $g 'scopes'))
        $matched = @($all | Where-Object { $_ -in @($Rule.scopes) })
        if ($matched.Count -eq 0) { continue }
        $evidence += [ordered]@{
            consentType           = 'AllPrincipals'
            matchedScopes         = $matched
            allScopes             = $all
            resourceId            = [string](Get-Prop $g 'resourceId')
            resolvedResourceAppId = $resolved
        }
    }
    if ($evidence.Count -eq 0) { return $null }
    return @{ Severity = $Rule.severity; Evidence = $evidence }
}

# NHI-009: same test as NHI-007 (an active secret on either object). The difference is WHICH
# identities it runs on, and that lives in risk-rules.json (appliesTo.identityType), not here.
function Test-Nhi009 {
    param($Identity, $Rule)
    return Test-Nhi007 $Identity $Rule
}

# NHI-010 / NHI-011: "no enabled sponsor". Blueprints keep sponsors on the application object,
# agents on the service principal. A null list means the scanner could not read it: that is
# "unknown", so it warns instead of firing (never guess). [] means confirmed no sponsors.
function Test-SponsorRule {
    param($Identity, $Rule, [string]$OnObject)
    $obj = Get-Prop $Identity $OnObject
    # Read the property directly, NOT through Get-Prop: a function returning an empty array
    # hands back $null, which would turn "confirmed no sponsors" into "unknown".
    $prop = if ($null -ne $obj) { $obj.PSObject.Properties['sponsors'] } else { $null }
    if ($null -eq $prop -or $null -eq $prop.Value) {
        Add-ScanWarning -Code 'sponsorLookupUnknown' -Identity $Identity `
            -Message "Sponsors for this identity are unknown (lookup failed or the inventory predates sponsor collection), so $($Rule.id) was not evaluated." `
            -Detail @{ onObject = $OnObject; rule = $Rule.id }
        return $null
    }
    $all = @($prop.Value | Where-Object { $null -ne $_ })
    # A group cannot be checked for enabled members (membership is not inventoried), so it counts.
    $accountable = @($all | Where-Object {
        ([string](Get-Prop $_ 'type') -like '*group') -or ((Get-Prop $_ 'accountEnabled') -eq $true)
    })
    if ($accountable.Count -gt 0) { return $null }
    return @{
        Severity = $Rule.severity
        Evidence = @([ordered]@{
            onObject        = $OnObject
            sponsorCount    = $all.Count
            disabledOrUnknownSponsors = @($all | ForEach-Object { [string](Get-Prop $_ 'userPrincipalName') })
        })
    }
}

function Invoke-NhiRule {
    param($Identity, $Rule)
    switch ($Rule.id) {
        'NHI-001' { return Test-Nhi001 $Identity $Rule }
        'NHI-002' { return Test-Nhi002 $Identity $Rule }
        'NHI-003' { return Test-Nhi003 $Identity $Rule }
        'NHI-004' { return Test-Nhi004 $Identity $Rule }
        'NHI-005' { return Test-Nhi005 $Identity $Rule }
        'NHI-007' { return Test-Nhi007 $Identity $Rule }
        'NHI-008' { return Test-Nhi008 $Identity $Rule }
        'NHI-009' { return Test-Nhi009 $Identity $Rule }
        'NHI-010' { return Test-SponsorRule $Identity $Rule 'application' }
        'NHI-011' { return Test-SponsorRule $Identity $Rule 'servicePrincipal' }
        # An active rule with no evaluator must stop the run, not be silently skipped.
        default   { throw "Rule $($Rule.id) is active in the rules file but this engine version has no evaluator for it." }
    }
}

# ---------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------

function Invoke-Main {
    $invPath   = (Resolve-Path -LiteralPath $InventoryPath).Path
    $rulesPath = (Resolve-Path -LiteralPath $RulesPath).Path
    $inventory = Read-JsonFile $invPath
    $script:Rules = Read-JsonFile $rulesPath

    $meta = Get-Prop $inventory 'scanMetadata'
    $script:ScanStart = ConvertTo-UtcDateTimeOffset (Get-Prop $meta 'scanStartUtc') 'scanMetadata.scanStartUtc'
    if ($null -eq $script:ScanStart) { throw "Inventory has no scanMetadata.scanStartUtc; the engine will not fall back to the wall clock." }

    $identities = @(Get-Prop $inventory 'identities')

    # servicePrincipal.id -> appId, built from the inventory itself.
    $script:SpIndex = @{}
    foreach ($i in $identities) {
        $sp = Get-Prop $i 'servicePrincipal'
        if ($null -eq $sp) { continue }
        $spId = [string](Get-Prop $sp 'id')
        if ($spId) { $script:SpIndex[$spId] = [string](Get-Prop $i 'appId') }
    }

    $tierPoints = $script:Rules.scoring.tierPoints
    $activeRules = @($script:Rules.rules | Where-Object { $_.status -eq 'active' })
    $skippedRules = @($script:Rules.rules | Where-Object { $_.status -ne 'active' } |
        ForEach-Object { [ordered]@{ id = $_.id; status = $_.status } })
    $allCombos = @(Get-Prop $script:Rules 'combinations' | Where-Object { $null -ne $_ -and $_.status -eq 'active' })
    # Per-identity combinations run in pass 1; cross-identity ones (COMBO-U3) need every
    # identity's findings first, so they run in pass 2 below.
    $combinations = @($allCombos | Where-Object { (Get-Prop $_ 'scope') -ne 'crossIdentity' })
    $crossCombos  = @($allCombos | Where-Object { (Get-Prop $_ 'scope') -eq 'crossIdentity' })
    $cap = $script:Rules.scoring.scoreCap

    $scored = foreach ($identity in $identities) {
        $ownerType = [string](Get-Prop $identity 'ownerType')
        if (-not $ownerType) { $ownerType = 'Unknown' }
        # Inventories written before scanner v0.2.0 have no identityType: everything was 'application'.
        $identityType = [string](Get-Prop $identity 'identityType')
        if (-not $identityType) { $identityType = 'application' }

        $findings = @()
        foreach ($rule in $activeRules) {
            if ($ownerType -notin @($rule.appliesTo.ownerType)) { continue }
            # identityType scoping is optional: a rule without it runs on every identity type.
            $typeScope = Get-Prop $rule.appliesTo 'identityType'
            if ($null -ne $typeScope -and $identityType -notin @($typeScope)) { continue }
            $hit = Invoke-NhiRule $identity $rule
            if ($null -eq $hit) { continue }
            $findings += [ordered]@{
                ruleId   = $rule.id
                name     = $rule.name
                severity = $hit.Severity
                points   = [int]$tierPoints.($hit.Severity)
                nist     = @($rule.nist)
                evidence = @($hit.Evidence)
            }
        }

        $fired = @($findings | ForEach-Object { $_.ruleId })
        $uplifts = @()
        foreach ($combo in $combinations) {
            # Three condition shapes, all optional:
            #   anyOf    - at least one of these fired
            #   allOf    - every one of these fired
            #   allOfAny - a list of groups; every group needs at least one fired rule
            #              (COMBO-U1: [[NHI-004, NHI-005], [NHI-007, NHI-009]])
            $any = @(Get-Prop $combo.requires 'anyOf' | Where-Object { $_ })
            $all = @(Get-Prop $combo.requires 'allOf' | Where-Object { $_ })
            $groups = @(Get-Prop $combo.requires 'allOfAny' | Where-Object { $null -ne $_ })
            $anyOk = ($any.Count -eq 0) -or (@($any | Where-Object { $_ -in $fired }).Count -gt 0)
            $allOk = (@($all | Where-Object { $_ -notin $fired }).Count -eq 0)
            $groupsOk = $true
            $groupRules = @()
            foreach ($g in $groups) {
                $hits = @(@($g) | Where-Object { $_ -in $fired })
                if ($hits.Count -eq 0) { $groupsOk = $false }
                $groupRules += @($g)
            }
            if ($anyOk -and $allOk -and $groupsOk) {
                $uplifts += [ordered]@{
                    id     = $combo.id
                    name   = $combo.name
                    points = [int]$combo.uplift
                    because = @($fired | Where-Object { $_ -in $any -or $_ -in $all -or $_ -in $groupRules })
                }
            }
        }

        # Plain loops: findings and uplifts are ordered dictionaries, not objects.
        $base = 0
        foreach ($f in $findings) { $base += [int]$f.points }
        $uplift = 0
        foreach ($u in $uplifts) { $uplift += [int]$u.points }
        $total  = $base + $uplift
        $capped = $false
        if ($null -ne $cap -and $total -gt $cap) { $total = [int]$cap; $capped = $true }

        [ordered]@{
            appId        = [string](Get-Prop $identity 'appId')
            displayName  = [string](Get-Prop $identity 'displayName')
            ownerType    = $ownerType
            identityType = $identityType
            score        = [ordered]@{ base = $base; uplift = $uplift; total = $total; capApplied = $capped }
            findings     = $findings
            uplifts      = $uplifts
        }
    }
    $scored = @($scored)

    # ---- Pass 2: Agent ID parent/child links, COMBO-U3 and the (context-only) roll-up ----
    # An agent names its blueprint by appId (servicePrincipal.agentIdentityBlueprintId).
    $resultByAppId = @{}
    foreach ($s in $scored) { $resultByAppId[$s.appId] = $s }
    $childrenByParent = @{}
    foreach ($identity in $identities) {
        $parentAppId = [string](Get-Prop (Get-Prop $identity 'servicePrincipal') 'agentIdentityBlueprintId')
        if (-not $parentAppId) { continue }
        $child = $resultByAppId[[string](Get-Prop $identity 'appId')]
        $parent = $resultByAppId[$parentAppId]
        if ($null -eq $parent -or $parent.identityType -ne 'agentBlueprint') {
            Add-ScanWarning -Code 'unresolvedBlueprint' -Identity $identity `
                -Message 'This agent names a blueprint that is not an agentBlueprint in the inventory, so it cannot be linked or take part in COMBO-U3.' `
                -Detail @{ agentIdentityBlueprintId = $parentAppId }
            $child['parentBlueprint'] = [ordered]@{ appId = $parentAppId; displayName = $null; resolved = $false }
            continue
        }
        $child['parentBlueprint'] = [ordered]@{ appId = $parentAppId; displayName = $parent.displayName; resolved = $true }
        if (-not $childrenByParent.ContainsKey($parentAppId)) { $childrenByParent[$parentAppId] = [System.Collections.Generic.List[object]]::new() }
        $childrenByParent[$parentAppId].Add($child)
    }

    foreach ($bp in @($scored | Where-Object { $_.identityType -eq 'agentBlueprint' })) {
        # Children in a fixed (ordinal appId) order so the output is byte-identical run to run.
        $kids = [System.Collections.Generic.List[object]]::new()
        if ($childrenByParent.ContainsKey($bp.appId)) { foreach ($k in $childrenByParent[$bp.appId]) { $kids.Add($k) } }
        $kids.Sort([System.Comparison[object]]{ param($a, $b) [string]::CompareOrdinal([string]$a.appId, [string]$b.appId) })
        $kids = @($kids)

        $selfFired = @($bp.findings | ForEach-Object { $_.ruleId })
        foreach ($combo in $crossCombos) {
            $needSelf  = @(Get-Prop $combo.requires 'self' | Where-Object { $_ })
            $needChild = @(Get-Prop $combo.requires 'anyChild' | Where-Object { $_ })
            if (@($needSelf | Where-Object { $_ -notin $selfFired }).Count -gt 0) { continue }
            $qualifying = @($kids | Where-Object {
                $kidFired = @($_.findings | ForEach-Object { $_.ruleId })
                @($needChild | Where-Object { $_ -in $kidFired }).Count -gt 0
            })
            if ($qualifying.Count -eq 0) { continue }
            $bp.uplifts += [ordered]@{
                id       = $combo.id
                name     = $combo.name
                points   = [int]$combo.uplift
                because  = @($selfFired | Where-Object { $_ -in $needSelf })
                children = @($qualifying | ForEach-Object {
                    $kidFired = @($_.findings | ForEach-Object { $_.ruleId })
                    [ordered]@{ appId = $_.appId; displayName = $_.displayName; rules = @($kidFired | Where-Object { $_ -in $needChild }) }
                })
            }
            $bp.score.uplift += [int]$combo.uplift
            $bp.score.total  = $bp.score.base + $bp.score.uplift
            if ($null -ne $cap -and $bp.score.total -gt $cap) { $bp.score.total = [int]$cap; $bp.score.capApplied = $true }
        }

        # Context only: never added to the score (project owner's decision, risk-rules.json).
        # worstChild is the highest-scoring child with a score above 0 (ties: first in appId
        # order); null when no child has any finding, so a clean blueprint names no "worst" agent.
        $worst = $null
        foreach ($k in $kids) {
            if ($k.score.total -le 0) { continue }
            if ($null -eq $worst -or $k.score.total -gt $worst.score.total) { $worst = $k }
        }
        $bp['agentRollup'] = [ordered]@{
            agentCount         = $kids.Count
            agentsWithFindings = @($kids | Where-Object { $_.findings.Count -gt 0 }).Count
            worstChild         = if ($null -ne $worst) { [ordered]@{ appId = $worst.appId; displayName = $worst.displayName; score = $worst.score.total } } else { $null }
        }
    }
    # Order: score descending, then displayName, then appId. The two string keys use ORDINAL
    # comparison (UTF-16 code units), not Sort-Object's culture-sensitive one, so the order is the
    # same on every machine whatever its regional settings. appId is unique per identity, so no two
    # identities compare equal and the (unstable) List.Sort cannot change the outcome.
    $sorted = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $scored) { $sorted.Add($s) }
    $sorted.Sort([System.Comparison[object]]{
        param($a, $b)
        if ($a.score.total -ne $b.score.total) { return $b.score.total.CompareTo($a.score.total) }
        $c = [string]::CompareOrdinal([string]$a.displayName, [string]$b.displayName)
        if ($c -ne 0) { return $c }
        return [string]::CompareOrdinal([string]$a.appId, [string]$b.appId)
    })
    $scored = @($sorted)

    $findingsByRule = [ordered]@{}
    foreach ($r in $activeRules) {
        $findingsByRule[$r.id] = @($scored | Where-Object { @($_.findings | Where-Object { $_.ruleId -eq $r.id }).Count -gt 0 }).Count
    }

    $invFile = Split-Path -Leaf $invPath
    $stamp = if ($invFile -match '^inventory-(.+)\.json$') { $Matches[1] } else { $script:ScanStart.UtcDateTime.ToString('yyyyMMdd-HHmmss') + 'Z' }

    # No generation timestamp on purpose: output depends only on its inputs, so re-running
    # on the same files gives byte-identical output.
    $output = [ordered]@{
        engine = [ordered]@{ name = 'Invoke-NhiScoring.ps1'; version = $script:EngineVersion }
        inputs = [ordered]@{
            inventoryFile      = $invFile
            inventorySha256    = Get-FileSha256 $invPath
            rulesFile          = Split-Path -Leaf $rulesPath
            rulesSha256        = Get-FileSha256 $rulesPath
            rulesSchemaVersion = [string]$script:Rules.schemaVersion
            scanStartUtc       = Format-Utc $script:ScanStart
            inventoryScannerVersion = [string](Get-Prop $meta 'scannerVersion')
        }
        scoring = [ordered]@{
            model      = [string]$script:Rules.scoring.model
            tierPoints = $tierPoints
            scoreCap   = $cap
        }
        skippedRules = $skippedRules
        warnings     = @($script:Warnings)
        summary = [ordered]@{
            identitiesScored       = $scored.Count
            identitiesWithFindings = @($scored | Where-Object { $_.findings.Count -gt 0 }).Count
            maxScore               = if ($scored.Count) { $scored[0].score.total } else { 0 }
            findingsByRule         = $findingsByRule
            warningCount           = $script:Warnings.Count
        }
        identities = $scored
    }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
    $outPath = Join-Path (Resolve-Path -LiteralPath $OutputDirectory).Path "findings-$stamp.json"
    $json = $output | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($outPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))

    # ---- console summary ----
    Write-Host ''
    Write-Host "NHI scoring  engine $($script:EngineVersion)"
    Write-Host "  inventory : $invFile"
    Write-Host "  scan start: $(Format-Utc $script:ScanStart)  (the clock used for every rule)"
    Write-Host "  identities: $($scored.Count) scored, $($output.summary.identitiesWithFindings) with findings, max score $($output.summary.maxScore)"
    Write-Host "  skipped   : $((@($skippedRules | ForEach-Object { "$($_.id) ($($_.status))" })) -join ', ')"
    Write-Host "  warnings  : $($script:Warnings.Count)"
    $ranked = @($scored | Where-Object { $_.score.total -gt 0 } | Select-Object -First $Top | ForEach-Object -Begin { $n = 0 } -Process {
        $n++
        [pscustomobject]@{
            Rank   = $n
            Score  = $_.score.total
            Base   = $_.score.base
            Uplift = $_.score.uplift
            Owner  = $_.ownerType
            Type   = $_.identityType
            Name   = $_.displayName
            Rules  = (@($_.findings | ForEach-Object { $_.ruleId }) -join ',')
        }
    })
    if ($ranked.Count -gt 0) { $ranked | Format-Table -AutoSize | Out-Host }
    Write-Host '  findings  :'
    return $outPath
}

try {
    Invoke-Main
}
catch {
    Write-Error "Invoke-NhiScoring failed: $($_.Exception.Message)"
    exit 1
}
