#Requires -Version 7.0
<#
.SYNOPSIS
    READ-ONLY inventory of every app registration and service principal in the tenant.

.DESCRIPTION
    Phase 2 of the NHI Governance Toolkit. This script records FACTS only. It does not
    judge anything ("expired", "risky", "stale" are deliberately absent) - the scoring
    layer in Phase 3 will read this file and apply rules from risk-rules.json.

    Approach, in plain language:
      1. Sign in interactively with read-only scopes.
      2. Pull applications and service principals (paged).
      3. Pull the things that attach to a service principal: app role assignments
         (application permissions), oauth2 permission grants (delegated consent),
         directory role assignments (active + PIM eligible), sign-in activity.
      4. Merge everything into ONE record per appId and write it as JSON.
      5. (Phase 4) Recognise Entra Agent ID objects from their Graph @odata.type, record each
         agent's parent blueprint and the sponsors of blueprints and agents.

    Every Graph call goes through Invoke-GraphGet below, which hard-codes -Method GET.
    That is the single choke point guaranteeing the scanner cannot write to the tenant.

.PARAMETER OutputDirectory
    Where the JSON file is written. Default .\output (gitignored - it contains tenant data).

.PARAMETER SkipSignInActivity
    Skip the beta sign-in activity report (e.g. when licensing/permission is missing).
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = '.\output',
    [switch]$SkipSignInActivity
)

$ErrorActionPreference = 'Stop'
# Captured before auth so it is a stable "as of" instant. Rules (credential age,
# 90-day inactivity, etc.) must evaluate against scanStartUtc, never the wall clock
# at scoring time, so re-scoring the same file always gives the same answer.
$scanStart = (Get-Date).ToUniversalTime()
$ScannerVersion = '0.2.0'
$warnings = [System.Collections.Generic.List[string]]::new()

function Add-ScanWarning {
    param([string]$Message)
    $warnings.Add($Message)
    Write-Warning $Message
}

# ---------------------------------------------------------------------------
# Graph helpers
# ---------------------------------------------------------------------------

# The ONLY place a Graph request is made. -Method GET is hard-coded on purpose.
function Invoke-GraphGet {
    param([Parameter(Mandatory)][string]$Uri)
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Hashtable
}

# Follows @odata.nextLink until exhausted. This is the "-All" behaviour: Graph returns
# at most one page at a time, and silently stopping after page 1 would under-report.
function Get-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-GraphGet -Uri $next
        if ($page.ContainsKey('value')) { foreach ($v in $page['value']) { $items.Add($v) } }
        $next = $page['@odata.nextLink']
    }
    , $items.ToArray()
}

# Keep dates as raw UTC ISO 8601 strings. Graph normally returns strings already, but if
# the deserializer hands us a [datetime] we convert it rather than let it reformat.
function ConvertTo-IsoUtc {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'") }
    return [string]$Value
}

# Credential projections are WHITELISTS, not blacklists: we copy only the named fields,
# so 'hint', 'key' and 'secretText' cannot leak even if Graph adds or populates them.
function ConvertTo-SafePasswordCredential {
    param($Cred)
    [ordered]@{
        keyId         = $Cred['keyId']
        displayName   = $Cred['displayName']
        startDateTime = ConvertTo-IsoUtc $Cred['startDateTime']
        endDateTime   = ConvertTo-IsoUtc $Cred['endDateTime']
    }
}
function ConvertTo-SafeKeyCredential {
    param($Cred)
    [ordered]@{
        keyId               = $Cred['keyId']
        displayName         = $Cred['displayName']
        startDateTime       = ConvertTo-IsoUtc $Cred['startDateTime']
        endDateTime         = ConvertTo-IsoUtc $Cred['endDateTime']
        type                = $Cred['type']
        usage               = $Cred['usage']
        customKeyIdentifier = $Cred['customKeyIdentifier']   # public thumbprint, not key material
    }
}

function ConvertTo-SafeOwner {
    param($Owner)
    [ordered]@{
        id                = $Owner['id']
        type              = $Owner['@odata.type']
        displayName       = $Owner['displayName']
        userPrincipalName = $Owner['userPrincipalName']
    }
}

function Get-Owners {
    param([string]$Collection, [string]$ObjectId, [string]$Label)
    try {
        $owners = Get-GraphPaged "https://graph.microsoft.com/v1.0/$Collection/$ObjectId/owners?`$select=id,displayName,userPrincipalName"
        # The leading comma stops PowerShell unrolling an empty array into $null on return,
        # so "confirmed no owners" (@()) stays distinct from "lookup failed" ($null).
        return , @($owners | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-SafeOwner $_ })
    }
    catch {
        Add-ScanWarning "Owners lookup failed for $Label ($ObjectId): $($_.Exception.Message)"
        return $null   # null = "we don't know", distinct from @() = "confirmed no owners"
    }
}

# Agent ID @odata.type values, as returned by Graph v1.0 (confirmed in the lab, Phase 4 probe).
$TypeBlueprint          = '#microsoft.graph.agentIdentityBlueprint'
$TypeBlueprintPrincipal = '#microsoft.graph.agentIdentityBlueprintPrincipal'
$TypeAgentIdentity      = '#microsoft.graph.agentIdentity'

# Whitelist projection, like owners. accountEnabled is filled in per user below, because the
# sponsors endpoint returns a user's default properties and accountEnabled is not one of them.
function ConvertTo-SafeSponsor {
    param($Sponsor, $AccountEnabled)
    [ordered]@{
        id                = $Sponsor['id']
        type              = $Sponsor['@odata.type']
        displayName       = $Sponsor['displayName']
        userPrincipalName = $Sponsor['userPrincipalName']
        accountEnabled    = $AccountEnabled   # null for groups, or if the user lookup failed
    }
}

# Sponsors of a blueprint (on the application) or an agent (on the service principal).
# Same null contract as Get-Owners: @() = confirmed none, $null = we don't know.
$accountEnabledCache = @{}
function Get-Sponsors {
    param([ValidateSet('blueprint', 'agent')][string]$Kind, [string]$ObjectId, [string]$Label)
    $path = if ($Kind -eq 'blueprint') { "applications/$ObjectId/microsoft.graph.agentIdentityBlueprint/sponsors" }
            else                       { "servicePrincipals/$ObjectId/microsoft.graph.agentIdentity/sponsors" }
    try {
        $raw = Get-GraphPaged "https://graph.microsoft.com/v1.0/$path"
        $out = foreach ($s in @($raw | Where-Object { $null -ne $_ })) {
            $enabled = $null
            if ($s['@odata.type'] -eq '#microsoft.graph.user') {
                $uid = $s['id']
                if (-not $accountEnabledCache.ContainsKey($uid)) {
                    try   { $accountEnabledCache[$uid] = (Invoke-GraphGet "https://graph.microsoft.com/v1.0/users/$uid`?`$select=id,accountEnabled")['accountEnabled'] }
                    catch { Add-ScanWarning "accountEnabled lookup failed for sponsor $uid of $Label`: $($_.Exception.Message)"; $accountEnabledCache[$uid] = $null }
                }
                $enabled = $accountEnabledCache[$uid]
            }
            ConvertTo-SafeSponsor $s $enabled
        }
        return , @($out)
    }
    catch {
        Add-ScanWarning "Sponsors lookup failed for $Label ($ObjectId): $($_.Exception.Message)"
        return $null
    }
}

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
$requestedScopes = @(
    'Application.Read.All',
    'Directory.Read.All',
    'RoleManagement.Read.Directory',
    'AuditLog.Read.All'
)

# Drop any cached session first. A leftover session from the seed script would carry
# write scopes into this read-only scan.
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Connect-MgGraph -Scopes $requestedScopes -NoWelcome | Out-Null

$context = Get-MgContext
$grantedScopes = @($context.Scopes)
$writeScopesPresent = [bool]($grantedScopes | Where-Object { $_ -like '*ReadWrite*' })
if ($writeScopesPresent) {
    Add-ScanWarning ("WRITE-CAPABLE SCOPES PRESENT: " + (($grantedScopes | Where-Object { $_ -like '*ReadWrite*' }) -join ', ') +
        ". The scanner never writes, but the token could. These scopes come from the existing consent grant on the " +
        "'Microsoft Graph Command Line Tools' enterprise app, so reconnecting will not remove them; revoke them on that " +
        "grant in Entra if you want a read-only-only app.")
}
$tenantId = $context.TenantId

# ---------------------------------------------------------------------------
# 1. Applications
# ---------------------------------------------------------------------------
Write-Host 'Collecting applications...'
$appSelect = 'id,appId,displayName,createdDateTime,signInAudience,tags,passwordCredentials,keyCredentials,requiredResourceAccess'
$rawApps = Get-GraphPaged "https://graph.microsoft.com/v1.0/applications?`$select=$appSelect&`$top=999"

$applications = @{}   # appId -> projected application object
foreach ($a in $rawApps) {
    $label = "application '$($a['displayName'])'"
    $isBlueprint = ($a['@odata.type'] -eq $TypeBlueprint)
    $applications[$a['appId'].ToLower()] = [ordered]@{
        id                  = $a['id']
        appId               = $a['appId']
        displayName         = $a['displayName']
        # Graph returns @odata.type per item even with $select; it is how a blueprint is told apart.
        odataType           = $a['@odata.type']
        createdDateTime     = ConvertTo-IsoUtc $a['createdDateTime']
        signInAudience      = $a['signInAudience']
        tags                = @($a['tags'])
        owners              = Get-Owners -Collection 'applications' -ObjectId $a['id'] -Label $label
        passwordCredentials = @($a['passwordCredentials'] | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-SafePasswordCredential $_ })
        keyCredentials      = @($a['keyCredentials'] | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-SafeKeyCredential $_ })
        # Requested permissions only (what the app asks for), NOT what was granted.
        requiredResourceAccess = @($a['requiredResourceAccess'])
    }
    # Only blueprints carry sponsors on the application, so only they get the key.
    if ($isBlueprint) {
        $applications[$a['appId'].ToLower()]['sponsors'] = Get-Sponsors -Kind blueprint -ObjectId $a['id'] -Label $label
    }
}

# ---------------------------------------------------------------------------
# 2. Service principals
# ---------------------------------------------------------------------------
Write-Host 'Collecting service principals...'
$spSelect = 'id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,tags,passwordCredentials,keyCredentials,appRoles'
$rawSps = Get-GraphPaged "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$spSelect&`$top=999"

# id -> displayName, used to name the resource side of oauth2 grants without extra calls.
# resourceRoleMap: resource SP id -> @{ appRoleId -> permission value }. Every resource an
# app role can point at is itself a service principal in this tenant, so the list we
# just pulled already contains everything needed - no per-resource lookups.
# Agent identities: the parent link (agentIdentityBlueprintId) is a property of the
# agentIdentity type, so it is read from the type-cast collection rather than added to the
# base $select above. Same paging, same GET-only helper.
$blueprintIdByAgentSpId = @{}
try {
    foreach ($ag in (Get-GraphPaged 'https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,agentIdentityBlueprintId&$top=999')) {
        $blueprintIdByAgentSpId[$ag['id']] = $ag['agentIdentityBlueprintId']
    }
}
catch { Add-ScanWarning "Agent identity parent links unavailable (continuing without them): $($_.Exception.Message)" }

$spNameById = @{}
$resourceRoleMap = @{}
foreach ($s in $rawSps) {
    $spNameById[$s['id']] = $s['displayName']
    $roles = @{}
    foreach ($role in @($s['appRoles']) | Where-Object { $null -ne $_ }) { $roles[$role['id']] = $role['value'] }
    $resourceRoleMap[$s['id']] = $roles
}

# ---------------------------------------------------------------------------
# 4 (done early). oauth2PermissionGrants - one tenant-wide call, grouped by clientId
# (clientId = the SP that was granted delegated access).
# ---------------------------------------------------------------------------
Write-Host 'Collecting oauth2 permission grants...'
$grantsByClient = @{}
try {
    foreach ($g in (Get-GraphPaged 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999')) {
        $client = $g['clientId']
        if (-not $grantsByClient.ContainsKey($client)) { $grantsByClient[$client] = [System.Collections.Generic.List[object]]::new() }
        $grantsByClient[$client].Add([ordered]@{
                consentType          = $g['consentType']      # AllPrincipals = tenant-wide, Principal = one user
                principalId          = $g['principalId']      # null for AllPrincipals
                resourceId           = $g['resourceId']
                resourceDisplayName  = $spNameById[$g['resourceId']]
                # 'scope' is one space-delimited string like "Mail.Read User.Read"
                scopes               = @(([string]$g['scope']) -split ' ' | Where-Object { $_ })
            })
    }
}
catch { Add-ScanWarning "oauth2PermissionGrants collection failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# 5. Directory role assignments (Active) and PIM eligibility (Eligible)
# ---------------------------------------------------------------------------
Write-Host 'Collecting directory role assignments...'
$roleNameById = @{}
try {
    foreach ($rd in (Get-GraphPaged 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName')) {
        $roleNameById[$rd['id']] = $rd['displayName']
    }
}
catch { Add-ScanWarning "roleDefinitions lookup failed; role names will be null: $($_.Exception.Message)" }

$rolesByPrincipal = @{}
function Add-RoleRecord {
    param($Assignment, [string]$Type)
    $principalId = $Assignment['principalId']
    if (-not $rolesByPrincipal.ContainsKey($principalId)) { $rolesByPrincipal[$principalId] = [System.Collections.Generic.List[object]]::new() }
    $rolesByPrincipal[$principalId].Add([ordered]@{
            roleDefinitionId = $Assignment['roleDefinitionId']
            roleName         = $roleNameById[$Assignment['roleDefinitionId']]
            directoryScopeId = $Assignment['directoryScopeId']   # "/" = tenant-wide, otherwise scoped (e.g. an admin unit)
            assignmentType   = $Type
        })
}
try {
    foreach ($ra in (Get-GraphPaged 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments')) { Add-RoleRecord $ra 'Active' }
}
catch { Add-ScanWarning "Active directory role assignments failed: $($_.Exception.Message)" }
try {
    foreach ($re in (Get-GraphPaged 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances')) { Add-RoleRecord $re 'Eligible' }
}
catch { Add-ScanWarning "PIM eligibility schedules unavailable (continuing without them): $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# 6. Sign-in activity (beta; needs P1/P2 + AuditLog.Read.All)
# ---------------------------------------------------------------------------
$signInByAppId = @{}
$signInActivityAvailable = $false
if ($SkipSignInActivity) {
    Add-ScanWarning 'Sign-in activity skipped (-SkipSignInActivity); signInActivity is null on every record.'
}
else {
    Write-Host 'Collecting sign-in activity...'
    try {
        foreach ($si in (Get-GraphPaged 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities')) {
            $clean = [ordered]@{}
            foreach ($k in $si.Keys) { if ($k -notlike '@odata.*') { $clean[$k] = $si[$k] } }
            $signInByAppId[([string]$si['appId']).ToLower()] = $clean
        }
        $signInActivityAvailable = $true
    }
    catch {
        $signInByAppId = @{}
        Add-ScanWarning "Sign-in activity unavailable (licensing/permission?): $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 3. Per-SP: app role assignments (needs resource SP appRoles to name the permission)
# ---------------------------------------------------------------------------
Write-Host "Collecting per-service-principal details for $($rawSps.Count) service principals..."
$servicePrincipals = @{}   # appId -> projected SP object
$i = 0
foreach ($s in $rawSps) {
    $i++
    Write-Progress -Activity 'Service principal details' -Status "$i / $($rawSps.Count)" -PercentComplete (100 * $i / $rawSps.Count)
    $spId = $s['id']
    $label = "service principal '$($s['displayName'])'"

    $assignments = $null
    try {
        $assignments = @(foreach ($ara in (Get-GraphPaged "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignments")) {
                $permission = $null
                if ($ara['appRoleId'] -eq '00000000-0000-0000-0000-000000000000') {
                    $permission = 'Default access'   # no specific app role; do not treat as a named permission
                }
                else {
                    $permission = $resourceRoleMap[$ara['resourceId']][$ara['appRoleId']]
                    if (-not $permission) { Add-ScanWarning "Could not resolve appRoleId $($ara['appRoleId']) on resource $($ara['resourceId']) for $label" }
                }
                [ordered]@{
                    resourceId          = $ara['resourceId']
                    resourceDisplayName = $ara['resourceDisplayName']
                    appRoleId           = $ara['appRoleId']
                    permission          = $permission   # null = could not resolve; never guessed
                }
            })
    }
    catch { Add-ScanWarning "appRoleAssignments failed for $label ($spId): $($_.Exception.Message)" }

    $appIdKey = $s['appId'].ToLower()
    $servicePrincipals[$appIdKey] = [ordered]@{
        id                     = $spId
        appId                  = $s['appId']
        displayName            = $s['displayName']
        servicePrincipalType   = $s['servicePrincipalType']
        appOwnerOrganizationId = $s['appOwnerOrganizationId']
        accountEnabled         = $s['accountEnabled']
        tags                   = @($s['tags'])
        owners                 = Get-Owners -Collection 'servicePrincipals' -ObjectId $spId -Label $label
        passwordCredentials    = @($s['passwordCredentials'] | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-SafePasswordCredential $_ })
        keyCredentials         = @($s['keyCredentials'] | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-SafeKeyCredential $_ })
        appRoleAssignments     = $assignments
        # Filter nulls: @($null) is a one-element array, which would serialize as [null].
        oauth2PermissionGrants = @($grantsByClient[$spId] | Where-Object { $null -ne $_ })
        directoryRoles         = @($rolesByPrincipal[$spId] | Where-Object { $null -ne $_ })
        signInActivity         = if ($signInActivityAvailable) { $signInByAppId[$appIdKey] } else { $null }
        odataType              = $s['@odata.type']
    }
    # Agent identities: parent blueprint (its appId) and sponsors. Agents have no application
    # object, so the service principal is the only place these can live.
    if ($s['@odata.type'] -eq $TypeAgentIdentity) {
        $servicePrincipals[$appIdKey]['agentIdentityBlueprintId'] = $blueprintIdByAgentSpId[$spId]
        $servicePrincipals[$appIdKey]['sponsors'] = Get-Sponsors -Kind agent -ObjectId $spId -Label $label
    }
}
Write-Progress -Activity 'Service principal details' -Completed

# ---------------------------------------------------------------------------
# Classification + merge: one record per appId
# ---------------------------------------------------------------------------
# Microsoft-owned publisher tenants, confirmed against the owner-org IDs seen in the lab tenant:
#   f8cdef31-... Microsoft first-party services (ESTS, Exchange Online, etc.)
#   72f988bf-... Microsoft corp tenant
#   cdc5aeea-... Microsoft Graph Command Line Tools publisher
$microsoftTenants = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
    '72f988bf-86f1-41af-91ab-2d7cd011db47',
    'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'
)

function Get-OwnerType {
    param($Sp)
    # Order matters: a managed identity's owner org can look like "this tenant", but
    # it is a different kind of identity, so it is decided first.
    if ($null -eq $Sp) { return 'ThisTenant' }   # app registration with no SP lives in this tenant by definition
    if ($Sp.servicePrincipalType -eq 'ManagedIdentity') { return 'ManagedIdentity' }
    $org = $Sp.appOwnerOrganizationId
    if ($org -and $org -eq $tenantId) { return 'ThisTenant' }
    if ($org -and $org -in $microsoftTenants) { return 'Microsoft' }
    if ($org) { return 'ThirdParty' }
    return 'Unknown'   # never guess
}

# identityType comes from Graph's own @odata.type, never from names or tags.
function Get-IdentityType {
    param($App, $Sp)
    if ($Sp -and $Sp.odataType -eq $TypeAgentIdentity) { return 'agentIdentity' }
    if ($App -and $App.odataType -eq $TypeBlueprint) { return 'agentBlueprint' }
    if ($Sp -and $Sp.odataType -eq $TypeBlueprintPrincipal) { return 'agentBlueprintPrincipal' }   # blueprint app lives in another tenant
    return 'application'
}

$allAppIds = @($applications.Keys) + @($servicePrincipals.Keys) | Sort-Object -Unique
$identities = foreach ($key in $allAppIds) {
    $app = $applications[$key]
    $sp = $servicePrincipals[$key]
    [ordered]@{
        appId            = if ($app) { $app.appId } else { $sp.appId }
        displayName      = if ($app) { $app.displayName } else { $sp.displayName }
        ownerType        = Get-OwnerType $sp
        identityType     = Get-IdentityType $app $sp
        application      = $app
        servicePrincipal = $sp
    }
}
$identities = @($identities)

# Agents come back with appOwnerOrganizationId = null (lab probe, Phase 4), which Get-OwnerType
# reports as Unknown. An agent can only exist under a blueprint, so it inherits the blueprint's
# ownerType (project owner's decision). No parent in the inventory = stays Unknown, with a warning.
$byAppId = @{}
foreach ($id in $identities) { $byAppId[([string]$id.appId).ToLower()] = $id }
foreach ($id in @($identities | Where-Object { $_.identityType -eq 'agentIdentity' })) {
    $parentAppId = [string]$id.servicePrincipal.agentIdentityBlueprintId
    $parent = if ($parentAppId) { $byAppId[$parentAppId.ToLower()] } else { $null }
    if ($parent) { $id.ownerType = $parent.ownerType }
    else { Add-ScanWarning "Agent '$($id.displayName)' names blueprint '$parentAppId', which is not in the inventory; ownerType left as $($id.ownerType)." }
}

$both = @($identities | Where-Object { $_.application -and $_.servicePrincipal }).Count
$appOnly = @($identities | Where-Object { $_.application -and -not $_.servicePrincipal }).Count
$spOnly = @($identities | Where-Object { -not $_.application -and $_.servicePrincipal }).Count

$scanEnd = (Get-Date).ToUniversalTime()
$inventory = [ordered]@{
    scanMetadata = [ordered]@{
        scannerVersion          = $ScannerVersion
        tenantId                = $tenantId
        account                 = $context.Account
        scanStartUtc            = $scanStart.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        scanEndUtc              = $scanEnd.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        grantedScopes           = $grantedScopes
        writeScopesPresent      = $writeScopesPresent
        signInActivityAvailable = $signInActivityAvailable
        warnings                = @($warnings)
        counts                  = [ordered]@{
            identities        = $identities.Count
            applications      = $applications.Count
            servicePrincipals = $servicePrincipals.Count
            appOnly           = $appOnly
            spOnly            = $spOnly
            both              = $both
            agentBlueprints   = @($identities | Where-Object { $_.identityType -eq 'agentBlueprint' }).Count
            agentIdentities   = @($identities | Where-Object { $_.identityType -eq 'agentIdentity' }).Count
        }
    }
    identities   = $identities
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory | Out-Null }
$outFile = Join-Path $OutputDirectory ("inventory-{0}Z.json" -f $scanStart.ToString('yyyyMMdd-HHmmss'))
$inventory | ConvertTo-Json -Depth 15 | Out-File -FilePath $outFile -Encoding utf8

$c = $inventory.scanMetadata.counts
Write-Host ''
Write-Host '=== NHI inventory complete ===' -ForegroundColor Cyan
Write-Host "Tenant:        $tenantId"
Write-Host "Identities:    $($c.identities)  (apps $($c.applications), SPs $($c.servicePrincipals); both $($c.both), app-only $($c.appOnly), SP-only $($c.spOnly))"
Write-Host "Agent ID:      $($c.agentBlueprints) blueprint(s), $($c.agentIdentities) agent identit(ies)"
Write-Host "Sign-in data:  $signInActivityAvailable"
Write-Host "Write scopes:  $writeScopesPresent"
Write-Host "Warnings:      $($warnings.Count)"
Write-Host "Output:        $outFile"
