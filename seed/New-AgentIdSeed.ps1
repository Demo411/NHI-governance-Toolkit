#Requires -Version 7.0
<#
.SYNOPSIS
    Phase 4 seed: Entra Agent ID blueprints and agent identities with known-good and known-bad setups.

.DESCRIPTION
    WRITES to the tenant (write scopes, separate from the read-only scanner). Run -WhatIf first.

    Creates (or reuses, matched by displayName):
      NHI-Seed-BP-Clean   blueprint, certificate credential (self-signed, 90 days, non-exportable key)
        NHI-Seed-Agent-Clean-1   Graph User.Read.All (application)  - not a high-risk permission
        NHI-Seed-Agent-Clean-2   no permissions
      NHI-Seed-BP-Risky   blueprint, client secret (value discarded immediately, never printed)
        NHI-Seed-Agent-Risky-1   first high-risk Graph permission Entra will grant to an agent
        NHI-Seed-Agent-Risky-2   no permissions

    Answer key: seed/expected-findings.json (Phase 4 entries).

    Markers: blueprints are created with tags = nhi-lab-seed, and existing blueprints missing the
    tag get it added. An agent identity's tags are the union of its own and its blueprint's tags
    (Graph docs, agentIdentity resource), so the agents carry the marker through their blueprint.
    Agent ID objects have no 'notes' property, so Remove-NhiLabSeed.ps1 (which requires tags AND
    notes) deliberately does not touch them.

    Agent guardrail (observed 2026-10-16): Entra refuses some permissions for agent identities
    ("The specified app role cannot be granted to agent identities"). Directory.ReadWrite.All was
    refused; Mail.ReadWrite was accepted. Risky-1 tries candidates in order and records refusals in
    the manifest as evidence.

    Writes .\output\agentid-seed.json (gitignored: contains tenant object IDs).

.EXAMPLE
    ./seed/New-AgentIdSeed.ps1 -WhatIf
.EXAMPLE
    ./seed/New-AgentIdSeed.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$CertDays   = 90,
    [int]$SecretDays = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SeedTag    = 'nhi-lab-seed'
$Graph      = 'https://graph.microsoft.com'
$GraphAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph's well-known appId
$Headers    = @{ 'OData-Version' = '4.0' }              # required with @odata.type bodies

# Ordered from most to least dangerous. The first one Entra accepts is kept.
$RiskyCandidates = @('Directory.ReadWrite.All', 'Mail.ReadWrite', 'Files.ReadWrite.All', 'Sites.ReadWrite.All', 'Directory.Read.All')

# ---------------------------------------------------------------- connect (write scopes)
$Scopes = @(
    'AgentIdentityBlueprint.Create',
    'AgentIdentityBlueprint.AddRemoveCreds.All',
    'AgentIdentityBlueprint.ReadWrite.All',
    'AgentIdentityBlueprintPrincipal.Create',
    'AgentIdentity.Create.All',
    'AppRoleAssignment.ReadWrite.All',
    'Application.Read.All',
    'User.Read'
)
# Same pattern as the other scripts: no tenant ID in the repo. Sign in to the lab tenant.
Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
Write-Host "Connected as $((Get-MgContext).Account) to tenant $((Get-MgContext).TenantId)" -ForegroundColor Cyan

# ---------------------------------------------------------------- helpers
function Invoke-Graph {
    param([string]$Method, [string]$Path, $Body)
    $p = @{ Method = $Method; Uri = "$Graph$Path"; Headers = $Headers; OutputType = 'Hashtable' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
    Invoke-MgGraphRequest @p
}

function Get-ByName {
    param([string]$Path, [string]$Name)
    $f = [uri]::EscapeDataString("displayName eq '$Name'")
    @((Invoke-Graph GET "$Path`?`$filter=$f")['value']) | Select-Object -First 1
}

$me = Invoke-Graph GET '/v1.0/me'
$meBind = "$Graph/v1.0/users/$($me['id'])"
Write-Host "Sponsor/owner: $($me['userPrincipalName'])"

function New-Blueprint {
    param([string]$Name)
    $bp = Get-ByName '/v1.0/applications/microsoft.graph.agentIdentityBlueprint' $Name
    if ($bp) {
        Write-Host "  [=] Blueprint exists: $Name" -ForegroundColor DarkGray
        # Seeds created before the tagging fix have no marker; add it (tags only, nothing else).
        if (@($bp['tags']) -notcontains $SeedTag) {
            if ($PSCmdlet.ShouldProcess($Name, "Add tag '$SeedTag'")) {
                Invoke-Graph PATCH "/v1.0/applications/$($bp['id'])" @{ tags = @(@($bp['tags']) + $SeedTag | Where-Object { $_ }) } | Out-Null
                Write-Host "  [+] Tagged $SeedTag" -ForegroundColor Green
            }
        }
    }
    elseif ($PSCmdlet.ShouldProcess($Name, 'Create agent identity blueprint (sponsor + owner = you, tagged)')) {
        $bp = Invoke-Graph POST '/v1.0/applications' @{
            '@odata.type'         = 'Microsoft.Graph.AgentIdentityBlueprint'
            displayName           = $Name
            tags                  = @($SeedTag)
            'sponsors@odata.bind' = @($meBind)   # a sponsor is required for a blueprint
            'owners@odata.bind'   = @($meBind)
        }
        Write-Host "  [+] Blueprint created: $Name ($($bp['appId']))" -ForegroundColor Green
    }
    if (-not $bp) { return $null }   # -WhatIf on a blueprint that does not exist yet

    # The blueprint principal is NOT created automatically.
    $f = [uri]::EscapeDataString("appId eq '$($bp['appId'])'")
    $sp = @((Invoke-Graph GET "/v1.0/servicePrincipals?`$filter=$f")['value']) | Select-Object -First 1
    if (-not $sp -and $PSCmdlet.ShouldProcess($Name, 'Create blueprint principal')) {
        $sp = Invoke-Graph POST '/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' @{ appId = $bp['appId'] }
        Write-Host '  [+] Blueprint principal created' -ForegroundColor Green
    }
    [pscustomobject]@{ App = $bp; Principal = $sp }
}

function New-Agent {
    param([string]$Name, [string]$BlueprintAppId)
    $ag = Get-ByName '/v1.0/servicePrincipals/microsoft.graph.agentIdentity' $Name
    if ($ag) { Write-Host "    [=] Agent exists: $Name" -ForegroundColor DarkGray; return $ag }
    if (-not $PSCmdlet.ShouldProcess($Name, 'Create agent identity (sponsor = you)')) { return $null }
    $body = @{
        displayName              = $Name
        agentIdentityBlueprintId = $BlueprintAppId
        'sponsors@odata.bind'    = @($meBind)
    }
    try { $ag = Invoke-Graph POST '/v1.0/servicePrincipals/microsoft.graph.agentIdentity' $body }
    catch {
        # Microsoft's own create example uses beta; v1.0 worked in the lab, beta is the fallback.
        Write-Host "    v1.0 create failed, retrying on beta: $($_.Exception.Message)" -ForegroundColor Yellow
        $ag = Invoke-Graph POST '/beta/servicePrincipals/microsoft.graph.agentIdentity' $body
    }
    Write-Host "    [+] Agent created: $Name ($($ag['id']))" -ForegroundColor Green
    $ag
}

$f = [uri]::EscapeDataString("appId eq '$GraphAppId'")
$graphSp = @((Invoke-Graph GET "/v1.0/servicePrincipals?`$filter=$f")['value'])[0]

# Returns $true if granted (or already granted), $false if Entra blocks it for agents.
function Grant-GraphAppRole {
    param($Agent, [string]$RoleValue)
    if (-not $Agent) { return $false }
    $role = @($graphSp['appRoles'] | Where-Object { $_['value'] -eq $RoleValue })[0]
    $existing = @((Invoke-Graph GET "/v1.0/servicePrincipals/$($Agent['id'])/appRoleAssignments")['value'] |
        Where-Object { $_['appRoleId'] -eq $role['id'] })
    if ($existing.Count -gt 0) { Write-Host "    [=] $RoleValue already granted" -ForegroundColor DarkGray; return $true }
    if (-not $PSCmdlet.ShouldProcess($Agent['displayName'], "Grant Graph $RoleValue (application)")) { return $false }
    try {
        Invoke-Graph POST "/v1.0/servicePrincipals/$($Agent['id'])/appRoleAssignments" @{
            principalId = $Agent['id']; resourceId = $graphSp['id']; appRoleId = $role['id']
        } | Out-Null
        Write-Host "    [+] Granted Graph $RoleValue (application)" -ForegroundColor Green
        return $true
    }
    catch {
        if ("$_" -match 'cannot be granted to agent identities') {
            Write-Host "    [x] BLOCKED by Entra: $RoleValue cannot be granted to agent identities" -ForegroundColor Yellow
            return $false
        }
        throw
    }
}

# ---------------------------------------------------------------- Blueprint A: clean
Write-Host "`nBlueprint A (clean)" -ForegroundColor Cyan
$A = New-Blueprint 'NHI-Seed-BP-Clean'
if ($A -and @($A.App['keyCredentials']).Count -eq 0 -and $PSCmdlet.ShouldProcess('NHI-Seed-BP-Clean', "Add self-signed certificate ($CertDays days)")) {
    # Non-exportable private key stays in the local certificate store; only the public part is uploaded.
    $cert = New-SelfSignedCertificate -Subject 'CN=NHI-Seed-BP-Clean' -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy NonExportable -KeySpec Signature -KeyLength 2048 -NotAfter (Get-Date).AddDays($CertDays)
    Invoke-Graph PATCH "/v1.0/applications/$($A.App['id'])" @{
        keyCredentials = @(@{
            type = 'AsymmetricX509Cert'; usage = 'Verify'; displayName = "nhi-lab-seed cert $CertDays days"
            key  = [Convert]::ToBase64String($cert.RawData)
        })
    } | Out-Null
    Write-Host "  [+] Certificate added (thumbprint $($cert.Thumbprint), expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor Green
}
$A1 = if ($A) { New-Agent 'NHI-Seed-Agent-Clean-1' $A.App['appId'] }
$A2 = if ($A) { New-Agent 'NHI-Seed-Agent-Clean-2' $A.App['appId'] }
Grant-GraphAppRole $A1 'User.Read.All' | Out-Null

# ---------------------------------------------------------------- Blueprint B: risky
Write-Host "`nBlueprint B (risky)" -ForegroundColor Cyan
$B = New-Blueprint 'NHI-Seed-BP-Risky'
if ($B -and @($B.App['passwordCredentials']).Count -eq 0 -and $PSCmdlet.ShouldProcess('NHI-Seed-BP-Risky', "Add client secret ($SecretDays days, value discarded)")) {
    $pw = Invoke-Graph POST "/v1.0/applications/$($B.App['id'])/addPassword" @{
        passwordCredential = @{
            displayName = 'nhi-lab-seed secret (value discarded)'
            endDateTime = (Get-Date).ToUniversalTime().AddDays($SecretDays).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        }
    }
    $end = $pw['endDateTime']
    $pw = $null   # discard: the seed only needs the secret to EXIST (CLAUDE.md guardrail 1)
    Write-Host "  [+] Client secret added (value discarded, expires $end)" -ForegroundColor Green
}
$B1 = if ($B) { New-Agent 'NHI-Seed-Agent-Risky-1' $B.App['appId'] }
$B2 = if ($B) { New-Agent 'NHI-Seed-Agent-Risky-2' $B.App['appId'] }
$B1Granted = @(); $B1Blocked = @()
foreach ($perm in $RiskyCandidates) {
    if (Grant-GraphAppRole $B1 $perm) { $B1Granted += $perm; break }
    $B1Blocked += $perm
}

# ---------------------------------------------------------------- manifest (skipped under -WhatIf)
if (-not $WhatIfPreference -and $A -and $B) {
    New-Item -ItemType Directory -Path '.\output' -Force | Out-Null
    $manifest = [ordered]@{
        createdUtc = (Get-Date).ToUniversalTime().ToString('o')
        blueprints = @(
            [ordered]@{ name = 'NHI-Seed-BP-Clean'; appId = $A.App['appId']; objectId = $A.App['id']; principalId = $A.Principal['id']
                        credential = 'certificate'; expected = 'clean'
                        agents = @(
                            [ordered]@{ name = 'NHI-Seed-Agent-Clean-1'; id = $A1['id']; graphAppRoles = @('User.Read.All') },
                            [ordered]@{ name = 'NHI-Seed-Agent-Clean-2'; id = $A2['id']; graphAppRoles = @() }) },
            [ordered]@{ name = 'NHI-Seed-BP-Risky'; appId = $B.App['appId']; objectId = $B.App['id']; principalId = $B.Principal['id']
                        credential = 'clientSecret'; expected = 'risky'
                        agents = @(
                            [ordered]@{ name = 'NHI-Seed-Agent-Risky-1'; id = $B1['id']; graphAppRoles = $B1Granted; blockedByEntra = $B1Blocked },
                            [ordered]@{ name = 'NHI-Seed-Agent-Risky-2'; id = $B2['id']; graphAppRoles = @() }) }
        )
    }
    $manifest | ConvertTo-Json -Depth 10 | Set-Content '.\output\agentid-seed.json' -Encoding utf8
    Write-Host "`nManifest written to .\output\agentid-seed.json" -ForegroundColor Cyan
}

Disconnect-MgGraph | Out-Null   # least privilege: write scopes end with the run
Write-Host 'Done. Disconnected (write session closed).' -ForegroundColor Cyan
