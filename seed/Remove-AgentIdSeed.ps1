#Requires -Version 7.0
<#
.SYNOPSIS
    Removes the Phase 4 Entra Agent ID seeds (blueprints, blueprint principals, agent identities).

.DESCRIPTION
    WRITES to the tenant (unless -WhatIf). Companion to New-AgentIdSeed.ps1. It exists because
    Remove-NhiLabSeed.ps1 requires tags AND notes, and Agent ID objects have no 'notes', so that
    script (correctly) never touches them. Its rule is left alone: it protects the 11 classic seeds.

    What counts as a seed (IDs and Graph types only, never display names):
      Blueprint  an application whose @odata.type is #microsoft.graph.agentIdentityBlueprint
                 AND whose tags contain nhi-lab-seed.
      Agent      an agentIdentity whose agentIdentityBlueprintId is the appId of one of those
                 blueprints. Agents' own tags come back empty in practice, so the marker is
                 inherited through the parent link (the same rule as Test-NhiFindings.ps1).
      Principal  the blueprint principal (service principal) with the blueprint's appId.

    Order: agents -> blueprint principals -> blueprints (children before parents).

    Soft delete vs purge:
      Without -Purge the objects are soft-deleted: they sit in deleted items for 30 days and can be
      restored, and their display names stay RESERVED for those 30 days.
      -Purge also permanently deletes only the IDs collected above (never "everything in the
      recycle bin"), with retries because an object can take a moment to appear in deleted items.
      Purging needs the *.ReadWrite.All scopes (the docs list no narrower one) and the signed-in
      user needs the Agent ID Administrator role (or to own the objects).

    Scopes (delegated), per Microsoft Learn:
      Always (read)   Application.Read.All, Directory.Read.All
      Delete          AgentIdentity.DeleteRestore.All
                      AgentIdentityBlueprintPrincipal.DeleteRestore.All
                      AgentIdentityBlueprint.DeleteRestore.All
      -Purge adds     AgentIdentity.ReadWrite.All
                      AgentIdentityBlueprintPrincipal.ReadWrite.All
                      AgentIdentityBlueprint.ReadWrite.All
      Under -WhatIf only the two read scopes are requested, so a dry run never prompts for consent
      to a write scope.

    NOT YET TESTED: the -Purge path (and its retry loop) has never run against the tenant. Only the
    -WhatIf dry run has. Treat the first real cleanup as the test and check deleted items afterwards.

    Safety model, same as Remove-NhiLabSeed.ps1: prints exactly what will be deleted, requires
    typing DELETE (skip with -Force), disconnects at the end. Reads no credentials and prints none.

.EXAMPLE
    ./seed/Remove-AgentIdSeed.ps1 -WhatIf
.EXAMPLE
    ./seed/Remove-AgentIdSeed.ps1 -Purge
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [switch]$Purge
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SeedTag = 'nhi-lab-seed'
$Graph   = 'https://graph.microsoft.com'
$TypeBlueprint          = '#microsoft.graph.agentIdentityBlueprint'
$TypeBlueprintPrincipal = '#microsoft.graph.agentIdentityBlueprintPrincipal'

# ---------------------------------------------------------------- connect (least privilege)
$Scopes = @('Application.Read.All', 'Directory.Read.All')
if (-not $WhatIfPreference) {
    $Scopes += 'AgentIdentity.DeleteRestore.All', 'AgentIdentityBlueprintPrincipal.DeleteRestore.All', 'AgentIdentityBlueprint.DeleteRestore.All'
    if ($Purge) {
        $Scopes += 'AgentIdentity.ReadWrite.All', 'AgentIdentityBlueprintPrincipal.ReadWrite.All', 'AgentIdentityBlueprint.ReadWrite.All'
    }
}
# Under -WhatIf PowerShell would also "what-if" the module's own type-data setup on load (pure noise),
# so the module is loaded explicitly with the preference switched off, then restored.
# Loading a module changes nothing in the tenant.
$savedWhatIf = $WhatIfPreference
$WhatIfPreference = $false
Import-Module Microsoft.Graph.Authentication
$WhatIfPreference = $savedWhatIf
# Drop any cached session first: a leftover seed-script session would carry write scopes into a dry run.
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
Write-Host "Connected to tenant $((Get-MgContext).TenantId) with scopes: $($Scopes -join ', ')" -ForegroundColor Cyan

# ---------------------------------------------------------------- helpers
# The Agent ID endpoints have no SDK cmdlets, so the Graph call is made directly. Method is explicit.
function Invoke-Graph {
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path)
    Invoke-MgGraphRequest -Method $Method -Uri "$Graph$Path" -OutputType Hashtable
}

# Follows @odata.nextLink so a long list is never silently cut after page 1.
function Get-Paged {
    param([Parameter(Mandatory)][string]$Path)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = "$Graph$Path"
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable
        if ($page.ContainsKey('value')) { foreach ($v in $page['value']) { $items.Add($v) } }
        $next = $page['@odata.nextLink']
    }
    $items.ToArray()
}

# ---------------------------------------------------------------- 1. find (GET only)
# Blueprints: Graph's own @odata.type AND the seed tag. The tag is filtered client-side so no
# advanced-query (ConsistencyLevel) header is needed.
$blueprints = @(Get-Paged '/v1.0/applications?$select=id,appId,displayName,tags&$top=999' |
    Where-Object { $_['@odata.type'] -eq $TypeBlueprint -and @($_['tags']) -contains $SeedTag })
$blueprintAppIds = @($blueprints | ForEach-Object { $_['appId'].ToLower() })

# Agents: only the parent link counts. The typed collection is what exposes agentIdentityBlueprintId.
$agents = @(Get-Paged '/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$select=id,displayName,agentIdentityBlueprintId&$top=999' |
    Where-Object { $_['agentIdentityBlueprintId'] -and $blueprintAppIds -contains ([string]$_['agentIdentityBlueprintId']).ToLower() })

# Blueprint principals: looked up by the blueprint's appId and confirmed by Graph type.
$principals = @()
foreach ($bp in $blueprints) {
    try { $sp = Invoke-Graph GET "/v1.0/servicePrincipals(appId='$($bp['appId'])')?`$select=id,appId,displayName" }
    catch { Write-Host "  [=] No blueprint principal for $($bp['appId']) (never created or already removed)" -ForegroundColor DarkGray; continue }
    if ($sp['@odata.type'] -eq $TypeBlueprintPrincipal) { $principals += $sp }
}

if ($blueprints.Count -eq 0) {
    Write-Host 'No agent identity blueprints tagged nhi-lab-seed. Done.'
    Disconnect-MgGraph | Out-Null
    return
}

# ---------------------------------------------------------------- 2. show and confirm
Write-Host "`nThe following will be DELETED$(if ($Purge) { ' and PERMANENTLY PURGED' } else { ' (soft delete: restorable for 30 days, names stay reserved)' }):" -ForegroundColor Yellow
$agents     | Select-Object @{n='Type';e={'AgentIdentity'}},      @{n='DisplayName';e={$_['displayName']}}, @{n='Id';e={$_['id']}} | Format-Table -AutoSize
$principals | Select-Object @{n='Type';e={'BlueprintPrincipal'}}, @{n='DisplayName';e={$_['displayName']}}, @{n='Id';e={$_['id']}} | Format-Table -AutoSize
$blueprints | Select-Object @{n='Type';e={'Blueprint'}},          @{n='DisplayName';e={$_['displayName']}}, @{n='Id';e={$_['id']}} | Format-Table -AutoSize

if (-not $Force -and -not $WhatIfPreference) {
    $answer = Read-Host 'Type DELETE to continue'
    if ($answer -cne 'DELETE') { Write-Host 'Aborted. Nothing changed.'; Disconnect-MgGraph | Out-Null; return }
}

# ---------------------------------------------------------------- 3. delete, children before parents
foreach ($ag in $agents) {
    if ($PSCmdlet.ShouldProcess($ag['displayName'], 'Delete agent identity')) {
        Invoke-Graph DELETE "/v1.0/servicePrincipals/$($ag['id'])/microsoft.graph.agentIdentity" | Out-Null
    }
}
foreach ($sp in $principals) {
    if ($PSCmdlet.ShouldProcess($sp['displayName'], 'Delete blueprint principal')) {
        Invoke-Graph DELETE "/v1.0/servicePrincipals/$($sp['id'])/microsoft.graph.agentIdentityBlueprintPrincipal" | Out-Null
    }
}
foreach ($bp in $blueprints) {
    if ($PSCmdlet.ShouldProcess($bp['displayName'], 'Delete blueprint')) {
        Invoke-Graph DELETE "/v1.0/applications/$($bp['id'])/microsoft.graph.agentIdentityBlueprint" | Out-Null
    }
}

# ---------------------------------------------------------------- 4. purge (opt-in)
# Only IDs collected in step 1 are purged. Retry because deleted items can lag the delete.
if ($Purge) {
    $ids = @($agents | ForEach-Object { $_['id'] }) + @($principals | ForEach-Object { $_['id'] }) + @($blueprints | ForEach-Object { $_['id'] })
    foreach ($id in $ids) {
        if (-not $PSCmdlet.ShouldProcess($id, 'Permanently purge from deleted items')) { continue }
        for ($i = 1; $i -le 6; $i++) {
            try { Invoke-Graph DELETE "/v1.0/directory/deletedItems/$id" | Out-Null; Write-Host "Purged $id"; break }
            catch {
                if ($i -eq 6) { Write-Warning "Could not purge $id : $($_.Exception.Message)" }
                else { Start-Sleep -Seconds 5 }
            }
        }
    }
}
else {
    Write-Host 'Soft-deleted only. Re-run with -Purge to remove permanently; until then the names stay reserved (30 days).' -ForegroundColor DarkGray
}

Disconnect-MgGraph | Out-Null   # least privilege: write scopes end with the run
Write-Host 'Done.' -ForegroundColor Green
