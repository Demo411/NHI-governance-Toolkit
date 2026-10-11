<#
.SYNOPSIS
    Removes ONLY objects tagged 'nhi-lab-seed', then permanently purges them from deleted items.

.DESCRIPTION
    Safety model:
      1. Finds apps and service principals whose `tags` contain nhi-lab-seed AND whose `notes`
         start with nhi-lab-seed. Both markers must match; one alone is not enough.
      2. Prints exactly what it will delete.
      3. Requires you to type DELETE (skip with -Force for scripted use).
      4. Soft-deletes, then purges from the directory recycle bin so names are reusable
         and nothing lingers for 30 days.

.EXAMPLE
    ./Remove-NhiLabSeed.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$SeedTag = 'nhi-lab-seed'

Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'RoleManagement.ReadWrite.Directory' -NoWelcome | Out-Null
Write-Host "Connected to tenant $((Get-MgContext).TenantId)"

# Filtering on a collection property (tags/any) is an "advanced query": needs eventual consistency + count.
$apps = @(Get-MgApplication -Filter "tags/any(t:t eq '$SeedTag')" -ConsistencyLevel eventual -CountVariable c -All |
    Where-Object { $_.Notes -like "$SeedTag*" })
$sps = @(Get-MgServicePrincipal -Filter "tags/any(t:t eq '$SeedTag')" -ConsistencyLevel eventual -CountVariable c -All |
    Where-Object { $_.Notes -like "$SeedTag*" })

if ($apps.Count -eq 0 -and $sps.Count -eq 0) { Write-Host 'Nothing tagged nhi-lab-seed. Done.'; Disconnect-MgGraph | Out-Null; return }

Write-Host "`nThe following will be DELETED and PERMANENTLY PURGED:" -ForegroundColor Yellow
$apps | Select-Object @{n='Type';e={'Application'}}, DisplayName, Id | Format-Table -AutoSize
$sps  | Select-Object @{n='Type';e={'ServicePrincipal'}}, DisplayName, Id | Format-Table -AutoSize

if (-not $Force -and -not $WhatIfPreference) {
    $answer = Read-Host "Type DELETE to continue"
    if ($answer -cne 'DELETE') { Write-Host 'Aborted. Nothing changed.'; Disconnect-MgGraph | Out-Null; return }
}

# 1. Role assignments first (explicit, so none are left dangling).
foreach ($sp in $sps) {
    $assignments = @(Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($sp.Id)'" -All)
    foreach ($a in $assignments) {
        if ($PSCmdlet.ShouldProcess($sp.DisplayName, "Remove directory role assignment $($a.Id)")) {
            Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $a.Id
        }
    }
}

# 2. Service principals, then apps (soft delete). Deleting the SP also removes its consent grants.
foreach ($sp in $sps)   { if ($PSCmdlet.ShouldProcess($sp.DisplayName, 'Delete service principal'))  { Remove-MgServicePrincipal -ServicePrincipalId $sp.Id } }
foreach ($app in $apps) { if ($PSCmdlet.ShouldProcess($app.DisplayName, 'Delete app registration')) { Remove-MgApplication -ApplicationId $app.Id } }

# 3. Purge from deleted items. The object can take a moment to appear there, so retry.
#    Only IDs we collected above are purged - never "everything in the recycle bin".
$ids = @($sps | ForEach-Object Id) + @($apps | ForEach-Object Id)
foreach ($id in $ids) {
    if (-not $PSCmdlet.ShouldProcess($id, 'Permanently purge from deleted items')) { continue }
    for ($i = 1; $i -le 6; $i++) {
        try { Remove-MgDirectoryDeletedItem -DirectoryObjectId $id; Write-Host "Purged $id"; break }
        catch {
            if ($i -eq 6) { Write-Warning "Could not purge $id : $($_.Exception.Message)" }
            else { Start-Sleep -Seconds 5 }
        }
    }
}
Disconnect-MgGraph | Out-Null   # least privilege: write scopes end with the run
Write-Host 'Done.' -ForegroundColor Green
