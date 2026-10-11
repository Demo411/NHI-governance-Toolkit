<#
.SYNOPSIS
    Seeds the lab tenant with 10 deliberately risky (or deliberately clean) non-human identities.

.DESCRIPTION
    Creates the ground truth the Phase 2 scanner is tested against. Every object is tagged
    'nhi-lab-seed' in BOTH `tags` and `notes` (app registration AND service principal) so
    Remove-NhiLabSeed.ps1 can find exactly what was created and nothing else.

    This script WRITES to the tenant, so it needs write scopes. The scanner never does.
    Run with -WhatIf first to see every change without making it.

    Secrets: created and discarded immediately. No secret value is ever stored, printed or logged.

.EXAMPLE
    ./New-NhiLabSeed.ps1 -WhatIf
.EXAMPLE
    ./New-NhiLabSeed.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SeedTag    = 'nhi-lab-seed'
$GraphAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph's well-known appId (identifies the API, not a permission)

# ---------------------------------------------------------------------------
# The seed definitions. This table IS the design; expected-findings.json is its answer key.
# ---------------------------------------------------------------------------
$SeedApps = @(
    @{ Name = 'seed-01-ownerless';          HasOwner = $false; SecretDays = 0;
       Purpose = 'No owner, nothing else' },
    @{ Name = 'seed-02-longsecret';         HasOwner = $true;  SecretDays = 730;
       Purpose = 'Client secret valid 2 years' },
    @{ Name = 'seed-03-expiring';           HasOwner = $true;  SecretDays = 1;
       Purpose = 'Secret expires in 1 day (expired by Phase 2)' },
    @{ Name = 'seed-04-mailread-app';       HasOwner = $true;  SecretDays = 0;
       GrantedAppRoles = @('Mail.Read');
       Purpose = 'Mail.Read application permission, admin-consented' },
    @{ Name = 'seed-05-dirwrite';           HasOwner = $false; SecretDays = 0;
       GrantedAppRoles = @('Directory.ReadWrite.All');
       Purpose = 'Directory.ReadWrite.All application permission, no owner' },
    @{ Name = 'seed-06-appadmin';           HasOwner = $true;  SecretDays = 0;
       DirectoryRole = 'Application Administrator';
       Purpose = 'Service principal holds Application Administrator' },
    @{ Name = 'seed-07-requested-only';     HasOwner = $true;  SecretDays = 0;
       RequestedOnlyAppRoles = @('RoleManagement.ReadWrite.Directory');
       Purpose = 'Requests RoleManagement.ReadWrite.Directory, never consented (requested vs granted)' },
    @{ Name = 'seed-08-mailread-delegated'; HasOwner = $true;  SecretDays = 0;
       GrantedDelegatedScopes = @('Mail.Read');
       Purpose = 'Mail.Read delegated, consented (should score lower than seed-04)' },
    @{ Name = 'seed-09-worstcase';          HasOwner = $false; SecretDays = 730;
       GrantedAppRoles = @('RoleManagement.ReadWrite.Directory');
       Purpose = 'No owner + 2-year secret + RoleManagement.ReadWrite.Directory granted' },
    @{ Name = 'seed-10-clean';              HasOwner = $true;  SecretDays = 0;
       Purpose = 'Negative control: owner, no credentials, no risky permissions' }
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Entra is eventually consistent: a just-created app may 404 for a few seconds when
# we immediately reference it. Retrying is simpler and more honest than a fixed sleep.
function Invoke-WithRetry {
    param([scriptblock]$Action, [int]$Attempts = 6, [int]$DelaySeconds = 5)
    for ($i = 1; $i -le $Attempts; $i++) {
        try { return (& $Action) }
        catch {
            if ($i -eq $Attempts) { throw }
            Write-Verbose "Attempt $i failed ($($_.Exception.Message)); retrying in $DelaySeconds s"
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# Permission IDs are looked up by NAME from the Graph SP so the script never carries GUIDs
# that could be wrong or stale.
function Resolve-AppRoleId {
    param([string]$Name)
    $role = $script:GraphSp.AppRoles |
        Where-Object { $_.Value -eq $Name -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "Application permission '$Name' not found on the Microsoft Graph service principal." }
    return $role.Id
}

function Resolve-ScopeId {
    param([string]$Name)
    $scope = $script:GraphSp.Oauth2PermissionScopes | Where-Object { $_.Value -eq $Name }
    if (-not $scope) { throw "Delegated permission '$Name' not found on the Microsoft Graph service principal." }
    return $scope.Id
}

function Get-DirectoryObjectRef {
    param([string]$Id)
    return @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$Id" }
}

# ---------------------------------------------------------------------------
# Connect (write scopes - this is the seeder, not the scanner)
# ---------------------------------------------------------------------------
$scopes = @(
    'Application.ReadWrite.All',            # create apps/SPs, secrets, owners
    'AppRoleAssignment.ReadWrite.All',      # admin consent for application permissions
    'DelegatedPermissionGrant.ReadWrite.All', # admin consent for delegated permissions
    'RoleManagement.ReadWrite.Directory',   # assign Application Administrator
    'Directory.Read.All'                    # look up users and role definitions
)
Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
$ctx = Get-MgContext
Write-Host "Connected to tenant $($ctx.TenantId) as $($ctx.Account)"

$script:GraphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
$adminUser      = Get-MgUser -UserId $ctx.Account

$results = @()

foreach ($seed in $SeedApps) {
    # StrictMode throws on a missing hashtable key (e.g. $def.GrantedAppRoles on a seed that
    # doesn't list it). Start from defaults so every key exists, then overlay this seed's own keys.
    $def = @{
        GrantedAppRoles        = @()
        RequestedOnlyAppRoles  = @()
        GrantedDelegatedScopes = @()
        DirectoryRole          = $null
    }
    foreach ($key in $seed.Keys) { $def[$key] = $seed[$key] }

    $name = $def.Name
    Write-Host "`n=== $name ===" -ForegroundColor Cyan

    # Idempotency: skip anything that already exists. If an untagged app has our name,
    # it is NOT ours - warn and leave it alone rather than adopt it.
    $existing = Get-MgApplication -Filter "displayName eq '$name'" -All
    if ($existing) {
        $ours = $existing | Where-Object { $_.Tags -contains $SeedTag }
        if ($ours) { Write-Host "Already exists (tagged) - skipping." ; $results += [pscustomobject]@{ App = $name; Status = 'Skipped (exists)' }; continue }
        Write-Warning "An app named '$name' exists but is NOT tagged $SeedTag. Skipping; not touching it."
        $results += [pscustomobject]@{ App = $name; Status = 'Skipped (name clash, untagged)' }
        continue
    }

    $app = $null; $sp = $null

    # Per-app transaction: with $ErrorActionPreference='Stop' a mid-way failure would leave a
    # half-configured seed that the next run skips as "already exists". So on failure we delete
    # whatever this app created, record it, and move on to the next app.
    try {
        # Everything the app *requests* goes in requiredResourceAccess. Requested != granted;
        # seed-07 relies on that difference (requested here, never consented below).
        $access = @()
        foreach ($r in @($def.GrantedAppRoles) + @($def.RequestedOnlyAppRoles) | Where-Object { $_ }) {
            $access += @{ Id = (Resolve-AppRoleId $r); Type = 'Role' }
        }
        foreach ($s in @($def.GrantedDelegatedScopes) | Where-Object { $_ }) {
            $access += @{ Id = (Resolve-ScopeId $s); Type = 'Scope' }
        }
        $appParams = @{
            DisplayName    = $name
            SignInAudience = 'AzureADMyOrg'
            Tags           = @($SeedTag)
            Notes          = "$SeedTag - $($def.Purpose)"
        }
        if ($access.Count -gt 0) {
            $appParams.RequiredResourceAccess = @(@{ ResourceAppId = $GraphAppId; ResourceAccess = $access })
        }

        if ($PSCmdlet.ShouldProcess($name, 'Create app registration')) {
            $app = New-MgApplication @appParams
        }

        if ($PSCmdlet.ShouldProcess($name, 'Create service principal')) {
            $sp = Invoke-WithRetry { New-MgServicePrincipal -AppId $app.AppId -Tags @($SeedTag, 'WindowsAzureActiveDirectoryIntegratedApp') -Notes "$SeedTag - $($def.Purpose)" }
        }

        # Secret: create and discard. `$null =` means the SecretText is never held in a variable,
        # never printed, never written anywhere. Nobody (including us) can ever read it back.
        if ($def.SecretDays -gt 0 -and $PSCmdlet.ShouldProcess($name, "Add client secret valid $($def.SecretDays) day(s); value discarded")) {
            $cred = @{
                DisplayName   = 'nhi-lab-seed secret (value discarded)'
                StartDateTime = (Get-Date).ToUniversalTime()
                EndDateTime   = (Get-Date).ToUniversalTime().AddDays($def.SecretDays)
            }
            $null = Invoke-WithRetry { Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $cred }
        }

        # Application permissions: admin consent = an appRoleAssignment on the Graph SP.
        foreach ($r in @($def.GrantedAppRoles) | Where-Object { $_ }) {
            if ($PSCmdlet.ShouldProcess($name, "Grant admin consent: application permission $r")) {
                $null = Invoke-WithRetry {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
                        -PrincipalId $sp.Id -ResourceId $script:GraphSp.Id -AppRoleId (Resolve-AppRoleId $r)
                }
            }
        }

        # Delegated permissions: admin consent for all users = oauth2PermissionGrant, AllPrincipals.
        foreach ($s in @($def.GrantedDelegatedScopes) | Where-Object { $_ }) {
            if ($PSCmdlet.ShouldProcess($name, "Grant admin consent (AllPrincipals): delegated permission $s")) {
                $null = Invoke-WithRetry {
                    New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType 'AllPrincipals' `
                        -ResourceId $script:GraphSp.Id -Scope $s
                }
            }
        }

        # Directory role: look the role up by display name rather than hardcoding its template GUID.
        if ($def.DirectoryRole -and $PSCmdlet.ShouldProcess($name, "Assign directory role '$($def.DirectoryRole)' to the service principal")) {
            $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$($def.DirectoryRole)'"
            $null = Invoke-WithRetry {
                New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $sp.Id `
                    -RoleDefinitionId $roleDef.Id -DirectoryScopeId '/'
            }
        }

        # Owners: don't trust the default. Depending on how the object was created, the caller
        # may or may not be auto-added as owner. Make the end state match the definition exactly:
        #  - ownerless seeds: remove whoever got added
        #  - owned seeds: ensure the admin is owner (otherwise they'd wrongly trigger NHI-001)
        if ($PSCmdlet.ShouldProcess($name, "Verify owners (ownerless: $(-not $def.HasOwner))")) {
            $targets = @(
                @{ Kind = 'app'; Id = $app.Id },
                @{ Kind = 'sp';  Id = $sp.Id }
            )
            foreach ($t in $targets) {
                $owners = if ($t.Kind -eq 'app') { @(Get-MgApplicationOwner -ApplicationId $t.Id -All) }
                          else                   { @(Get-MgServicePrincipalOwner -ServicePrincipalId $t.Id -All) }
                if ($def.HasOwner) {
                    if (@($owners | ForEach-Object Id) -notcontains $adminUser.Id) {
                        if ($t.Kind -eq 'app') { New-MgApplicationOwnerByRef -ApplicationId $t.Id -BodyParameter (Get-DirectoryObjectRef $adminUser.Id) }
                        else                   { New-MgServicePrincipalOwnerByRef -ServicePrincipalId $t.Id -BodyParameter (Get-DirectoryObjectRef $adminUser.Id) }
                    }
                }
                else {
                    foreach ($o in $owners) {
                        Write-Host "  Removing auto-added owner $($o.Id) from $($t.Kind)"
                        if ($t.Kind -eq 'app') { Remove-MgApplicationOwnerByRef -ApplicationId $t.Id -DirectoryObjectId $o.Id }
                        else                   { Remove-MgServicePrincipalOwnerByRef -ServicePrincipalId $t.Id -DirectoryObjectId $o.Id }
                    }
                }
            }
            # Re-read to prove the end state rather than assume it.
            $appOwners = @(Get-MgApplicationOwner -ApplicationId $app.Id -All).Count
            $spOwners  = @(Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -All).Count
            $expected  = [int][bool]$def.HasOwner
            if ($appOwners -ne $expected -or $spOwners -ne $expected) {
                throw "Owner check failed for $name (app=$appOwners, sp=$spOwners, expected=$expected each)"
            }
            Write-Host "  Owner check OK (app=$appOwners, sp=$spOwners)"
        }
    }
    catch {
        Write-Warning "$name failed: $($_.Exception.Message) - rolling back"
        # Deleting the SP also drops its consent grants and role assignment.
        # Best effort: a rollback error must not stop the remaining apps.
        if ($sp) {
            try { Remove-MgServicePrincipal -ServicePrincipalId $sp.Id; Remove-MgDirectoryDeletedItem -DirectoryObjectId $sp.Id -ErrorAction SilentlyContinue }
            catch { Write-Warning "Rollback could not remove service principal $($sp.Id): $($_.Exception.Message)" }
        }
        if ($app) {
            try { Remove-MgApplication -ApplicationId $app.Id; Remove-MgDirectoryDeletedItem -DirectoryObjectId $app.Id -ErrorAction SilentlyContinue }
            catch { Write-Warning "Rollback could not remove application $($app.Id): $($_.Exception.Message)" }
        }
        # Only claim a rollback if something was actually created (nothing is in -WhatIf).
        $failStatus = if ($app) { 'Failed (rolled back)' } else { 'Failed (nothing created)' }
        $results += [pscustomobject]@{ App = $name; Status = $failStatus }
        continue
    }
    $results += [pscustomobject]@{ App = $name; Status = $(if ($app) { 'Created' } else { 'WhatIf' }) }
}

Write-Host "`nSummary:" -ForegroundColor Green
$results | Format-Table -AutoSize

# Least privilege: the write scopes live only for the duration of this run.
Disconnect-MgGraph | Out-Null
