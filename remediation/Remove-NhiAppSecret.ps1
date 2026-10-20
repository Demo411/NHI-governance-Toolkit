#Requires -Version 7.0
<#
.SYNOPSIS
    Phase 5, last step: deletes ONE client secret (by keyId) from a tagged seed app, but only once
    the app already has the matching GitHub federated credential.

.DESCRIPTION
    WRITES to the tenant (unless -WhatIf). Run it ONLY after the GitHub workflow has proven the
    federated login (appidacr = 2). The script cannot see GitHub, so that ordering is yours: the
    guard below checks that the trust EXISTS, not that it WORKS.

    Refuses (and changes nothing) unless ALL of these hold; the checks are reads and also run
    under -WhatIf, so a dry run shows a refusal:
      - Exactly one application with that display name carries the nhi-lab-seed tag AND notes marker.
      - That application already has a federated credential whose issuer, subject and audiences
        match EXACTLY (case-sensitive, no wildcards).
      - The -KeyId you passed is a client secret on that application.
    Only the app registration's secret is removed. A secret on the service principal (the hidden
    credential pattern) is a different object and is not touched; it is listed if present.

    Prints the keyId and the secret's display name. It never reads or prints a secret value (Graph
    does not return one after creation anyway).

    Graph endpoints:
      GET  /v1.0/applications?$filter=displayName eq '...'&$select=...,passwordCredentials
      GET  /v1.0/applications/{id}/federatedIdentityCredentials
      POST /v1.0/applications/{id}/removePassword   body { keyId }     (the only write)
    Scopes (delegated): Application.Read.All under -WhatIf; Application.ReadWrite.All otherwise.

.PARAMETER KeyId
    The secret to remove. Get it from the inventory (application.passwordCredentials[].keyId).

.EXAMPLE
    ./remediation/Remove-NhiAppSecret.ps1 -KeyId <guid> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][guid]$KeyId,
    [string]$AppDisplayName = 'seed-02-longsecret',
    [string]$Issuer         = 'https://token.actions.githubusercontent.com',
    [string]$Subject        = 'repo:Demo411/NHI-governance-Toolkit:environment:lab',
    [string]$Audience       = 'api://AzureADTokenExchange',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SeedTag = 'nhi-lab-seed'
$Graph   = 'https://graph.microsoft.com'

# ---------------------------------------------------------------- connect (least privilege)
$Scopes = if ($WhatIfPreference) { @('Application.Read.All') } else { @('Application.ReadWrite.All') }
$savedWhatIf = $WhatIfPreference
$WhatIfPreference = $false
Import-Module Microsoft.Graph.Authentication
$WhatIfPreference = $savedWhatIf

try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
    Write-Host "Connected to tenant $((Get-MgContext).TenantId) with scopes: $($Scopes -join ', ')" -ForegroundColor Cyan

    # ------------------------------------------------------------ 1. the app, confirmed by marker (GET only)
    $nameForFilter = $AppDisplayName.Replace("'", "''")
    $uri = "$Graph/v1.0/applications?`$filter=displayName eq '$nameForFilter'&`$select=id,appId,displayName,tags,notes,passwordCredentials"
    $found = @((Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType Hashtable)['value'])
    $apps = @($found | Where-Object { @($_['tags']) -contains $SeedTag -and ([string]$_['notes']).StartsWith($SeedTag) })
    if ($apps.Count -ne 1) {
        throw "Expected exactly one application named '$AppDisplayName' carrying the $SeedTag tag AND notes marker, found $($apps.Count). Nothing changed."
    }
    $app = $apps[0]
    Write-Host "Target: $($app['displayName'])  (object id $($app['id']))"

    # ------------------------------------------------------------ 2. guard: the federated credential must exist
    $ficUri = "$Graph/v1.0/applications/$($app['id'])/federatedIdentityCredentials"
    $fics = @((Invoke-MgGraphRequest -Method GET -Uri $ficUri -OutputType Hashtable)['value'])
    $match = @($fics | Where-Object {
        $_['issuer'] -ceq $Issuer -and $_['subject'] -ceq $Subject -and
        ((@($_['audiences']) | Sort-Object -CaseSensitive) -join '|') -ceq $Audience })
    if ($match.Count -lt 1) {
        throw "Refusing: '$AppDisplayName' has no federated credential matching issuer/subject/audience exactly, so deleting its secret could lock the app out. Run Add-NhiFederatedCredential.ps1 and prove the GitHub login first. Nothing changed."
    }
    Write-Host "Guard passed: federated credential '$($match[0]['name'])' is present (subject $Subject)." -ForegroundColor Green

    # ------------------------------------------------------------ 3. the secret to remove
    $secrets = @($app['passwordCredentials'] | Where-Object { $null -ne $_ })
    $target = @($secrets | Where-Object { [guid]$_['keyId'] -eq $KeyId })
    if ($target.Count -ne 1) {
        throw "keyId $KeyId is not a client secret on '$AppDisplayName' (it has $($secrets.Count) secret(s)). Nothing changed."
    }
    Write-Host "`nWill delete this client secret (value never read):" -ForegroundColor Yellow
    Write-Host "  keyId        $KeyId"
    Write-Host "  displayName  $($target[0]['displayName'])"
    if ($secrets.Count -gt 1) { Write-Warning "$($secrets.Count - 1) other secret(s) remain on the app; this script removes only the one you named." }

    if (-not $WhatIfPreference -and -not $Force) {
        if ((Read-Host "`nType DELETE to remove this secret") -cne 'DELETE') { Write-Host 'Cancelled. Nothing changed.'; return }
    }

    # ------------------------------------------------------------ 4. delete and verify
    if ($PSCmdlet.ShouldProcess("application '$($app['displayName'])'", "Remove client secret keyId $KeyId")) {
        Invoke-MgGraphRequest -Method POST -Uri "$Graph/v1.0/applications/$($app['id'])/removePassword" `
            -Body (@{ keyId = $KeyId.ToString() } | ConvertTo-Json) -ContentType 'application/json' | Out-Null

        $after = (Invoke-MgGraphRequest -Method GET -Uri "$Graph/v1.0/applications/$($app['id'])?`$select=passwordCredentials" -OutputType Hashtable)
        $left = @($after['passwordCredentials'] | Where-Object { $null -ne $_ -and [guid]$_['keyId'] -eq $KeyId })
        if ($left.Count -ne 0) { throw 'removePassword returned, but the secret is still listed. Check the app in the portal.' }
        Write-Host "Removed and verified: keyId $KeyId is gone. Remaining secrets on the app: $(@($after['passwordCredentials']).Count)." -ForegroundColor Green
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
