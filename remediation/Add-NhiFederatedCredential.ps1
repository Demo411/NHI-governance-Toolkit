#Requires -Version 7.0
<#
.SYNOPSIS
    Phase 5, step 1: adds a GitHub Actions federated identity credential (FIC) to a tagged seed app.

.DESCRIPTION
    WRITES to the tenant (unless -WhatIf). It ADDS a trust; it does not remove anything. The client
    secret stays in place until Remove-NhiAppSecret.ps1 is run, and that script runs only after the
    federated login has been proven from GitHub.

    What a FIC is: a rule on the app registration saying "accept a token signed by <issuer> whose
    subject is <subject> and audience is <audience> as proof that you are this app". There is no
    secret anywhere in it, so there is nothing to leak or rotate.

    Safety checks (all read-only, all run under -WhatIf too, so the dry run shows a refusal):
      - The app is found by display name, then CONFIRMED by marker: tags contain nhi-lab-seed AND
        notes start with nhi-lab-seed (guardrail 4). Exactly one app must match.
      - The subject must be exact: no '*' or '?' (Entra does not support wildcards in a FIC subject,
        and a broad subject would let more than one workflow act as the app).
      - If an identical FIC already exists the script reports it and changes nothing.
      - If the FIC name is already used by a different trust, it refuses instead of overwriting.

    Graph endpoints:
      GET  /v1.0/applications?$filter=displayName eq '...'           find and confirm the app
      GET  /v1.0/applications/{id}/federatedIdentityCredentials      existing trusts
      POST /v1.0/applications/{id}/federatedIdentityCredentials      create the trust (the only write)

    Scopes (delegated): Application.Read.All under -WhatIf; Application.ReadWrite.All otherwise
    (the narrowest delegated permission Microsoft lists for creating a FIC). Reads and prints no
    secret. Disconnects at the end.

.PARAMETER Issuer, Subject, Audience
    Defaults are the project's design decision and must equal expected_federation in
    seed/expected-findings.json (a test enforces that).

.EXAMPLE
    ./remediation/Add-NhiFederatedCredential.ps1 -WhatIf
.EXAMPLE
    ./remediation/Add-NhiFederatedCredential.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$AppDisplayName = 'seed-02-longsecret',
    [string]$FicName        = 'github-actions-lab',
    [string]$Issuer         = 'https://token.actions.githubusercontent.com',
    [string]$Subject        = 'repo:Demo411/NHI-governance-Toolkit:environment:lab',
    [string]$Audience       = 'api://AzureADTokenExchange'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SeedTag = 'nhi-lab-seed'
$Graph   = 'https://graph.microsoft.com'

if ($Subject -match '[*?]') { throw "Refusing: subject '$Subject' contains a wildcard character. Use an exact subject." }
if ($FicName -notmatch '^[A-Za-z0-9_-]{1,120}$') { throw "Refusing: FIC name '$FicName' must be 1-120 letters, digits, '-' or '_'." }

# ---------------------------------------------------------------- connect (least privilege)
$Scopes = if ($WhatIfPreference) { @('Application.Read.All') } else { @('Application.ReadWrite.All') }
# Under -WhatIf PowerShell would also "what-if" the module's own type-data setup on load (pure noise),
# so the module is loaded explicitly with the preference switched off, then restored.
# Loading a module changes nothing in the tenant.
$savedWhatIf = $WhatIfPreference
$WhatIfPreference = $false
Import-Module Microsoft.Graph.Authentication
$WhatIfPreference = $savedWhatIf

try {
    # Drop any cached session first: a leftover session could carry write scopes into a dry run.
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
    Write-Host "Connected to tenant $((Get-MgContext).TenantId) with scopes: $($Scopes -join ', ')" -ForegroundColor Cyan

    # ------------------------------------------------------------ 1. find and confirm the app (GET only)
    $nameForFilter = $AppDisplayName.Replace("'", "''")   # OData escapes a single quote by doubling it
    $uri = "$Graph/v1.0/applications?`$filter=displayName eq '$nameForFilter'&`$select=id,appId,displayName,tags,notes"
    $found = @((Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType Hashtable)['value'])
    $apps = @($found | Where-Object { @($_['tags']) -contains $SeedTag -and ([string]$_['notes']).StartsWith($SeedTag) })

    if ($found.Count -gt $apps.Count) {
        Write-Warning "$($found.Count - $apps.Count) application(s) named '$AppDisplayName' lack the $SeedTag tag/notes marker and are ignored."
    }
    if ($apps.Count -ne 1) {
        throw "Expected exactly one application named '$AppDisplayName' carrying the $SeedTag tag AND notes marker, found $($apps.Count). Nothing changed."
    }
    $app = $apps[0]
    Write-Host "Target: $($app['displayName'])  (object id $($app['id']))"

    # ------------------------------------------------------------ 2. what trusts already exist (GET only)
    $ficUri = "$Graph/v1.0/applications/$($app['id'])/federatedIdentityCredentials"
    $existing = @((Invoke-MgGraphRequest -Method GET -Uri $ficUri -OutputType Hashtable)['value'])
    $identical = @($existing | Where-Object {
        $_['issuer'] -ceq $Issuer -and $_['subject'] -ceq $Subject -and
        ((@($_['audiences']) | Sort-Object -CaseSensitive) -join '|') -ceq $Audience })
    if ($identical.Count -gt 0) {
        Write-Host "Already present: federated credential '$($identical[0]['name'])' with this issuer, subject and audience. Nothing to do." -ForegroundColor Green
        return
    }
    if (@($existing | Where-Object { $_['name'] -eq $FicName }).Count -gt 0) {
        throw "A federated credential named '$FicName' already exists with DIFFERENT values. Refusing to overwrite; pick another -FicName or review it in the portal."
    }

    # ------------------------------------------------------------ 3. show and create
    Write-Host "`nWill add this federated identity credential:" -ForegroundColor Yellow
    Write-Host "  name      $FicName"
    Write-Host "  issuer    $Issuer"
    Write-Host "  subject   $Subject"
    Write-Host "  audience  $Audience"
    Write-Host '  The client secret is NOT touched.'

    if ($PSCmdlet.ShouldProcess("application '$($app['displayName'])'", "Add federated credential '$FicName' (subject $Subject)")) {
        $body = @{
            name        = $FicName
            issuer      = $Issuer
            subject     = $Subject
            audiences   = @($Audience)
            description = 'nhi-lab-seed: GitHub Actions OIDC for the Phase 5 demo'
        } | ConvertTo-Json
        Invoke-MgGraphRequest -Method POST -Uri $ficUri -Body $body -ContentType 'application/json' | Out-Null

        # Read it back rather than trusting the POST.
        $after = @((Invoke-MgGraphRequest -Method GET -Uri $ficUri -OutputType Hashtable)['value'] |
            Where-Object { $_['issuer'] -ceq $Issuer -and $_['subject'] -ceq $Subject })
        if ($after.Count -ne 1) { throw 'Created, but the read-back did not find exactly one matching credential. Check the app in the portal.' }
        Write-Host "Created and verified: '$($after[0]['name'])'." -ForegroundColor Green
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
