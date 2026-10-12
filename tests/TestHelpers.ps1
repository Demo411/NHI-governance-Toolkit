# Shared helpers for the Pester 5 tests. No tenant, no network: every test builds a tiny
# synthetic inventory in $TestDrive and runs the real scripts against it.
#
# Dot-source this inside BeforeAll (Pester 5 runs Describe bodies at discovery time, so setup
# code must live in BeforeAll).

# Constants are functions, not $script: variables, so they resolve the same way everywhere.
function Get-GraphAppId { '00000003-0000-0000-c000-000000000000' }
function Get-GraphSpId  { 'sp-graph-0000' }

function Get-RepoRoot { Split-Path $PSScriptRoot -Parent }

# Order-insensitive, comma-joined rendering of a list (rule IDs, appIds), so an assertion
# reads `Format-Set $ids | Should -Be 'NHI-002,NHI-007'`. An empty list renders as ''.
# (Comparing arrays directly with Should -Be is awkward when one side is empty.)
function Format-Set {
    param($Items)
    (@($Items | Where-Object { $_ } | Sort-Object)) -join ','
}

# ---- synthetic inventory builders -------------------------------------------------------

function Format-SynDate {
    param([datetimeoffset]$Value)
    $Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function New-SynCredential {
    param([string]$Start, [string]$End, [string]$KeyId = ([guid]::NewGuid().ToString()), [string]$Name = 'synthetic')
    [ordered]@{ keyId = $KeyId; displayName = $Name; startDateTime = $Start; endDateTime = $End }
}

# A secret that starts at $Start and lasts exactly $Days days (plus optional hours/minutes).
function New-SynSecretForDays {
    param([string]$Start, [double]$Days, [double]$ExtraMinutes = 0, [string]$KeyId = ([guid]::NewGuid().ToString()))
    $s = [datetimeoffset]::Parse($Start, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
    New-SynCredential -Start (Format-SynDate $s) -End (Format-SynDate $s.AddDays($Days).AddMinutes($ExtraMinutes)) -KeyId $KeyId
}

function New-SynAppRole {
    param([string]$Permission, [string]$ResourceId = (Get-GraphSpId), [string]$ResourceDisplayName = 'Microsoft Graph')
    [ordered]@{ resourceId = $ResourceId; resourceDisplayName = $ResourceDisplayName; appRoleId = [guid]::NewGuid().ToString(); permission = $Permission }
}

function New-SynGrant {
    param([string[]]$Scopes, [string]$ResourceId = (Get-GraphSpId), [string]$ConsentType = 'AllPrincipals', [string]$ResourceDisplayName = 'Microsoft Graph')
    [ordered]@{ consentType = $ConsentType; principalId = $null; resourceId = $ResourceId; resourceDisplayName = $ResourceDisplayName; scopes = @($Scopes) }
}

function New-SynRole {
    param([string]$RoleDefinitionId, [string]$RoleName = 'synthetic role', [string]$AssignmentType = 'Active')
    [ordered]@{ roleDefinitionId = $RoleDefinitionId; roleName = $RoleName; directoryScopeId = '/'; assignmentType = $AssignmentType }
}

function New-SynIdentity {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$AppId = ([guid]::NewGuid().ToString()),
        [string]$SpId = ([guid]::NewGuid().ToString()),
        [string]$OwnerType = 'ThisTenant',
        [int]$Owners = 1,
        [object[]]$AppSecrets = @(),
        [object[]]$AppCerts = @(),
        [object[]]$SpSecrets = @(),
        [object[]]$SpCerts = @(),
        [object[]]$AppRoleAssignments = @(),
        [object[]]$Grants = @(),
        [object[]]$Roles = @(),
        [string[]]$Tags = @(),
        [switch]$NoApplication
    )
    $ownerList = @()
    if ($Owners -gt 0) { $ownerList = @(1..$Owners | ForEach-Object { [ordered]@{ id = [guid]::NewGuid().ToString() } }) }
    $application = $null
    if (-not $NoApplication) {
        $application = [ordered]@{
            id = [guid]::NewGuid().ToString(); appId = $AppId; displayName = $Name; tags = @($Tags)
            owners = $ownerList; passwordCredentials = @($AppSecrets); keyCredentials = @($AppCerts)
        }
    }
    [ordered]@{
        appId = $AppId; displayName = $Name; ownerType = $OwnerType
        application = $application
        servicePrincipal = [ordered]@{
            id = $SpId; appId = $AppId; displayName = $Name; servicePrincipalType = 'Application'
            tags = @($Tags); owners = $ownerList
            passwordCredentials = @($SpSecrets); keyCredentials = @($SpCerts)
            appRoleAssignments = @($AppRoleAssignments); oauth2PermissionGrants = @($Grants); directoryRoles = @($Roles)
            signInActivity = $null
        }
    }
}

# Microsoft Graph's own service principal, so resourceId can resolve to the real Graph appId.
function New-SynGraphIdentity {
    New-SynIdentity -Name 'Microsoft Graph' -AppId (Get-GraphAppId) -SpId (Get-GraphSpId) -OwnerType 'Microsoft' -Owners 0 -NoApplication
}

function Write-SynInventory {
    param(
        [Parameter(Mandatory)][object[]]$Identities,
        [Parameter(Mandatory)][string]$ScanStartUtc,
        [Parameter(Mandatory)][string]$Directory,
        [string]$Stamp = '20260101-000000Z',
        [switch]$WithoutGraph
    )
    $all = @($Identities)
    if (-not $WithoutGraph) { $all = @(New-SynGraphIdentity) + $all }
    $inventory = [ordered]@{
        scanMetadata = [ordered]@{ scannerVersion = 'synthetic'; scanStartUtc = $ScanStartUtc }
        identities   = $all
    }
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $path = Join-Path $Directory "inventory-$Stamp.json"
    $inventory | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8
    return $path
}

# ---- run the real scripts as child processes (real exit codes, real CLI) -----------------

function Get-PwshPath { (Get-Process -Id $PID).Path }

function Invoke-SynEngine {
    param([Parameter(Mandatory)][string]$InventoryPath, [Parameter(Mandatory)][string]$OutputDirectory)
    $script = Join-Path (Get-RepoRoot) 'scanner/Invoke-NhiScoring.ps1'
    $text = & (Get-PwshPath) -NoProfile -File $script -InventoryPath $InventoryPath -OutputDirectory $OutputDirectory 2>&1 | Out-String
    $code = $LASTEXITCODE
    $stamp = [System.IO.Path]::GetFileNameWithoutExtension($InventoryPath) -replace '^inventory-', ''
    $path = Join-Path $OutputDirectory "findings-$stamp.json"
    $parsed = $null
    if ($code -eq 0 -and (Test-Path -LiteralPath $path)) { $parsed = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String }
    [pscustomobject]@{ ExitCode = $code; Output = $text; Path = $path; Findings = $parsed }
}

function Invoke-SynValidator {
    param(
        [Parameter(Mandatory)][string]$FindingsPath,
        [Parameter(Mandatory)][string]$InventoryPath,
        [Parameter(Mandatory)][string]$AnswerKeyPath
    )
    $script = Join-Path (Get-RepoRoot) 'scanner/Test-NhiFindings.ps1'
    $text = & (Get-PwshPath) -NoProfile -File $script -FindingsPath $FindingsPath -InventoryPath $InventoryPath -AnswerKeyPath $AnswerKeyPath 2>&1 | Out-String
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $text }
}

function New-SynAnswerKey {
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][hashtable]$Apps, [object[]]$Constraints = @())
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $path = Join-Path $Directory 'expected-findings.json'
    [ordered]@{ ignored_rules = @('NHI-006'); apps = $Apps; score_constraints = @($Constraints) } |
        ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8
    return $path
}

# The same time_dependent block used by the real answer key for seed-03.
function Get-Seed03Expectation {
    @{
        'seed-03-expiring' = [ordered]@{
            time_dependent = [ordered]@{
                clock = 'scanMetadata.scanStartUtc'
                pivot = 'endDateTime of the single client secret in application.passwordCredentials'
                expired_when = 'endDateTime <= scanStartUtc'
                before_expiry = [ordered]@{ expected_rules = @('NHI-007') }
                after_expiry  = [ordered]@{ expected_rules = @('NHI-003') }
            }
        }
    }
}

# ---- reading results ---------------------------------------------------------------------

function Get-SynResult {
    param($Run, [string]$AppId)
    $hit = @($Run.Findings.identities | Where-Object { $_.appId -eq $AppId })
    if ($hit.Count -ne 1) { throw "Expected exactly one scored identity for appId $AppId, found $($hit.Count)." }
    return $hit[0]
}

function Get-SynRuleIds {
    param($Result)
    @($Result.findings | ForEach-Object { $_.ruleId })
}

function Get-SynFinding {
    param($Result, [string]$RuleId)
    @($Result.findings | Where-Object { $_.ruleId -eq $RuleId })[0]
}
