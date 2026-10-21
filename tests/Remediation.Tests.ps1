# Phase 5 remediation: the two tenant-changing scripts and the workflow, tested WITHOUT a tenant (Pester 5).
#
# The scripts are run for real in a child process, with the four Graph/auth commands replaced by stubs
# that record every call and answer from a canned state. That lets us assert what the scripts would
# READ, what they would WRITE, and when they refuse. The workflow is checked as text.

BeforeDiscovery {
    $script:haveGraphAuth = [bool](Get-Module -ListAvailable Microsoft.Graph.Authentication)
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:addScript = Join-Path (Get-RepoRoot) 'remediation/Add-NhiFederatedCredential.ps1'
    $script:rmScript  = Join-Path (Get-RepoRoot) 'remediation/Remove-NhiAppSecret.ps1'
    $script:keyId = '11111111-1111-1111-1111-111111111111'

    # The harness: stubs win over real cmdlets (functions outrank cmdlets), so nothing touches Graph.
    $script:harness = Join-Path $TestDrive 'harness.ps1'
    @'
param([string]$ScriptPath, [string]$StatePath, [string]$ArgsJson)
$ErrorActionPreference = 'Stop'
$global:state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -AsHashtable
$global:calls = [System.Collections.Generic.List[string]]::new()
$global:scopesUsed = $null
$global:disconnected = 0
function Connect-MgGraph { [CmdletBinding()] param($Scopes, [switch]$NoWelcome) $global:scopesUsed = @($Scopes) }
function Disconnect-MgGraph { [CmdletBinding()] param() $global:disconnected++ }
function Get-MgContext { @{ TenantId = 'synthetic-tenant' } }
function Invoke-MgGraphRequest {
    [CmdletBinding()] param($Method, $Uri, $Body, $ContentType, $OutputType)
    $global:calls.Add("$Method $Uri")
    $app = $global:state.apps[0]
    if ($Method -eq 'POST' -and $Uri -match '/federatedIdentityCredentials$') {
        $b = $Body | ConvertFrom-Json -AsHashtable
        $global:state.fics = @($global:state.fics) + @($b); return $null
    }
    if ($Method -eq 'PATCH' -and $Uri -match '/federatedIdentityCredentials/([^/]+)$') {
        $fid = $Matches[1]; $b = $Body | ConvertFrom-Json -AsHashtable
        foreach ($x in @($global:state.fics)) { if ($x.id -eq $fid) { foreach ($k in $b.Keys) { $x[$k] = $b[$k] } } }
        return $null
    }
    if ($Method -eq 'POST' -and $Uri -match '/removePassword$') {
        $k = ($Body | ConvertFrom-Json).keyId
        $app.passwordCredentials = @($app.passwordCredentials | Where-Object { $_.keyId -ne $k }); return $null
    }
    if ($Method -ne 'GET') { throw "unexpected $Method $Uri" }
    if ($Uri -match '/federatedIdentityCredentials$') { return @{ value = @($global:state.fics) } }
    if ($Uri -match '/applications\?') { return @{ value = @($global:state.apps) } }
    if ($Uri -match '/applications/[^/?]+\?') { return $app }
    throw "unrouted GET $Uri"
}
$splat = @{}
if ($ArgsJson) { ($ArgsJson | ConvertFrom-Json -AsHashtable).GetEnumerator() | ForEach-Object { $splat[$_.Key] = $_.Value } }
$threw = $null
try { & $ScriptPath @splat *> $null } catch { $threw = $_.Exception.Message }
[ordered]@{ threw = $threw; calls = @($global:calls); scopes = $(if ($null -eq $global:scopesUsed) { ,@() } else { $global:scopesUsed }); disconnected = $global:disconnected } | ConvertTo-Json -Compress
'@ | Set-Content -LiteralPath $script:harness -Encoding utf8

    function script:New-State {
        param([hashtable]$App = @{}, [object[]]$Fics = @(), [object[]]$Secrets = @(@{ keyId = $script:keyId; displayName = 'seed secret' }))
        $a = @{ id = 'app-object-id'; appId = 'app-client-id'; displayName = 'seed-02-longsecret'
                tags = @('nhi-lab-seed'); notes = 'nhi-lab-seed: synthetic'; passwordCredentials = @($Secrets) }
        foreach ($k in $App.Keys) { $a[$k] = $App[$k] }
        @{ apps = @($a); fics = @($Fics) }
    }
    function script:ConvertTo-Fic {
        param([string]$Subject = 'repo:Demo411@181002116/NHI-governance-Toolkit@1415658131:environment:lab')
        @{ id = 'fic-object-id'; name = 'github-actions-lab'; issuer = 'https://token.actions.githubusercontent.com'; subject = $Subject; audiences = @('api://AzureADTokenExchange') }
    }
    function script:Invoke-Harness {
        param([string]$Script, [hashtable]$State, [hashtable]$Arguments = @{})
        $sp = Join-Path $TestDrive ("state-{0}.json" -f [guid]::NewGuid())
        $State | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $sp -Encoding utf8
        $json = & (Get-PwshPath) -NoProfile -File $script:harness -ScriptPath $Script -StatePath $sp -ArgsJson ($Arguments | ConvertTo-Json -Compress) | Select-Object -Last 1
        $json | ConvertFrom-Json
    }
    function script:Get-Writes { param($Result) @($Result.calls | Where-Object { $_ -notmatch '^GET ' }) }
}

Describe 'Add-NhiFederatedCredential.ps1' -Skip:(-not $haveGraphAuth) {
    It '-WhatIf: reads only, requests the read scope only, writes nothing, disconnects' {
        $r = Invoke-Harness $script:addScript (New-State) @{ WhatIf = $true }
        $r.threw | Should -BeNullOrEmpty
        @(Get-Writes $r).Count | Should -Be 0
        @($r.scopes) | Should -Be @('Application.Read.All')
        $r.disconnected | Should -BeGreaterThan 0
    }
    It 'real run: exactly one write, a POST to federatedIdentityCredentials, with the write scope' {
        $r = Invoke-Harness $script:addScript (New-State)
        $r.threw | Should -BeNullOrEmpty
        $w = @(Get-Writes $r)
        $w.Count | Should -Be 1
        $w[0] | Should -Match '^POST https://graph.microsoft.com/v1.0/applications/app-object-id/federatedIdentityCredentials$'
        @($r.scopes) | Should -Be @('Application.ReadWrite.All')
    }
    It 'an identical FIC already exists: reports it and writes nothing' {
        $r = Invoke-Harness $script:addScript (New-State -Fics @(ConvertTo-Fic))
        $r.threw | Should -BeNullOrEmpty
        @(Get-Writes $r).Count | Should -Be 0
    }
    It 'the same FIC name with an OLD name-based subject: one PATCH of the subject, no POST, write scope' {
        $old = 'repo:Demo411/NHI-governance-Toolkit:environment:lab'
        $r = Invoke-Harness $script:addScript (New-State -Fics @(ConvertTo-Fic -Subject $old))
        $r.threw | Should -BeNullOrEmpty
        $w = @(Get-Writes $r)
        $w.Count | Should -Be 1
        $w[0] | Should -Match '^PATCH https://graph.microsoft.com/v1.0/applications/app-object-id/federatedIdentityCredentials/fic-object-id$'
        @($r.scopes) | Should -Be @('Application.ReadWrite.All')
    }
    It '-WhatIf with an old subject: reads only, read scope only, writes nothing' {
        $r = Invoke-Harness $script:addScript (New-State -Fics @(ConvertTo-Fic -Subject 'repo:Demo411/NHI-governance-Toolkit:environment:lab')) @{ WhatIf = $true }
        $r.threw | Should -BeNullOrEmpty
        @(Get-Writes $r).Count | Should -Be 0
        @($r.scopes) | Should -Be @('Application.Read.All')
    }
    It 'the same FIC name with a different ISSUER: refuses, no write' {
        $fic = ConvertTo-Fic -Subject 'repo:x/y:environment:z'; $fic.issuer = 'https://sts.windows.net/x/'
        $r = Invoke-Harness $script:addScript (New-State -Fics @($fic))
        $r.threw | Should -Match 'different issuer or audience'
        @(Get-Writes $r).Count | Should -Be 0
    }
    It 'the same FIC name with a different AUDIENCE: refuses, no write' {
        $fic = ConvertTo-Fic -Subject 'repo:x/y:environment:z'; $fic.audiences = @('api://Other')
        $r = Invoke-Harness $script:addScript (New-State -Fics @($fic))
        $r.threw | Should -Match 'different issuer or audience'
        @(Get-Writes $r).Count | Should -Be 0
    }
    It 'an app without the nhi-lab-seed tag is refused' {
        $r = Invoke-Harness $script:addScript (New-State -App @{ tags = @() })
        $r.threw | Should -Match 'exactly one'
        @(Get-Writes $r).Count | Should -Be 0
    }
    It 'an app with the tag but without the notes marker is refused' {
        $r = Invoke-Harness $script:addScript (New-State -App @{ notes = 'something else' })
        $r.threw | Should -Match 'exactly one'
        @(Get-Writes $r).Count | Should -Be 0
    }
    It 'a wildcard subject is refused before any sign-in' {
        $r = Invoke-Harness $script:addScript (New-State) @{ Subject = 'repo:Demo411/*:environment:lab' }
        $r.threw | Should -Match 'wildcard'
        $r.calls.Count | Should -Be 0
        @($r.scopes).Count | Should -Be 0
    }
}

Describe 'Remove-NhiAppSecret.ps1' -Skip:(-not $haveGraphAuth) {
    It 'REFUSES when the app has no federated credential at all (real run, -Force): no write' {
        $r = Invoke-Harness $script:rmScript (New-State) @{ KeyId = $script:keyId; Force = $true }
        $r.threw | Should -Match 'no federated credential matching'
        @(Get-Writes $r).Count | Should -Be 0
    }
    It 'REFUSES when the only federated credential has a different subject: no write' {
        $r = Invoke-Harness $script:rmScript (New-State -Fics @(ConvertTo-Fic -Subject 'repo:Demo411/other:environment:lab')) @{ KeyId = $script:keyId; Force = $true }
        $r.threw | Should -Match 'no federated credential matching'
        @(Get-Writes $r).Count | Should -Be 0
    }
    It 'REFUSES an app without the nhi-lab-seed marker, even with the matching federated credential' {
        $r = Invoke-Harness $script:rmScript (New-State -App @{ tags = @() } -Fics @(ConvertTo-Fic)) @{ KeyId = $script:keyId; Force = $true }
        $r.threw | Should -Match 'exactly one'
        @(Get-Writes $r).Count | Should -Be 0
    }
    It 'REFUSES a keyId that is not a secret on the app' {
        $r = Invoke-Harness $script:rmScript (New-State -Fics @(ConvertTo-Fic)) @{ KeyId = '22222222-2222-2222-2222-222222222222'; Force = $true }
        $r.threw | Should -Match 'not a client secret'
        @(Get-Writes $r).Count | Should -Be 0
    }
    It '-WhatIf with the guard satisfied: reads only, read scope only, no write' {
        $r = Invoke-Harness $script:rmScript (New-State -Fics @(ConvertTo-Fic)) @{ KeyId = $script:keyId; WhatIf = $true }
        $r.threw | Should -BeNullOrEmpty
        @(Get-Writes $r).Count | Should -Be 0
        @($r.scopes) | Should -Be @('Application.Read.All')
    }
    It 'real run with the guard satisfied: exactly one write, removePassword, then verifies' {
        $r = Invoke-Harness $script:rmScript (New-State -Fics @(ConvertTo-Fic)) @{ KeyId = $script:keyId; Force = $true }
        $r.threw | Should -BeNullOrEmpty
        $w = @(Get-Writes $r)
        $w.Count | Should -Be 1
        $w[0] | Should -Match '^POST https://graph.microsoft.com/v1.0/applications/app-object-id/removePassword$'
        @($r.scopes) | Should -Be @('Application.ReadWrite.All')
        $r.disconnected | Should -BeGreaterThan 0
    }
}

Describe 'Remediation scripts: static guard rails' {
    It 'both scripts parse, support -WhatIf, and disconnect in a finally block' -ForEach @(
        @{ Name = 'Add-NhiFederatedCredential.ps1' }, @{ Name = 'Remove-NhiAppSecret.ps1' }
    ) {
        $path = Join-Path (Get-RepoRoot) "remediation/$Name"
        $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errs)
        @($errs).Count | Should -Be 0
        $text = Get-Content -LiteralPath $path -Raw
        $text | Should -Match 'SupportsShouldProcess'
        $text | Should -Match '(?s)finally\s*\{\s*Disconnect-MgGraph'
        # They never create, read or print a secret value.
        $text | Should -Not -Match 'addPassword|secretText|\.hint\b'
    }
    It 'requests only Application.Read.All / Application.ReadWrite.All' {
        foreach ($n in 'Add-NhiFederatedCredential.ps1', 'Remove-NhiAppSecret.ps1') {
            $text = Get-Content -LiteralPath (Join-Path (Get-RepoRoot) "remediation/$n") -Raw
            $scopes = [regex]::Matches($text, "@\('([A-Za-z.]+)'\)") | ForEach-Object { $_.Groups[1].Value }
            @($scopes | Sort-Object -Unique) | Should -Be @('Application.Read.All', 'Application.ReadWrite.All')
        }
    }
    It 'parameter defaults equal expected_federation in the answer key (one source of truth)' -ForEach @(
        @{ Name = 'Add-NhiFederatedCredential.ps1' }, @{ Name = 'Remove-NhiAppSecret.ps1' }
    ) {
        $key = Get-Content -LiteralPath (Join-Path (Get-RepoRoot) 'seed/expected-findings.json') -Raw | ConvertFrom-Json
        $want = $key.apps.'seed-02-longsecret'.state_dependent.expected_federation
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-RepoRoot) "remediation/$Name"), [ref]$null, [ref]$null)
        $defaults = @{}
        foreach ($p in $ast.ParamBlock.Parameters) {
            if ($p.DefaultValue) { $defaults[$p.Name.VariablePath.UserPath] = $p.DefaultValue.SafeGetValue() }
        }
        $defaults['Issuer']  | Should -BeExactly $want.issuer
        $defaults['Subject'] | Should -BeExactly $want.subject
        $defaults['Audience'] | Should -BeExactly $want.audiences[0]
        $defaults['AppDisplayName'] | Should -BeIn @($key.apps.PSObject.Properties.Name)
    }
}

Describe 'Workflow .github/workflows/oidc-demo.yml (static checks)' {
    BeforeAll {
        $script:yml = Get-Content -LiteralPath (Join-Path (Get-RepoRoot) '.github/workflows/oidc-demo.yml') -Raw
        $script:code = ($script:yml -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    }
    It 'is manually triggered only' {
        $script:code | Should -Match '(?m)^on:\s*\n\s+workflow_dispatch:'
        $script:code | Should -Not -Match '(?m)^\s+(push|pull_request|schedule|pull_request_target):'
    }
    It 'runs in the lab environment with only id-token: write and contents: read' {
        $script:code | Should -Match '(?m)^\s+environment: lab\s*(#.*)?$'
        $script:code | Should -Match '(?m)^\s+id-token: write\s*(#.*)?$'
        $script:code | Should -Match '(?m)^\s+contents: read\s*(#.*)?$'
        $script:code | Should -Not -Match '(?m)^\s+(contents|actions|packages|pull-requests|issues): write'
    }
    It 'pins every action by a full 40-character commit SHA with a version comment' {
        $uses = [regex]::Matches($script:code, '(?m)^\s*-?\s*uses:\s*(\S+)(.*)$')
        $uses.Count | Should -BeGreaterThan 0
        foreach ($u in $uses) {
            $u.Groups[1].Value | Should -Match '@[0-9a-f]{40}$'
            $u.Groups[2].Value | Should -Match '#\s*v\d+\.\d+\.\d+'
        }
    }
    It 'takes client and tenant IDs from secrets and uses allow-no-subscriptions' {
        $script:code | Should -Match 'client-id: \$\{\{ secrets\.AZURE_CLIENT_ID \}\}'
        $script:code | Should -Match 'tenant-id: \$\{\{ secrets\.AZURE_TENANT_ID \}\}'
        $script:code | Should -Match 'allow-no-subscriptions: true'
    }
    It 'never prints the token, tenant ID or client ID' {
        # Each secret is referenced where it is needed and nowhere else.
        ([regex]::Matches($script:code, 'secrets\.AZURE_TENANT_ID')).Count | Should -Be 1   # the azure/login input
        ([regex]::Matches($script:code, 'secrets\.AZURE_CLIENT_ID')).Count | Should -Be 2  # login input + the in-memory comparison
        $lines = $script:code -split "`n"
        # No line that writes to the log may mention the token, the expected client ID, or the raw claims object.
        $printing = @($lines | Where-Object { $_ -match 'Write-Host|Write-Output|echo\b|Out-File|Set-Content|GITHUB_OUTPUT|GITHUB_ENV|GITHUB_STEP_SUMMARY|\$claims\s*(\||$)' })
        foreach ($l in $printing) {
            $l | Should -Not -Match '\$token\b'
            $l | Should -Not -Match 'EXPECTED_CLIENT_ID'
            $l | Should -Not -Match '\$claims\.(tid|appid)\b' -Because 'only the true/false comparison may be printed'
        }
        $script:code | Should -Not -Match 'tenant-id:\s*[0-9a-f]{8}-'   # no literal GUID
    }
    It 'prints exactly the three safe claims' {
        $script:code | Should -Match 'idtyp\s+:'
        $script:code | Should -Match 'appidacr:'
        $script:code | Should -Match 'appid equals the client ID:'
    }
}