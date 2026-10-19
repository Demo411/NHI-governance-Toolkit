#Requires -Version 7.0
<#
.SYNOPSIS
    Validates a findings file against the Phase 1 answer key (seed/expected-findings.json).

.DESCRIPTION
    OFFLINE ONLY. Reads local JSON files and prints a per-seed pass/fail table.
    Exit code 0 = everything passed, 1 = at least one failure (or an integrity problem).

    Rules of the road:
      - A seed is any identity carrying the 'nhi-lab-seed' tag on its application or service
        principal, or an agent identity whose parent blueprint (by appId) is such a seed.
        Display names never decide this; the answer key's names are only labels used to look up
        which expectations apply to a tag-verified seed.
      - It fails if a tagged identity has no answer-key entry, or an entry has no tagged identity.
      - Time-dependent expectations (seed-03) are resolved against the INVENTORY's own
        scanMetadata.scanStartUtc, using the credential's endDateTime read from the inventory.
      - Before judging anything it re-hashes the inventory and risk-rules.json and refuses to
        continue if they differ from what the findings file says it was built from.

.PARAMETER FindingsPath
    findings-*.json from Invoke-NhiScoring.ps1.

.PARAMETER InventoryPath
    The inventory it was built from. Defaults to the file named inside the findings, looked up
    in the same folder as the findings file.

.PARAMETER AnswerKeyPath
    Defaults to seed/expected-findings.json.

.PARAMETER RulesPath
    Defaults to risk-rules.json next to this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FindingsPath,

    [string]$InventoryPath,

    [string]$AnswerKeyPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'seed/expected-findings.json'),

    [string]$RulesPath = (Join-Path $PSScriptRoot 'risk-rules.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SeedTag = 'nhi-lab-seed'

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Read-JsonFile {
    param([string]$Path)
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -DateKind String)
}

function Get-FileSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function ConvertTo-UtcDateTimeOffset {
    param($Value, [string]$What)
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $parsed = [datetimeoffset]::MinValue
    if ($null -eq $Value -or -not [datetimeoffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        throw "Cannot parse '$Value' as a date ($What)."
    }
    return $parsed
}

function Format-Set {
    param($Items)
    $a = @($Items | Where-Object { $_ })
    if ($a.Count -eq 0) { return '(none)' }
    return ($a | Sort-Object) -join ','
}

# --- load and integrity-check ---------------------------------------------------------

$failures = [System.Collections.Generic.List[string]]::new()

try {
    $findingsFile = (Resolve-Path -LiteralPath $FindingsPath).Path
    $findings = Read-JsonFile $findingsFile
    $answerKey = Read-JsonFile (Resolve-Path -LiteralPath $AnswerKeyPath).Path
    $rulesFile = (Resolve-Path -LiteralPath $RulesPath).Path
    $rules = Read-JsonFile $rulesFile

    if (-not $InventoryPath) { $InventoryPath = Join-Path (Split-Path $findingsFile -Parent) $findings.inputs.inventoryFile }
    $invFile = (Resolve-Path -LiteralPath $InventoryPath).Path
    $inventory = Read-JsonFile $invFile

    $integrityOk = $true
    if ((Get-FileSha256 $invFile) -ne $findings.inputs.inventorySha256) {
        $failures.Add('INTEGRITY: the inventory file does not match the hash recorded in the findings file.')
        $integrityOk = $false
    }
    if ((Get-FileSha256 $rulesFile) -ne $findings.inputs.rulesSha256) {
        $failures.Add('INTEGRITY: risk-rules.json does not match the hash recorded in the findings file.')
        $integrityOk = $false
    }
    if (-not $integrityOk) { throw 'Findings were not produced from these inputs; refusing to validate.' }

    # The inventory's own clock, independent of the engine.
    $scanStart = ConvertTo-UtcDateTimeOffset $inventory.scanMetadata.scanStartUtc 'scanMetadata.scanStartUtc'
    if ((ConvertTo-UtcDateTimeOffset $findings.inputs.scanStartUtc 'findings scanStartUtc') -ne $scanStart) {
        $failures.Add('INTEGRITY: findings scanStartUtc differs from the inventory scanStartUtc.')
    }

    $ignored = @(Get-Prop $answerKey 'ignored_rules')

    # --- identify seeds by TAG, never by name ------------------------------------------
    $directlyTagged = @($inventory.identities | Where-Object {
        $tags = @(Get-Prop (Get-Prop $_ 'application') 'tags') + @(Get-Prop (Get-Prop $_ 'servicePrincipal') 'tags')
        $tags -contains $SeedTag
    })
    # Agent identities (Phase 4): Graph documents an agent's tags as the union of its own and its
    # blueprint's, but in the lab (2026-10-19) the tagged blueprints' agents came back with
    # tags = []. So an UNTAGGED agent counts as a seed when its parent link
    # (servicePrincipal.agentIdentityBlueprintId, an appId) points at a tagged seed BLUEPRINT.
    # Still decided by IDs and tags only, never by display name.
    $taggedBlueprintAppIds = @($directlyTagged | Where-Object { (Get-Prop $_ 'identityType') -eq 'agentBlueprint' } |
        ForEach-Object { ([string]$_.appId).ToLowerInvariant() })
    $inheritedAgents = @($inventory.identities | Where-Object {
        $_ -notin $directlyTagged -and
        (Get-Prop $_ 'identityType') -eq 'agentIdentity' -and
        ([string](Get-Prop (Get-Prop $_ 'servicePrincipal') 'agentIdentityBlueprintId')).ToLowerInvariant() -in $taggedBlueprintAppIds
    })
    $tagged = @($directlyTagged) + @($inheritedAgents)
    $keys = @($answerKey.apps.PSObject.Properties.Name)

    $byLabel = @{}
    foreach ($t in $tagged) {
        if ($byLabel.ContainsKey($t.displayName)) {
            $failures.Add("Two tagged identities share the label '$($t.displayName)'; the answer key cannot tell them apart.")
        }
        else { $byLabel[$t.displayName] = $t }
    }
    foreach ($t in $tagged) {
        if ($t.displayName -notin $keys) { $failures.Add("Tagged seed '$($t.displayName)' has no entry in the answer key.") }
    }
    foreach ($k in $keys) {
        if (-not $byLabel.ContainsKey($k)) { $failures.Add("Answer-key entry '$k' has no identity tagged '$SeedTag' in the inventory.") }
    }

    $findingsByAppId = @{}
    foreach ($f in $findings.identities) { $findingsByAppId[$f.appId] = $f }

    # --- per-seed rule sets ------------------------------------------------------------
    $rows = foreach ($k in $keys) {
        if (-not $byLabel.ContainsKey($k)) {
            [pscustomobject]@{ Seed = $k; State = ''; Expected = '?'; Actual = '?'; Score = ''; Result = 'FAIL'; Note = 'no tagged identity' }
            continue
        }
        $identity = $byLabel[$k]
        $entry = $answerKey.apps.$k
        $state = ''
        $expected = $null
        $note = ''

        $td = Get-Prop $entry 'time_dependent'
        if ($null -ne $td) {
            if ($td.expired_when -ne 'endDateTime <= scanStartUtc') {
                $note = "unsupported expired_when '$($td.expired_when)'"
            }
            else {
                $secrets = @(Get-Prop (Get-Prop $identity 'application') 'passwordCredentials' | Where-Object { $null -ne $_ })
                if ($secrets.Count -ne 1) { $note = "pivot needs exactly 1 application secret, found $($secrets.Count)" }
                else {
                    $end = ConvertTo-UtcDateTimeOffset $secrets[0].endDateTime 'pivot endDateTime'
                    if ($end -le $scanStart) { $state = 'after expiry';  $expected = @($td.after_expiry.expected_rules) }
                    else                     { $state = 'before expiry'; $expected = @($td.before_expiry.expected_rules) }
                }
            }
        }
        else { $expected = @($entry.expected_rules) }

        $fid = $findingsByAppId[[string]$identity.appId]
        $actual = if ($null -ne $fid) { @($fid.findings | ForEach-Object { $_.ruleId }) } else { @() }
        $score = if ($null -ne $fid) { $fid.score.total } else { $null }

        $result = 'FAIL'
        if ($null -eq $fid) { $note = 'identity missing from findings' }
        elseif ($null -ne $expected) {
            $exp = @($expected | Where-Object { $_ -notin $ignored } | Sort-Object)
            $act = @($actual   | Where-Object { $_ -notin $ignored } | Sort-Object)
            $missing    = @($exp | Where-Object { $_ -notin $act })
            $unexpected = @($act | Where-Object { $_ -notin $exp })
            if ($missing.Count -eq 0 -and $unexpected.Count -eq 0) { $result = 'PASS' }
            else { $note = ((@(if ($missing.Count) { "missing: $($missing -join ',')" }) + @(if ($unexpected.Count) { "unexpected: $($unexpected -join ',')" })) -join '; ') }
        }
        if ($result -eq 'FAIL') { $failures.Add("Rule set mismatch for '$k'. $note") }

        [pscustomobject]@{
            Seed = $k; State = $state; Expected = (Format-Set $expected); Actual = (Format-Set $actual)
            Score = $score; Result = $result; Note = $note
        }
    }

    # --- score constraints -------------------------------------------------------------
    $tierPoints = $rules.scoring.tierPoints
    function Get-SeedScore {
        param([string]$Label)
        if (-not $byLabel.ContainsKey($Label)) { return $null }
        $f = $findingsByAppId[[string]$byLabel[$Label].appId]
        if ($null -eq $f) { return $null }
        return [int]$f.score.total
    }

    $constraintRows = foreach ($c in @($answerKey.score_constraints)) {
        $ok = $false
        $detail = ''
        switch ($c.type) {
            'max_among_seeds' {
                $s = Get-SeedScore $c.subject
                $all = @($keys | ForEach-Object { Get-SeedScore $_ } | Where-Object { $null -ne $_ })
                if ($null -ne $s -and $all.Count -gt 0) {
                    $max = ($all | Measure-Object -Maximum).Maximum
                    $ok = ($s -eq $max)
                    $detail = "score $s, seed max $max"
                    # Informational only: how it compares with non-seed identities.
                    $overall = $findings.summary.maxScore
                    if ($s -lt $overall) { $detail += "; NOTE a non-seed identity scores $overall" }
                }
                else { $detail = 'subject missing' }
            }
            'less_than' {
                $l = Get-SeedScore $c.left; $r = Get-SeedScore $c.right
                if ($null -ne $l -and $null -ne $r) { $ok = ($l -lt $r); $detail = "$l < $r" } else { $detail = 'subject missing' }
            }
            'equals' {
                $s = Get-SeedScore $c.subject
                if ($null -ne $s) { $ok = ($s -eq [int]$c.value); $detail = "$s == $($c.value)" } else { $detail = 'subject missing' }
            }
            'greater_than' {
                $s = Get-SeedScore $c.subject
                if ($null -ne $s) { $ok = ($s -gt [int]$c.value); $detail = "$s > $($c.value)" } else { $detail = 'subject missing' }
            }
            'equals_rule_weight' {
                $s = Get-SeedScore $c.subject
                $rule = @($rules.rules | Where-Object { $_.id -eq $c.rule })
                if ($rule.Count -ne 1 -or $rule[0].severity -eq 'variable') { $detail = "rule $($c.rule) has no single weight" }
                elseif ($null -ne $s) { $w = [int]$tierPoints.($rule[0].severity); $ok = ($s -eq $w); $detail = "$s == weight($($c.rule)) = $w" }
                else { $detail = 'subject missing' }
            }
            default { $detail = "unknown constraint type '$($c.type)'" }
        }
        if (-not $ok) { $failures.Add("Constraint $($c.id) failed: $($c.text) ($detail)") }
        [pscustomobject]@{ Id = $c.id; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail; Constraint = $c.text }
    }

    Write-Host ''
    Write-Host "Findings : $(Split-Path -Leaf $findingsFile)"
    Write-Host "Inventory: $(Split-Path -Leaf $invFile)  (scan start $($scanStart.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")))"
    Write-Host "Seeds    : $($tagged.Count) identified by the '$SeedTag' tag ($($inheritedAgents.Count) agent(s) through their tagged blueprint), $($keys.Count) in the answer key"
    Write-Host ''
    Write-Host 'Rule sets per seed'
    @($rows) | Format-Table Seed, State, Expected, Actual, Score, Result -AutoSize | Out-Host
    foreach ($r in @($rows) | Where-Object { $_.Note }) { Write-Host "  $($r.Seed): $($r.Note)" }
    Write-Host 'Score constraints'
    @($constraintRows) | Format-Table Id, Result, Detail, Constraint -AutoSize -Wrap | Out-Host
}
catch {
    $failures.Add("ERROR: $($_.Exception.Message)")
}

if ($failures.Count -eq 0) {
    Write-Host 'RESULT: PASS' -ForegroundColor Green
    exit 0
}
Write-Host "RESULT: FAIL ($($failures.Count) problem(s))" -ForegroundColor Red
foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
exit 1
