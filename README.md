# NHI Governance Toolkit

A read-only governance toolkit for non-human identities (app registrations and service principals) in Microsoft Entra ID. It inventories every one, including the credentials hidden on service principals that app-registration-only tooling misses, scores each against documented rules mapped to NIST SP 800-53, and checks its own results against a deliberately seeded answer key.

```mermaid
flowchart LR
    A["seed/New-NhiLabSeed.ps1<br/>11 tagged lab identities"] --> B["scanner/Invoke-NhiInventory.ps1<br/>read-only Graph GETs"]
    B --> C[("inventory JSON<br/>facts only")]
    C --> D["scanner/Invoke-NhiScoring.ps1<br/>offline, rules from risk-rules.json"]
    D --> E[("findings JSON<br/>score, evidence, hashes")]
    E --> F["scanner/Test-NhiFindings.ps1<br/>vs seed/expected-findings.json"]
    F --> G{{"exit 0 = PASS<br/>exit 1 = FAIL"}}
```

## Results

Measured on the lab tenant (inventory `20261012-130643Z`):

- **89 identities** scored (89 service principals, 11 of which also have an app registration in the tenant); **11 seeded identities** with a known expected outcome. 9 identities have findings, and all 9 are seeds.
- **7 of 8 rules active** (NHI-006 deferred). All 11 seeds match the answer key and all 7 score constraints hold: `RESULT: PASS`.
- **49 Pester tests** on synthetic inventories (no tenant needed), **mutation-checked**: loosening the NHI-002 boundary, the NHI-003 expiry comparison, or the resolved-appId check each makes tests fail.
- **Reproducibility demo:** `seed-03-expiring` has a 1-day secret. Scored on a scan taken before it expired it gets NHI-007 and **10** points; scored on a later scan it gets NHI-003 and **3**. Re-running the engine on the older inventory produced a findings file with the identical SHA-256, and across the two findings files `seed-03-expiring` was the only identity that changed. See [`examples/`](examples/).

## Rules

| ID | Finding | Severity | NIST 800-53 |
|----|---------|----------|-------------|
| NHI-001 | No owner / sponsor | Medium | AC-2 |
| NHI-002 | Client secret lifetime over 180 days | Medium | IA-5 |
| NHI-003 | Expired credential still attached | Low | IA-5, AC-2 |
| NHI-004 | High-risk application permission granted | Critical or High (by permission) | AC-6 |
| NHI-005 | Privileged directory role assigned to a service principal | Critical | AC-6 |
| NHI-006 | No sign-in in 90+ days | Medium, **deferred** (not scored) | AC-2 |
| NHI-007 | Active client secret in use | Medium | IA-5 |
| NHI-008 | Tenant-wide consent to a high-risk delegated permission | Low | AC-6 |

## Scoring

Scores are additive by severity tier: Critical 40, High 25, Medium 10, Low 3, with no cap. Each rule fires at most once per identity. One combination uplift, **COMBO-U1 "armed privilege"**, adds 15 when an identity has a dangerous permission or role (NHI-004 or NHI-005) **and** an active client secret (NHI-007): the privilege is only usable by an attacker who can obtain a credential, and an expired secret does not qualify. An uplift for "ownerless plus privilege" was considered and rejected as a governance gap, not extra exploitability. Every weight and its reasoning is in [`docs/risk-model.md`](docs/risk-model.md).

## Design decisions

- **Read-only by code.** Every Graph call in the scanner goes through one function that hard-codes `-Method GET`, and the scanner requests only read scopes. Honest caveat: the delegated token can still carry write scopes, because Entra reuses the existing consent grant of the "Microsoft Graph Command Line Tools" app. The scanner records `writeScopesPresent` and a warning in the inventory when that happens; it never uses them.
- **Credentials from both objects.** Secrets and certificates are read from the app registration *and* the service principal. A secret added directly to a service principal is invisible if you only look at app registrations (seed-11 is the regression test).
- **IDs, never display names.** Graph is matched by its well-known appId, privileged roles by role template ID, and seeds by the `nhi-lab-seed` tag. A look-alike service principal named "Microsoft Graph" does not match.
- **Scan-start clock.** Rules evaluate against the inventory's `scanStartUtc`, never the current time, so the same inventory always yields the same findings. The output carries no generation timestamp and records SHA-256 hashes of its inputs.
- **Facts in the scanner, judgments in the engine.** The scanner records what exists; the scoring engine decides what is risky, offline, from `risk-rules.json`.

## Quick start

**Prerequisites:** PowerShell 7+; the Microsoft Graph PowerShell SDK (v2); Pester 5.x (`Install-Module Pester -Scope CurrentUser -SkipPublisherCheck -MaximumVersion 5.99.99`); Entra ID P1/P2 for sign-in activity data (otherwise pass `-SkipSignInActivity` to the scanner).

**Scanner scopes (delegated, interactive sign-in only):** `Application.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`, `AuditLog.Read.All`.

```powershell
# 1. Scan (signs in interactively; writes output/inventory-<timestamp>.json)
pwsh scanner/Invoke-NhiInventory.ps1

# 2. Score (offline; writes output/findings-<timestamp>.json)
pwsh scanner/Invoke-NhiScoring.ps1 -InventoryPath output/inventory-<timestamp>.json

# 3. Validate against the seed answer key (exit 0 = pass, 1 = fail)
pwsh scanner/Test-NhiFindings.ps1 -FindingsPath output/findings-<timestamp>.json -InventoryPath output/inventory-<timestamp>.json

# Tests (no tenant required)
pwsh tests/Invoke-Tests.ps1
```

Step 3 only applies to a tenant that was seeded; on any other tenant, use steps 1 and 2.

## Lab warning

`seed/New-NhiLabSeed.ps1` deliberately creates risky identities (an ownerless app, a 2-year secret, apps granted `Directory.ReadWrite.All` and `RoleManagement.ReadWrite.Directory`, a service principal holding Application Administrator). It needs write scopes and changes the tenant. **Use a dedicated test tenant only, never production.** Run it with `-WhatIf` first. `seed/Remove-NhiLabSeed.ps1` removes only objects tagged `nhi-lab-seed`. The seeder discards each secret as it is created; no secret value is stored or printed.

## Known limitations

- NHI-006 (no sign-in in 90+ days) is deferred: how to treat a null sign-in value is undecided.
- NHI-005 counts **Active** role assignments only; Eligible (PIM) assignments are not scored. Whether service principals can self-activate eligible roles via the API is an open research item.
- The NHI-005 role list (5 roles) and the NHI-004 High-tier and NHI-008 scope lists are hand-maintained; the High tier is an unresearched project convention.
- NHI-008 covers tenant-wide (`AllPrincipals`) grants only. Per-user grants of critical delegated scopes are considered and deferred.
- Severity tiers, point values and the 180-day secret threshold are this project's own conventions, not an external standard.
- Findings reflect only what the inventory captured. Tested on a single small lab tenant.

Full list: [`docs/risk-model.md`](docs/risk-model.md) section 6 and [`TODO.md`](TODO.md).

## Repo layout

```
.
├── README.md  LICENSE  TODO.md  CLAUDE.md
├── seed/
│   ├── New-NhiLabSeed.ps1        # creates 11 tagged lab identities (writes to the tenant)
│   ├── Remove-NhiLabSeed.ps1     # removes only objects tagged nhi-lab-seed
│   └── expected-findings.json    # answer key + score constraints
├── scanner/
│   ├── Invoke-NhiInventory.ps1   # read-only inventory -> JSON
│   ├── Invoke-NhiScoring.ps1     # offline scoring engine -> findings JSON
│   ├── Test-NhiFindings.ps1      # validator against the answer key
│   └── risk-rules.json           # rules, tiers, uplift, NIST mapping
├── tests/                        # Pester 5, synthetic inventories
├── examples/                     # sanitized before/after outputs
└── docs/risk-model.md            # why each rule and weight exists
```

## Roadmap

- **Phase 4:** Entra Agent ID (blueprint, agent identity, sponsor); confirm the scanner detects it, within inventory, sponsor and permissions.
- **Phase 5:** replace one app's client secret with GitHub Actions OIDC workload identity federation, then re-scan for a before/after.
- **Phase 6:** controls mapping, architecture diagram, write-up.

## License

[MIT](LICENSE)
