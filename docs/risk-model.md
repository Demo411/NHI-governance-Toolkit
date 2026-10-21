# Risk model

Why each rule and weight exists. The machine-readable version is `scanner/risk-rules.json`;
this document is the justification. Weights are the project owner's decisions; where a number is still
open it says so.

**Status:** implemented. `scanner/Invoke-NhiScoring.ps1` (engine v0.2.0) applies these rules to
an inventory file, `scanner/Test-NhiFindings.ps1` checks the result against the answer key, and
`tests/` holds 117 Pester 5 tests on synthetic inventories. See section 8; Agent ID (Phase 4) is
section 9.

## 1. Scoring model

**Additive tiers plus one named combination uplift.**

| Tier | Points | Used by |
|------|--------|---------|
| Critical | 40 | NHI-005; NHI-004 (privilege-granting permissions) |
| High | 25 | NHI-004 (all other high-risk permissions); NHI-009 (blueprint secret) |
| Medium | 10 | NHI-001, NHI-002, NHI-007, NHI-010, NHI-011 (NHI-006 deferred) |
| Low | 3 | NHI-003, NHI-008 |

- An identity's score is the sum of its findings' points, plus any combination uplift.
- Each rule fires at most once per identity. NHI-004 fires at its **highest** matching tier, so
  piling up permissions does not multiply the score.
- A rule's points come only from its severity tier. One place to change a weight.
- A lone finding scores exactly its tier points (constraint: seed-11 == weight(NHI-007)).
  Uplifts need two findings, so they cannot disturb that.
- The tier names and point values are this project's own convention, not taken from CVSS or any
  other standard.

### Combination uplift

**COMBO-U1 "Armed privilege": (NHI-004 or NHI-005) and NHI-007, +15, once.**
Privilege only matters if someone can authenticate as the identity. An active client secret is
a usable credential, so capability plus a live secret is exploitable now. Microsoft's own
guidance says an exposed secret lets an attacker escalate "depending on the permissions of the
application".

NHI-002 is deliberately not in the condition. NHI-002 measures how the secret was issued and
can fire on an already-expired secret, which says nothing about current usability.

Since Phase 4 the condition is written `allOfAny: [[NHI-004, NHI-005], [NHI-007, NHI-009]]`:
NHI-009 is the blueprint form of NHI-007 (same active secret, scored as a blueprint secret), so
it arms the uplift the same way. For every non-blueprint identity the behaviour is unchanged.

**COMBO-U3 "Shared credential over a privileged agent": blueprint has NHI-009 and any child
agent has NHI-004 or NHI-005, +15 on the blueprint, once.** See section 9.

### Considered and rejected

**COMBO-U2 "Unattended privilege": (NHI-004 or NHI-005) and NHI-001, +10.** Rejected. An
ownerless identity is a governance gap, not an exploitability gap: lacking an owner does not
make the identity easier to abuse. NHI-001 already scores in its own right. Side effect that
also argued against it: it would have pushed seed-05 (45) above seed-06 (40).

### Considered and deferred

**Per-user (`Principal`) grants of Critical-class delegated scopes are not covered by NHI-008.**
NHI-008 is defined on `AllPrincipals` (tenant-wide) consent only. Considered and deferred: an
admin consenting for themselves on Microsoft admin tooling is routine and bounded by their own
rights; revisit if third-party apps appear with such grants. Concretely, on the newest inventory
the Microsoft Graph Command Line Tools app holds a per-user grant that includes
`Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory` and
`AppRoleAssignment.ReadWrite.All`; its `AllPrincipals` grant is only `openid`,
`Application.Read.All`, `offline_access` and `profile`, so NHI-008 correctly reports nothing for
it. No new rule was added. A related open item is splitting NHI-008 by scope tier, like NHI-004
(TODO.md).

### NHI-002 and NHI-007 on the same secret

Both fire on seed-02 and seed-09 and both are counted. This is intended, not double counting.
They answer different questions: NHI-007 is "does a live shared secret exist", NHI-002 is "how
long was it issued for". Counting both gives a gradient: a 730-day live secret (seed-02, 20)
scores higher than a 90-day live secret (seed-11, 10), which is the behaviour we want.

## 2. Rules

| Rule | Severity | Control | Why |
|------|----------|---------|-----|
| NHI-001 No owner | Medium | AC-2 | No accountable human. Excludes Microsoft first-party and managed identities (see "Which identities each rule covers"). |
| NHI-002 Secret lifetime > 180d | Medium | IA-5 | Longer issuance window for a leaked secret. |
| NHI-003 Expired credential attached | Low | IA-5, AC-2 | Cleanup hygiene; not exploitable alone. Covers secrets and certificates. |
| NHI-004 High-risk app permission | Critical or High | AC-6 | Application permissions are tenant-wide and need no user. Tiered below. |
| NHI-005 Privileged directory role | Critical | AC-6 | Standing tenant-wide control. |
| NHI-006 No sign-in 90+ days | Medium (deferred) | AC-2 | Cannot be seeded; null handling undecided; contributes 0. |
| NHI-007 Active client secret | Medium | IA-5 | Usable shared secret; Microsoft says not for production. |
| NHI-008 Tenant-wide delegated consent | Low | AC-6 | Bounded by the signed-in user's rights, so lower than the application equivalent. |
| NHI-009 Active secret on an agent blueprint | High | IA-5 | One blueprint secret reaches every child agent. Replaces NHI-007 on blueprints (section 9). |
| NHI-010 Blueprint has no enabled sponsor | Medium | AC-2 | Nobody accountable for the whole agent type (no sponsor, or only disabled ones). |
| NHI-011 Agent has no enabled sponsor | Medium | AC-2 | NHI-001 for agents, whose accountability is a sponsor, not an owner. |

### Which identities each rule covers

The scanner assigns every identity an `ownerType`: `ThisTenant`, `Microsoft`, `ThirdParty`,
`ManagedIdentity` or `Unknown` (it never guesses, so `Unknown` is never excluded). Policy: every
rule covers every type unless its `appliesToReason` in `risk-rules.json` says why not.

| Rule | Covers | Reason |
|------|--------|--------|
| NHI-001 | ThisTenant, ThirdParty, Unknown | Microsoft first-party apps are never owned by tenant users (about 78 meaningless findings). Managed identities have no owner concept; their lifecycle follows the Azure resource. Third-party is included on purpose and will be noisy. |
| NHI-002 | All five | A secret on any service principal here was created here, including hidden credentials on third-party or Microsoft service principals. |
| NHI-003 | All five | Stale credentials on any service principal here are this tenant's cleanup job. |
| NHI-004 | All five | Grants are decided by this tenant whoever published the app: third-party consent and managed-identity privilege are the targets. |
| NHI-005 | All five | Role assignments are tenant-controlled for every identity type. |
| NHI-006 | All five (deferred) | An unused service principal is an AC-2 gap whoever published it. |
| NHI-007 | All five | A live secret on any service principal here is a usable credential. |
| NHI-008 | All five | Tenant-wide consent is a tenant decision; third-party apps are the main target. |

Phase 4 adds a second, independent scope, `identityType` (`application`, `agentBlueprint`,
`agentBlueprintPrincipal`, `agentIdentity`). A rule without `appliesTo.identityType` runs on every
identity type, so all rules above keep their coverage except: NHI-001 skips agent identities
(NHI-011 covers them), NHI-007 skips blueprints (NHI-009 covers them), and NHI-009/010/011 run
only on their own type. Details in section 9.

An earlier draft scoped every rule except NHI-001 to `ThisTenant` + `Microsoft`, which silently
excluded `ThirdParty` and `ManagedIdentity`. That was a mistake and is fixed. The
managed-identity exclusion for NHI-001 rests on reasoning about how managed identities work
(no owner concept; lifecycle follows the Azure resource), not on a cited source.

### Identifying seeds

Seeds are identified by the `nhi-lab-seed` tag in `application.tags` or
`servicePrincipal.tags`, never by display name (all 11 seeds carry it on both). The inventory
does not capture `notes`, so the tag is the only usable marker. The answer key is still keyed by
display name, but only as a lookup label for which expectations apply to a tag-verified seed;
the validator fails if a tagged identity has no key or a key has no tagged identity. A
per-seed tag (for example `nhi-lab-seed:seed-03`) would remove even that, but needs re-seeding.
Tags are editable by anyone with write access to the app, so this is a lab convenience, not a
security boundary.

Evaluation details that affect results:
- **Clock:** everything is evaluated against `scanMetadata.scanStartUtc`. Expired means
  `endDateTime <= scanStartUtc`; active means `endDateTime > scanStartUtc`.
- **Credentials:** NHI-002, 003 and 007 read both `application.*` and `servicePrincipal.*`
  (seed-11 is the regression test).
- **NHI-002 lifetime** is `floor(TotalDays)` of end minus start, and fires on `> 180`. Whole
  days absorb the sub-day skew between client-side and server-side timestamps (see TODO.md).
- **180 days is a project threshold, stricter than Microsoft's secret guidance.** Microsoft
  recommends under 12 months for client secrets (24 months maximum). The 180-day figure is
  Microsoft's recommended maximum for *certificates*. We apply it to secrets because secrets are
  the weaker credential; say so if asked.
- **Resource matching (NHI-004 and NHI-008)** never uses `resourceDisplayName`. Each
  `appRoleAssignments[]` / `oauth2PermissionGrants[]` entry has a `resourceId`, which is the
  object id of the resource's service principal in this tenant. The engine indexes the
  inventory (`servicePrincipal.id` -> `appId`), resolves `resourceId`, and requires the resolved
  appId to be `00000003-0000-0000-c000-000000000000` (Microsoft Graph). A display name can be
  chosen by anyone; Graph's appId cannot be reused by a tenant app. On the newest inventory all
  6 references resolve. A `resourceId` missing from the inventory cannot match and is recorded
  as an `unresolvedResource` warning in the findings file.
- **NHI-005 matching** is by built-in role template ID (`roleDefinitionId`); display names are
  labels only. See section 3a.
- **NHI-005 counts Active assignments only.** An Active assignment is usable right now. An
  Eligible (PIM) assignment is only a right to ask for the role, and activation is a separate
  step. Whether a service principal can perform that activation itself through the API is not
  established, so counting Eligible would assert an exposure we have not shown. The inventory
  records Eligible assignments anyway, so this can be revisited without a rescan (TODO.md:
  check whether service principals can self-activate eligible roles via the API).

## 3. NHI-004 tiers

**Critical (40), privilege-granting:** `RoleManagement.ReadWrite.Directory`,
`AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`.

- `RoleManagement.ReadWrite.Directory`: manages directory RBAC, so the holder can assign roles
  up to Global Administrator. BloodHound documents the path.
- `AppRoleAssignment.ReadWrite.All`: Microsoft's caution text says it lets an app "grant
  additional privileges to itself, other applications, or any user". BloodHound documents the
  chain: grant yourself `RoleManagement.ReadWrite.Directory`, then assign Global Administrator.
- `Application.ReadWrite.All`: Microsoft's caution text says credential-managing permissions
  "allow an application to act as other entities, and use the privileges they were granted".
  The holder can add a credential to a more privileged app and authenticate as it.

**High (25), everything else high-risk:** `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`,
`Files.ReadWrite.All`, `Directory.ReadWrite.All`.

> **Status of the High list: unresearched, project convention.** It is simply the NHI-008 list
> minus the three Critical entries. Only `Directory.ReadWrite.All` has been checked against
> outside evidence (below). The rest is a research TODO (TODO.md); do not present it as
> externally validated.

### Does `Directory.ReadWrite.All` belong in Critical?

**Recommendation: keep it High.**

What the evidence says:
- Microsoft's description: "read and write data in your organization's directory, such as users
  and groups ... Does not allow user or group deletion." It is not labelled privileged in the
  text that was read.
- SpecterOps tested it in 2024. They found it **could not**: promote itself to Global Admin,
  grant itself an app role, reset any user's password, add credentials to an app or service
  principal, add owners to an app or service principal, or add members/owners to
  role-assignable groups. It **could**: add members/owners to non-role-assignable security
  groups, and add new users. Their conclusion: closer to the Groups Administrator role than to
  Global Administrator.
- Residual risk they describe: non-role-assignable groups can hold Azure RBAC role assignments,
  so group manipulation can still be a stepping stone to Azure resources.

Why High and not Critical: the Critical tier means "can grant itself or others more privilege".
Every escalation primitive tested failed for this permission; its remaining paths depend on how
the tenant uses groups.

Caveats you should be able to state:
- The evidence is one third-party test from February 2024, not Microsoft documentation. SpecterOps
  itself says Microsoft's documentation states otherwise and that Graph behaviour changes.
- It was not tested in the lab tenant (that would need a tenant change).
- If the lab tenant uses groups for Conditional Access scoping, app assignment or Azure RBAC, the
  residual risk is higher than in an empty lab.
- If you moved it to Critical: seed-05 would score 50 instead of 35, above seed-06 (40). No
  constraint breaks.

### What else is High?

Accepted as-is for now (decision: NHI-008 list minus Critical). Candidates for the research
TODO, none researched yet: `Files.Read.All`, `Sites.ReadWrite.All`, `User.ReadWrite.All`,
`Group.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`.

## 3a. NHI-005 privileged roles

A hand-maintained static list of built-in role template IDs. A custom role can copy a display
name but not a built-in template ID, so the ID is the key and the name is only a label.

| Role | Template ID (`roleDefinitionId`) | Confirmed privileged |
|------|----------------------------------|----------------------|
| Global Administrator | `62e90394-69f5-4237-9190-012177145e10` | "This is a privileged role" in its section |
| Privileged Role Administrator | `e8611ab8-c189-46e8-94e1-60213ab1f814` | same |
| Privileged Authentication Administrator | `7be44c8a-adaf-4e2a-84d6-ab2649e08a13` | same |
| Application Administrator | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` | same; also `IsPrivileged: True` in the privileged-roles page example |
| Cloud Application Administrator | `158c047a-c907-4556-b7ef-446551a6b5f7` | same |

How this was verified: the privileged-roles-permissions page defines the label but does not list
roles by name; it points to the built-in roles page for the list. The five roles and their
template IDs were checked on that page (read in sections; the ID table is in the first part of
the page). The Global Administrator ID also appears, unnamed, in the example privileged
assignments on the privileged-roles page, which is consistent but not independent proof of the
name. Application Administrator's ID (`9b895d92-...`) also matches the
`seed-06` assignment in the inventory. This list is a deliberate subset: Microsoft marks many
more roles privileged (for example Helpdesk Administrator, Authentication Administrator and
Conditional Access Administrator appear in the privileged-roles page examples).

## 4. Scores for the 11 seeds

These are the engine's actual results on `inventory-20261011-143429Z.json` (scan start
2026-10-11T14:34:29Z, before seed-03's secret expired), confirmed by `Test-NhiFindings.ps1`:
all 11 rule sets match and all 7 score constraints pass. The "after expiry" row for seed-03 is
covered by the synthetic tests, not by a live inventory yet.

| Seed | Findings | Base | Uplift | Score |
|------|----------|------|--------|-------|
| 01-ownerless | 001 | 10 | | **10** |
| 02-longsecret | 002, 007 | 20 | | **20** |
| 03-expiring, before expiry | 007 | 10 | | **10** |
| 03-expiring, after expiry | 003 | 3 | | **3** |
| 04-mailread-app | 004 (High, Mail.Read) | 25 | | **25** |
| 05-dirwrite | 001, 004 (High, Directory.ReadWrite.All) | 35 | | **35** |
| 06-appadmin | 005 | 40 | | **40** |
| 07-requested-only | none | 0 | | **0** |
| 08-mailread-delegated | 008 | 3 | | **3** |
| 09-worstcase | 001, 002, 004 (Critical, RoleManagement.ReadWrite.Directory), 007 | 70 | +15 | **85** |
| 10-clean | none | 0 | | **0** |
| 11-sp-secret | 007 | 10 | | **10** |

seed-09 math: 10 + 10 + 40 + 10 = 70, plus U1 15 = 85.

### Constraint check (from `seed/expected-findings.json`)

The answer key now stores constraints as machine-readable objects (the original sentence is kept
in each `text` field), so the validator executes them rather than a person reading them.

| Id | Constraint | Result |
|----|------------|--------|
| C1 | seed-09 is the maximum across seeds | Pass: 85, next is seed-06 at 40 |
| C2 | seed-08 < seed-04 | Pass: 3 < 25 |
| C3a / C3b | seed-10 == 0 and seed-07 == 0 | Pass |
| C4 | seed-08 > 0 | Pass: 3 |
| C5a / C5b | seed-11 == weight(NHI-007), and > 0 | Pass: 10 == 10; no uplift because it has no NHI-004/005 |

seed-03 appears in none of the constraints, so both of its states pass them.

## 5. seed-03 and time

seed-03's secret expires one day after seeding. The three existing inventories were all taken
before that, so they correctly show **NHI-007 (10)**, not NHI-003. The answer key now carries a
`time_dependent` block for seed-03: the validator compares the credential's `endDateTime` (read
from the inventory) with that inventory's `scanStartUtc`. Expired (`end <= scanStart`) expects
NHI-003 (3); otherwise NHI-007 (10). Because the clock is the scan's own timestamp, an old
inventory validates the same way forever. Synthetic tests (`tests/Validator.Tests.ps1`) cover
one second before, exactly at and one second after the end time, through both the engine and the
validator; end == scanStart counts as expired.

## 5a. Results across the whole tenant

The engine scores every identity, not just seeds. On the newest inventory it scored 89 identities
with 0 warnings; only the 9 seeds with findings have any. No non-seed identity has a finding,
including NHI-008: the only non-seed identity with `AllPrincipals` grants is Microsoft Graph
Command Line Tools, and none of its tenant-wide scopes are in the NHI-008 list. See "Considered
and deferred" in section 1 for what that does and does not mean.

## 6. Open decisions

Decided:
- `scoreCap`: none. Scores rank identities; a cap would flatten the top. Max possible is 131, so
  scores are not a 0-100 scale.
- NHI-005: static list keyed by template ID (section 3a); Active assignments only.
- NHI-004 High list: accepted as-is, flagged unresearched.
- Resource matching by resolved appId, not display name.
- Phase 4 (section 9): new identityType values; agents inherit their blueprint's ownerType;
  NHI-009 High replaces NHI-007 on blueprints; COMBO-U3 +15 on the blueprint; agent roll-up is
  context only.

Considered and deferred:
- Per-user (`Principal`) grants of Critical-class delegated scopes (section 1).

Still open:
- NHI-005: Eligible assignments (depends on the self-activation research).
- NHI-004 High list research.
- NHI-008 split by scope tier, like NHI-004.
- NHI-006 null sign-in handling (deferred).

## 7. Reference verification log

Checked on 2026-10-11. Only pages that were actually opened are cited as verified.

| Source | URL | What it supports | Caveat |
|--------|-----|------------------|--------|
| Privileged roles and permissions in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions | PRIVILEGED label exists; Application Administrator shown with `IsPrivileged: True` | Label is in preview. It does not list the roles; it defers to the page below. |
| Microsoft Entra built-in roles | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference | Template IDs and "This is a privileged role" for the five NHI-005 roles | Page is ~403k characters; all but the last ~3k were read, through summaries of each 100k block, not line by line. |
| Microsoft Graph permissions reference | https://learn.microsoft.com/en-us/graph/permissions-reference | Caution text for Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All | Page is huge; only the first part was read. Directory.ReadWrite.All and RoleManagement.ReadWrite.Directory descriptions came from a third-party mirror (graphpermissions.merill.net), not the official page. |
| Add and manage app credentials | https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials | Secrets not for production; under 12 months recommended; 24-month cap; federation for workloads | |
| Enforce secret and certificate standards | https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tutorial-enforce-secret-standards | 180 days is the recommended certificate maximum; recommends disabling client secrets | Not a secret-lifetime recommendation. |
| Migrate applications away from secrets | https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/migrate-applications-from-secrets | Exposed secret can escalate depending on app permissions; managed identity / federation | |
| BloodHound AZMGGrantAppRoles | https://bloodhound.specterops.io/resources/edges/az-mg-grant-app-roles | Escalation chain to Global Administrator | Third party |
| SpecterOps, Directory.ReadWrite.All | https://specterops.io/blog/2024/02/12/directory-readwrite-all-is-not-as-powerful-as-you-might-think/ | What Directory.ReadWrite.All can and cannot do | Third party; 2024 test |
| NIST SP 800-53 Rev. 5 | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final | Publication exists | AC-2/AC-6/IA-5 text not re-read |

**Deliberately not cited:** the claim that the portal's add-secret dialog recommends 180 days
for client secrets could not be verified as Microsoft guidance. The verified secret guidance is
"under 12 months", and 180 days is the certificate figure. The tier names and points are not
tied to CVSS or any other standard; they are a project convention.

## 8. Implementation

**Run it** (all offline: no sign-in, no Graph module, no network):

```powershell
pwsh scanner/Invoke-NhiScoring.ps1 -InventoryPath output/inventory-<timestamp>.json
pwsh scanner/Test-NhiFindings.ps1  -FindingsPath  output/findings-<timestamp>.json
pwsh tests/Invoke-Tests.ps1        # needs Pester 5.x; no tenant required
```

**Engine** (`scanner/Invoke-NhiScoring.ps1`):
- Reads one inventory and `scanner/risk-rules.json`; writes `output/findings-<timestamp>.json`
  (gitignored, like the inventory). It scores every identity.
- The clock is the inventory's `scanStartUtc`; the machine clock is never read, and a missing
  `scanStartUtc` is an error. The output has no generation timestamp, so the same inputs give
  byte-identical output.
- Identities are ordered by total score descending, then `displayName` ascending, then `appId`
  ascending. Both string keys use **ordinal** comparison (`[string]::CompareOrdinal`, UTF-16 code
  units), not `Sort-Object`'s culture-sensitive comparison, so the order is identical on any
  machine whatever its regional settings (for example `B-app` sorts before `a-app`). `appId` is
  unique per identity, so equal scores never fall back to input order. A Pester test pins this.
- Rules run only on identities whose `ownerType` the rule covers; rules whose status is not
  `active` are skipped and listed under `skippedRules`.
- Each finding records its rule id, severity, points and the exact triggering items: credential
  `keyId` and which object it is on, permission name, role template ID, or grant scope.
- Score is shown as `base` (sum of finding points), `uplift` (COMBO-U1) and `total`.
- The file records the inventory file name, the SHA-256 of the inventory and of
  `risk-rules.json`, the engine version, and warnings (for example `unresolvedResource`).
- An active rule with no evaluator in the engine stops the run, so a rule added to the JSON
  cannot be silently ignored.

**Validator** (`scanner/Test-NhiFindings.ps1`): re-hashes the inventory and the rules file and
refuses to continue if they differ from what the findings say they were built from; identifies
seeds by tag; resolves seed-03's time-dependent expectation; compares rule sets and executes the
score constraints; prints a per-seed table and exits 0 (pass) or 1 (fail).

**Tests** (`tests/`, Pester 5, synthetic inventories only): NHI-002 at 179/180/180d23h59m/181
days; seed-03 before, at and after expiry; the four resource-resolution cases for NHI-004 and
NHI-008; a service-principal-only credential (seed-11); COMBO-U1 with active and expired secrets;
NHI-004 tiering; NHI-005 matching by template ID and Active only; ownerType scope; determinism;
and the validator's guard rails (tag versus name, hash tampering, failing constraint). The
suite was mutation-checked: loosening the NHI-002 boundary, the NHI-003 expiry comparison, the resolved-appId check, or
the ordinal output ordering each makes tests fail.

**Known limits:** the NHI-005 role list and the NHI-004/008 scope lists are hand-maintained;
Eligible role assignments and per-user grants are not scored (section 6); findings reflect only
what the inventory captured.

## 9. Phase 4: Entra Agent ID

### The object model, as Graph actually returns it

Checked in the lab with a read-only probe (2026-10-17), not assumed from documentation:

| Object | Where it appears | How the scanner recognises it |
|--------|------------------|-------------------------------|
| Agent identity blueprint | `/applications`, like any app registration | `@odata.type = #microsoft.graph.agentIdentityBlueprint` |
| Blueprint principal | `/servicePrincipals`, `servicePrincipalType = Application`, owner org = this tenant | `@odata.type = #microsoft.graph.agentIdentityBlueprintPrincipal` |
| Agent identity | `/servicePrincipals` only (no application object), `servicePrincipalType = ServiceIdentity` | `@odata.type = #microsoft.graph.agentIdentity`; parent in `agentIdentityBlueprintId` (the blueprint's appId) |

Facts that shaped the design:
- **Agents come back with `appOwnerOrganizationId = null`**, so the Phase 2 classifier labelled
  every agent `Unknown`. Decision: an agent inherits its blueprint's `ownerType` (it cannot exist
  without one). An agent whose blueprint is not in the inventory stays `Unknown` with a warning.
- **A blueprint's object ID equals its appId**, and so does an agent's. Classic apps have two
  different IDs. Nothing in the engine relied on them differing.
- **Agents have sponsors, not owners.** The seed agents have a sponsor and zero owners, so
  NHI-001 would have flagged every agent. Sponsors are read from
  `/v1.0/servicePrincipals/{id}/microsoft.graph.agentIdentity/sponsors` and
  `/v1.0/applications/{id}/microsoft.graph.agentIdentityBlueprint/sponsors`; the sponsor's
  `accountEnabled` comes from a per-user lookup (the sponsors endpoint does not return it).
- **Tags: the docs and the tenant disagree.** Graph documents an agent's `tags` as the union of
  its own and its blueprint's. In the lab (2026-10-19), after tagging both blueprints, the tag
  appeared on the blueprints and their blueprint principals, but all four agents came back with
  `tags = []`. So the validator treats an untagged agent as a seed when its
  `agentIdentityBlueprintId` points at a tagged seed blueprint (an ID link, never a name).
  Agent ID objects have no `notes` property, so `Remove-NhiLabSeed.ps1` (tags AND notes) never
  touches them.

### Why COMBO-U3 exists

COMBO-U1 needs privilege and an active secret on the **same** identity. Agent ID splits them:
the credential lives on the blueprint (agents have none of their own) and the permissions on the
agent. Scored one identity at a time, the lab's risky pair looks like two unrelated medium
risks: the blueprint has a secret, the agent has `Mail.ReadWrite`. But the blueprint's secret is
exchanged for the agent's token, so together they are armed privilege. COMBO-U3 restores that
link in a second pass after every identity has its own findings.

- **Where:** on the blueprint, because that is where the credential and the fix are. The child
  keeps only its own finding, so a harmless sibling (Risky-2) is not penalised.
- **How much:** +15, the same as COMBO-U1. **Once**, however many children qualify; the evidence
  lists every qualifying child.
- **Not counted:** an expired blueprint secret (NHI-003, not NHI-009) and certificates.

### Roll-up (context only)

Each blueprint carries `agentRollup` (`agentCount`, `agentsWithFindings`, `worstChild`) and each
agent carries `parentBlueprint`. The roll-up never adds points: COMBO-U3 already scores the
dangerous case, and adding the worst child's score as well would count the same risk twice.

### Microsoft's own agent guardrail (lab evidence)

Granting Graph application permissions to the risky agent (2026-10-16):

| Permission | Result |
|------------|--------|
| `Directory.ReadWrite.All` | **Refused**: "The specified app role cannot be granted to agent identities." |
| `Mail.ReadWrite` | Granted |

Microsoft's authorization page lists four blocked permissions (`Application.ReadWrite.All`,
`RoleManagement.ReadWrite.All`, `User.ReadWrite.All`, `Directory.AccessAsUser.All`) and says
tenant-wide write or control is not allowed for agents. `Directory.ReadWrite.All` is not on that
list but was refused, so the enforced list is wider than the documented one. Tenant-wide
**mailbox** write was allowed: the guardrail protects the directory, not data. So NHI-004 stays
fully relevant for agents.

### Expected lab scores

| Identity | Rules | Score |
|----------|-------|-------|
| NHI-Seed-BP-Risky | NHI-009 + COMBO-U3 | 25 + 15 = 40 |
| NHI-Seed-Agent-Risky-1 | NHI-004 (Mail.ReadWrite, High) | 25 |
| NHI-Seed-BP-Clean, Clean-1, Clean-2, Risky-2 | none | 0 |

Constraints C6-C8 in the answer key pin these. NHI-002 does not fire on the risky blueprint: its
"180-day" secret has a whole-day lifetime of 179 (client vs server timestamp skew, as in TODO.md).

### Not covered

Agent Conditional Access and ID Protection need licensing this lab does not have (CLAUDE.md,
Phase 4 scope). Agent user accounts were not seeded. Sponsor groups count as accountable without
checking their members.

## 10. Phase 5: replacing seed-02's client secret with GitHub Actions OIDC federation

### What changes, and what does not

seed-02 is the 730-day client secret (NHI-002 + NHI-007, score 20 in the Phase 3 table). The fix is
**workload identity federation**: instead of holding a secret, the app registration holds a
*federated identity credential* (FIC), a rule that says "accept a token issued by GitHub for this
exact repository and environment as proof that the caller is this app". Nothing secret is stored in
GitHub or in Entra, so there is nothing to rotate or leak.

| Field | Value | Why |
|-------|-------|-----|
| issuer | `https://token.actions.githubusercontent.com` | GitHub's OIDC issuer |
| subject | `repo:Demo411@181002116/NHI-governance-Toolkit@1415658131:environment:lab` | exact match, no wildcards; the `environment:lab` form ties the trust to one GitHub environment that has a required reviewer; the `@<id>` parts are GitHub's immutable owner and repo IDs (see "Lab finding" below) |
| audience | `api://AzureADTokenExchange` | the audience Entra expects for token exchange |

No rule is added. The scanner records FICs as facts; the existing NHI-002 and NHI-007 simply stop
firing once the secret is gone. A future rule for a **broad FIC subject** is in TODO.md.

### Scanner v0.3.0: collecting FICs

`GET /v1.0/applications/{id}/federatedIdentityCredentials`, one call per app, through the same
GET-only helper as everything else, needing only `Application.Read.All`. The list endpoint cannot
`$select` or `$expand` FICs, which is why it is a per-app call (the same shape as owners). Only
`name`, `issuer`, `subject` and `audiences` are kept. A failed lookup stores `null` plus a warning;
`null` means "unknown" and is deliberately different from `[]` ("confirmed none"). Inventories from
before v0.3.0 have no `federatedIdentityCredentials` property at all.

### Lab finding: the name-based subject was already obsolete (2026-10-20)

The first design used the classic subject `repo:Demo411/NHI-governance-Toolkit:environment:lab`.
The first workflow run failed with **AADSTS700213** (no matching federated identity credential),
which was the correct outcome: GitHub now sends an **immutable subject** for repositories created
after 2026-07-15, `repo:Demo411@181002116/NHI-governance-Toolkit@1415658131:environment:lab`, so the
name-based credential could never match. Nothing was weakened and no secret was touched; the
secret was still in place and the failure was a lockout of the new path only.

Why the immutable form is the better trust, not just the one that works: a name-based subject
identifies a repo by *names*, and names can be recycled. If the repository or organisation were
deleted or renamed and another party registered the same name, their workflow would present the same
subject and Entra would accept it. The numeric owner and repository IDs never repeat, so the
credential stays bound to the one repository. The IDs are public values, so they are committed.
The old credential is therefore the **weaker** trust and is replaced, not kept alongside.

How the toolkit handles it: `Add-NhiFederatedCredential.ps1` now PATCHes the `subject` of an existing
credential with the same name (same issuer and audience), and `-WhatIf` prints `old subject` and
`new subject`. A different issuer or audience under the same name is still refused, because that is a
different trust rather than a stale subject. The answer key's `expected_federation.subject` and
`Remove-NhiAppSecret.ps1`'s precondition use the immutable form, so a leftover name-based credential
does not count as federated. A scanner rule for GitHub-issuer credentials whose subject lacks the
`@<id>` parts (subject-recycling risk) is recorded in TODO.md, not built.

Refs: Microsoft Learn "workload-identities-github-immutable-subjects"; GitHub changelog
2026-04-23 "Immutable subject claims for GitHub Actions OIDC tokens".

### The state-dependent answer key

seed-02's entry is a `state_dependent` block, like seed-03's `time_dependent`. The pivot is read
from the inventory, never from names:

| Inventory shows | State | Expected rules |
|-----------------|-------|----------------|
| at least one **active** client secret on the application **or** the service principal | `with_secret` | NHI-002, NHI-007 |
| **no** client secret at all, and a FIC matching `expected_federation` **exactly** | `federated` | none |
| anything else (no secret and no matching FIC; only expired secrets) | undefined | **validator fails** |

- A FIC with a different subject, a different issuer, a different audience set, or even a different
  letter case does not count. Comparison is case-sensitive on all three fields.
- Mixed state (secret and FIC together) is `with_secret`. That is the true state between steps C
  and E, and the engine still reports both rules then.
- The secret check reads `application.passwordCredentials` and `servicePrincipal.passwordCredentials`
  (the seed-11 lesson: a secret hidden on the service principal still counts).
- Old inventories still validate: they have a secret and no FIC property, so they resolve to
  `with_secret`.
- "Fail loudly" is deliberate. If the secret is deleted before the FIC exists, the app has no
  working credential, and a validator that passed that state would hide the mistake.

### The workflow (`.github/workflows/oidc-demo.yml`)

It lives at the **repository root**: GitHub only runs workflows from `.github/workflows/` there, so
the `remediation/.github/...` path in the original layout would never execute.

- `workflow_dispatch` only; job `environment: lab`; `permissions: id-token: write, contents: read`.
- `azure/login` is pinned by full commit SHA (`7184910d...` = v2.3.1, looked up from
  github.com/Azure/login on 2026-10-19; the tag object and the commit lookup agree). A tag can be
  moved to different code, a SHA cannot. v3.x exists; v2 was chosen deliberately, and moving to v3 is
  a separate, reviewed change.
- `allow-no-subscriptions: true`: the lab has no Azure subscription; only a Graph token is needed.
- The repository is public, so its logs are public. Client ID and tenant ID are environment
  **secrets** (GitHub masks them in logs) and the job never prints them or the token.
- Proof step: get a Graph token, decode the payload in memory, print only `idtyp`, `appidacr` and
  whether `appid` equals the client ID (true/false). `appidacr` is `2` for a client assertion
  (certificate or federated) and `1` for a client secret. The job fails if `appidacr` is not 2 or
  the appid does not match. `idtyp` is printed but does not gate the job, because it is an optional
  claim in some token versions.

### The two tenant-changing scripts (`remediation/`)

| Script | Writes | Guard |
|--------|--------|-------|
| `Add-NhiFederatedCredential.ps1` | `POST .../federatedIdentityCredentials`, or `PATCH .../{id}` (subject only) | app confirmed by tag **and** notes marker; exact subject (no `*`/`?`); identical FIC is a no-op; same name with a different subject is PATCHed (one credential, `-WhatIf` shows old -> new); same name with a different issuer or audience is refused |
| `Remove-NhiAppSecret.ps1` | `POST .../removePassword` (one `keyId`) | app confirmed by tag and notes; **a matching FIC must already exist**; the `keyId` must be a secret on that app; prints keyId and secret display name only |

Both support `-WhatIf` (which requests only `Application.Read.All`), request the narrowest delegated
write scope (`Application.ReadWrite.All`), run their guards on reads so a dry run shows a refusal,
and disconnect in a `finally`. They are two scripts, not one, so deleting a secret can never happen
in the same run that creates its replacement. The script can check that the FIC *exists* but not
that the GitHub login *works*; that proof is the workflow run, and the order is a human gate.

### Tests

`tests/Federation.Tests.ps1`: seed-02 in each state through the real engine and validator; a FIC with
a different subject (and four other near misses) does not count; an SP-only secret counts as a
secret; undefined states fail; FIC projection drops `id`/`description` and a failed lookup returns
`null`. `tests/Remediation.Tests.ps1`: the scripts run in a child process with the Graph commands
stubbed, asserting reads, writes, scopes and refusals; the workflow is checked as text (SHA pins,
triggers, permissions, nothing sensitive printed). The "FIC must exist" guard was mutation-checked:
disabling it makes two tests fail.

### Live outcome (2026-10-21)

All steps ran against the lab tenant. The FIC was updated to the immutable subject (one PATCH, subject only), and workflow run `oidc-demo #2` printed `idtyp` app, `appidacr` 2 and `appid` match true. `appidacr` 2 means the client authenticated with a federated assertion rather than a secret. Only after that did `Remove-NhiAppSecret.ps1` delete seed-02's one secret (keyId `44ea7c15-...`, on the application object), and a re-read showed 0 secrets.

Re-scan `20261021-021751Z`: seed-02 has no secret and one matching FIC, the validator resolves state `federated`, expected rules are none, actual none, score 0 (before: NHI-002 + NHI-007 = 20). 10 identities have findings (was 11); the validator prints `RESULT: PASS` for 17 seeds and constraints C1-C8. Sanitized records: `examples/seed-02-before.json` and `examples/seed-02-after.json`.

Residual lab risks, recorded in TODO.md: the environment setting "Allow administrators to bypass configured protection rules" is still on, and the scanner has no rule yet for broad or mutable GitHub FIC subjects.

### Verification

FIC create, FIC subject update, `removePassword` and the workflow were verified live on 2026-10-20/21.
