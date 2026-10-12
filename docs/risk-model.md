# Risk model (DRAFT)

Why each rule and weight exists. The machine-readable version is `scanner/risk-rules.json`;
this document is the justification. Weights are the project owner's decisions; where a number is still
open it says so.

## 1. Scoring model

**Additive tiers plus one named combination uplift.**

| Tier | Points | Used by |
|------|--------|---------|
| Critical | 40 | NHI-005; NHI-004 (privilege-granting permissions) |
| High | 25 | NHI-004 (all other high-risk permissions) |
| Medium | 10 | NHI-001, NHI-002, NHI-007 (NHI-006 deferred) |
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

### Considered and rejected

**COMBO-U2 "Unattended privilege": (NHI-004 or NHI-005) and NHI-001, +10.** Rejected. An
ownerless identity is a governance gap, not an exploitability gap: lacking an owner does not
make the identity easier to abuse. NHI-001 already scores in its own right. Side effect that
also argued against it: it would have pushed seed-05 (45) above seed-06 (40).

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

My earlier draft scoped every rule except NHI-001 to `ThisTenant` + `Microsoft`, which silently
excluded `ThirdParty` and `ManagedIdentity`. That was a mistake, now fixed. The managed-identity
exclusion for NHI-001 rests on my reading of how managed identities work, not on a cited source.

### Identifying seeds

Seeds are identified by the `nhi-lab-seed` tag in `application.tags` or
`servicePrincipal.tags`, never by display name (all 11 seeds carry it on both). The inventory
does not capture `notes`, so the tag is the only usable marker. The answer key is still keyed by
display name, but only as a lookup label for which expectations apply to a tag-verified seed;
the validator must fail if a tagged identity has no key or a key has no tagged identity. A
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
  6 references resolve. A `resourceId` missing from the inventory cannot match and must be
  reported as an `unresolvedResource` warning.
- **NHI-005 matching** is by built-in role template ID (`roleDefinitionId`); display names are
  labels only. See section 3a.
- **NHI-005 counts Active assignments only.** An Active assignment is usable right now. An
  Eligible (PIM) assignment is only a right to ask for the role, and activation is a separate
  step. Whether a service principal can perform that activation itself through the API is not
  established, so counting Eligible would assert an exposure we have not shown. The inventory
  records Eligible assignments anyway, so this can be revisited without a rescan (TODO.md).

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
  and groups ... Does not allow user or group deletion." It is not labelled privileged on the
  page I read.
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
- I did not test it in the lab tenant (that would need a tenant change).
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

| Constraint | Result |
|------------|--------|
| seed-09 is the maximum | Pass: 85, next is seed-06 at 40 |
| seed-08 < seed-04 | Pass: 3 < 25 |
| seed-10 == 0 and seed-07 == 0 | Pass |
| seed-08 > 0 | Pass: 3 |
| seed-11 == weight(NHI-007) and > 0 | Pass: 10 == 10; no uplift because it has no NHI-004/005 |

Both seed-03 states pass every constraint (it appears in none of them).

## 5. seed-03 and time

seed-03's secret expires one day after seeding. The three existing inventories were all taken
before that, so they correctly show **NHI-007 (10)**, not NHI-003. The answer key now carries a
`time_dependent` block for seed-03: the validator compares the credential's `endDateTime` (read
from the inventory) with that inventory's `scanStartUtc`. Expired (`end <= scanStart`) expects
NHI-003 (3); otherwise NHI-007 (10). Because the clock is the scan's own timestamp, an old
inventory validates the same way forever. Synthetic fixtures cover both states and the exact
boundary (TODO.md).

## 6. Open decisions

Decided:
- `scoreCap`: none. Scores rank identities; a cap would flatten the top. Max possible is 131, so
  scores are not a 0-100 scale.
- NHI-005: static list keyed by template ID (section 3a); Active assignments only.
- NHI-004 High list: accepted as-is, flagged unresearched.
- Resource matching by resolved appId, not display name.

Still open:
- NHI-005: Eligible assignments (depends on the self-activation research).
- NHI-004 High list research.
- NHI-006 null sign-in handling (deferred).

## 7. Reference verification log

Checked on 2026-10-11. Only pages I actually opened are cited as verified.

| Source | URL | What it supports | Caveat |
|--------|-----|------------------|--------|
| Privileged roles and permissions in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions | PRIVILEGED label exists; Application Administrator shown with `IsPrivileged: True` | Label is in preview. It does not list the roles; it defers to the page below. |
| Microsoft Entra built-in roles | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference | Template IDs and "This is a privileged role" for the five NHI-005 roles | Page is ~403k characters; I read all but the last ~3k, through summaries of each 100k block, not line by line. |
| Microsoft Graph permissions reference | https://learn.microsoft.com/en-us/graph/permissions-reference | Caution text for Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All | Page is huge; I read the first part only. Directory.ReadWrite.All and RoleManagement.ReadWrite.Directory descriptions came from a third-party mirror (graphpermissions.merill.net), not the official page. |
| Add and manage app credentials | https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials | Secrets not for production; under 12 months recommended; 24-month cap; federation for workloads | |
| Enforce secret and certificate standards | https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tutorial-enforce-secret-standards | 180 days is the recommended certificate maximum; recommends disabling client secrets | Not a secret-lifetime recommendation. |
| Migrate applications away from secrets | https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/migrate-applications-from-secrets | Exposed secret can escalate depending on app permissions; managed identity / federation | |
| BloodHound AZMGGrantAppRoles | https://bloodhound.specterops.io/resources/edges/az-mg-grant-app-roles | Escalation chain to Global Administrator | Third party |
| SpecterOps, Directory.ReadWrite.All | https://specterops.io/blog/2024/02/12/directory-readwrite-all-is-not-as-powerful-as-you-might-think/ | What Directory.ReadWrite.All can and cannot do | Third party; 2024 test |
| NIST SP 800-53 Rev. 5 | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final | Publication exists | AC-2/AC-6/IA-5 text not re-read |

**Correction to my earlier message:** I said the portal's add-secret dialog recommends 180 days
for client secrets. I could not verify that as Microsoft guidance, so it is not cited. The
verified secret guidance is "under 12 months", and 180 days is the certificate figure.
I also said the tiers "follow CVSS-style bands"; that was loose, so the doc now calls them a
project convention.
