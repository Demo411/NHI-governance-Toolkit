# Controls mapping: NIST SP 800-53 Rev. 5

## Scope note

- This is a **lab tenant, point-in-time** mapping. The evidence comes from scans of one Microsoft Entra ID lab tenant; the latest is inventory `20261021-021751Z`.
- It is **not a compliance attestation**. It says which controls each rule *tests* and which toolkit output *provides evidence for* that test. It does not say a control is met, and it makes no claim about any system outside the lab.
- Scope of controls: the four **base controls** AC-2, AC-6, IA-5 and CM-8 of NIST SP 800-53 Rev. 5. No enhancements, and no other frameworks.
- Clause letters (for example "AC-2(b)") refer to the lettered parts of the base-control statement, not to enhancements.
- The mapping is the author's reading of the control text. The `nist` field of each rule in `scanner/risk-rules.json` is the machine-readable form of the same mapping.

## Summary

| Control | Rules that test it | Clauses tested | Key evidence |
|---------|--------------------|----------------|--------------|
| **AC-2** Account Management | NHI-001, NHI-003, NHI-006 (**deferred, scores 0**), NHI-010, NHI-011 | (b), (g), (j) | `findings-*.json` `identities[].findings[]` for those rule IDs; `inputs.inventorySha256` |
| **AC-6** Least Privilege | NHI-004, NHI-005, NHI-008, COMBO-U1, COMBO-U3 | the single least-privilege statement (**indicators, not proof**) | `findings-*.json` findings and `uplifts[]`; the answer-key validator output |
| **IA-5** Authenticator Management | NHI-002, NHI-003, NHI-007, NHI-009, COMBO-U1, COMBO-U3; Phase 5 federation remediation | (c), (d), (f), (g) | `findings-*.json`; `examples/seed-02-before.json` and `examples/seed-02-after.json`; workflow run `oidc-demo #2` |
| **CM-8** System Component Inventory | none (the inventory itself) | (a)(1), (a)(2), (a)(4), (a)(5); gaps: (a)(3), (b) | `inventory-*.json` `identities[]`, `scanMetadata.counts` |

Evidence files named here are produced by `scanner/Invoke-NhiInventory.ps1` (inventory), `scanner/Invoke-NhiScoring.ps1` (findings) and `scanner/Test-NhiFindings.ps1` (validator). Raw outputs live in `output/`, which is gitignored because they contain tenant data. The repo holds only sanitized records, in `examples/`.

## Sources and method

- **Control text:** NIST SP 800-53 Rev. 5.2.0, read from the OSCAL catalog in NIST's `usnistgov/oscal-content` repository (`nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json`, catalog last modified 2026-05-11). The text of AC-2, AC-6, IA-5 and CM-8 was read from that file on 2026-10-21.
- **Publication page:** https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- The summaries below are paraphrases. Organization-defined parameters in the control text (for example the refresh interval in IA-5(f)) are left to the organization; this toolkit supplies its own lab values, which are not NIST values.
- Severity weights and thresholds (for example the 180-day secret lifetime) are the lab's documented drafts. See `docs/risk-model.md` for why each exists.

---

## AC-2 Account Management

### 1. Control summary

AC-2 asks the organization to manage system accounts through their life: define the account types allowed, assign account managers, set conditions and approvals for membership and creation, create, enable, modify, disable and remove accounts according to policy, **monitor the use of accounts**, notify managers when accounts are no longer needed, authorize access on a valid basis, and **review accounts** against account-management requirements.

### 2. Rules that test it

| Rule | Checks | Clause |
|------|--------|--------|
| NHI-001 No owner / sponsor | An application or service principal has no owner on either object (Microsoft first-party and managed identities are excluded; agents are covered by NHI-011). | (b) assign account managers |
| NHI-003 Expired credential still attached | A secret or certificate whose `endDateTime` is at or before the scan start is still attached. | (j) review accounts. It finds accounts carrying stale credentials that a review should have caught. |
| NHI-006 No sign-in in 90+ days | **Deferred.** Defined in `risk-rules.json` but skipped by the engine, so it adds 0 to every score and produces no evidence. Sign-in activity cannot be seeded, and the treatment of "never signed in" is undecided. | (g) monitor the use of accounts |
| NHI-010 Blueprint has no enabled sponsor | An Entra Agent ID blueprint has no sponsor, or only disabled ones. | (b) |
| NHI-011 Agent identity has no enabled sponsor | An agent identity has no sponsor, or only disabled ones. | (b) |

### 3. Evidence the toolkit produces

- `findings-*.json`, `identities[].findings[]`: one entry per fired rule with `ruleId`, `severity`, `points`, `nist` and rule-specific `evidence` (for NHI-001: `applicationOwners` and `servicePrincipalOwners` counts).
- `inputs.inventoryFile`, `inputs.inventorySha256`, `inputs.rulesFile`, `inputs.rulesSha256`: bind each findings file to the exact inventory and rules it was computed from.
- `skippedRules` records that NHI-006 was not evaluated.
- Latest scan (`20261021-021751Z`): 101 identities scored, 10 with findings; rule counts are in `summary.findingsByRule`.

### 4. How an auditor re-performs it

1. Take the inventory file and `scanner/risk-rules.json` named in `inputs` and check both SHA-256 values.
2. Run `scanner/Invoke-NhiScoring.ps1` on that inventory. The engine never reads the wall clock (it uses the inventory's `scanStartUtc`) and orders its output ordinally, so the same inputs give a byte-identical findings file.
3. Run `scanner/Test-NhiFindings.ps1`. It re-hashes the inventory and rules first and refuses to continue if either differs from what the findings file records.

The inventory contains tenant identifiers and is not in the repo, so a reviewer outside the lab can re-perform steps 2 and 3 only on the synthetic inventories in `tests/` (`tests/Invoke-Tests.ps1`), not on the original lab scan.

### 5. Remediation evidence

None recorded for AC-2. The Phase 5 remediation targets a credential (IA-5).

### 6. Limitations and gaps

- AC-2 is mostly procedural (approvals, notification, termination alignment, policy). The toolkit tests only account **ownership/sponsorship** and **stale credentials** on non-human identities; it does not test approvals, notification, or termination processes.
- Ownership is tested for existence, not quality. An owner who left, or a sponsor *group* with no members, is not detected. Group sponsors count as accountable without checking members.
- NHI-006 is deferred, so **account use is not currently monitored** by any active rule.
- NHI-010/NHI-011 are only as good as the sponsor lookup; a failed lookup records a warning and fires nothing (`null` is "unknown", not "none").
- Human accounts are out of scope.

---

## AC-6 Least Privilege

> **Indicators, not proof.** The AC-6 rules flag permissions, roles and consents that are *commonly high-risk*. They do **not** test whether the access is *necessary* for the identity's assigned tasks, which is what AC-6 actually asks. A finding means "a person should check this is needed", not "least privilege is violated"; no finding does not show that privilege is minimal.

### 1. Control summary

AC-6 asks the organization to apply the principle of least privilege: allow only the accesses that are authorized and necessary for users, or for processes acting on their behalf, to accomplish assigned tasks.

### 2. Rules that test it

| Rule | Checks |
|------|--------|
| NHI-004 High-risk application permission | A **granted** application permission (admin-consented app role) in the rule's tiered list, for example `RoleManagement.ReadWrite.Directory` (Critical tier) or `Directory.ReadWrite.All`. Requested-but-not-consented and delegated-only permissions do not count. |
| NHI-005 Privileged directory role | A service principal holds a role from the rule's privileged-role list (for example Global Administrator, Application Administrator). |
| NHI-008 Tenant-wide delegated consent | An `AllPrincipals` consent to a high-risk delegated permission such as `Mail.Read` or `Files.ReadWrite.All`. |
| COMBO-U1 Armed privilege (+15) | A High-risk permission or privileged role together with an active secret: the privilege is usable. |
| COMBO-U3 Shared credential over a privileged agent (+15) | An active secret on an agent blueprint (NHI-009) while one of its agents holds NHI-004 or NHI-005. This is the one cross-identity uplift. |

### 3. Evidence the toolkit produces

- `findings-*.json` findings with `evidence` naming the permission or role, the resource and the grant; `uplifts[]` for COMBO-U1/U3 and the contributing rule IDs.
- Resource matching uses the resolved `appId` of the resource service principal, never a display name (`risk-rules.json`, `evaluation.resourceResolution`).
- `scoring.tierPoints` and `inputs.rulesSha256` fix the weights used.
- Validator output: the seed rule sets and score constraints C1 to C8 (for example NHI-008 scores below NHI-004, a clean seed scores 0, the risky blueprint outranks its agent).

### 4. How an auditor re-performs it

As for AC-2: check the two hashes, re-run the engine on the inventory, run the validator. To check one finding by hand, open the inventory record named in the finding and compare `servicePrincipal.appRoleAssignments[]`, `oauth2PermissionGrants[]` or `directoryRoles[]` with the rule's list in `risk-rules.json`.

### 5. Remediation evidence

None recorded. Removing a permission or role is a tenant change the toolkit does not make; the seeds that carry these findings are deliberately left risky as ground truth.

### 6. Limitations and gaps

- **Indicators only** (see the note at the top of this section): necessity of the access is never assessed.
- The permission tiers and the privileged-role list are hand-maintained subsets and can go out of date (open items in `TODO.md`).
- NHI-008 is weighted Low because a delegated grant is still bounded by the signed-in user; the weight is a lab decision.
- Only Microsoft Graph application permissions are resolved. Other resource APIs are not scored.
- PIM-eligible role assignments are not tested for self-activation by service principals.
- Group-based and Azure RBAC (subscription-level) access are out of scope.

---

## IA-5 Authenticator Management

### 1. Control summary

IA-5 asks the organization to manage authenticators over their life: verify the identity of the recipient on initial distribution, set initial content, make sure authenticators are **strong enough for their use**, set procedures for distribution and for **revoking** lost, compromised or damaged authenticators, change defaults before first use, **change or refresh authenticators** on an organization-defined schedule or event, **protect authenticator content** from unauthorized disclosure and modification, require protective controls, and change group authenticators when membership changes.

### 2. Rules that test it

| Rule | Checks | Clause |
|------|--------|--------|
| NHI-002 Secret lifetime over 180 days | Any client secret, on the application or the service principal, with a lifetime over 180 days (evaluated whether or not it has expired). | (f) change or refresh. The 180 days is a lab draft; NIST leaves the interval to the organization. |
| NHI-003 Expired credential attached | A secret or certificate past its end date is still attached. | (d) revoking authenticators, and (f) |
| NHI-007 Active client secret in use | A non-expired client secret exists (certificates do not count). A stored shared secret is a disclosure risk by nature. | (g) protect authenticator content |
| NHI-009 Active secret on an agent blueprint | The same test on an agent identity blueprint, where one secret is shared by every agent beneath it. | (g) |
| COMBO-U1, COMBO-U3 | Privilege plus a usable secret (see AC-6). | (g), for the secret half |
| Phase 5 federation remediation | Replaces a stored client secret with a GitHub Actions OIDC federated credential. | (c) sufficient strength of mechanism, and (g) |

### 3. Evidence the toolkit produces

- Findings for NHI-002/003/007/009 carry per-credential evidence: `credentialType`, `onObject` (application or servicePrincipal), `keyId`, `displayName`, `startDateTime`, `endDateTime`, `expiredAtScan`, `lifetimeDays`. **No secret value is ever read or stored**; the inventory records metadata only.
- Inventory field `application.federatedIdentityCredentials[]` (scanner v0.3.0): issuer, subject and audiences of each federated credential. `null` means the lookup failed (unknown); `[]` means confirmed none.
- Hashes in `inputs` bind the findings to the inventory and rules, as under AC-2.

### 4. How an auditor re-performs it

Same procedure as AC-2 (hash check, engine, validator). For a single credential, read its `keyId`, `startDateTime` and `endDateTime` in the inventory and recompute `lifetimeDays` and the expiry comparison against `scanStartUtc` (expired means `endDateTime <= scanStartUtc`).

### 5. Remediation evidence (Phase 5, `seed-02-longsecret`)

| | Before | After |
|--|--------|-------|
| Inventory | `20261019-231744Z` | `20261021-021751Z` |
| Client secrets | 1 (730-day lifetime, on the application) | 0 |
| Federated credential | not collected (scanner older than 0.3.0) | 1: issuer `https://token.actions.githubusercontent.com`, immutable subject `repo:Demo411@181002116/NHI-governance-Toolkit@1415658131:environment:lab`, audience `api://AzureADTokenExchange` |
| Findings and score | NHI-002 + NHI-007, score 20 | none, score 0 |
| Validator state | `with_secret` | `federated`, `RESULT: PASS` (17 seeds, C1 to C8) |

- **Clause (c), strength of mechanism:** a stored shared secret becomes a short-lived federated assertion. The live proof is workflow run `oidc-demo #2`, which printed `idtyp` app, `appidacr` **2** and `appid` match true. In Entra, `appidacr` 1 means the client authenticated with a shared secret and 2 means with a certificate or federated assertion. Before the change the app had only its secret to authenticate with.
- **Clause (g), protection of content:** after removal there is no stored secret to disclose. The secret was deleted by `keyId` only after the federated login worked.
- The "federated" state is accepted only when there is no secret **and** a federated credential matches the answer key exactly (issuer, subject, whole audiences set, case-sensitive).
- Sanitized records: `examples/seed-02-before.json`, `examples/seed-02-after.json`. Run details and the immutable-subject lab finding are in `docs/risk-model.md` section 10.

### 6. Limitations and gaps

- Only **client secrets** are scored. Certificates are checked for expiry (NHI-003) but not for strength, key storage or lifetime.
- The toolkit cannot see secrets' strength or where they are stored; it only sees their presence and age. IA-5 clauses on initial distribution, defaults and lost authenticators are procedural and untested.
- Federated credentials are recorded as facts. No rule yet judges them, so a broad or mutable GitHub subject (wildcard-like, branch-only, name-based without the `@<id>` parts) is **not flagged** (`TODO.md`). Only the seed-02 credential is checked, by the answer key.
- Workflow-side strength (the environment's branch rule, required reviewer, trigger) is configured in GitHub and is not inventoried by the scanner. It is described in the README.
- Human authenticators (passwords, MFA) are out of scope.
- The `appidacr` proof is one workflow run, not continuous monitoring.

---

## CM-8 System Component Inventory

### 1. Control summary

CM-8 asks the organization to develop and document an inventory of system components that accurately reflects the system, includes all components, has no duplicate accounting and no components assigned to other systems, is at the level of granularity needed for tracking and reporting, and carries the information needed for accountability; and to review and update it on an organization-defined schedule.

### 2. Rules that test it

No rule maps to CM-8. The **inventory itself** is the evidence, and its clauses are:

| Clause | How the inventory provides evidence |
|--------|-------------------------------------|
| (a)(1) accurately reflects the system | Read-only enumeration of applications and service principals through Microsoft Graph, with the number of objects found recorded in the scan metadata. |
| (a)(2) includes all components | Counts every application registration, service principal, managed identity, agent identity blueprint and agent identity visible to the scanning account. |
| (a)(4) granularity | One record per identity with its application and service principal objects joined on `appId`, plus `identityType` (`application`, `agentBlueprint`, `agentIdentity`). |
| (a)(5) accountability information | Per record: `ownerType`, `identityType`, `owners`, `sponsors` (blueprints and agents), tags, credentials, permissions, and the **parent link** from each agent identity to its blueprint (`agentIdentityBlueprintId`). |

### 3. Evidence the toolkit produces

- `inventory-*.json`: `identities[]` with the fields above, and `scanMetadata` (scanner version, tenant, account, `scanStartUtc`/`scanEndUtc`, `grantedScopes`, `warnings`, `counts`).
- Latest scan (`20261021-021751Z`): 101 identities; by `identityType`: 95 application, 2 agent blueprint, 4 agent identity; by `ownerType`: 84 Microsoft, 17 ThisTenant.
- The scoring step re-hashes the inventory (`inputs.inventorySha256`), so an inventory cannot be altered after scoring without detection.

### 4. How an auditor re-performs it

Compare `scanMetadata.counts` and the identity list with the tenant's own Entra portal lists for app registrations, enterprise applications and agent identities. The validator's seed check is a completeness test of a kind: every identity tagged `nhi-lab-seed` must be in the answer key and every answer-key entry must be found, otherwise it fails.

### 5. Remediation evidence

None. The inventory is read-only and changes nothing.

### 6. Limitations and gaps

- **(a)(3) not evidenced:** the toolkit does not test for duplicate accounting or for components assigned to another system. Identities are joined by `appId`; nothing checks that a tenant object belongs to this system rather than another.
- **(b) not evidenced:** the control asks for the inventory to be reviewed and updated on a defined schedule. The scanner can be re-run, but nothing in the toolkit schedules, requires or records a review.
- The inventory covers identities only, not other system components (hosts, software, data stores).
- Completeness depends on the scanning account's read scopes (`Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`); anything those scopes cannot read is missing, and failed lookups are recorded as warnings, not as zero.
- A point-in-time snapshot: it reflects the tenant at `scanStartUtc` only.
