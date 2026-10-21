# TODO

## Phase 3 backlog
- [x] Unit-test the NHI-002 lifetime boundary at 179 / 180 / 181 days using synthetic inventory
      data (no tenant needed). The rule is "> 180 days", so 180 must NOT fire. Live seeds can't
      test this reliably: client-side endDateTime vs server-side startDateTime can land either
      side of exactly 180. (tests/Scoring.Tests.ps1; also 180d 23:59 and an expired 400d secret)
- [x] Credential rules (NHI-002/003/007) must read both `application.*` and `servicePrincipal.*`
      credentials (seed-11 is the regression test). (tests/Scoring.Tests.ps1: SP-only secret,
      identity with no application object, expired certificate)
- [x] seed-03 fixtures: synthetic inventories for BOTH states (scanStartUtc before the secret's
      endDateTime -> NHI-007 only; after -> NHI-003 only) plus the exact boundary
      (endDateTime == scanStartUtc counts as expired). Validator reads the
      `time_dependent` block in seed/expected-findings.json. (tests/Validator.Tests.ps1)
- [x] Resource-resolution fixtures: an appRoleAssignment / oauth2PermissionGrant whose
      resourceId is (a) the Graph SP, (b) another API's SP with the same permission name,
      (c) a display-named "Microsoft Graph" SP with a different appId, (d) missing from the
      inventory (must emit an `unresolvedResource` warning, not match). Rules match on the
      resolved appId, never on resourceDisplayName.

## Phase 4 backlog
- [x] Live run 20261019-231744Z: scanner v0.2.0, engine v0.2.0, validator PASS (17 seeds, C1-C8).
- [x] Agent ID cleanup script: seed/Remove-AgentIdSeed.ps1 (tag + parent-link markers, soft delete by
      default, -Purge opt-in, read-only scopes under -WhatIf). Dry run found exactly the 8 seeds.
      Not yet run for real: Phase 5 and the write-up still need the seeds. The -Purge path (and its
      retry loop) is untested until the first real cleanup; check it then.
- [x] Checked whether agents' `tags` include the blueprint's `nhi-lab-seed` (documented as a union).
      Live inventory 20261019-231744Z: they do NOT (agents show `[]`). The validator now inherits the
      seed marker through the parent link instead (tests/Validator.Tests.ps1).
- [ ] Track Microsoft's agent permission block list. Lab: Directory.ReadWrite.All refused,
      Mail.ReadWrite allowed (2026-10-16); the documented list names four permissions. Re-test
      Files.ReadWrite.All / Sites.ReadWrite.All and record results in risk-model.md section 9.
- [ ] Sponsor groups count as accountable without checking members. Revisit if group sponsors
      appear (dynamic or Microsoft 365 groups only, per Microsoft).

## Phase 5 backlog (GitHub Actions OIDC for seed-02)
- [x] A: scanner v0.3.0 collects FICs; state-dependent answer key; workflow; remediation scripts; tests.
- [x] B: create GitHub environment `lab` (required reviewer) and secrets AZURE_CLIENT_ID / AZURE_TENANT_ID.
- [x] C: add the FIC to seed-02 (tenant change, -WhatIf first).
- [x] D: run and approve the workflow; check appidacr = 2.
- [x] E: delete seed-02's secret by keyId, only after D (tenant change, -WhatIf first).
- [x] F: rescan, score, validate; save sanitized before/after under examples/; update README results.
- [ ] (future work, kept) New rule idea: "broad / mutable GitHub FIC subject" (wildcard-like or branch-only subjects such as
      `repo:org/repo:ref:refs/heads/main`, `pull_request` subjects, a missing environment, or an
      issuer that is not a known OIDC provider). Needs FIC data from several apps first; today the
      scanner only records the facts.
- [ ] New rule idea: "GitHub FIC without immutable IDs" (subject recycling). A federated credential
      whose issuer is `https://token.actions.githubusercontent.com` and whose subject lacks the
      `owner@<id>/repo@<id>` parts is name-based: if the repo or org is deleted, renamed or
      re-created, another owner of that name can mint a token the credential accepts. Found live in
      Phase 5 (risk-model.md section 10). Detectable from the facts the scanner already records.
- [ ] Untick "Allow administrators to bypass configured protection rules" on GitHub environment `lab` (Settings > Environments > lab) so the required reviewer cannot be bypassed even by an admin. GitHub setting: ask before changing.
- [ ] Consider moving azure/login from v2.3.1 to v3.x as a separate, reviewed change (pinned by SHA).
- [ ] Check whether the FIC listing works on Agent ID blueprints (the scanner warns if not).

## Considered and deferred
- Per-user (Principal) grants of Critical-class delegated scopes are not covered. Considered and
  deferred: an admin consenting for themselves on Microsoft admin tooling is routine and bounded
  by their own rights; revisit if third-party apps appear with such grants.

## Research backlog
- [ ] NHI-005: check whether service principals can self-activate Eligible (PIM) directory
      roles via the API. If they can, revisit counting Eligible assignments (currently Active
      only; the inventory already records both).
- [ ] NHI-004 High tier: research the list (currently the NHI-008 list minus the Critical
      entries; unresearched, project convention). Candidates: Files.Read.All,
      Sites.ReadWrite.All, User.ReadWrite.All, Group.ReadWrite.All,
      Policy.ReadWrite.ConditionalAccess. Decide each against external evidence.
- [ ] Consider splitting NHI-008 by scope tier, like NHI-004 (for example Critical-class
      delegated scopes such as RoleManagement.ReadWrite.Directory and
      Application.ReadWrite.All vs the mail/files scopes). Today every NHI-008 finding is Low (3).
- [ ] Optionally re-test the SpecterOps Directory.ReadWrite.All findings in the lab tenant
      (needs an approved tenant change); the High placement rests on a 2024 third-party test.
- [ ] NHI-005 role list is a hand-maintained subset of Microsoft's privileged roles. Decide
      whether to add `isPrivileged` to the inventory (scanner change) to replace it.
