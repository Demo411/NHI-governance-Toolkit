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
