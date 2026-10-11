# TODO

## Phase 3 backlog
- [ ] Unit-test the NHI-002 lifetime boundary at 179 / 180 / 181 days using synthetic inventory
      data (no tenant needed). The rule is "> 180 days", so 180 must NOT fire. Live seeds can't
      test this reliably: client-side endDateTime vs server-side startDateTime can land either
      side of exactly 180.
- [ ] Credential rules (NHI-002/003/007) must read both `application.*` and
      `servicePrincipal.*` credentials (seed-11 is the regression test).
