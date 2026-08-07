## Summary

<!-- What behavior or problem does this change address? -->

<!-- Use "Closes #123" when a primary Issue exists. -->

## Approach

<!-- Explain the implementation and important tradeoffs. -->

## Validation

- [ ] `cargo fmt --check`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Additional focused or smoke tests are listed below

<!-- List additional commands and results. -->

## Evidence

<!-- Record the highest state supported by the verification evidence. For an
uncommitted candidate, identify HEAD plus the intentional working-tree diff;
do not claim immutable hosted or merge proof. -->

- Evidence state: `hypothesis` / `reproduced` / `validated`
- Review disposition: `not-required` / `review-required` / `review-complete`
- Delivery status: `unmerged` / `merged` / `rejected/duplicate`
- Baseline and candidate identity:
- Before/after behavior or documentation proof:
- Canonical owner, root cause, and affected siblings (when applicable):
- Skipped checks and residual risk:
- Hosted or merge evidence tied to the exact revision (when applicable):
- Remaining uncertainty:

## AI assistance

<!-- State none, assisted, or primarily generated; name the tool if useful. -->

- Assistance:
- Author understanding confirmed: yes/no
- Testing level: untested/lightly tested/fully tested

## Impact

<!-- Describe API, migration, configuration, compatibility, security, or
operator impact. Write "None" where applicable. -->

- API/compatibility:
- Persistence/migrations:
- Configuration/operations:
- Security/privacy:

## Context

<!-- Link the issue, design discussion, or other context when available. -->

## Review readiness

- [ ] The PR implements one focused outcome.
- [ ] New behavior and regressions have focused tests where practical.
- [ ] Documentation, examples, configuration, and migrations are updated where required.
- [ ] No secrets, credentials, local databases, or sensitive logs are included.
