# Gunshi eval-gated promotion and bounded auto-dispatch

Issue: [#280](https://github.com/Sannrox/sekai-chisei/issues/280)  
Envelope research: [279-gunshi-auto-allocation-envelope.md](research/279-gunshi-auto-allocation-envelope.md)

## Default posture

| Control | Default |
| --- | --- |
| Namespace allocation policy | None until an operator installs a baseline |
| Auto-dispatch | **Off** (advisory only) |
| Namespace opt-in | Required after a promoted revision with `dispatch.enabled=true` |
| Kill switch | Off; when on, forces advisory and clears opt-in |
| Default-on auto | **Forbidden** |

## Operator flow

1. **Install baseline** — advisory revision (`dispatch.enabled=false`) + evaluation gate.
2. Collect advisory outcomes and suite evaluations with attributable evidence.
3. **Promote** a candidate revision when the gate passes (CAS on `expected_revision`).
4. **Opt in** the namespace to live auto-dispatch.
5. Call **AuthorizeGunshiAutoDispatch** (or `sekaictl gunshi authorize-auto`) before dispatching; attach returned receipt attributes.
6. **Kill switch** or **rollback** to return to advisory / prior revision.

Promotion enforces a 60s cooldown per namespace to reduce thrash.

## Receipt attributes (auto path)

When authorization succeeds, receipt attributes include:

- `auto_dispatch=true`
- `gunshi_allocation_id`
- `allocation_policy_revision`
- `dispatch_policy_id` / `dispatch_policy_version`
- `promotion_gate_id` / `gate_version`
- `dispatch_mode=automatic`

Denials set `auto_dispatch=false` and `dispatch_denial_reasons`.

## Hard limits (cannot relax under auto)

- Approval / human review requirements
- Privacy / egress hard limits at promotion
- Operation risk above `Low`
- Tool set must match required tools exactly
- Budget may only decrease within envelopes
- Namespace and operation-class allow-lists are explicit (no `*`)

## CLI

```text
sekaictl gunshi install-baseline --namespace <ns> --snapshot <json> --gate <json>
sekaictl gunshi promote --namespace <ns> --candidate <json> --baseline-eval <json> --candidate-eval <json> --expected-revision <id>
sekaictl gunshi auto-opt-in --namespace <ns> --expected-revision <id>
sekaictl gunshi kill-switch --namespace <ns> --reason <text>
sekaictl gunshi rollback --namespace <ns> --expected-revision <id> --reason <text>
sekaictl gunshi allocation-status --namespace <ns>
sekaictl gunshi authorize-auto --namespace <ns> --plan <json> --operation <json> --capacity <json>
sekaictl gunshi promote-feedback --namespace <ns> --suite-id feedback-<ns>:<class> --issuance-id <id> --allocation-id <id>
```

## Feedback → eval suites (#300)

Authorized operator choices can be promoted into append-only suites whose ids
start with `feedback-`. Case ids are deterministic from
`(issuance_id, allocation_id)` so promotion is idempotent. Operator rationale is
redacted in the stored case spec; promotion is audited.

## Persistence

SQLite table `chisei_gunshi_allocation_state` stores the durable control blob with
revision CAS. PostgreSQL community runtime returns unavailable for these methods
until parity is added. Mutations also emit audit decisions under
`gunshi.allocation_policy.*`.
