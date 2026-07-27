# External evidence producer contract for Action submit

Issue: [#401](https://github.com/Sannrox/sekai-chisei/issues/401).  
Evidence funnel: [../adapters/README.md](../adapters/README.md).  
Action admit: [governed-action-instances.md](governed-action-instances.md).

## Purpose

Domain adapters that receive external events follow a **thin, domain-neutral**
path:

```text
verify → normalize → SubmitEvidence* → (optional) SubmitActionInstance
```

Adapters own webhook/VCS shapes. The plane core never embeds GitHub issue types
or product-specific schemas.

## Contract

1. **Stable source identity** — producer registration + idempotency key per
   external event; increasing sequence when the source provides one.
2. **Untrusted remote text** — titles, bodies, and comments are data. Mark them
   as untrusted in schemas and adapter docs. The plane must not treat them as
   instructions, tool directives, or policy text.
3. **Optional Action submit** — only after evidence admission (or with explicit
   evidence_submission_ids linkage) when adapter-local policy-shaped conditions
   match. No core condition engine is required here.
4. **Least privilege** — producer credentials may submit evidence and Action
   instances only. They must not hold remote mutation credentials; external
   writes use the permit path after host claim.

## Threat notes

| Threat | Mitigation |
| --- | --- |
| Prompt injection via remote body | Parameters/evidence content are untrusted data; never execute as plane instructions |
| Replay storms | Idempotency keys + digests on evidence and Action submit |
| Privilege escalation | Separate producer principal; no external write tokens |
| Silent auto-admit | Action submit is explicit; evidence alone does not dispatch runtimes |

## Reference path (tests / examples)

- Synthetic evidence envelope → optional `SubmitActionInstance` with
  `evidence_submission_ids` (see unit test
  `producer_contract_evidence_then_optional_action_submit`).
- Existing adapters under `adapters/` remain observation funnels; they may call
  Action submit after local policy without becoming runners.

## Explicit non-support

- Treating remote titles/bodies as executable instructions
- Full source-control maintenance automation in core
- Hosted multi-tenant event gateway as a core product surface
