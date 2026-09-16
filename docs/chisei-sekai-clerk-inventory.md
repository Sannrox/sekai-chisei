# Chisei → Sekai clerk inventory

Chisei may not open a database. Every `RuntimeDb` / `SekaiDb` use in
`src/chisei` maps to a `SekaiService` clerk call or stays in-process only in
combined compatibility mode.

## First slice (shipped with ADR 0082)

| Chisei need | Clerk RPC | Notes |
| --- | --- | --- |
| Action types / tools | `DiscoverCapabilities`, `GetGovernedActionType` | Route menu |
| Object context | `GetObject`, `ListObjects`, `EvaluateObjectSet` | Live facts |
| Persist after admit | `PersistAdmittedAction` | Instance + effect + audit + receipt, one transaction |
| Read receipt | `GetPersistedOperationReceipt` | Chisei `GetOperationReceipt` proxies this |
| Client-facing invoke | `ChiseiService.InvokeActionInstance` | Decides, then persist |

## Remaining `RuntimeDb` surfaces (follow-up)

These still use `crate::db` in combined mode. Each becomes a clerk RPC before
the Chisei repo can drop `RuntimeDb`.

| Module | Typical use | Intended clerk |
| --- | --- | --- |
| `budget.rs` | counters, transfers | budget consume / read |
| `eval.rs`, `evaluation_*` | suites, runs | eval objects |
| `kioku.rs` | memory candidates | evidence + memory objects |
| `pipeline.rs`, `lookup_first.rs` | graph walk, schema | object / ontology reads |
| `action_describe_preview.rs` | object + type | `GetObject` + `GetGovernedActionType` |
| `action_instance_admission.rs` | admit + persist | decision local; persist RPC |
| `action_work_lifecycle.rs` | parked work | action work RPCs (already on Sekai) |
| `workflow_action.rs` | bridge | invoke + persist |
| `execution_evidence.rs` | evidence | `SubmitEvidence` |
| `external_permit.rs`, `external_action*` | permits | permit objects |
| `capability.rs`, `promotion.rs`, `gate.rs` | learning objects | object writes |
| `gunshi*.rs` | allocation | capacity objects |
| `tenant_quota.rs` | quota | budget clerk |
| `scoring.rs`, `sampling.rs` | eval reads | eval clerk |
| `affinity.rs`, `controller.rs` | graph | object reads |
| `data_quality.rs`, `learning_change.rs` | decisions | `RecordDecision` |

Auth: credentials stay in Sekai. Chisei forwards `authorization`.
