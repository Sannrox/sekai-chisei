# Budget topology (multi-region)

Issue: [#294](https://github.com/Sannrox/sekai-chisei/issues/294)  
Design freeze: [research/292-multi-region-consistency.md](research/292-multi-region-consistency.md)  
Single-region multi-replica baseline: [replica-safety.md](replica-safety.md)

## Modes

| Mode | Config value | Budgets | When to use |
| --- | --- | --- | --- |
| **Single region** (default) | `single_region` | Shared store as today; home pins ignored | Community SQLite, single AZ/region PostgreSQL |
| **Regional pinned** | `regional_pinned` | Per-scope `home_site_id`; foreign site fail closed; no transfer | Multi-region without a shared spend pool |
| **Regional with transfer** | `regional_with_transfer` | Regional homes + audited transfer of **limit capacity** for pooled ceilings | Multi-region org with rare reallocation |

`active_active_global_sc` is **not** supported and is rejected at config parse time.

## Authority

- **Single writer per budget scope** (home pin or single-region store).
- Gateway `CheckBudget`, fat-decide budget admission, and execution reserve share the same `BudgetTracker` / shared-store APIs. There is no process-local or region-shadow ledger for durable spend.
- Auto-allocation / Gunshi budget hard limits that consult control-plane budgets must use that same tracker path when wired to the plane.
- Transfer is a **rare admin path**: move of limit/capacity between homes, not two-phase commit on every request.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SEKAI_BUDGET_TOPOLOGY` or `BUDGET_TOPOLOGY_MODE` | `single_region` | Topology mode |
| `SEKAI_BUDGET_SITE_ID` or `BUDGET_SITE_ID` | empty | Local site identity for home-pin checks (required for regional modes) |
| `SEKAI_BUDGET_PARTITION_SIMULATED` | unset | Set `1`/`true` to refuse transfers (fail closed under simulated partition) |

See also [configuration.md](configuration.md).

## Data model

- `chisei_budget_limits.home_site_id` — writer pin for the scope limit.
- `chisei_budget_limits.pool_id` — membership in a pooled combined ceiling.
- `chisei_budget_pools` — combined ceiling per `(pool_id, metric)`.
- `chisei_budget_transfers` — idempotent `transfer_id` rows (`completed` or `refused`).

Pool invariant: sum of member `max_amount` values must not exceed the pool ceiling. Transfers only reallocate capacity among members; they do not raise the combined ceiling.

## Fail-closed rules

| Situation | Behavior |
| --- | --- |
| Foreign `home_site_id` under regional modes | Reserve / positive debit **denied** |
| Transfer under `regional_pinned` or `single_region` | Denied |
| Transfer while `SEKAI_BUDGET_PARTITION_SIMULATED=1` | Refused row + audit decision; no capacity move |
| Member limits sum &gt; pool ceiling | `set_limit` / transfer **denied** |
| Unknown topology / global SC mode | Config parse **error** (server falls back to single_region with a warning if loaded via env) |

Under partition, regional scopes spend only their **local allocation**. Because capacity is pre-split (and only moved by audited transfer), the sum of local spends cannot exceed the combined pool ceiling even when regions cannot coordinate.

## Operator runbook

### Stay on single-region (default)

No topology env vars required. Multi-replica within one region still needs a shared store ([replica-safety.md](replica-safety.md)).

### Enable regional pins without pooling

```bash
export SEKAI_BUDGET_TOPOLOGY=regional_pinned
export SEKAI_BUDGET_SITE_ID=us-east-1
```

Set scope limits with the home site for that region (API: `BudgetTracker::set_limit_scoped`). Foreign sites cannot debit those scopes.

### Enable pooled ceilings with transfer

```bash
export SEKAI_BUDGET_TOPOLOGY=regional_with_transfer
export SEKAI_BUDGET_SITE_ID=us-east-1
```

1. Create a pool ceiling (`set_pool_ceiling("org", "tokens", combined, period)`).
2. Create regional scope limits with the same `pool_id` and distinct `home_site_id`s. Initial member limits must sum to ≤ pool ceiling.
3. Reallocate with `transfer_capacity(transfer_id, from, to, amount, metric, actor)` — idempotent on `transfer_id`.
4. Confirm audit: decision action `budget.transfer`, target = from scope, evidence includes transfer_id / amount / status.

### Simulated partition drills

```bash
export SEKAI_BUDGET_PARTITION_SIMULATED=1
```

Transfers refuse fail-closed. Local homes continue to enforce only their allocated limits. Clear the flag (or restart without it) to re-enable transfers after connectivity is restored.

### Pressure views

Regional vs global (pool) pressure is meaningful only when topology exposes both: local scope usage/limits under regional modes, plus pool membership when `pool_id` is set. Single-region deployments keep today's chain pressure only.

## Non-goals

- Global strongly consistent active/active budget partition for every preflight.
- Exactly-once external side effects.
- Cross-plane budget mutation without attestation / federation policy (#291).
- Lease/permit multi-region pins (#293) — independent `site_id` string on budget scopes for this feature.
