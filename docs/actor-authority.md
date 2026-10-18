# Per-principal and per-agent authority (#1563)

Tenant quotas bound a tenant. This gate bounds the identities on an actor
chain so one user or one agent cannot exhaust RPC and MCP capacity, and so an
agent cannot inherit a grant its own ceiling lacks.

## Flag

Off by default until callers send actor chains.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SEKAI_ACTOR_CHAIN_ENFORCEMENT` | unset | Set `1` to enforce rate limits and the agent grant ceiling |
| `SEKAI_PRINCIPAL_REQUESTS_PER_MINUTE` | `60` | Token-bucket refill for the delegating user (or the subject when `act` is absent) |
| `SEKAI_AGENT_REQUESTS_PER_MINUTE` | `60` | Token-bucket refill for the agent/`sub` when `act` is present |

## Actor chain

`sub` is the authenticated principal. `act` is the delegating user. When both
are present and distinct, rate limits charge both buckets and effective
permission is the user's grants intersected with the agent's grant ceiling.

## Surfaces

- RPC and HTTP/MCP authenticate through the token interceptor; exhaustion
  returns `RESOURCE_EXHAUSTED` with `retry-after-ms` and a retry hint.
- Claim and apply of Action work re-validate the agent ceiling when the flag
  is on. Refusal reason `agent_ceiling_grant_missing` is audited.

## Acceptance mapping

| Criterion | Evidence |
| --- | --- |
| Agent without the grant cannot use the user's grant | Claim/apply unit tests |
| Per-agent throttle | Token-bucket unit tests and interceptor test |
| Re-validation at claim and apply | Extends #1402 on `ActionWorkLifecycle` |
