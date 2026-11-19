# Per-principal and per-agent authority (#1563)

Tenant quotas bound a tenant. This gate bounds the identities on an actor
chain so one user or one agent cannot exhaust RPC and MCP capacity, and so an
agent cannot inherit a grant its own ceiling lacks.

## Flag

Rate limits are off by default until callers send actor chains. The agent
grant ceiling does not depend on the flag.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SEKAI_ACTOR_CHAIN_ENFORCEMENT` | unset | Set `1` to enforce rate limits |
| `SEKAI_PRINCIPAL_REQUESTS_PER_MINUTE` | `60` | Token-bucket refill for the delegating user (or the subject when `act` is absent) |
| `SEKAI_AGENT_REQUESTS_PER_MINUTE` | `60` | Token-bucket refill for the agent/`sub` when `act` is present |

## Actor chain

`sub` is the authenticated principal. `act` is the delegating user. When both
are present and distinct, rate limits charge both buckets.

## Agent grant ceiling (#2435)

An agent has a ceiling once it holds a namespace role of its own. Under the
enterprise identity extension, which owns agent grants, every agent has one.

- **Defined ceiling.** Delegated work gets the user's grants intersected with
  the agent's, and no variable turns that off. Work outside the ceiling is
  refused with `agent_ceiling_grant_missing`. The refusal receipt names the
  agent whose ceiling refused it (`agent_ceiling`).
- **No ceiling.** The agent acts with the delegating user's rights. Its
  receipt records `actor_scope: user`. Work bounded by a ceiling records
  `actor_scope: agent_ceiling`.
- **No `act`.** Work without a distinct delegating user is unchanged and
  records no `actor_scope`.

To bound an agent that runs without a ceiling, give it a namespace role, for
example `sekaictl admin access team join --namespace <name> --principal <agent> --role editor`.

## Surfaces

- RPC and HTTP/MCP authenticate through the token interceptor; exhaustion
  returns `RESOURCE_EXHAUSTED` with `retry-after-ms` and a retry hint.
- Claim and apply of Action work re-validate a defined agent ceiling.
  Refusal reason `agent_ceiling_grant_missing` is audited.

## Acceptance mapping

| Criterion | Evidence |
| --- | --- |
| Agent without the grant cannot use the user's grant | Claim/apply unit tests |
| Per-agent throttle | Token-bucket unit tests and interceptor test |
| Re-validation at claim and apply | Extends #1402 on `ActionWorkLifecycle` |
