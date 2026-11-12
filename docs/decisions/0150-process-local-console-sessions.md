# ADR 0150: Keep operator console sessions process-local across failover

- Status: accepted (effective on merge)
- Date: 2026-11-12
- Owners: @Sannrox
- Discussion: none
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2088
- Supersedes: none
- Superseded by: none
- Related: [ADR 0082](0082-separate-chisei-and-sekai-durable-stores.md),
  [ADR 0099](0099-shared-identity-and-tenancy.md)

## Context

The operator console mints an opaque HttpOnly cookie (`sekai_console_sid`)
that maps to an in-process `SessionStore`. Durable trust already lives in
`sekai_principal_credentials` and is re-checked on every console request.
`docs/operator-console.md` already told operators to pin console traffic to
one instance or re-login after failover, but no decision recorded whether
that was a permanent limit or a gap.

Milestone 3.1.0 named the operator outcome as "sessions that survive
failover". Issue #2088 prefers process-local sessions that do not survive
and instead fail closed. Combined replicas share the runtime databases;
they do not share process memory. A load balancer that is not pinned, a
rolling restart, or a replica crash will present instance A's cookie to
instance B.

The console is a few-user admin shell. `sekaictl` remains the canonical
automation interface and already sends the Bearer token on every call.

## Decision

1. **Keep console sessions process-local.** Do not store session rows in
   Sekai or Chisei. Do not sign the cookie. Inventory the surface as
   `ops.console.sessions` / `process_local_ok`. Callers must not pass it to
   `ReplicaSafetyInventory::require_authoritative`.
2. **Fail closed on a SID this process does not hold.** HTML data routes
   return 303 to `/console/login`. `GET /console/login` returns 200 with the
   sign-in form (never 303 to itself). JSON returns 401. A presented and
   rejected cookie is cleared (`Max-Age=0`, same attributes as logout).
   Never render signed-in chrome, `authenticated: true`, a principal field,
   or 5xx for a missing map entry. Unknown, expired, revoked, and foreign
   SIDs are one unauthenticated class.
3. **Recovery is Bearer re-login** on the surviving replica with the same
   still-active principal token. That mints a new SID in that process. Do
   not copy sessions. Sticky pin remains optional UX, not a trust
   requirement.
4. **3.1.0 means clean re-auth, not cookie survival.** Credentials and
   grants already survive on the shared store. The GitHub milestone
   description is updated in the same change so closeout cannot claim
   cookie survival.

If this decision is reversed later, session rows belong on the Sekai store
(identity), never Chisei, and need a new ADR, migration, expiry, and
fencing.

## Alternatives considered

- **Shared session table in the runtime database.** Cookie would survive
  failover without a pin, matching a literal reading of the milestone.
  Adds a schema, SQLite and PostgreSQL migration, purge, and fencing for
  an operator-only cookie map. Rejected: YAGNI; few users; `sekaictl`
  already survives failover.
- **Stateless signed cookies.** Survive process death without a table, but
  need a shared signing secret, rotation that does not fail open, and a
  revocation list (a session store by another name) or coarse credential
  revoke for logout. Rejected.
- **Document pin-only, leave the code unchanged.** Unknown SIDs already
  303/401, but the cookie is not cleared and no test locks A→B. Rejected
  as the sole outcome; pinning remains optional UX on top of this
  decision.
- **Console leader lease.** One `SessionStore` by construction, at the
  cost of a singleton and split-brain risk for a convenience UI. Rejected.

## Consequences

- Operators re-login after unpinned failover and after restart of the
  minting process. Authorization does not widen.
- No migration, no new env vars, no proto/gateway/CLI change.
- Rolling deploys mix two `SessionStore` maps; a request that crosses
  processes is the A→B case and must fail closed.
- Reversal requires a new ADR and Sekai-store ownership.

## Validation

- `session_from_instance_a_is_unauthenticated_on_instance_b` in
  `src/obs/console.rs` (includes `GET /console/login` on B, cookie clear,
  recovery SID honor, and A's SID still 401 on B).
- `cargo test --locked obs::console`
- `cargo test --locked --test it inventory_fixture_is_valid_and_evidence_exists`
- `cargo test --locked -p sekai-core replica_safety::tests::inventory_evidence_paths_exist`
- `sh scripts/adr-index.sh --check`
