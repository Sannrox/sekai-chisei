# Hosted session

Issue: [#2132](https://github.com/Sannrox/sekai-chisei/issues/2132).  
Contract: `sekai.hosted-session/v1`.

A Chisei host admits a bounded set of identities into one durable session,
applies their intents at the host clock, and persists each member's graph.
Domain rules stay in the workload library. The host records the intent; it
does not reimplement game maths.

## Objects

| Kind | Written by | Identity |
| --- | --- | --- |
| `hosted_session` | `hosted_session.create` | caller-chosen `object_id` |
| `hosted_session_member` | `hosted_session.join`, `hosted_session.intent` | `hs:{session_id}:{member_id}` |

`session_id`, `member_id`, and the session's `object_id` must not contain
whitespace or `:`. Direct `CreateObject` / `UpdateObject` of either kind is
refused.

## Actions

Submit through `SubmitActionInstance`. Idempotency is the existing
`(namespace, idempotency_key)` rule.

| Type | Mutation | Host rule |
| --- | --- | --- |
| `hosted_session.create` | create session | `cap` is an integer ≥ 1 |
| `hosted_session.join` | create member | refused at cap; the submitter must be `member_id` |
| `hosted_session.intent` | update member | `client_clock_ms` is ignored; `applied_at_ms` is the host clock; the submitter must be `member_id` |

`hosted_session.intent` also carries the closed criterion `member_owns_graph`
(`subject_equals_property` on `member_id`).

## Read view

`read_view` returns session seed, cap, the member list, and the caller's
graph. Another member's graph is omitted. The `graph` property is
`sensitive`; GetObject redacts it for principals without restricted-property
read.

## Restart

Session and member objects are store rows. Reopening the same database
resumes the same session. There is no separate session process.

## Non-goals

A listen-server on a player's machine, peer lockstep, a dedicated
game-server binary, Tenkai tenant coupling, and teaching the core contract
domain types from a workload.
