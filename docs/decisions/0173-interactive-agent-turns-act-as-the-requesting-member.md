# ADR 0173: Interactive agent turns act as the requesting member

- Status: accepted
- Date: 2026-11-26
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3046 (#3046)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0136](0136-site-agent-instances.md),
  [ADR 0137](0137-agent-turns-share-the-scheduling-split.md),
  [ADR 0142](0142-agent-turn-worker-authority.md),
  [ADR 0143](0143-runtime-token-act-is-the-requester.md),
  [ADR 0146](0146-turn-worker-is-not-the-instance.md)

## Context

A turn acts as its instance's principal, and a manual wake keeps that
principal while recording the requester as `act` (ADR 0143). A member who
runs an agent from a conversation has no instance and owns no site
responsibility. Acting as an instance principal would let the member reach
what the org principal can reach. Handing the worker the member's own
credential would outlive the run, which ADR 0142 rejects.

Older planes map every `sekai_agent_turn` row strictly. An unknown cause
fails the mapping inside claim and listing, so one instance-less row would
fail `ClaimAgentTurn` and listing for the whole namespace. An older plane
would also retire such a row as "site agent instance is gone".

## Decision

1. **A turn cause `interactive`.** Only the member admits it, for
   themself. Admission takes no on-behalf field and refuses an `agent:`
   principal, a registered service principal, a machine credential, a
   runtime token and a delegated `act`. The member needs write access to
   the namespace. The turn names a published, certified agent definition
   revision in the namespace and an agent member of it, checked at
   admission as ADR 0136 checks instances. It has no instance, no
   responsibility, no wake policy and no working memory.
2. **The turn's principal is the member.** Its runtime token has the member
   as subject, the claiming worker as `worker`, and no `act`. It admits the
   same calls as other turn tokens (ADR 0142, 0146) and checks the live
   claim on every use. A worker whose subject is the member is refused at
   claim time, as ADR 0146 refuses a worker that is the instance principal.
3. **Live authority.** Every call reads the member's grants, markings,
   clearance and namespace membership at the time of the call, so the turn
   never holds more than the member holds now. Revoking the member's access
   refuses the turn's next call, and the turn fails with that reason.
4. **Bounded by the revision.** The turn may submit only the Action types
   in the agent member's `allowed_action_types` at the turn's revision, and
   call only its bound tools, with each tool binding's `approval_policy`
   applied. Effective authority is the member's live grants intersected
   with the revision's declared scope. An agent built for one job does not
   receive the member's whole authority.
5. **Agent rules, not autonomy grants.** A call on an interactive turn
   token is an agent action: agent write freezes and the namespace write
   freeze apply. Turn tokens authenticate with a machine credential kind,
   so `block_agent_actions` freezes already classify them as agent. Action
   policy decides as for the member. Agent autonomy grants do not apply,
   because there is no agent principal, and propose-only would force a
   second approver for an Action the member may submit directly.
6. **Receipts.** The turn row and the receipts of its Actions name the
   member, the definition revision digest, the agent member and a
   caller-supplied trace id.
7. **Stored format.** Interactive turns live in their own table,
   `sekai_interactive_agent_turn`, on SQLite and PostgreSQL (migration
   0191), which no older plane reads. It has the claim and park columns of
   `sekai_agent_turn`, no `instance_id`, and adds `member_id` (equal to
   `admitted_by`), `definition_revision_digest`, `agent_member`, `trace_id`
   and `request_id`. Turn ids take the prefix `iturn-`, a hash of
   namespace, member, revision, agent member and request id, so a lookup
   routes by id and never probes both tables. `member_id` and `admitted_by`
   are retained identities under the same basis as a turn's requester.
8. **Wire (experimental, additive).** `AdmitInteractiveAgentTurn` admits a
   turn, idempotent per request id. `AgentTurn` gains
   `definition_revision_digest`, `agent_member` and `trace_id`; an
   interactive turn has cause `interactive`, an empty `instance_id`, and the
   member as `principal_id`. Workers opt in with `accepts_interactive`
   (default false) on the claim and listing calls, so an older worker
   binary never receives an instance-less turn.
9. **Delivery in slices, each failing closed.** The first slice adds this
   record, the storage and the admission call; admitted turns stay pending
   because no claim path reads the table. The next slice adds the opt-in
   claim and listing, the member-subject token, the Action type bound,
   receipt attributes (`ActionInstance.agent_turn`) and the freeze test.
   The third slice adds parking and tool-binding approval. Turn-token
   reads (transcript and working memory) follow. Until a slice lands, its
   calls are refused on interactive turns.

## Clarifications

- 2026-11-27 (#3046): An interactive turn parks as an instance turn does
  (ADR 0142): on an Action it submitted under its claim, at most
  `MAX_PARKS` times, and it is claimable again with that Action as its
  continuation once the decision stands, only by a worker that sets
  `accepts_continuation`. A parked turn whose member lost access fails on
  its first call after it resumes. For decision 4, a bound tool of kind `action` whose name is the
  submitted Action type and that names an `approval_policy` parks the
  submission for approval under the rule
  `agent_tool:{agent member}:{policy}`, after autonomy, as an Action
  binding's approval does. The policy name labels the rule; the Action
  type's approvers decide it, and the submitting member cannot. Query and
  gateway tools keep their policies at the gateway.

## Alternatives considered

- **Run on an instance with the member as subject.** Rejected: the
  instance's principal, responsibility and freeze would describe a run they
  do not govern.
- **Act as the member with no bound beyond the member's grants.** Rejected:
  an agent built for one job would hold the member's whole authority. The
  revision's declared scope is the bound instead (decision 4).
- **Act as the intersection of an instance principal and the member, as
  working-memory reads do.** Rejected: it needs an instance per
  conversational agent, and the org principal would still bound what a
  member's own agent may do.
- **Give the worker a member credential.** Rejected by ADR 0142: it
  outlives the claim.
- **Store interactive turns in `sekai_agent_turn` with `instance_id`
  unset.** Rejected: older planes would fail claim and listing for the
  namespace and retire the rows during a rolling deploy.
- **Keep these runs outside the plane.** Rejected: the platform would keep
  a second authority and history.

## Consequences

- Turns gain an instance-less form bound to a definition revision, in a
  table of its own on both stores.
- Turn tokens may name a member subject; the token format gains no field.
- An older plane never reads the new table, so it cannot lease, list or
  fail other turns because of an interactive turn during a rolling deploy.
  An older worker never receives one, because it does not set
  `accepts_interactive`.
- Interactive Actions are not propose-only by default. An operator who
  wants them parked uses an Action type's approval or an agent write
  freeze.
- Rolling back below the release that adds the table leaves it in place,
  unread.

## Validation

On a running plane, once the slices land: an interactive turn reads and
writes nothing the member cannot; its receipts name the member, revision
and trace id; revoking the member's access refuses the next call; an agent
write freeze stops its Actions; an uncertified revision is refused at
admission; an older instance in a mixed deploy leaves interactive turns
alone.
