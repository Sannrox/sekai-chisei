# ADR 0157: An agent turn records its transcript

- Status: accepted
- Date: 2026-11-24
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3045 (#3045)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0137](0137-agent-turns-share-the-scheduling-split.md), [ADR 0142](0142-agent-turn-worker-authority.md), [ADR 0146](0146-turn-worker-is-not-the-instance.md)

## Context

An agent turn records scheduling facts only: cause, claim, status and the
parked Action. What the turn did (model route, tokens, prompt, tool calls and
Actions) lived only in a console's own copy. That copy held prompt text outside
the plane's markings and subject erasure, and could disagree with the turn.

## Decision

- **Separate tables.** `sekai_agent_turn_transcript` holds usage and the prompt;
  `sekai_agent_turn_step` holds ordered steps. Ack and claim never rewrite them,
  so an older plane in a rolling deploy cannot drop a transcript. The turn row
  and its domain struct are unchanged.
- **Fenced, idempotent appends.** `SekaiService.AppendAgentTurnTranscript`
  (experimental) checks the live claim's generation, fencing token and lease in
  the same transaction as the write. A step is keyed by `step_id` within the
  turn: the same id and content is one step; the same id with other content is
  refused. The turn runtime token admits the call (ADR 0142).
- **Usage is the worker's report.** Model route and token counts are the
  latest the worker reported. They are not reconciled against the plane's model
  call records.
- **Prompt under a marking.** The prompt is recorded once per turn as a
  reference, a required marking and optional text. The marking must be one the
  turn's instance principal is cleared for under the namespace lattice;
  otherwise the append is refused with `permission_denied`. An identical prompt
  is a no-op; a different one is refused.
- **Action steps point, never copy.** An `action` step stores only the Action
  id, which must name an Action in the turn's namespace. Its status, approval
  decision and receipt are read from the Action on every list, as the park
  continuation does (ADR 0142).
- **Read gate.** `ListSiteAgentInstanceTurns` keeps its visibility check and
  attaches each turn's transcript. Prompt text is returned only when the request
  sets `include_prompt_text` and the caller is cleared for the marking; otherwise
  `prompt_text_withheld` is set. Append responses never echo prompt text.
- **Bounds refuse.** At most 256 steps per turn, 64 KiB of prompt text, and
  512 bytes per short field. An append past a bound is refused, never truncated.
- **Erasure.** Subject erasure on both stores clears prompt text for turns
  whose prompt names the subject, whose instance principal is the subject
  (`agent`), or whose manual requester is the subject (`user`). It sets
  `erased_at_ms`; the turn and its steps remain and later appends are refused
  with `invalid_argument`.

## Consequences

- A console reads run history from the plane, under the plane's markings.
- PostgreSQL erasure still refuses an `agent` or `user` subject named in a
  turn's identity columns, as before this change; the transcript is cleared
  first, inside the same transaction, so a refusal leaves nothing half-erased.
  Lifting that refusal is #3444.
- Listing a page of turns reads one transcript per turn, plus one Action per
  action step. Pages are capped at 500 turns.
- Stored data: two tables on both stores (SQLite migration, PostgreSQL
  migration 0174). Rolling back to a plane without them leaves the tables
  unread.
