# Agent-turn transcripts

A claimed agent turn records what it did: the model route and token counts, the
prompt under a marking, and ordered tool-call and Action steps (ADR 0157).

`AppendAgentTurnTranscript` and the transcript fields on `AgentTurn` are
experimental. A plane serves them only with `SEKAI_EXPERIMENTAL_RPCS=1` or a
build with the `experimental-rpcs` feature.

## Writing

The turn's worker appends under its live claim, with the claim's
`runtime_id`, `claim_generation` and `fencing_token`, as for `AckWork`. The
turn runtime token admits the call. Each request sets at least one of:

| Field | Meaning |
| --- | --- |
| `usage` | Model route and token counts. A later report replaces the earlier one. |
| `prompt` | Reference, marking and optional text. Recorded once per turn. |
| `step` | One `tool_call` or `action`, keyed by `step_id` within the turn. |

- A retried step with the same `step_id` and content is one step. Other content
  under the same id is refused with `invalid_argument`.
- A lapsed or superseded claim is refused with `failed_precondition`.
- The prompt marking (`public`, `internal`, `confidential`, `restricted`, or a
  namespace lattice token) is required and must be within the instance
  principal's ceiling; otherwise `permission_denied`.
- An `action` step names an Action in the turn's namespace. Its status,
  approval decision and receipt are read from the Action, never stored.
- Bounds: 256 steps per turn, 64 KiB of prompt text, 512 bytes for other
  fields. Past a bound the append is refused, never truncated.

## Reading

`ListSiteAgentInstanceTurns` returns each turn's `transcript` to any caller who
can see the instance. Prompt text is returned only when the request sets
`include_prompt_text` and the caller is cleared for the prompt marking;
otherwise `prompt_text_withheld` is true.

## Erasure

Subject erasure clears prompt text for turns whose prompt names the subject,
whose instance principal is an erased `agent`, or whose manual requester is an
erased `user`. The turn and its steps remain, `erased_at_ms` is set, and later
appends are refused. The turn's identity columns (its agent principal and a
manual turn's requester) are a retained identity, like audit actors, and keep
the subject on SQLite and PostgreSQL alike; see
[ADR 0157](decisions/0157-an-agent-turn-records-its-transcript.md#addendum-turn-identity-is-a-retained-identity-3444).
