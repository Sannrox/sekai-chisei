# ADR 0109: Agent dry run is an evaluation-style record that cannot certify

- Status: accepted
- Date: 2026-10-15
- Owners: @Sannrox
- Discussion: none — resolved in Issue #1533
- Issue: #1533 (for #1050 / platform #1313)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0079](0079-evaluation-promotion-gate.md),
  [ADR 0093](0093-agent-drafts-use-definition-members.md),
  [ADR 0094](0094-scoped-definition-draft-authoring.md),
  [ADR 0071](0071-rpc-maturity.md)

## Context

Agent drafts are stored as definition members (ADR 0093). Publishing a
revision that changes an agent member requires a bound evaluation
certification (ADR 0079). Between those two, an author has no way to try
one input against an exact draft revision and see what the agent would do.
A full evaluation suite can bind certification. An external runtime with
Actions stubbed cannot attest that nothing was submitted.

## Decision

1. **Evaluation-style record, not a new execution kind.** `DryRunAgent`
   records the attempt as a stored eval run whose `config_ref` is `dry_run`.
   That mark is the only difference from an ordinary suite result. There is
   no second execution plane and no new suite language.
2. **Certification refuses the mark.** `PutDefinitionCertification` copies
   suite identity and pass/fail from a stored eval run. A run marked
   `dry_run` is not a suite result. Binding it fails closed with
   `agent_promotion_certification_dry_run`. A later edit does not turn a
   dry-run record into a certifiable suite.
3. **One admitted route, one attempt.** The RPC reads the Agent member at
   an exact revision the same way `GetDefinitionMember` does (same
   unavailable answer). It then admits the namespace's model route and
   checks budget once. Admission or budget failure is returned as-is. The
   plane does not retry another route or silently skip the check.
4. **Trace, never submit.** The response is a step trace: model steps, tool
   calls, and every Action the agent proposed. An allowed Action whose
   parameters pass the governed action type's closed parameter schema is
   `would_submit`. An Action type outside `allowed_action_types` is
   `refused` with that reason. Missing types or schema failures are
   `refused` as invalid parameters. No Action instance is created and no
   effect runs.
5. **Experimental.** `DryRunAgent` is classified `experimental` (ADR 0071).

## Alternatives considered

- A new execution kind beside evaluation. Rejected: the store, identity,
  and certification lookup already speak eval runs. A second kind would
  duplicate that path and still need a refuse-to-certify rule.
- A single-case evaluation suite. Rejected: suites bind certification,
  which a dry run must never do.
- An external agent runtime with Actions stubbed. Rejected: the plane
  then cannot attest that nothing was submitted.

## Consequences

Authors can try one input against a draft or published revision without
creating work or unlocking promotion. Console dry-run panels consume this
RPC. The default host admits the namespace route and checks budget once,
then refuses `agent_dry_run_model_unavailable`. It does not echo the
input or invent Actions as a successful model step. A completion host
supplies the model step and proposed Actions when one is configured
(`SekaiServiceImpl::with_dry_run_host`). Live provider completion stays
behind the same admission and budget checks and cannot submit or certify.

## Validation

A dry run that proposes Actions creates zero Action instances and zero
effects, and returns them as `would_submit`. A disallowed Action type
appears as `refused`. A caller without the `GetDefinitionMember` read
gets that same unavailable answer. `PutDefinitionCertification` refuses
a dry-run record. Budget and route admission failures are returned once.
