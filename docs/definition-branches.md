# Governed definition branches

Governed definition branches let an authorized schema author evolve one exact
namespace-scoped definition revision without changing published definitions or
runtime facts. The experimental product-tier contract now also publishes or
rejects one pinned candidate through a proposal, compares two revisions,
classifies compatibility, and proposes an append-only rollback of a prior
published revision. Rollback never rewrites history.
`CreateDefinitionBranch`, `ApplyDefinitionBranchEdit`,
`CompareDefinitionRevisions`, `ReportDefinitionConsumerImpact`, and
`CreateDefinitionProposal` are `stable` (#2095). The human review-and-publish
calls `GetDefinitionBranch`, `GetDefinitionProposal`,
`ApproveDefinitionProposal`, `MergeDefinitionProposal`,
`GetDefinitionCertificationGate`, `ListPublishedDefinitionRevisions`, and
`GetDefinitionMember` are `stable` too (#2407). `GetPublishedDefinitionRevision`
stays `stable`. Remaining branch, proposal, rollback, compatibility, and
fact-migration RPCs stay `experimental` and are rejected unless
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is enabled.
See [rpc-maturity.md](rpc-maturity.md). The isolated tracer in
[definition-change-tracer.md](definition-change-tracer.md) walks the agent MCP
path plus human approve and merge on an in-memory plane.

## Contract

`CreateDefinitionBranch` creates a stable branch identity from an existing
authorized published revision. The request supplies:

- `namespace`;
- a canonical `branch_id`;
- the exact `parent_revision_digest`; and
- an `idempotency_key`.

The new branch initially has the parent as both its base and head. Creation
does not update the namespace's published head.

**Genesis.** Every namespace starts from a deterministic, empty, published
genesis revision (no members, no parent). An empty `parent_revision_digest`
means "branch from genesis". It is accepted only while the namespace has
published nothing else: the caller needs namespace write authority, genesis is
seeded idempotently as the published head, and the branch starts there. The
first real revision then follows the normal edit, proposal, approval, and merge
flow, with `expected_published_digest` set to the genesis digest. Once a
namespace has published anything else, an empty parent fails
`FAILED_PRECONDITION`; branch from the published head instead.

`GetDefinitionBranch` returns the current authorized branch head and a
content-addressed `pin_digest` bound to the branch contract, namespace,
branch id, and head revision. A delivery consumer verifies the pin against
that same identity; the pin is not a second authority. Use this read after
a stale-head result before preparing another edit. The path reauthorizes
the current revision and returns no member bodies.

`ApplyDefinitionBranchEdit` advances an existing branch. The request supplies
the exact `expected_head_digest`, bounded member upserts and removals, and an
idempotency key. The server:

1. rechecks namespace and member authorization;
2. canonicalizes each upserted JSON object;
3. recomputes every supplied member digest;
4. applies the resource-level changes to the immutable parent member map;
5. computes a new immutable revision digest;
6. stores members, revision, request result, and audit evidence; and
7. advances the branch head with compare-and-swap.

The response reports the new digest for every upsert and the prior digest for
every removal, sorted and deduplicated as one changed-member set.

A competing writer that already advanced the head makes the request stale.
The server does not automatically merge it.

`CreateDefinitionProposal` pins the current published head as `base_digest`
and the branch head as `candidate_digest`. Optional `eval_plan_digests` are
frozen Chisei dependencies covered by the proposal digest. The server does not
read Chisei, so the MCP proposal tool checks each one against a stored plan
before creating ([capability catalog](capability-catalog.md#definition-branch-tools));
no gate runs a plan at proposal time. `named_foreign_digests` may be recorded but never
enter the published member map. Optional `migration_plan_digest` names the
[change bundle](definition-change-bundles.md#apply) the proposal migrates by;
it is part of the approved proposal digest, so `ApplyDefinitionChangeBundle`
runs only that bundle, and `MergeDefinitionProposal` refuses the proposal
(`definition_proposal_requires_bundle_apply`): only apply publishes it.
Creating a proposal does not move the published head.

Optional `dataset_proposals` attach open dataset branch merge proposals, at
most one per dataset and at most 16 (#2199). Each must be in the caller's
tenant and dataset-writable by the caller, and may not be a change-bundle
`bundle-` branch. A missing or foreign one reads as not found. Create pins
each attachment's parent version and branch digest into the proposal and its
`proposal_digest`; such proposals use contract `sekai.definition-proposal/v2`,
which older binaries refuse to load. Proposals without attachments keep the
v1 contract and digests. Attachments with a `migration_plan_digest` are
refused. While an open definition proposal attaches it, a dataset proposal
cannot merge on its own (`FailedPrecondition`); closing the definition
proposal releases it. The dataset proposal's own self-merge rule applies to
the definition merger.

Every RPC that returns a definition proposal lists its attachments in
`dataset_proposals` (#2222): dataset id, dataset proposal id, and the pinned
parent version and branch digest. A reader sees an attachment only when it
passes the dataset branch read check for that dataset in the tenant the
attachment was pinned in. Otherwise the entry carries only `hidden`, and
hidden entries follow the readable ones, so a reader learns that the data
exists and nothing else. A proposal without attachments omits the field.

`ApproveDefinitionProposal` records a live approval on an open proposal.
An agent principal that created the proposal cannot approve or merge it,
including when that principal still holds namespace write and changed-member
admin (#1311). `MergeDefinitionProposal` requires `expected_published_digest` and rechecks
that the live published head equals both that digest and the pinned base, the
branch head still equals the candidate, the candidate descends from the pinned
base, at least one recorded approver still holds namespace write and
changed-member admin, and named foreign digests are not members. It classifies
the candidate against the published head and refuses the whole merge when a
`function`, `transform`, or `policy` change is breaking, or when any member
kind is unknown, naming `compatibility_gate:{member_kind}`. Breaking
object-type, interface, ontology, link, action, and control members still
publish so checkpointed fact migration can follow the published head. A
refused gate leaves the published head unchanged. It then compare-and-swaps
the namespace published head, stores a durable `receipt_id` on the merged
proposal, and writes the receipt, audit, and idempotency record in the same
transaction. Exact replay of the same idempotency key returns that receipt
without moving the published head again. With attachments, merge locks the
attached datasets in dataset id order, rechecks every pin, merges each
dataset proposal with `merged_by` `definition-proposal:<proposal_id>`, and
then compare-and-swaps the published head, all in that one transaction. The
merge receipt id covers the dataset merge receipt ids. A moved dataset parent,
a changed or deleted branch, or a dataset proposal no longer open fails the
whole merge as `definition_proposal_dataset_stale` and writes nothing.
A stale expected digest or a
candidate that is not a descendant of the pinned base fails closed as not
mergeable. Interrupted merges leave the published head unchanged and store no
receipt.

`CloseDefinitionProposal` rejects an open proposal with a canonical
`reason_code` (`operator_abort`, `superseded`, or `policy_denied`) without
moving the published head. Merge of a closed proposal remains denied.
`GetPublishedDefinitionRevision` returns the current published pointer.
`ListPublishedDefinitionRevisions` returns that namespace's published merge history, newest first. Each entry names the published revision digest, previous published digest, merged proposal id, merge receipt id, actor, and time. Optional `member_kind` and `member_id` must both be set or both empty and keep only merges that added, removed, or digest-changed that member. Pagination is keyset on merge time then proposal id so a concurrent merge cannot duplicate or skip an earlier page. Auth matches `GetPublishedDefinitionRevision`. A nonempty member filter also reauthorizes that member the same way `GetDefinitionMember` does, so a later removal cannot disclose its history to a caller without that grant. The RPC does not restore or roll back a revision.

`ProposeDefinitionRollback` opens a draft whose candidate members match a
previously published revision `A` while remaining a descendant of the live
published head `B`. It creates the branch, applies the restore edits, and
pins the proposal in one transaction. The response returns the proposal and a
preview diff of `B` versus the candidate. Auth matches
`CreateDefinitionProposal`: namespace write plus write on every member that
would change. `restored_from_digest` and optional `migration_plan_digest` are
additive proposal fields. Merge of that proposal publishes a new revision `C`
(never a rewrite of `A`) and records `restored_from_digest` on the merge
receipt. When the rollback would drop object-type properties that live objects
or datasets still carry, merge without a pinned `migration_plan_digest` fails
`definition_rollback_requires_migration_plan`. The pin is a digest, not an
executed fact migration; `ExecuteDefinitionFactMigration` still requires the
TO revision to already be the published head.

### Rebase and archive (#2434)

`RebaseDefinitionBranch` moves a branch onto the live published head with a
three-way merge per member: base, branch head, and published head. A member
changed on one side only takes that side. A member changed on both sides is a
conflict, reported with the three member digests (empty means absent), and the
rebase writes nothing until each conflict has a resolution of `keep_branch` or
`take_published`. A resolution for a member that is not in conflict fails as
invalid. `expected_head_digest` and `onto_published_digest` must match the
stored branch head and published head, or the call fails stale. `dry_run`
returns the same outcome and a preview diff of the published head against the
rebased head, and writes nothing. A written rebase stores the new head
revision, sets base and head, closes the branch's open proposals as
`superseded`, and records a `rebase` audit row in one transaction; a retry with
the same key, dry or not, replays it. Auth: namespace write, read on the branch
head and the published head, and write on every member the rebase changes.

`SetDefinitionBranchArchived` archives or restores a branch. Archiving records
the reason (at most 1024 bytes) and closes the branch's open proposals as
`operator_abort`. An archived branch refuses edits, new proposals, and rebase
with `definition_branch_archived`. Restore reopens the branch for edits; the
closed proposals stay closed. A branch whose head was merged cannot be
archived. Both transitions write an `archive` or `restore` audit row. Auth:
namespace write and read on the branch head.

Both RPCs are experimental.

### Definition file trees (#1618)

`ImportDefinitionTree` (experimental) opens a branch and proposal whose
candidate holds exactly the given members on top of the published head, like
a package import without a signature. It is what
`sekaictl ontology import` calls. The proposal records `source_commit` (7 to
64 lowercase hex digits), and the response carries the diff preview and the
compatibility classification of the published head against the candidate,
and the lint findings the candidate introduces, as `GetDefinitionProposal`
reports them (#1619). Every grant is checked before the first write.

### Signed definition packages (#1700)

`ExportDefinitionPackage` and `ImportDefinitionPackage` (experimental, behind
`SEKAI_EXPERIMENTAL_RPCS=1`) move published definitions between namespaces or
planes as a signed `sekai.definition-package/v1` envelope.

- **Format.** Each member is `kind`, `id`, and canonical `definition_json`.
  Its member digest covers kind, id, and those bytes, without the namespace.
  Members are sorted, and the package digest is SHA-256 over the member list,
  so the same definitions have the same package digest in every namespace.
  Provenance (source namespace, source revision, export time) is signed with
  the package digest but sits outside it. A package carries definitions only:
  never objects, datasets, sources, credentials, or run history. Governed
  transform definitions are `transform` members (#1799): the document is the
  JobSpec without `namespace`, `definition_digest`, `schedule`, or `trigger`,
  so the same pipeline has the same digest in every namespace. Schedule and
  trigger stay local. Unknown member kinds are refused.
- **Export** packages a published revision (the head when `revision_digest`
  is empty). The published head overlays the namespace's governed transforms
  as `transform` members; a historical revision keeps the members it already
  carries. It needs read access to the revision, as `GetDefinitionMember`
  does, and signs with this plane's key: `SEKAI_DEFINITION_PACKAGE_SIGNING_KEY`
  (file with a 32-byte hex Ed25519 seed) and `SEKAI_DEFINITION_PACKAGE_SIGNER`
  (`identity/key_id`).
- **Import** verifies the envelope against `SEKAI_DEFINITION_PACKAGE_TRUSTED_KEYS`
  (JSON array of `{"identity", "key_id", "public_key"}`), recomputes every
  digest, then opens a branch and proposal whose candidate holds exactly the
  package members. Target members absent from the package are removals. The
  proposal records `source_package_digest`, which is part of its digest and
  so of its merge receipt. Import never merges: compatibility, lint, and
  Agent certification gates apply at merge as for any proposal. Auth matches
  rollback: namespace write plus write on every member that would change.
  Each governed transform's projected output columns must exist on the output
  object type in the candidate, or in the target when the package does not
  carry that type; a mismatch is `definition_package_incompatible:
  transform_output_incompatible` and writes nothing. A store transform that
  is not a published member is `definition_package_incompatible:
  transform_store_conflict` so merge cannot overwrite a Put-only pipeline
  that rollback could not restore. Merge applies those transform members to
  the namespace's transform store. Unchanged members leave local schedule
  and trigger in place; a changed member is written without them. Rolling
  the proposal back restores the previous transform revision.
- **Refusals** are `FAILED_PRECONDITION` with a named reason, and nothing is
  written: `definition_package_unverified` (unknown, unusable, or wrong
  signature, or no trusted keys configured), `definition_package_tampered`
  (a digest does not match its content), and
  `definition_package_incompatible` (format, member kind, member document,
  transform I/O, or an untracked store transform).
- Keys are read at call time, so rotating them needs no restart. Without them,
  export and import fail closed.

### Namespace packages (#3093)

`ExportNamespacePackage` (experimental) packages a namespace for install into
a namespace of another tenant as a signed `sekai.namespace-package/v1`
manifest (ADR 0169). The request names the package (`a-z`, `0-9`, `.`, `_`,
`-`, at most 128 bytes), its version (at least 1), and the datasets to
package.

- One `definition_package` entry carries the published definitions the
  caller may read. Its digest is the namespace-free definition package
  digest, and the response's `ontology_digest` is the same value. Governed
  transforms are not carried.
- One `dataset_version` entry per selected dataset carries its name, columns
  (name, type, classification) and partition keys, never rows. Its digest
  covers columns and partition keys. A dataset that is missing, unreadable, or
  has an unreadable column is `PERMISSION_DENIED` with `dataset <id> is not
  readable`; one not bound to an object in the namespace is
  `FAILED_PRECONDITION`.
- `withheld` counts the definition members the caller may not read, by kind,
  never naming them.
- The package digest covers the whole manifest and is signed with the
  definition package key above. Verification refuses with
  `namespace_package_unverified`, `namespace_package_tampered`, or
  `namespace_package_incompatible`, naming the entry.

`InstallNamespacePackage` (experimental) installs a package into a namespace
the caller may write. Every check comes before the first write:

- the signature against the package keyring (`SEKAI_DEFINITION_PACKAGE_*`)
  and every digest;
- one target per dataset entry in `datasets`, keyed by entry id. An output
  names a new dataset id and an object in the namespace to bind it to. An
  input names an existing dataset bound in the namespace whose columns and
  partition keys match the entry's schema digest. An unmapped entry, a
  target with no entry, or a mismatched input is refused by name;
- the namespace holds no published definitions.

The definitions then open as proposal `package/<name>/v<version>`, which goes
through the namespace's normal review. The output datasets are created
without rows. `GetNamespacePackageInstallation` reports the installation as
`pending_definitions` until that proposal merges, then `installed`, or
`diverged` when the merged definitions do not reproduce the ontology digest.
Installing the same package again returns the same installation; another
version of an installed package is refused until upgrade ships.

`CompareDefinitionRevisions` takes two revision digests in one namespace. It
reauthorizes every member on both revisions, then reports added, removed, and
changed members in kind-then-id order. Changed object-type properties are
named without returning definition JSON. Unknown property constructs fail
closed. Unauthorized or missing revisions are unavailable and do not
distinguish hidden from absent members.

`ClassifyDefinitionRevisionCompatibility` reuses that authorized comparison
and assigns a worst-wins class of `compatible`, `conditional`, `breaking`, or
`unknown`, with content-bound reasons that name member identities, property
keys, and reason codes. Reason volume inherits the revision member and
definition-byte ceilings. It does not return definition bodies, mutate a
published parent, or execute a fact migration.

Classification vocabulary:

- `compatible`: additive optional properties and new `object_type`,
  `interface_type`, `ontology_class`, `ontology_relation`, or `link_type`
  members. Removing a required constraint without removing the property is
  compatible, as are changes to `owner`, `lint_suppressions`, `source_turn`,
  and the [text fields](#descriptions-and-alternative-names) of object and
  link types.
- `conditional`: new `action_type`, `function`, `transform`, `policy`, or
  `control` members, `access_marking` changes, and known field changes such
  as `name` or `mode`. These require live authorization or review before
  effect; they are not silent success.
- `breaking`: removed members, removed properties, and newly required
  properties. Breaking changes need an approved migration path before facts
  can follow the candidate.
- `unknown`: a well-formed change the classifier does not map, such as an
  unrecognized field. Unknown is never treated as compatible.

Malformed `properties`, `required`, or `access_marking` constructs fail closed
instead of producing a class. The compatibility digest binds both revision
digests, the class, the ordered reasons, and the compare digest.

## Content identity

Member contract `sekai.definition-member/v1` supports these domain-neutral
member kinds:

- `object_type`
- `interface_type`
- `ontology_class`
- `ontology_relation`
- `link_type`
- `action_type`
- `function`
- `transform`
- `policy`
- `control`

Member identity binds the contract version, namespace, member kind, stable
member ID, and canonical definition JSON. Objects are key-sorted recursively;
arrays retain their declared order. Duplicate object keys, non-object
definitions, unsupported member kinds, and a supplied digest that differs from
the server result are invalid.

Revision contract `sekai.definition-revision/v1` binds the namespace, exact
parent revision, and the deterministically ordered map of member identities and
digests. Author and timestamp metadata do not affect content identity.

Branch contract `sekai.definition-branch/v1` treats the branch head as a
mutable concurrency projection. Members and revisions remain insert-only
authority.

## Authorization and non-disclosure

Every operation requires namespace write access. Creating a branch also
requires read access to every member inherited from its published parent.
Editing requires read access to every inherited member and administrative
access to every changed member through the existing schema, ontology, or
action authorization boundary.

Unknown and unauthorized revision identities return an unavailable result
without definition bodies. Errors and audit rows never include member JSON or
restricted property values.

## Retry and recovery

Idempotency is scoped by namespace, authenticated actor, and key. Exact replay
returns the recorded branch or edit result. Reusing the key with different
canonical input fails explicitly.

Member, revision, idempotency, audit, and head writes share one backend
transaction. A failed transaction cannot leave an advanced branch head without
its immutable revision and audit evidence.

## Current limits

- Branch creation starts from a published parent or from genesis. There is no
  implicit snapshot of legacy mutable schema or ontology rows.
- A branch cannot be used to migrate runtime facts.
- `CompareDefinitionRevisions` reports deterministic added, removed, and
  changed members and property keys between two authorized revisions without
  returning definition bodies.
- `ClassifyDefinitionRevisionCompatibility` classifies that same authorized
  pair as compatible, conditional, breaking, or unknown.
- `ExecuteDefinitionFactMigration` runs one approved checkpointed fact
  migration from an ancestor revision onto the published head, with dry-run,
  execute, resume-by-replay, and rollback. Unknown compatibility, stale
  parents, and unapproved breaking or conditional changes fail closed. Blocked
  transforms do not mutate objects. Published definition rows are never
  rewritten. Rollback names the stored parent and candidate. It restores
  only properties still at their post-migration value; a property edited
  after the migration keeps its value and is listed in `kept_edits`. A
  migration executed before this check restores whole and sets
  `edit_detection_unavailable`. Live object and
  property grants are rechecked at effect; hidden objects are omitted and
  ungranted properties are not stripped. Mutation, audit, and object lineage
  share one transaction. `GetDefinitionFactMigration` does not distinguish
  missing from unauthorized revisions. See
  [ADR 0028](decisions/0028-checkpointed-fact-migration.md).
- Runtime objects of `object_type` members are rebound by that migration.
  Source bindings remain attached to their existing type identities.
- Package identity is not a runtime grant. Evaluation-plan digests on a
  proposal are frozen references, not a second merge protocol.

See [ADR 0024](decisions/0024-governed-definition-branches.md) for the
branch/revision foundation, [ADR 0026](decisions/0026-governed-branch-proposals.md)
for publication as a digest-bound proposal, and
[the native protocol](../proto/sekai.proto) for exact messages.

## Agent draft documents and exact member reads

`agent` members use this strict document shape:

```json
{
  "contract_version": "sekai.agent-definition/v1",
  "name": "Triage",
  "task_class": "lookup",
  "instructions": "Inspect records.",
  "allowed_action_types": ["Ticket.inspect"]
}
```

Names, task classes, and Action references must be nonempty canonical identifiers
of at most 256 bytes. Instructions must be nonempty text of at most 128 KiB,
without NUL bytes. The Action allowlist contains at most 128 unique references.
Unknown fields, missing fields, duplicate JSON keys, and unsupported document
versions are rejected before persistence. Action references grant no authority.

Use existing branch edits to save a draft. `GetDefinitionMember` accepts the
namespace, exact `revision_digest`, `member_kind`, and `member_id`, returning
canonical `definition_json`, its member digest, and the revision digest. It
supports existing member kinds too. A read requires namespace access and read
grants for every member of the selected revision, preserving revision-wide
visibility. Missing and denied members return the same generic NotFound status;
corrupt or incorrectly bound content returns a generic Internal status.

The RPC is `stable`. This does not change
credential scopes or resource grants. Merging a proposal that changes an
agent-definition member requires a current, non-revoked, baseline-passing
certification bound to the candidate revision
([ADR 0079](decisions/0079-evaluation-promotion-gate.md)). Missing, stale,
failed, or revoked evidence is `failed_precondition` with a stable
`agent_promotion_*` reason. Direct publish of an agent member is still
refused. `PutDefinitionCertification` binds suite identity and pass/fail from
a stored eval run (`certification_id`) to the candidate revision. Authors
of agent-member changes since the published base cannot bind; a later bind
cannot clear `revoked_at_ms`; expiry cannot exceed 90 days from
`bound_at_ms`.
Binding also records the run's mean case score. When the published revision
holds a non-revoked, scored certification on the same suite, a candidate whose
mean score falls more than `SEKAI_AGENT_PROMOTION_MAX_REGRESSION_PERCENT`
(default 20) below it is refused with `agent_promotion_eval_regression`
(status `regressed`). No published certification, another suite, or an
unscored row keeps the pass/fail gate.
An agent definition may bind `tools`: entries of kind `action`, `query` or
`gateway` with a name and an optional `approval_policy`. When the list is
empty it is omitted, so existing definitions keep their digests. A tool's
effect is derived, never declared:
- a query reads;
- an Action is destructive if its governed type may `external_mutate`, and
  mutating if it creates or updates objects, dispatches runtime work or
  notifies; an unknown Action type is destructive;
- a gateway tool is destructive until the gateway publishes its annotations.
Merge refuses a revision whose mutating or destructive tool has no approval
policy, with `agent_tool_approval_required:<tool>`. Drafts may be saved
without policies. Enforcing the policy at runtime is the gateway's job.
Effects use the enabled versions of a governed Action type, the same rule
`SubmitActionInstance` admits. `GetDefinitionCertificationGate` and
`PutDefinitionCertification` return each agent member's bound tools with the
derived `effect` and `blocks_publish`. `DiscoverCapabilities` returns
`tool_effect` on each Action entry, so a console never re-derives effects.
`GetDefinitionCertificationGate` reports the same admitted or refused state
the merge uses. Proposals that do not change agent members are unchanged.
See [ADR 0093](decisions/0093-agent-drafts-use-definition-members.md).

`DryRunAgent` runs one caller-supplied input against an Agent member at an
exact revision. Auth matches `GetDefinitionMember`, including the same
unavailable answer for a missing or unreadable member. The response is a
step trace: model steps, tool calls, and proposed Actions marked
`would_submit` or `refused`. No Action instance is created. The attempt is
stored as an eval run marked `dry_run` and cannot bind
`PutDefinitionCertification` ([ADR 0109](decisions/0109-agent-dry-run.md)).
Route admission and budget are checked once; a failure is returned, not
retried. The RPC is experimental.

`RunAgentShadow` replays durably recorded trigger envelopes through
`DryRunAgent` against an active revision and a candidate. There is no live
trigger path and no cron. The report lists proposed-Action differences with
cost and latency. No Action is submitted. A namespace that opts in with
`require_for_promotion` needs a passing report in addition to certification
(ADR 0079); the report never certifies. `GetAgentShadowReport` reads the
stored report. The RPCs are experimental.

Governed transforms gate the same way (#1796). A namespace opts in with
`ShadowGovernedTransform`'s `require_for_promotion`. From then on, a proposal
that changes a `transform` member merges only with a stored passing shadow
report for that candidate against the revision running now. New and removed
transforms, changes a shadow cannot compare (another output, or
isolated-process), and rollbacks are exempt. See
[governed transforms](governed-transforms.md#promotion).

### Scoped draft authoring

Scoped authenticated contexts can call qualified `sekai.SekaiService`
`GetDefinitionBranch`, `CreateDefinitionBranch`, and `ApplyDefinitionBranchEdit`
through the normal server-established RPC identity. All three are `stable`.
Creation and editing require actual namespace write scope and grants; editing
also requires revision-wide read visibility and administration of changed members.
The server attributes writes to the authenticated subject, not caller metadata.

Use separate idempotency keys for branch creation and each edit. Every edit
requires the exact expected head digest. A stale head returns FailedPrecondition;
a conflicting request under the same key returns AlreadyExists. After a timeout,
the outcome is unknown: retry the identical operation and key with a fresh
assertion. Identical retries return the original receipt, even after the head has
advanced. Reload before choosing a new edit following a conflict.

Draft authoring never advances the published pointer. See
[ADR 0094](decisions/0094-scoped-definition-draft-authoring.md).

Scoped contexts can also call qualified `GetDefinitionProposal`,
`CreateDefinitionProposal`, `ApproveDefinitionProposal`, and
`MergeDefinitionProposal` to publish a draft. The same namespace write, member
administration, approval, expected-published-digest, and ADR 0079 certification
checks apply; `CloseDefinitionProposal` is not available to scoped contexts. See
[ADR 0111](decisions/0111-scoped-definition-proposals.md).

#### Drafting from a conversation

An agent that interviews a domain expert drafts through the same calls
(#1461). Each drafted member names the conversation turn it came from in an
optional `source_turn` string inside `definition_json`, for example
`"source_turn":"interview-7#turn-3"`. It must be non-empty, at most 256
bytes, with no control characters or surrounding whitespace. The reference
is opaque to the core: it is part of the member's content and digest, stays
with the member through publication, and changing it is a compatible change
(`changed_source_turn`). Markings are drafted as `access_marking` on the
member they protect. Agent members do not take `source_turn`: the Agent
document contract is strict, so an Agent definition carrying it is refused.

#### Descriptions and alternative names

Object and link types can carry human text inside `definition_json`
(#2298). Every field is optional:

| Field | Value |
| --- | --- |
| `description` | one string, at most 1,024 bytes |
| `alternative_names` | up to 32 distinct names people use for the type, each at most 128 bytes |
| `property_descriptions` | object type only: declared property to a description |
| `property_alternative_names` | object type only: declared property to its alternative names |
| `unreviewed` | paths of texts nobody has reviewed yet: `description`, `alternative_names`, `property_descriptions/<property>`, `property_alternative_names/<property>` |

Texts are non-empty, with no control characters or surrounding whitespace.
A definition edit is refused when a property key is not in `properties`, or
when an `unreviewed` path names a text the definition does not hold. A
reviewer accepts a text by removing its path from `unreviewed`, after
editing it if needed; there is no accept call. Each remaining path is one
`unreviewed_text` lint warning ([ontology lint](ontology-lint.md)).

Text never touches facts, so changing any of these fields is compatible
(`changed_description`, `changed_unreviewed`, and so on). On other member
kinds the keys are not part of the document and stay unknown fields.
`GetDefinitionMember` and the published revision reads return the fields as
part of `definition_json`; there is no separate search call. A plane that
predates these fields still stores and reads them, but classifies a change
to a member that carries them as `unknown`, so it refuses that merge until
the newer version serves it.

Before proposing, the agent can lint the draft with `GetOntologyLintReport`
and `branch_id` ([ontology lint](ontology-lint.md)). The draft is then an
ordinary proposal: diffed, approved by someone other than its author, and
merged. A principal without namespace write is refused when it creates the
branch, and one without member administration when it edits.

## Lint gate

A merge is refused when the candidate introduces an unsuppressed error-level
[ontology lint](ontology-lint.md#proposal-gate) finding (#1687), such as an
object type no consumer references. `GetDefinitionProposal` lists the
findings the candidate introduces.
