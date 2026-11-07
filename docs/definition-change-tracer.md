# Definition-change tracer fixture

A local, deterministic tracer for the agent-driven definition-change path
(#2095, #2096). Domain vocabulary stays in the versioned package under
[`examples/definition-change-tracer/`](../examples/definition-change-tracer/).
The control plane sees only its normal schema, source-sync, link, definition-branch,
and proposal contracts.

Sibling harnesses can copy the package and drive the same steps through
`sekai-mcp` (agent) plus gRPC (human approve/merge). Approve and merge stay
off MCP.

## Run the fixture

From the repository root:

```bash
cargo run --locked --example definition_change_tracer
cargo test --locked --test definition_change_tracer_example
```

No server, provider, credential, or network is required. The report is JSON
and names a durable id for every step, including the human approval and the
merge `receipt_id`.

## What the command applies

1. An isolated in-memory plane with `experimental_rpcs = false`.
2. The agent principal, through MCP, creates a definition branch from genesis
   and upserts the `Issue` object type from `domain-v1.json`.
3. A connector principal admits two GitHub Issue records from `source-v1.json`
   through `ApplySourceBatch`. The batch transaction id is the ingest receipt.
4. The agent creates a `relates_to` link between those objects and reads it
   back through `sekai.links.get`.
5. The agent inspects diff and consumer impact, then opens a proposal.
6. The creating agent is refused on approve. A second human principal
   approves over gRPC, then merges. Merge stores `receipt_id` on the proposal.

The creating agent never approves or merges. There is no MCP approve or merge
tool.

## Out-of-tree reuse

Copy `examples/definition-change-tracer/` and drive the same steps against
`sekai-mcp` plus native gRPC. MCP JSON uses camelCase for definition tools and
`from_id` / `to_id` / `relation` for links. Keep `experimental_rpcs` off.

| Step | Surface | Name |
| --- | --- | --- |
| Create branch | MCP | `sekai.definitions.branch.create` |
| Upsert object type | MCP | `sekai.definitions.branch.edit` |
| Ingest source | gRPC | `ApplySourceBatch` |
| Create and read link | MCP | `sekai.links.create`, `sekai.links.get` |
| Diff / impact | MCP | `sekai.definitions.diff`, `sekai.definitions.impact` |
| Open proposal | MCP | `sekai.definitions.proposal.create` |
| Approve / merge | gRPC | `ApproveDefinitionProposal`, `MergeDefinitionProposal` |

`ApproveDefinitionProposal` and `MergeDefinitionProposal` stay experimental.
A live server rejects them unless `SEKAI_EXPERIMENTAL_RPCS=1` or the
`experimental-rpcs` Cargo feature is enabled. The in-process fixture invokes
them the same way the MCP definition-branch test already does.
