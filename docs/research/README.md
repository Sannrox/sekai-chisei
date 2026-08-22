# Research and design history

These documents capture completed investigations, constraints, and design
freezes. They are useful when changing architecture or understanding why a
contract exists. They are not operator guides and do not override current
protocol definitions, implementation, architecture decisions, or maintained
reference pages.

| Topic | Status or current documentation |
| --- | --- |
| [Semantic pattern-query surface](145-semantic-pattern-query.md) | Retired from the 1.0 runtime surface; retained as design history |
| [Governed what-if simulation](148-what-if-simulation.md) | Retired from the 1.0 runtime surface; retained as design history |
| [Governed hybrid retrieval](152-hybrid-retrieval.md) | Retired from the 1.0 runtime surface; retained as design history |
| [Gateway PEP fat-decide](163-gateway-pep-fat-decide.md) | Design freeze; see [Gateway and clients](../gateway.md) |
| [Lookup versus model call](175-lookup-vs-model-call.md) | Recommendation complete; see [Capability catalog](../capability-catalog.md) |
| [Cheap-default routing signals](527-cheap-default-routing.md) | Recommendation accepted; follow-up #529 is lookup-vs-golden only |
| [Gunshi auto-allocation envelope](279-gunshi-auto-allocation-envelope.md) | See [Gunshi auto-allocation](../gunshi-auto-allocation.md) |
| [Operator console information architecture](283-operator-console-ia.md) | See [Operator console](../operator-console.md) |
| [Federation and residency architecture](288-federation-residency-architecture.md) | See [Provider residency](../residency-policy.md) and [Federation profile](../federation-profile.md) |
| [Federation profile freeze](291-federation-profile.md) | See [Federation profile](../federation-profile.md) |
| [Multi-region consistency](292-multi-region-consistency.md) | See [Region pins](../region-pins.md) and [Budget topology](../budget-topology.md) |
| [Core product interface](383-core-product-interface.md) | Product-surface research and shrink shortlist |
| [Action and effect mapping](395-action-effect-mapping.md) | See [Governed action types](../governed-action-types.md) and the linked action lifecycle pages |
| [Parked-work resolution](410-parked-work-resolution.md) | Design for durable continuation input and fenced resumption |
| [External-action permit lifecycle surface](420-external-permit-lifecycle-surface.md) | Retain explicit lifecycle RPCs; consolidation would widen trust boundaries without removing implementation paths |
| [Gateway administration single-source boundary](421-gateway-administration-single-source.md) | Extract shared setup and reporting into a leaf administration-client crate after façade cleanup |
| [`SEKAI_AUTH_TOKEN` root-bootstrap retirement](423-auth-token-root-bootstrap.md) | Superseded by the 1.0 clean break: server bootstrap removed; clients use `SEKAI_CREDENTIAL` with durable principal credentials |
| [`sekaictl` command-surface reduction](442-sekaictl-command-surface.md) | Recommend core commands at the root and grouped expert operations under `admin`; implementation requires a Design Discussion |
| [Kernel and extension boundary](443-kernel-extension-boundary.md) | Keep one published governance product, narrow its public facade, and extract only acyclic leaf libraries with a measured independent-consumer dividend |
| [Managed Shikigami routing compatibility](471-managed-shikigami-routing.md) | Existing contract shape retained; #484 completed context-bound provider credentials, streamed tool calls, and situation-specific conformance evidence |
| [Epistemic profiles across federation contracts](500-epistemic-federation.md) | Existing signed receipts, provenance, peer-import, and handoff contracts compose without a new federation adapter; see the conformance fixture |
| [Epistemic RDF/OWL/PROV-O boundary](501-epistemic-rdf-owl-prov-o.md) | Small edge projection with explicit loss metadata; no RDF parser or reasoner in core; see the conformance fixture |
| [Durable `EpistemicAssertion` resource decision](502-epistemic-assertion-resource.md) | Projection remains sufficient; no new core resource, endpoint, or persistence family without independent unmet requirements |
| [Next query-time entailment constructs](658-query-time-entailment-constructs.md) | Keep the ADR 0001 profile; inverse and disjointness stay metadata; reopen only with unmet demand and PostgreSQL advertising the same profile |

For current usage and operations, return to the [documentation guide](../README.md)
or browse the [reference catalog](../reference.md).
