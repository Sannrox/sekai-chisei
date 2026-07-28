# Research and design history

These documents capture completed investigations, constraints, and design
freezes. They are useful when changing architecture or understanding why a
contract exists. They are not operator guides and do not override current
protocol definitions, implementation, architecture decisions, or maintained
reference pages.

| Topic | Status or current documentation |
| --- | --- |
| [Semantic pattern-query surface](145-semantic-pattern-query.md) | Recommendation complete; see [Pattern plan](../pattern-plan.md) |
| [Governed what-if simulation](148-what-if-simulation.md) | Shipped as [Scenario overlay](../scenario-overlay.md) |
| [Governed hybrid retrieval](152-hybrid-retrieval.md) | Shipped as [SQLite FTS](../text-fts.md) and [Hybrid retrieval](../hybrid-retrieval.md) |
| [Gateway PEP fat-decide](163-gateway-pep-fat-decide.md) | Design freeze; see [Gateway and clients](../gateway.md) |
| [Lookup versus model call](175-lookup-vs-model-call.md) | Recommendation complete; see [Capability catalog](../capability-catalog.md) |
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

For current usage and operations, return to the [documentation guide](../README.md)
or browse the [reference catalog](../reference.md).
