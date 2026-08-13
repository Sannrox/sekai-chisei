//! Shared discoverable-capability assembly for query and catalog RPCs.
//!
//! These are private implementation used by already-deep modules. They are not a
//! new ordered lifecycle.

use super::*;

impl SekaiServiceImpl {
    pub(super) fn discoverable_capabilities(
        &self,
        namespace: &str,
        principals: &[String],
    ) -> Result<Vec<CapabilityEntry>, Status> {
        check_team_namespace(&self.db, principals, namespace, false)
            .map_err(|_| Status::permission_denied("capability discovery denied"))?;
        let schema = self
            .schema_definitions
            .refresh_snapshot()
            .map_err(|_| Status::internal("capability catalog unavailable"))?;
        let visible_types = schema
            .all()
            .into_iter()
            .filter(|object_type| {
                !is_reserved_governance_kind(&object_type.kind)
                    && check_read(
                        &self.security,
                        &schema_object_id(&object_type.kind),
                        principals,
                    )
                    .is_ok()
            })
            .collect::<Vec<_>>();
        let mut entries = visible_types
            .iter()
            .map(object_query_capability)
            .collect::<Vec<_>>();
        entries.push(traverse_capability());
        entries.push(expand_relations_capability());
        entries.push(retrieve_context_capability());
        entries.push(explain_derivation_capability());
        entries.push(kioku_candidates_capability());
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }
}

fn base_capability(
    name: String,
    description: String,
    kind: &str,
    input_type: &str,
    output_type: &str,
) -> CapabilityEntry {
    let product_tier = capability_product_tier(&name).to_string();
    CapabilityEntry {
        name,
        description,
        kind: kind.to_string(),
        lifecycle_state: "active".to_string(),
        contract_version: capability::CONTRACT_VERSION.to_string(),
        minimum_compatible_version: capability::CONTRACT_VERSION.to_string(),
        maximum_compatible_version: capability::CONTRACT_VERSION.to_string(),
        replacement_capability: String::new(),
        input_type: input_type.to_string(),
        output_type: output_type.to_string(),
        required_scopes: Vec::new(),
        policy_decision_points: Vec::new(),
        risk_class: String::new(),
        approval_behavior: "none".to_string(),
        limits: Vec::new(),
        object_type: None,
        evidence_requirements: Vec::new(),
        product_tier,
    }
}

/// Product tier for catalog discovery (#386 / research #383).
/// Orthogonal to backend inventory completeness.
fn capability_product_tier(name: &str) -> &'static str {
    match name {
        semantic::CAPABILITY_EXPAND_RELATIONS
        | semantic::CAPABILITY_RETRIEVE_CONTEXT
        | semantic::CAPABILITY_EXPLAIN_DERIVATION => "core",
        "sekai.relations.traverse" => "core",
        other if other.starts_with("sekai.objects.query.") => "core",
        other if other.starts_with("sekai.actions.") => "advanced",
        other if other.contains("kioku") => "experimental",
        _ => "advanced",
    }
}

fn object_query_capability(object_type: &schema::ObjectType) -> CapabilityEntry {
    let mut entry = base_capability(
        format!("sekai.objects.query.{}", object_type.kind),
        format!("List authorized {} objects.", object_type.kind),
        "query",
        "sekai.ListObjectsRequest",
        "sekai.ListObjectsResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "schema_visibility".into(),
        "object_acl".into(),
    ];
    entry.object_type = Some(to_proto_schema_type(object_type));
    entry
}

fn traverse_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        "sekai.relations.traverse".into(),
        "Traverse authorized object relations with bounded depth.".into(),
        "query",
        "sekai.TraverseRequest",
        "sekai.TraverseResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec!["namespace_access".into(), "object_acl".into()];
    entry.limits = vec![CapabilityLimit {
        name: "max_depth".into(),
        value: 10,
    }];
    entry
}

fn semantic_reasoning_limits() -> Vec<CapabilityLimit> {
    vec![
        CapabilityLimit {
            name: "max_depth".into(),
            value: u64::from(retrieval::MAX_DEPTH),
        },
        CapabilityLimit {
            name: "max_links".into(),
            value: u64::from(retrieval::MAX_LINKS),
        },
        CapabilityLimit {
            name: "max_objects".into(),
            value: u64::from(retrieval::MAX_OBJECTS),
        },
        CapabilityLimit {
            name: "max_source_rows".into(),
            value: u64::from(retrieval::MAX_SOURCE_ROWS),
        },
        CapabilityLimit {
            name: "max_derived_rows".into(),
            value: u64::from(retrieval::MAX_DERIVED_ROWS),
        },
        CapabilityLimit {
            name: "max_derivation_steps".into(),
            value: u64::from(retrieval::MAX_DERIVATION_STEPS),
        },
        CapabilityLimit {
            name: "max_time_ms".into(),
            value: u64::from(retrieval::MAX_TIME_MS),
        },
        CapabilityLimit {
            name: "max_explanation_bytes".into(),
            value: retrieval::MAX_EXPLANATION_BYTES,
        },
        CapabilityLimit {
            name: "reasoning_profile_version".into(),
            value: semantic::REASONING_PROFILE_VERSION,
        },
        CapabilityLimit {
            name: "ontology_contract_version".into(),
            value: semantic::ONTOLOGY_CONTRACT_VERSION,
        },
        CapabilityLimit {
            name: "supports_asserted_only".into(),
            value: 1,
        },
        CapabilityLimit {
            name: "supports_entailment".into(),
            value: 1,
        },
    ]
}

fn epistemic_projection_limits() -> [CapabilityLimit; 6] {
    [
        CapabilityLimit {
            name: "epistemic_descriptor_source_refs".into(),
            value: crate::chisei::epistemic_descriptor::MAX_SOURCE_REFS as u64,
        },
        CapabilityLimit {
            name: "epistemic_descriptor_source_digests".into(),
            value: crate::chisei::epistemic_descriptor::MAX_SOURCE_DIGESTS as u64,
        },
        CapabilityLimit {
            name: "epistemic_descriptor_source_rows".into(),
            value: crate::chisei::epistemic_descriptor::MAX_SOURCE_ROWS as u64,
        },
        CapabilityLimit {
            name: "epistemic_descriptor_max_bytes".into(),
            value: crate::chisei::epistemic_descriptor::MAX_DESCRIPTOR_BYTES as u64,
        },
        CapabilityLimit {
            name: "backend_sqlite_entailment".into(),
            value: 1,
        },
        CapabilityLimit {
            name: "backend_postgres_entailment".into(),
            value: 0,
        },
    ]
}

fn expand_relations_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        semantic::CAPABILITY_EXPAND_RELATIONS.into(),
        "Expand authorized relations from a root in asserted or entailment mode.".into(),
        "retrieval",
        "sekai.ExpandRelationsRequest",
        "sekai.ExpandRelationsResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "object_acl".into(),
        "classification".into(),
        "ontology_acl".into(),
    ];
    entry.limits = semantic_reasoning_limits();
    entry.limits.extend(epistemic_projection_limits());
    entry.evidence_requirements = vec![
        "derivation_steps".into(),
        "source_fact_ids".into(),
        "ontology_revision".into(),
        "truncation_metadata".into(),
        "epistemic_descriptor_projection".into(),
    ];
    entry
}

fn retrieve_context_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        semantic::CAPABILITY_RETRIEVE_CONTEXT.into(),
        "Retrieve bounded, authorized context candidates with provenance.".into(),
        "retrieval",
        "sekai.RetrieveContextRequest",
        "sekai.RetrieveContextResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "object_acl".into(),
        "classification".into(),
        "ontology_acl".into(),
    ];
    entry.limits = semantic_reasoning_limits();
    entry.limits.extend(epistemic_projection_limits());
    entry.evidence_requirements = vec![
        "derivation_steps".into(),
        "source_fact_ids".into(),
        "ontology_revision".into(),
        "truncation_metadata".into(),
        "epistemic_descriptor_projection".into(),
    ];
    entry
}

fn explain_derivation_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        semantic::CAPABILITY_EXPLAIN_DERIVATION.into(),
        "Explain an authorized derivation path without hidden policy inputs.".into(),
        "retrieval",
        "sekai.ExplainDerivationRequest",
        "sekai.ExplainDerivationResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "object_acl".into(),
        "classification".into(),
        "ontology_acl".into(),
    ];
    entry.limits = semantic_reasoning_limits();
    entry.limits.extend(epistemic_projection_limits());
    entry.evidence_requirements = vec![
        "derivation_steps".into(),
        "source_fact_ids".into(),
        "ontology_revision".into(),
        "explicit_rules_only".into(),
        "epistemic_descriptor_projection".into(),
    ];
    entry
}

fn kioku_candidates_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        "chisei.kioku.candidates.list".into(),
        "List namespace-scoped Kioku candidates with their validation evidence.".into(),
        "retrieval",
        "chisei.ListKiokuCandidatesRequest",
        "chisei.ListKiokuCandidatesResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "memory:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "memory_lifecycle".into(),
        "classification".into(),
    ];
    entry.evidence_requirements = vec![
        "attributable_evidence_link".into(),
        "resolvable_source_operation".into(),
        "candidate_validation".into(),
    ];
    entry.limits = vec![CapabilityLimit {
        name: "max_results".into(),
        value: 100,
    }];
    entry
}
