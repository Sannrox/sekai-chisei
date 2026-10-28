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
        tenant_context: Option<&RequestEnterpriseContext>,
    ) -> Result<Vec<CapabilityEntry>, Status> {
        check_team_namespace(self.db.runtime(), principals, namespace, false)
            .map_err(|_| Status::permission_denied("capability discovery denied"))?;
        let schema = self
            .schema_definitions
            .refresh_snapshot()
            .map_err(|_| Status::internal("capability catalog unavailable"))?;
        let include_restricted = principals_can_query_restricted_properties(principals);
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
            .map(|object_type| object_query_capability(object_type, include_restricted))
            .collect::<Vec<_>>();
        entries.extend(self.discoverable_action_capabilities(
            namespace,
            principals,
            tenant_context,
            &schema,
            include_restricted,
        )?);
        entries.push(evaluate_object_set_capability());
        entries.push(object_change_subscription_capability());
        entries.push(traverse_capability());
        // Query-time entailment runs on both community runtimes (#1320).
        let entailment = true;
        entries.push(expand_relations_capability(entailment));
        entries.push(retrieve_context_capability(entailment));
        entries.push(explain_derivation_capability(entailment));
        entries.push(kioku_candidates_capability());
        let experimental = crate::rpc_maturity::experimental_rpcs_enabled();
        entries.push(search_query_capability(experimental));
        entries.push(search_status_capability(experimental));
        entries.push(neighborhood_capability(experimental));
        entries.push(paths_capability(experimental));
        entries.push(experimental_rpc_capability(experimental));
        entries.push(hosted_transform_capability(experimental));
        entries.push(analytical_transform_capability(experimental));
        entries.push(isolated_transform_capability(experimental));
        entries.push(scheduler_transform_capability(experimental));
        entries.push(preview_transform_capability(experimental));
        entries.push(adhoc_transform_capability(experimental));
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    fn discoverable_action_capabilities(
        &self,
        namespace: &str,
        principals: &[String],
        tenant_context: Option<&RequestEnterpriseContext>,
        schema: &schema::SchemaRegistry,
        include_restricted: bool,
    ) -> Result<Vec<CapabilityEntry>, Status> {
        match check_team_namespace(self.db.runtime(), principals, namespace, true) {
            Ok(()) => {}
            Err(status) if status.code() == tonic::Code::PermissionDenied => {
                return Ok(Vec::new());
            }
            Err(status) => return Err(status),
        }
        match enforce_namespace_tenant_context(self.db.runtime(), tenant_context, namespace, true) {
            Ok(()) => {}
            Err(status) if status.code() == tonic::Code::PermissionDenied => {
                return Ok(Vec::new());
            }
            Err(status) => return Err(status),
        }
        let service_scope = service_principal_scope(self.db.runtime(), tenant_context)?;
        let types = self
            .db
            .runtime()
            .list_governed_action_types(namespace, None, true)
            .map_err(|_| Status::internal("capability catalog unavailable"))?;
        let actor = principals.first().map(String::as_str).unwrap_or("");
        // #1646: the tool effect spans every enabled version of a type, the
        // same rule the publish refusal applies.
        let mut versions: std::collections::BTreeMap<String, Vec<_>> =
            std::collections::BTreeMap::new();
        for type_def in types.iter().filter(|type_def| type_def.enabled) {
            versions
                .entry(type_def.type_id.clone())
                .or_default()
                .push(type_def.clone());
        }
        let mut latest = std::collections::BTreeMap::new();
        for type_def in types {
            if !type_def.enabled {
                continue;
            }
            latest.insert(type_def.type_id.clone(), type_def);
        }
        let mut entries = Vec::new();
        for type_def in latest.into_values() {
            if !type_def.object_kind.is_empty()
                && (is_reserved_governance_kind(&type_def.object_kind)
                    || check_read(
                        &self.security,
                        &schema_object_id(&type_def.object_kind),
                        principals,
                    )
                    .is_err())
            {
                continue;
            }
            if !include_restricted
                && action_parameter_schema_discloses_restricted(&type_def, schema)
            {
                continue;
            }
            let project = if type_def.policy_scope.trim().is_empty() {
                namespace
            } else {
                type_def.policy_scope.as_str()
            };
            let policy = self
                .db
                .runtime()
                .resolve_action_policy(actor, namespace, project)
                .map_err(|_| Status::internal("capability catalog unavailable"))?;
            if action_discovery_decision(policy.as_ref(), &type_def.type_id)
                == crate::sekai::action_policy::ActionDecision::Deny
            {
                continue;
            }
            if let Some(scope) = &service_scope
                && !scope
                    .action_types
                    .iter()
                    .any(|allowed| allowed == &type_def.type_id)
            {
                continue;
            }
            let mut entry = action_capability(
                &type_def,
                action_submit_decision(policy.as_ref()),
                schema,
                include_restricted,
            );
            entry.tool_effect = crate::sekai::agent_definition::action_effect(
                versions
                    .get(&type_def.type_id)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            )
            .as_str()
            .into();
            entries.push(entry);
        }
        Ok(entries)
    }

    pub(super) fn published_ontology_revision(
        &self,
        namespace: &str,
        principals: &[String],
    ) -> Result<String, Status> {
        let Some(revision) = self
            .db
            .runtime()
            .get_published_definition_revision(namespace)
            .map_err(|_| Status::internal("capability catalog unavailable"))?
        else {
            return Ok(String::new());
        };
        match authorize_definition_revision(
            self,
            principals,
            namespace,
            &revision.revision_digest,
            true,
        ) {
            Ok(()) => Ok(revision.revision_digest),
            Err(_) => Ok(String::new()),
        }
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
        parameter_schema_json: String::new(),
        markings: Vec::new(),
        action_version: String::new(),
        tool_effect: String::new(),
    }
}

fn action_submit_decision(
    policy: Option<&crate::sekai::action_policy::ActionPolicy>,
) -> crate::sekai::action_policy::ActionDecision {
    use crate::sekai::action_instance::SUBMIT_POLICY_ACTION;
    use crate::sekai::action_policy::ActionDecision;
    use sekai_types::risk_class::RiskClass;
    match policy {
        Some(policy) => policy.decide(SUBMIT_POLICY_ACTION, RiskClass::Write),
        None => ActionDecision::Allow,
    }
}

fn action_discovery_decision(
    policy: Option<&crate::sekai::action_policy::ActionPolicy>,
    type_id: &str,
) -> crate::sekai::action_policy::ActionDecision {
    use crate::sekai::action_policy::ActionDecision;
    let submit = action_submit_decision(policy);
    if submit == ActionDecision::Deny {
        return ActionDecision::Deny;
    }
    match policy.and_then(|policy| policy.action_overrides.get(type_id)) {
        Some(ActionDecision::Deny) => ActionDecision::Deny,
        _ => submit,
    }
}

fn action_capability(
    type_def: &crate::sekai::governed_action_type::GovernedActionType,
    submit_decision: crate::sekai::action_policy::ActionDecision,
    schema: &schema::SchemaRegistry,
    include_restricted: bool,
) -> CapabilityEntry {
    use crate::sekai::action_policy::ActionDecision;
    let mut entry = base_capability(
        capability::action_capability_name(&type_def.type_id),
        if type_def.description.trim().is_empty() {
            format!("Submit governed Action {}.", type_def.type_id)
        } else {
            type_def.description.clone()
        },
        "action",
        "sekai.SubmitActionInstanceRequest",
        "sekai.SubmitActionInstanceResponse",
    );
    entry.product_tier = "core".into();
    entry.required_scopes = vec!["namespace:write".into(), "action:submit".into()];
    entry.policy_decision_points = vec!["namespace_access".into(), "action_policy".into()];
    entry.risk_class = "write".into();
    entry.approval_behavior = match submit_decision {
        ActionDecision::RequireApproval => "required",
        ActionDecision::Allow | ActionDecision::Deny => "none",
    }
    .into();
    entry.parameter_schema_json = type_def.parameter_schema_json.clone();
    entry.action_version = type_def.version.clone();
    if let Some(object_type) = schema.get(&type_def.object_kind) {
        entry.markings = visible_markings(object_type, include_restricted);
        entry
            .policy_decision_points
            .push("schema_visibility".into());
    }
    entry
}

fn action_parameter_schema_discloses_restricted(
    type_def: &crate::sekai::governed_action_type::GovernedActionType,
    schema: &schema::SchemaRegistry,
) -> bool {
    let Some(object_type) = schema.get(&type_def.object_kind) else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&type_def.parameter_schema_json)
    else {
        return true;
    };
    let Some(properties) = parsed.get("properties").and_then(|value| value.as_object()) else {
        return true;
    };
    object_type.properties.iter().any(|property| {
        schema::is_restricted_property_classification(&property.classification)
            && properties.contains_key(&property.name)
    })
}

fn visible_object_type(
    object_type: &schema::ObjectType,
    include_restricted: bool,
) -> schema::ObjectType {
    if include_restricted {
        return object_type.clone();
    }
    let mut visible = object_type.clone();
    visible.properties.retain(|property| {
        !schema::is_restricted_property_classification(&property.classification)
    });
    visible
}

fn visible_markings(object_type: &schema::ObjectType, include_restricted: bool) -> Vec<String> {
    let mut markings = visible_object_type(object_type, include_restricted)
        .properties
        .iter()
        .map(|property| {
            schema::normalize_property_classification(&property.classification).to_string()
        })
        .filter(|marking| !marking.is_empty())
        .collect::<Vec<_>>();
    markings.sort();
    markings.dedup();
    markings
}

/// Product tier for catalog discovery (#386 / research #383).
/// Orthogonal to backend inventory completeness.
fn capability_product_tier(name: &str) -> &'static str {
    match name {
        crate::rpc_maturity::EXPERIMENTAL_CAPABILITY => "core",
        crate::sekai::governed_transform::HOSTED_COMPUTE_CAPABILITY
        | crate::sekai::governed_transform::ANALYTICAL_COMPUTE_CAPABILITY
        | crate::sekai::governed_transform::ISOLATED_COMPUTE_CAPABILITY
        | crate::sekai::governed_transform::SCHEDULER_COMPUTE_CAPABILITY => "core",
        semantic::CAPABILITY_EXPAND_RELATIONS
        | semantic::CAPABILITY_RETRIEVE_CONTEXT
        | semantic::CAPABILITY_EXPLAIN_DERIVATION => "core",
        "sekai.relations.traverse" | "sekai.objects.evaluate_set" => "core",
        other if other.starts_with("sekai.objects.query.") => "core",
        other if other.starts_with("sekai.actions.") => "core",
        other if other.contains("kioku") => "experimental",
        "sekai.search.query" | "sekai.search.status" => "experimental",
        "sekai.relations.neighborhood" | "sekai.relations.paths" => "experimental",
        _ => "advanced",
    }
}

fn object_query_capability(
    object_type: &schema::ObjectType,
    include_restricted: bool,
) -> CapabilityEntry {
    let visible = visible_object_type(object_type, include_restricted);
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
    entry.object_type = Some(to_proto_schema_type(&visible));
    entry.markings = visible_markings(&visible, true);
    entry
}

/// Reference-platform analog: experimental catalog entries stay visible and gated off
/// so discovery does not advertise them as production-ready.
fn hosted_transform_capability(enabled: bool) -> CapabilityEntry {
    let mut entry = base_capability(
        crate::sekai::governed_transform::HOSTED_COMPUTE_CAPABILITY.into(),
        "In-process governed dataset transform host. Put, run, and inspect a JobSpec; outputs are datasets.".into(),
        "transform",
        "sekai.PutGovernedTransformRequest",
        "sekai.PutGovernedTransformResponse",
    );
    entry.required_scopes = vec!["namespace:write".into(), "dataset:read".into()];
    entry.policy_decision_points = vec!["namespace_access".into(), "credential_admin".into()];
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry
}

fn analytical_transform_capability(enabled: bool) -> CapabilityEntry {
    let mut entry = base_capability(
        crate::sekai::governed_transform::ANALYTICAL_COMPUTE_CAPABILITY.into(),
        "In-process analytical SQL transform profile. Multi-input join, aggregate, and derived columns on governed datasets.".into(),
        "transform",
        "sekai.PutGovernedTransformRequest",
        "sekai.PutGovernedTransformResponse",
    );
    entry.required_scopes = vec!["namespace:write".into(), "dataset:read".into()];
    entry.policy_decision_points = vec!["namespace_access".into(), "credential_admin".into()];
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry
}

fn isolated_transform_capability(enabled: bool) -> CapabilityEntry {
    let mut entry = base_capability(
        crate::sekai::governed_transform::ISOLATED_COMPUTE_CAPABILITY.into(),
        "Isolated-process governed transform profile. Admit a JobSpec, claim work, read pinned inputs, and commit fenced receipt-bound write-back.".into(),
        "transform",
        "sekai.ClaimTransformWorkRequest",
        "sekai.WriteTransformRunResultResponse",
    );
    entry.required_scopes = vec!["namespace:write".into(), "dataset:write".into()];
    entry.policy_decision_points = vec!["namespace_access".into(), "credential_admin".into()];
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry
}

fn scheduler_transform_capability(enabled: bool) -> CapabilityEntry {
    let mut entry = base_capability(
        crate::sekai::governed_transform::SCHEDULER_COMPUTE_CAPABILITY.into(),
        "Plane-owned scheduled and change-triggered transform admission. Idempotent ticks, dependency graph, and output freshness.".into(),
        "transform",
        "sekai.TickGovernedTransformsRequest",
        "sekai.TickGovernedTransformsResponse",
    );
    entry.required_scopes = vec!["namespace:write".into(), "dataset:write".into()];
    entry.policy_decision_points = vec!["namespace_access".into(), "credential_admin".into()];
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry
}

fn adhoc_transform_capability(enabled: bool) -> CapabilityEntry {
    let mut entry = base_capability(
        crate::sekai::governed_transform::ADHOC_COMPUTE_CAPABILITY.into(),
        "Run an inline governed transform once with the caller's read authority into an expiring scratch output, with a receipt.".into(),
        "transform",
        "sekai.RunAdHocGovernedTransformRequest",
        "sekai.RunAdHocGovernedTransformResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "dataset:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "marking".into(),
        "property_grant".into(),
    ];
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry
}

fn preview_transform_capability(enabled: bool) -> CapabilityEntry {
    let mut entry = base_capability(
        crate::sekai::governed_transform::PREVIEW_COMPUTE_CAPABILITY.into(),
        "Preview an unsaved governed transform on a bounded sample without committing output, receipt, or lineage.".into(),
        "transform",
        "sekai.PreviewGovernedTransformRequest",
        "sekai.PreviewGovernedTransformResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "dataset:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "row_filter".into(),
        "marking".into(),
        "property_grant".into(),
    ];
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry
}

fn evaluate_object_set_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        "sekai.objects.evaluate_set".into(),
        "Evaluate a revision-bound ObjectSet descriptor through authorized list and one-hop traverse.".into(),
        "query",
        "sekai.EvaluateObjectSetRequest",
        "sekai.EvaluateObjectSetResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "schema_visibility".into(),
        "object_acl".into(),
        "definition_revision".into(),
    ];
    entry.limits = vec![CapabilityLimit {
        name: "max_filters".into(),
        value: crate::sekai::object_set::MAX_PROPERTY_FILTERS as u64,
    }];
    entry
}

fn object_change_subscription_capability() -> CapabilityEntry {
    let mut entry = base_capability(
        "sekai.objects.read_change_subscription".into(),
        "Read a plane-owned page of committed object create, update, and delete facts.".into(),
        "query",
        "sekai.ReadObjectChangeSubscriptionRequest",
        "sekai.ReadObjectChangeSubscriptionResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "object_acl".into(),
        "event_subscription".into(),
    ];
    entry.limits = vec![
        CapabilityLimit {
            name: "max_page".into(),
            value: crate::sekai::object_change_subscription::MAX_PAGE as u64,
        },
        CapabilityLimit {
            name: "max_backlog".into(),
            value: crate::sekai::object_change_subscription::MAX_BACKLOG as u64,
        },
    ];
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

/// Policy every hop of ExpandNeighborhood and FindPaths applies, as Traverse does.
fn graph_explore_policy_points() -> Vec<String> {
    [
        "namespace_access",
        "row_filter",
        "object_acl",
        "marking",
        "marking_path_join",
        "purpose",
        "property_grant",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn neighborhood_capability(enabled: bool) -> CapabilityEntry {
    use super::graph_explore_rpc as explore;
    let mut entry = base_capability(
        explore::NEIGHBORHOOD_CAPABILITY.into(),
        "Expand seed objects over links in both directions with depth, fan-out and size caps; hidden objects are omitted.".into(),
        "query",
        "sekai.ExpandNeighborhoodRequest",
        "sekai.ExpandNeighborhoodResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = graph_explore_policy_points();
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry.limits = vec![
        CapabilityLimit {
            name: "max_depth".into(),
            value: explore::MAX_DEPTH as u64,
        },
        CapabilityLimit {
            name: "max_seeds".into(),
            value: explore::MAX_SEEDS as u64,
        },
        CapabilityLimit {
            name: "max_fan_out".into(),
            value: explore::MAX_FAN_OUT as u64,
        },
        CapabilityLimit {
            name: "max_nodes".into(),
            value: explore::MAX_NODES as u64,
        },
        CapabilityLimit {
            name: "examination_budget".into(),
            value: explore::EXAMINATION_BUDGET as u64,
        },
        CapabilityLimit {
            name: "scan_limit".into(),
            value: explore::SCAN_LIMIT as u64,
        },
    ];
    entry
}

fn paths_capability(enabled: bool) -> CapabilityEntry {
    use super::graph_explore_rpc as explore;
    let mut entry = base_capability(
        explore::PATHS_CAPABILITY.into(),
        "Shortest link paths between two readable objects through the caller's visible graph."
            .into(),
        "query",
        "sekai.FindPathsRequest",
        "sekai.FindPathsResponse",
    );
    entry.required_scopes = vec!["namespace:read".into(), "object:read".into()];
    entry.policy_decision_points = graph_explore_policy_points();
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry.limits = vec![
        CapabilityLimit {
            name: "max_depth".into(),
            value: explore::MAX_DEPTH as u64,
        },
        CapabilityLimit {
            name: "max_paths".into(),
            value: explore::MAX_PATHS as u64,
        },
        CapabilityLimit {
            name: "examination_budget".into(),
            value: explore::EXAMINATION_BUDGET as u64,
        },
        CapabilityLimit {
            name: "scan_limit".into(),
            value: explore::SCAN_LIMIT as u64,
        },
    ];
    entry
}

fn semantic_reasoning_limits(entailment: bool) -> Vec<CapabilityLimit> {
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
            value: u64::from(entailment),
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
            value: 1,
        },
    ]
}

fn expand_relations_capability(entailment: bool) -> CapabilityEntry {
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
    entry.limits = semantic_reasoning_limits(entailment);
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

fn retrieve_context_capability(entailment: bool) -> CapabilityEntry {
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
    entry.limits = semantic_reasoning_limits(entailment);
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

fn explain_derivation_capability(entailment: bool) -> CapabilityEntry {
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
    entry.limits = semantic_reasoning_limits(entailment);
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

fn search_query_capability(enabled: bool) -> CapabilityEntry {
    let mut entry = base_capability(
        super::search_rpc::SEARCH_CAPABILITY.into(),
        "Permission-aware text and hybrid (text plus vector) search over objects and dataset metadata. Discovery is not a grant.".into(),
        "query",
        "sekai.SearchRequest",
        "sekai.SearchResponse",
    );
    entry.required_scopes = vec!["namespace:discover".into(), "object:read".into()];
    entry.policy_decision_points = vec![
        "namespace_access".into(),
        "marking".into(),
        "object_acl".into(),
        "property_grant".into(),
        "row_filter".into(),
    ];
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry.limits = vec![
        CapabilityLimit {
            name: "max_page".into(),
            value: super::search_rpc::MAX_PAGE_SIZE as u64,
        },
        CapabilityLimit {
            name: "candidate_cap".into(),
            value: super::search_rpc::CANDIDATE_CAP as u64,
        },
    ];
    entry
}

fn search_status_capability(enabled: bool) -> CapabilityEntry {
    let mut entry = base_capability(
        super::search_rpc::SEARCH_STATUS_CAPABILITY.into(),
        "Per-namespace search index lag and analyzer identity. Not authority.".into(),
        "query",
        "sekai.GetSearchIndexStatusRequest",
        "sekai.GetSearchIndexStatusResponse",
    );
    entry.required_scopes = vec!["namespace:read".into()];
    entry.policy_decision_points = vec!["namespace_access".into()];
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry
}

fn experimental_rpc_capability(enabled: bool) -> CapabilityEntry {
    let mut entry = base_capability(
        crate::rpc_maturity::EXPERIMENTAL_CAPABILITY.into(),
        "Explicit capability to invoke experimental or remove-classified RPCs. Off by default; visibility is not a grant."
            .into(),
        "runtime",
        "sekai.DiscoverCapabilitiesRequest",
        "sekai.DiscoverCapabilitiesResponse",
    );
    entry.lifecycle_state = if enabled { "active" } else { "disabled" }.into();
    entry.limits = vec![CapabilityLimit {
        name: "enabled".into(),
        value: u64::from(enabled),
    }];
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_transform_capability_is_disabled_when_experimental_rpcs_are_off() {
        let off = hosted_transform_capability(false);
        assert_eq!(off.lifecycle_state, "disabled");
        assert_eq!(
            off.name,
            crate::sekai::governed_transform::HOSTED_COMPUTE_CAPABILITY
        );

        let on = hosted_transform_capability(true);
        assert_eq!(on.lifecycle_state, "active");
    }

    #[test]
    fn analytical_transform_capability_is_disabled_when_experimental_rpcs_are_off() {
        let off = analytical_transform_capability(false);
        assert_eq!(off.lifecycle_state, "disabled");
        assert_eq!(
            off.name,
            crate::sekai::governed_transform::ANALYTICAL_COMPUTE_CAPABILITY
        );
    }

    #[test]
    fn isolated_transform_capability_is_disabled_when_experimental_rpcs_are_off() {
        let off = isolated_transform_capability(false);
        assert_eq!(off.lifecycle_state, "disabled");
        assert_eq!(
            off.name,
            crate::sekai::governed_transform::ISOLATED_COMPUTE_CAPABILITY
        );
        let on = isolated_transform_capability(true);
        assert_eq!(on.lifecycle_state, "active");
    }

    #[test]
    fn preview_transform_capability_is_disabled_when_experimental_rpcs_are_off() {
        let off = preview_transform_capability(false);
        assert_eq!(off.lifecycle_state, "disabled");
        assert_eq!(
            off.name,
            crate::sekai::governed_transform::PREVIEW_COMPUTE_CAPABILITY
        );
        let on = preview_transform_capability(true);
        assert_eq!(on.lifecycle_state, "active");
    }

    #[test]
    fn scheduler_transform_capability_is_disabled_when_experimental_rpcs_are_off() {
        let off = scheduler_transform_capability(false);
        assert_eq!(off.lifecycle_state, "disabled");
        assert_eq!(
            off.name,
            crate::sekai::governed_transform::SCHEDULER_COMPUTE_CAPABILITY
        );
        let on = scheduler_transform_capability(true);
        assert_eq!(on.lifecycle_state, "active");
    }

    #[test]
    fn graph_explore_capabilities_follow_the_experimental_gate() {
        for (entry, backing) in [
            (neighborhood_capability(false), "ExpandNeighborhood"),
            (paths_capability(false), "FindPaths"),
        ] {
            assert_eq!(entry.lifecycle_state, "disabled");
            assert_eq!(entry.product_tier, "experimental");
            assert_eq!(
                crate::rpc_maturity::capability_backing_rpc(&entry.name),
                Some(backing)
            );
        }
        assert_eq!(neighborhood_capability(true).lifecycle_state, "active");
        assert_eq!(paths_capability(true).lifecycle_state, "active");
    }

    #[test]
    fn search_capabilities_are_disabled_when_experimental_rpcs_are_off() {
        let off = search_query_capability(false);
        assert_eq!(off.lifecycle_state, "disabled");
        assert_eq!(off.name, "sekai.search.query");
        assert_eq!(off.product_tier, "experimental");
        let on = search_query_capability(true);
        assert_eq!(on.lifecycle_state, "active");
        let status = search_status_capability(false);
        assert_eq!(status.lifecycle_state, "disabled");
        assert_eq!(status.name, "sekai.search.status");
    }
}
