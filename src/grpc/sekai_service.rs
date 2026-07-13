#![allow(clippy::result_large_err, clippy::collapsible_if, clippy::manual_clamp)]

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

use super::pb::sekai::sekai_service_server::SekaiService;
use super::pb::sekai::*;
use crate::chisei::scoring::{KnowledgeWriteOutcome, KnowledgeWriteRequest, KnowledgeWriter};
use crate::db::sekai::SekaiDb;
use crate::domain;
use crate::gateway_keys::hash_gateway_key;
use crate::sekai::action::{self, ActionExecutor, RiskClass};
use crate::sekai::action_approval;
use crate::sekai::action_policy::{self, ActionDecision};
use crate::sekai::attestation;
use crate::sekai::evidence as evidence_domain;
use crate::sekai::evidence_projection::EvidenceProjectionOutcome;
use crate::sekai::evidence_store::{
    EvidenceAdmission, EvidenceProducerCapability as DomainEvidenceProducerCapability,
    EvidenceSchemaDefinition as DomainEvidenceSchemaDefinition, EvidenceSubmissionFilter,
    EvidenceSubmissionRecord as DomainEvidenceSubmissionRecord,
};
use crate::sekai::schema::{self, SchemaRegistry};
use crate::sekai::security::SecurityChecker;
use crate::sekai::{audit, compute, coordination, dataset, function, retrieval, security};
use uuid::Uuid;

const REDACTED_VALUE: &str = "[redacted]";

pub struct SekaiServiceImpl {
    db: Arc<SekaiDb>,
    actions: Arc<RwLock<ActionExecutor>>,
    security: Arc<SecurityChecker>,
    schema: Arc<RwLock<SchemaRegistry>>,
    schema_unavailable_error: Arc<RwLock<Option<String>>>,
    schema_load_errors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    budget: Option<Arc<crate::chisei::budget::BudgetTracker>>,
}

impl SekaiServiceImpl {
    pub fn new(db: Arc<SekaiDb>) -> Self {
        let security = Arc::new(SecurityChecker::new());
        let grants = db.list_all_grants().unwrap_or_default();
        security.load(&grants);
        let action_types = match db.list_action_types() {
            Ok(action_types) => action_types,
            Err(error) => {
                tracing::error!(%error, "failed to load action types");
                Vec::new()
            }
        };
        let actions = match ActionExecutor::from_action_types(action_types) {
            Ok(actions) => actions,
            Err(error) => {
                tracing::error!(%error, "failed to initialize action registry");
                ActionExecutor::new()
            }
        };
        let (types, schema_unavailable_error, schema_load_errors) =
            match db.list_object_types_with_errors() {
                Ok((types, errors)) => {
                    for (kind, error) in &errors {
                        tracing::error!(kind, %error, "failed to load schema type");
                    }
                    (types, None, errors)
                }
                Err(error) => {
                    tracing::error!(%error, "failed to load schema types");
                    (Vec::new(), Some(error), std::collections::HashMap::new())
                }
            };
        let interfaces = match db.list_interfaces() {
            Ok(interfaces) => interfaces,
            Err(error) => {
                tracing::error!(%error, "failed to load interfaces");
                Vec::new()
            }
        };
        let registry = SchemaRegistry::from_types_and_interfaces(types, interfaces);
        let schema = Arc::new(RwLock::new(registry));
        Self {
            db,
            actions: Arc::new(RwLock::new(actions)),
            security,
            schema,
            schema_unavailable_error: Arc::new(RwLock::new(schema_unavailable_error)),
            schema_load_errors: Arc::new(RwLock::new(schema_load_errors)),
            budget: None,
        }
    }

    /// Construct sharing a chisei budget tracker so governed actions can be
    /// metered against action-class budgets (Plan 9, Phase C).
    pub fn with_budget(
        db: Arc<SekaiDb>,
        budget: Arc<crate::chisei::budget::BudgetTracker>,
    ) -> Self {
        let mut svc = Self::new(db);
        svc.budget = Some(budget);
        svc
    }

    fn require_schema_kind_loaded(&self, kind: &str) -> Result<(), Status> {
        self.recover_schema_registry()?;
        let errors = self
            .schema_load_errors
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        if let Some(error) = errors.get(kind) {
            return Err(Status::internal(format!(
                "schema type {kind} unavailable: {error}"
            )));
        }
        Ok(())
    }

    /// Execute an action's effect (target auth + schema validation + mutation +
    /// audit) without policy gating. Used to resume an approved held action.
    /// `principals` are the identities re-checked for write access at execution
    /// time. Returns the executor's success message.
    fn run_action_effect(
        &self,
        action_name: &str,
        params: &HashMap<String, String>,
        actor: &str,
        principals: &[String],
    ) -> Result<String, Status> {
        let actions = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?;
        let mask_missing_link = actions.masks_missing_link(action_name);
        let sensitive_params = actions.sensitive_param_names(action_name);
        let target_ids = actions
            .target_ids(&self.db, action_name, params)
            .map_err(|err| {
                if mask_missing_link && err == "link not found" {
                    Status::permission_denied("write denied")
                } else {
                    Status::invalid_argument(err)
                }
            })?;
        for target_id in &target_ids {
            check_write(&self.security, target_id, principals)?;
        }
        let schema_kinds = actions
            .schema_kinds(&self.db, action_name, params)
            .map_err(Status::invalid_argument)?;
        for kind in schema_kinds {
            self.require_schema_kind_loaded(&kind)?;
        }
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        actions
            .validate_action_schema(action_name, &schema)
            .map_err(Status::invalid_argument)?;
        let schema_restricted_property =
            schema_restricted_action_property(&self.db, &schema, params);
        let provisional_learning_grant = (action_name
            == crate::sekai::learning::RECORD_LEARNING_ACTION)
            .then(|| security::Grant {
                id: String::new(),
                object_id: params.get("id").cloned().unwrap_or_default(),
                principal: actor.to_string(),
                role: security::Role::Admin,
                created: now_millis(),
            })
            .filter(|grant| !grant.object_id.is_empty());
        if let Some(grant) = &provisional_learning_grant {
            self.security.add_grant(grant);
        }
        let msg = match actions.execute(&self.db, &schema, action_name, params, actor) {
            Ok(msg) => msg,
            Err(error) => {
                if let Some(grant) = &provisional_learning_grant {
                    self.security
                        .remove_grant(&grant.object_id, &grant.principal);
                }
                return Err(Status::invalid_argument(error));
            }
        };
        drop(actions);
        drop(schema);
        self.refresh_security_after_action(action_name, params, actor)?;
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now_millis(),
                actor: actor.to_string(),
                action: action_name.to_string(),
                reason: "execute_action".into(),
                evidence: redact_action_evidence(
                    params,
                    &sensitive_params,
                    schema_restricted_property,
                ),
                target_id: target_ids.first().cloned().unwrap_or_default(),
                outcome: redact_action_outcome(
                    action_name,
                    params,
                    &msg,
                    schema_restricted_property,
                ),
            })
            .map_err(Status::internal)?;
        Ok(msg)
    }

    fn refresh_security_after_action(
        &self,
        action_name: &str,
        params: &HashMap<String, String>,
        actor: &str,
    ) -> Result<(), Status> {
        if action_name != crate::sekai::learning::RECORD_LEARNING_ACTION {
            return Ok(());
        }
        let learning_id = params
            .get("id")
            .ok_or_else(|| Status::internal("record_learning id missing after execution"))?;
        let grants = self.db.list_grants(learning_id).map_err(Status::internal)?;
        if grants.is_empty() {
            return Err(Status::internal(
                "record_learning completed without a learning ACL",
            ));
        }
        self.security.remove_grant(learning_id, actor);
        for grant in &grants {
            self.security.add_grant(grant);
        }
        Ok(())
    }

    fn resolve_computed_for_response(
        &self,
        mut object: domain::Object,
        principals: &[String],
    ) -> Result<domain::Object, Status> {
        let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .clone();
        compute::resolve_schema_computed_with_filter(&mut object, &self.db, &schema, |candidate| {
            !is_reserved_governance_kind(&candidate.kind)
                && self.security.can_access(&candidate.id, &refs)
        })
        .map_err(Status::internal)?;
        Ok(redact_restricted_properties(
            object,
            &schema,
            &self.security,
            principals,
        ))
    }

    fn resolve_computed_for_responses(
        &self,
        objects: Vec<domain::Object>,
        principals: &[String],
    ) -> Result<Vec<domain::Object>, Status> {
        objects
            .into_iter()
            .map(|object| self.resolve_computed_for_response(object, principals))
            .collect()
    }

    fn recover_schema_registry(&self) -> Result<(), Status> {
        let current_error = self
            .schema_unavailable_error
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .clone();
        if current_error.is_none() {
            return Ok(());
        }

        match (
            self.db.list_object_types_with_errors(),
            self.db.list_interfaces(),
        ) {
            (Ok((types, errors)), Ok(interfaces)) => {
                for (kind, error) in &errors {
                    tracing::error!(kind, %error, "failed to load schema type");
                }
                *self
                    .schema
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? =
                    SchemaRegistry::from_types_and_interfaces(types, interfaces);
                *self
                    .schema_load_errors
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? = errors;
                *self
                    .schema_unavailable_error
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? = None;
                Ok(())
            }
            (Err(error), _) | (_, Err(error)) => {
                *self
                    .schema_unavailable_error
                    .write()
                    .map_err(|_| Status::internal("schema registry unavailable"))? =
                    Some(error.clone());
                Err(Status::internal(format!(
                    "schema registry unavailable: {error}"
                )))
            }
        }
    }
    fn admit_and_project_evidence(
        &self,
        envelope: &evidence_domain::EvidenceEnvelope,
        producer: &str,
        now_ms: i64,
    ) -> Result<EvidenceSubmissionResult, Status> {
        let admission = self
            .db
            .submit_evidence(envelope, producer, now_ms)
            .map_err(|_| Status::internal("evidence admission failed"))?;
        let projection = if admission.accepted {
            Some(
                self.db
                    .project_evidence_submission(&admission.submission.id, now_ms)
                    .map_err(|_| Status::internal("evidence projection failed"))?,
            )
        } else {
            None
        };
        if let Some(object_id) = projection
            .as_ref()
            .and_then(|projection| projection.evidence_object_id.as_deref())
        {
            for grant in self.db.list_grants(object_id).map_err(Status::internal)? {
                self.security.add_grant(&grant);
            }
        }
        evidence_submission_result(&self.db, admission, projection)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_evidence_lifecycle_marker(
        &self,
        submission_id: String,
        source_version: String,
        source_sequence: i64,
        idempotency_key: String,
        observed_at_ms: i64,
        intent: evidence_domain::EvidenceIntent,
        principals: &[String],
    ) -> Result<EvidenceSubmissionResult, Status> {
        let original = self
            .db
            .get_evidence_submission(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("evidence submission not found"))?;
        if !principals.contains(&original.producer_identity) {
            return Err(Status::permission_denied(
                "only the authenticated source producer may change evidence lifecycle",
            ));
        }
        if original.intent != evidence_domain::EvidenceIntent::Upsert
            || original.lifecycle_state != evidence_domain::EvidenceLifecycleState::Available
        {
            return Err(Status::failed_precondition(
                "only currently available source evidence can receive a lifecycle marker",
            ));
        }
        if source_version.trim().is_empty()
            || idempotency_key.trim().is_empty()
            || source_sequence <= original.source_sequence
        {
            return Err(Status::invalid_argument(
                "lifecycle marker requires a new source version, idempotency key, and higher source sequence",
            ));
        }
        let now_ms = now_millis();
        let mut marker = original
            .envelope
            .ok_or_else(|| Status::internal("available evidence envelope missing"))?;
        marker.source_version = source_version;
        marker.source_sequence = source_sequence;
        marker.observed_at_ms = if observed_at_ms == 0 {
            now_ms
        } else {
            observed_at_ms
        };
        marker.collected_at_ms = now_ms;
        marker.expires_at_ms = None;
        marker.relationships.clear();
        marker.content = serde_json::json!({
            "lifecycle_intent": match intent {
                evidence_domain::EvidenceIntent::Retract => "retract",
                evidence_domain::EvidenceIntent::MarkStale => "mark_stale",
                evidence_domain::EvidenceIntent::Upsert => "upsert",
            },
            "prior_content_digest": original.content_digest,
        });
        marker.content_digest =
            crate::sekai::evidence_store::canonical_content_digest(&marker.content)
                .map_err(Status::internal)?;
        marker.idempotency_key = idempotency_key;
        marker.intent = intent;
        marker
            .provenance
            .insert("lifecycle_marker".into(), "server_constructed".into());
        self.admit_and_project_evidence(&marker, &original.producer_identity, now_ms)
    }
}

fn caller_principals(req: &Request<impl std::any::Any>) -> Vec<String> {
    req.metadata()
        .get("x-principal")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["anonymous".to_string()])
}

fn work_unit_from_metadata(req: &Request<impl std::any::Any>) -> String {
    req.metadata()
        .get("x-chisei-work-unit")
        .or_else(|| req.metadata().get("x-chisei-task-id"))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

fn require_authenticated(principals: &[String]) -> Result<(), Status> {
    if principals.is_empty() || principals.iter().all(|principal| principal == "anonymous") {
        return Err(Status::unauthenticated("principal required"));
    }
    Ok(())
}

fn require_evidence_admin(security: &SecurityChecker, principals: &[String]) -> Result<(), Status> {
    let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("evidence", &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("evidence admin required"))
}

fn can_operate_evidence_submission(
    security: &SecurityChecker,
    submission: &DomainEvidenceSubmissionRecord,
    principals: &[String],
) -> bool {
    principals
        .iter()
        .any(|principal| principal == &submission.producer_identity)
        || require_evidence_admin(security, principals).is_ok()
}

fn parse_evidence_classification(
    value: &str,
) -> Result<evidence_domain::EvidenceClassification, Status> {
    match value.trim() {
        "public" => Ok(evidence_domain::EvidenceClassification::Public),
        "internal" => Ok(evidence_domain::EvidenceClassification::Internal),
        "confidential" => Ok(evidence_domain::EvidenceClassification::Confidential),
        "restricted" => Ok(evidence_domain::EvidenceClassification::Restricted),
        _ => Err(Status::invalid_argument("invalid evidence classification")),
    }
}

fn parse_evidence_intent(value: &str) -> Result<evidence_domain::EvidenceIntent, Status> {
    match value.trim() {
        "upsert" => Ok(evidence_domain::EvidenceIntent::Upsert),
        "retract" => Ok(evidence_domain::EvidenceIntent::Retract),
        "mark_stale" => Ok(evidence_domain::EvidenceIntent::MarkStale),
        _ => Err(Status::invalid_argument("invalid evidence intent")),
    }
}

fn parse_evidence_signal(value: &str) -> Result<evidence_domain::EvidenceSignal, Status> {
    match value.trim() {
        "acceptance" => Ok(evidence_domain::EvidenceSignal::Acceptance),
        "verification" => Ok(evidence_domain::EvidenceSignal::Verification),
        "delivery" => Ok(evidence_domain::EvidenceSignal::Delivery),
        "regression" => Ok(evidence_domain::EvidenceSignal::Regression),
        "resource_use" => Ok(evidence_domain::EvidenceSignal::ResourceUse),
        "operational_health" => Ok(evidence_domain::EvidenceSignal::OperationalHealth),
        "other" => Ok(evidence_domain::EvidenceSignal::Other),
        _ => Err(Status::invalid_argument("invalid evidence signal")),
    }
}

fn parse_schema_compatibility(value: &str) -> Result<evidence_domain::SchemaCompatibility, Status> {
    match value.trim() {
        "exact" => Ok(evidence_domain::SchemaCompatibility::Exact),
        "backward_compatible" => Ok(evidence_domain::SchemaCompatibility::BackwardCompatible),
        _ => Err(Status::invalid_argument(
            "invalid evidence schema compatibility",
        )),
    }
}

fn optional_nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn from_proto_evidence_envelope(
    envelope: EvidenceEnvelope,
) -> Result<evidence_domain::EvidenceEnvelope, Status> {
    let confidence_bps = u16::try_from(envelope.confidence_bps)
        .map_err(|_| Status::invalid_argument("confidence_bps out of range"))?;
    let content = serde_json::from_slice(&envelope.content_json)
        .map_err(|_| Status::invalid_argument("content_json must contain valid JSON"))?;
    let causality = envelope
        .causality
        .map(|causality| evidence_domain::EvidenceCausality {
            operation_id: optional_nonempty(causality.operation_id),
            parent_operation_id: optional_nonempty(causality.parent_operation_id),
            attempt_id: optional_nonempty(causality.attempt_id),
            model_call_id: optional_nonempty(causality.model_call_id),
            subject_references: causality.subject_references,
            trace_context: causality.trace_context.into_iter().collect(),
        });
    Ok(evidence_domain::EvidenceEnvelope {
        contract_version: envelope.contract_version,
        source_type: envelope.source_type,
        source_instance: envelope.source_instance,
        source_record_id: envelope.source_record_id,
        source_version: envelope.source_version,
        source_sequence: envelope.source_sequence,
        target: evidence_domain::EvidenceTarget {
            namespace: envelope.namespace,
            object_external_id: envelope.target_external_id,
            object_kind: envelope.target_kind,
        },
        evidence_type: envelope.evidence_type,
        signal: parse_evidence_signal(&envelope.signal)?,
        schema_id: envelope.schema_id,
        schema_version: envelope.schema_version,
        schema_compatibility: parse_schema_compatibility(&envelope.schema_compatibility)?,
        observed_at_ms: envelope.observed_at_ms,
        collected_at_ms: envelope.collected_at_ms,
        expires_at_ms: envelope.expires_at_ms,
        content,
        relationships: envelope
            .relationships
            .into_iter()
            .map(|relationship| evidence_domain::EvidenceRelationship {
                relation: relationship.relation,
                target_source_type: relationship.target_source_type,
                target_source_instance: relationship.target_source_instance,
                target_source_record_id: relationship.target_source_record_id,
            })
            .collect(),
        producer_identity: envelope.producer_identity,
        confidence_bps,
        classification: parse_evidence_classification(&envelope.classification)?,
        provenance: envelope.provenance.into_iter().collect(),
        idempotency_key: envelope.idempotency_key,
        content_digest: envelope.content_digest,
        intent: parse_evidence_intent(&envelope.intent)?,
        causality,
    })
}

fn from_proto_evidence_producer(
    capability: EvidenceProducerCapability,
) -> Result<DomainEvidenceProducerCapability, Status> {
    let max_payload_bytes = usize::try_from(capability.max_payload_bytes)
        .map_err(|_| Status::invalid_argument("max_payload_bytes out of range"))?;
    let max_relationships = usize::try_from(capability.max_relationships)
        .map_err(|_| Status::invalid_argument("max_relationships out of range"))?;
    let allowed_intents = capability
        .allowed_intents
        .iter()
        .map(|intent| parse_evidence_intent(intent))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DomainEvidenceProducerCapability {
        producer_identity: capability.producer_identity,
        config_version: capability.config_version,
        source_instances: capability.source_instances,
        namespaces: capability.namespaces,
        evidence_types: capability.evidence_types,
        target_kinds: capability.target_kinds,
        classification_ceiling: parse_evidence_classification(&capability.classification_ceiling)?,
        allowed_intents,
        allow_operation_attachment: capability.allow_operation_attachment,
        replay_window_ms: capability.replay_window_ms,
        max_clock_skew_ms: capability.max_clock_skew_ms,
        max_payload_bytes,
        max_relationships,
        rate_limit_per_minute: capability.rate_limit_per_minute,
        revoked: capability.revoked,
    })
}

fn to_proto_evidence_submission(
    submission: &DomainEvidenceSubmissionRecord,
) -> EvidenceSubmissionRecord {
    EvidenceSubmissionRecord {
        id: submission.id.clone(),
        producer_identity: submission.producer_identity.clone(),
        source_type: submission.source_type.clone(),
        source_instance: submission.source_instance.clone(),
        source_record_id: submission.source_record_id.clone(),
        source_version: submission.source_version.clone(),
        source_sequence: submission.source_sequence,
        namespace: submission.namespace.clone(),
        target_external_id: submission.target_external_id.clone(),
        target_kind: submission.target_kind.clone(),
        evidence_type: submission.evidence_type.clone(),
        schema_id: submission.schema_id.clone(),
        schema_version: submission.schema_version.clone(),
        content_digest: submission.content_digest.clone(),
        classification: submission.classification.as_str().into(),
        intent: match submission.intent {
            evidence_domain::EvidenceIntent::Upsert => "upsert",
            evidence_domain::EvidenceIntent::Retract => "retract",
            evidence_domain::EvidenceIntent::MarkStale => "mark_stale",
        }
        .into(),
        lifecycle_state: submission.lifecycle_state.as_str().into(),
        rejection_code: submission.rejection_code.clone().unwrap_or_default(),
        rejection_summary: submission.rejection_summary.clone().unwrap_or_default(),
        observed_at_ms: submission.observed_at_ms,
        collected_at_ms: submission.collected_at_ms,
        expires_at_ms: submission.expires_at_ms,
        received_at_ms: submission.received_at_ms,
        updated_at_ms: submission.updated_at_ms,
    }
}

fn evidence_submission_result(
    db: &SekaiDb,
    admission: EvidenceAdmission,
    projection: Option<EvidenceProjectionOutcome>,
) -> Result<EvidenceSubmissionResult, Status> {
    let submission = db
        .get_evidence_submission(&admission.submission.id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::internal("evidence submission disappeared"))?;
    Ok(EvidenceSubmissionResult {
        submission: Some(to_proto_evidence_submission(&submission)),
        admitted: admission.accepted,
        deduplicated: admission.deduplicated,
        projected: projection.is_some_and(|projection| projection.projected),
    })
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn redact_action_evidence(
    params: &std::collections::HashMap<String, String>,
    sensitive_params: &std::collections::HashSet<String>,
    schema_restricted_property: Option<bool>,
) -> std::collections::HashMap<String, String> {
    params
        .iter()
        // Reserved evidence keys are written by the attestation binding, not
        // by callers; a param with the same name must not be able to plant a
        // fake attestation reference in the audit log.
        .filter(|(key, _)| {
            key.as_str() != attestation::EVIDENCE_ATTESTATION_ID
                && key.as_str() != attestation::EVIDENCE_ATTESTATION_HASH
        })
        .map(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            let sensitive_property = params
                .get("key")
                .or_else(|| params.get("property"))
                .map(|property| {
                    schema_restricted_property.unwrap_or_else(|| is_sensitive_name(property))
                })
                .unwrap_or(false);
            let value = if is_sensitive_name(&lower)
                || sensitive_params.contains(key)
                || ((lower == "value" || lower == "new_value") && sensitive_property)
            {
                "[redacted]".to_string()
            } else {
                value.clone()
            };
            (key.clone(), value)
        })
        .collect()
}

fn redact_action_outcome(
    action: &str,
    params: &std::collections::HashMap<String, String>,
    outcome: &str,
    schema_restricted_property: Option<bool>,
) -> String {
    if action == "set_property"
        && params
            .get("key")
            .map(|property| {
                schema_restricted_property.unwrap_or_else(|| is_sensitive_name(property))
            })
            .unwrap_or(false)
    {
        return format!(
            "set {}.{} = [redacted]",
            params.get("id").cloned().unwrap_or_default(),
            params.get("key").cloned().unwrap_or_default()
        );
    }
    outcome.to_string()
}

fn schema_restricted_action_property(
    db: &SekaiDb,
    schema: &schema::SchemaRegistry,
    params: &std::collections::HashMap<String, String>,
) -> Option<bool> {
    let property_name = params.get("key").or_else(|| params.get("property"))?;
    let object_id = params.get("id").or_else(|| params.get("object_id"))?;
    let object = db.get_object(object_id).ok().flatten()?;
    let object_type = schema.get(&object.kind)?;
    let property = object_type
        .properties
        .iter()
        .find(|property| property.name == *property_name)?;
    Some(schema::is_restricted_property_classification(
        &property.classification,
    ))
}

fn is_sensitive_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("key")
        || lower.contains("password")
        || lower.contains("passphrase")
        || lower.contains("passwd")
        || lower.contains("credential")
}

fn check_read(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_access(object_id, &refs) {
        return Err(Status::permission_denied("access denied"));
    }
    Ok(())
}

fn check_write(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_write(object_id, &refs) {
        return Err(Status::permission_denied("write denied"));
    }
    Ok(())
}

fn check_schema_admin(
    security: &SecurityChecker,
    kind: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("schema", &refs)
        || security.can_admin(&schema_object_id(kind), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("schema admin required"))
}

fn check_interface_admin(
    security: &SecurityChecker,
    name: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("schema", &refs)
        || security.can_admin(&interface_object_id(name), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("interface admin required"))
}

fn check_action_admin(
    security: &SecurityChecker,
    name: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
        || security.can_admin("action", &refs)
        || security.can_admin(&action_object_id(name), &refs)
    {
        return Ok(());
    }
    Err(Status::permission_denied("action admin required"))
}

fn principal_matches(owner_principal: &str, principals: &[String]) -> bool {
    !owner_principal.is_empty()
        && principals
            .iter()
            .any(|principal| principal == owner_principal)
}

fn check_scope_read(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    if principal_matches(&scope.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("scope access denied"))
    }
}

fn check_scope_write(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    check_scope_read(scope, principals)
}

fn check_work_unit_read(
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_read(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit access denied"))
    }
}

fn check_work_unit_write(
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_write(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit write denied"))
    }
}

const DEFAULT_LIST_LIMIT: i32 = domain::DEFAULT_LIST_LIMIT;
const MAX_LIST_LIMIT: i32 = domain::MAX_LIST_LIMIT;

fn read_limit_offset(limit: i32, offset: i32) -> Result<(i32, i32), Status> {
    if offset < 0 {
        return Err(Status::invalid_argument("offset must be >= 0"));
    }
    let effective_limit = if limit <= 0 {
        DEFAULT_LIST_LIMIT
    } else {
        limit.min(MAX_LIST_LIMIT)
    };
    Ok((effective_limit, offset))
}

fn parse_property_operator(op: &str) -> Result<&'static str, Status> {
    match op.to_lowercase().as_str() {
        "eq" => Ok("eq"),
        "ne" | "neq" => Ok("ne"),
        "gt" => Ok("gt"),
        "gte" => Ok("gte"),
        "lt" => Ok("lt"),
        "lte" => Ok("lte"),
        "contains" => Ok("contains"),
        "prefix" => Ok("prefix"),
        "in" => Ok("in"),
        other => Err(Status::invalid_argument(format!(
            "unsupported property operator: {other}"
        ))),
    }
}

fn parse_order_by(order_by: &str) -> Result<String, Status> {
    if order_by.is_empty() {
        return Ok(String::new());
    }
    let normalized = order_by.trim().to_lowercase();
    if normalized == "name" || normalized == "created" || normalized == "updated" {
        return Ok(normalized);
    }
    if let Some((prefix, key)) = order_by.trim().split_once(':') {
        if !prefix.eq_ignore_ascii_case("property") {
            return Err(Status::invalid_argument("unsupported order_by"));
        }
        if !domain::is_valid_property_key(key) {
            return Err(Status::invalid_argument("invalid property key"));
        }
        return Ok(format!("property:{}", key.trim()));
    }
    Err(Status::invalid_argument("unsupported order_by"))
}

fn parse_list_filter(f: ListFilter) -> Result<domain::ListFilter, Status> {
    let (limit, offset) = read_limit_offset(f.limit, f.offset)?;
    let mut property_filters = Vec::new();
    for pf in f.property_filters {
        if !domain::is_valid_property_key(&pf.key) {
            return Err(Status::invalid_argument("invalid property key"));
        }
        property_filters.push(domain::PropertyFilter {
            key: pf.key,
            op: parse_property_operator(&pf.op)?.to_string(),
            value: pf.value,
        });
    }
    let interface_filter = parse_interface_filter(f.interface_filter)?;
    let order_by = parse_order_by(&f.order_by)?;
    Ok(domain::ListFilter {
        kind: if f.kind.is_empty() {
            None
        } else {
            Some(f.kind)
        },
        name: if f.name.is_empty() {
            None
        } else {
            Some(f.name)
        },
        namespace: if f.namespace.is_empty() {
            None
        } else {
            Some(f.namespace)
        },
        property_filters,
        interface_filter,
        limit,
        offset,
        order_by,
        descending: f.descending,
    })
}

fn to_proto_object_set(set: &domain::ObjectSet) -> ObjectSet {
    ObjectSet {
        id: set.id.clone(),
        name: set.name.clone(),
        description: set.description.clone(),
        filter: Some(to_proto_list_filter(&set.filter)),
        owner_principal: set.owner_principal.clone(),
        created: set.created,
    }
}

fn to_proto_list_filter(filter: &domain::ListFilter) -> ListFilter {
    ListFilter {
        kind: filter.kind.clone().unwrap_or_default(),
        name: filter.name.clone().unwrap_or_default(),
        namespace: filter.namespace.clone().unwrap_or_default(),
        property_filters: filter
            .property_filters
            .iter()
            .map(|pf| PropertyFilter {
                key: pf.key.clone(),
                op: pf.op.clone(),
                value: pf.value.clone(),
            })
            .collect(),
        limit: filter.limit,
        offset: filter.offset,
        order_by: filter.order_by.clone(),
        descending: filter.descending,
        interface_filter: filter.interface_filter.clone(),
    }
}

fn parse_set_filter_from_request(input: &ObjectSet) -> Result<domain::ListFilter, Status> {
    let filter = input
        .filter
        .clone()
        .ok_or(Status::invalid_argument("filter required"))?;
    let mut property_filters = Vec::new();
    for pf in filter.property_filters {
        if !domain::is_valid_property_key(&pf.key) {
            return Err(Status::invalid_argument("invalid property key"));
        }
        property_filters.push(domain::PropertyFilter {
            key: pf.key,
            op: parse_property_operator(&pf.op)?.to_string(),
            value: pf.value,
        });
    }
    let interface_filter = parse_interface_filter(filter.interface_filter)?;
    if filter.offset < 0 {
        return Err(Status::invalid_argument("offset must be >= 0"));
    }
    let order_by = parse_order_by(&filter.order_by)?;
    Ok(domain::ListFilter {
        kind: if filter.kind.is_empty() {
            None
        } else {
            Some(filter.kind)
        },
        name: if filter.name.is_empty() {
            None
        } else {
            Some(filter.name)
        },
        namespace: if filter.namespace.is_empty() {
            None
        } else {
            Some(filter.namespace)
        },
        property_filters,
        interface_filter,
        // Keep zero/negative input as "use runtime request default" for resolves.
        // Callers should treat persisted ObjectSet filters as declarative query
        // descriptors, not already-paginated result sets.
        limit: if filter.limit <= 0 {
            0
        } else {
            filter.limit.min(MAX_LIST_LIMIT)
        },
        offset: filter.offset.max(0),
        order_by,
        descending: filter.descending,
    })
}

fn parse_interface_filter(interface_filter: Vec<String>) -> Result<Vec<String>, Status> {
    let mut parsed = Vec::new();
    for interface_name in interface_filter {
        if interface_name.trim().is_empty() {
            return Err(Status::invalid_argument("interface name required"));
        }
        parsed.push(interface_name);
    }
    Ok(parsed)
}

fn to_domain_object_set(
    input: ObjectSet,
    owner_principal: &str,
) -> Result<domain::ObjectSet, Status> {
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(Status::invalid_argument("name required"));
    }
    let requested_owner = input.owner_principal.clone();
    if !requested_owner.is_empty() && requested_owner != owner_principal {
        return Err(Status::invalid_argument("owner_principal mismatch"));
    }

    let filter = parse_set_filter_from_request(&input)?;
    let created = if input.created > 0 {
        input.created
    } else {
        now_millis()
    };
    let id = if input.id.is_empty() {
        format!("set-{}", Uuid::new_v4().simple())
    } else {
        input.id
    };
    Ok(domain::ObjectSet {
        id,
        name,
        description: input.description,
        filter,
        owner_principal: if requested_owner.is_empty() {
            owner_principal.to_string()
        } else {
            requested_owner
        },
        created,
    })
}

fn to_proto_obj(o: &domain::Object) -> Object {
    Object {
        id: o.id.clone(),
        kind: o.kind.clone(),
        name: o.name.clone(),
        namespace: o.namespace.clone(),
        external_id: o.external_id.clone(),
        properties: o.properties.clone(),
        created: o.created,
        updated: o.updated,
    }
}

fn can_read_restricted_properties(
    security: &SecurityChecker,
    object: &domain::Object,
    principals: &[String],
) -> bool {
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
    {
        return true;
    }
    let refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    security.can_admin(&object.id, &refs)
}

fn redact_restricted_properties(
    mut object: domain::Object,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
) -> domain::Object {
    if can_read_restricted_properties(security, &object, principals) {
        return object;
    }
    let Some(object_type) = schema.get(&object.kind) else {
        return object;
    };
    for property in &object_type.properties {
        if schema::is_restricted_property_classification(&property.classification)
            && object.properties.contains_key(&property.name)
        {
            object
                .properties
                .insert(property.name.clone(), REDACTED_VALUE.to_string());
        }
    }
    object
}

fn restricted_property_names_for_kind(
    schema: &schema::SchemaRegistry,
    kind: &str,
) -> std::collections::HashSet<String> {
    if kind.is_empty() {
        return schema
            .all()
            .iter()
            .flat_map(|object_type| {
                object_type
                    .properties
                    .iter()
                    .filter(|property| {
                        schema::is_restricted_property_classification(&property.classification)
                    })
                    .map(|property| property.name.clone())
                    .collect::<Vec<_>>()
            })
            .collect();
    }
    schema
        .get(kind)
        .map(|object_type| {
            object_type
                .properties
                .iter()
                .filter(|property| {
                    schema::is_restricted_property_classification(&property.classification)
                })
                .map(|property| property.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn principals_can_query_restricted_properties(principals: &[String]) -> bool {
    principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
}

fn ensure_property_query_allowed(
    schema: &schema::SchemaRegistry,
    principals: &[String],
    kind: &str,
    properties: impl IntoIterator<Item = String>,
) -> Result<(), Status> {
    if principals_can_query_restricted_properties(principals) {
        return Ok(());
    }
    let restricted = restricted_property_names_for_kind(schema, kind);
    if restricted.is_empty() {
        return Ok(());
    }
    if let Some(property) = properties
        .into_iter()
        .find(|property| restricted.contains(property))
    {
        return Err(Status::permission_denied(format!(
            "restricted property filter denied: {property}"
        )));
    }
    Ok(())
}

fn ensure_list_filter_query_allowed(
    schema: &schema::SchemaRegistry,
    principals: &[String],
    filter: &domain::ListFilter,
) -> Result<(), Status> {
    let mut queried_properties = filter
        .property_filters
        .iter()
        .map(|property_filter| property_filter.key.clone())
        .collect::<Vec<_>>();
    if let Some(order_property) = queried_order_property(&filter.order_by) {
        queried_properties.push(order_property);
    }
    ensure_property_query_allowed(
        schema,
        principals,
        filter.kind.as_deref().unwrap_or_default(),
        queried_properties,
    )
}

fn queried_order_property(order_by: &str) -> Option<String> {
    order_by
        .strip_prefix("property:")
        .filter(|property| !property.is_empty())
        .map(ToOwned::to_owned)
}

fn preserve_redacted_restricted_properties(
    db: &SekaiDb,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
    object: &mut domain::Object,
) -> Result<(), Status> {
    if can_read_restricted_properties(security, object, principals) {
        return Ok(());
    }
    let Some(existing) = db.get_object(&object.id).map_err(Status::internal)? else {
        return Ok(());
    };
    let mut restricted = restricted_property_names_for_kind(schema, &object.kind);
    restricted.extend(restricted_property_names_for_kind(schema, &existing.kind));
    if object.kind != existing.kind
        && restricted
            .iter()
            .any(|property| existing.properties.contains_key(property))
    {
        return Err(Status::permission_denied(
            "restricted property mutation denied",
        ));
    }
    for property in restricted {
        if let Some(existing_value) = existing.properties.get(&property) {
            object.properties.insert(property, existing_value.clone());
        } else {
            object.properties.remove(&property);
        }
    }
    Ok(())
}

fn ensure_restricted_create_properties_allowed(
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
    object: &domain::Object,
) -> Result<(), Status> {
    if can_read_restricted_properties(security, object, principals) {
        return Ok(());
    }
    let restricted = restricted_property_names_for_kind(schema, &object.kind);
    if let Some(property) = restricted.into_iter().find(|property| {
        object
            .properties
            .get(property)
            .is_some_and(|value| !value.is_empty())
    }) {
        return Err(Status::permission_denied(format!(
            "restricted property mutation denied: {property}"
        )));
    }
    Ok(())
}

fn ensure_function_allows_restricted_properties(
    schema: &schema::SchemaRegistry,
    principals: &[String],
    function: &function::Function,
) -> Result<(), Status> {
    for step in &function.pipeline {
        match step.op.as_str() {
            "filter" if !step.property.is_empty() => {
                ensure_property_query_allowed(
                    schema,
                    principals,
                    &step.kind,
                    [step.property.clone()],
                )?;
            }
            "aggregate" | "transform" if !step.field.is_empty() => {
                ensure_property_query_allowed(schema, principals, "", [step.field.clone()])?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn redact_object_change_values(
    change: audit::ObjectChange,
    object_id: &str,
    kind: &str,
    schema: &schema::SchemaRegistry,
    security: &SecurityChecker,
    principals: &[String],
) -> ObjectChange {
    let object = domain::Object {
        id: object_id.into(),
        kind: kind.into(),
        name: String::new(),
        namespace: String::new(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 0,
        updated: 0,
    };
    let restricted = if can_read_restricted_properties(security, &object, principals) {
        std::collections::HashSet::new()
    } else {
        restricted_property_names_for_kind(schema, kind)
    };
    let should_redact = change
        .field
        .strip_prefix("properties.")
        .is_some_and(|property| restricted.contains(property));
    ObjectChange {
        id: change.id,
        object_id: change.object_id,
        field: change.field,
        old_value: if should_redact {
            REDACTED_VALUE.into()
        } else {
            change.old_value
        },
        new_value: if should_redact {
            REDACTED_VALUE.into()
        } else {
            change.new_value
        },
        changed_by: change.changed_by,
        timestamp: change.timestamp,
    }
}

fn to_proto_link(l: &domain::Link) -> Link {
    Link {
        id: l.id.clone(),
        from_id: l.from_id.clone(),
        to_id: l.to_id.clone(),
        relation: l.relation.clone(),
        created: l.created,
    }
}

fn from_proto_obj(o: &Object) -> domain::Object {
    domain::Object {
        id: o.id.clone(),
        kind: o.kind.clone(),
        name: o.name.clone(),
        namespace: o.namespace.clone(),
        external_id: o.external_id.clone(),
        properties: o.properties.clone(),
        created: o.created,
        updated: o.updated,
    }
}

fn to_proto_schema_type(object_type: &schema::ObjectType) -> ObjectType {
    ObjectType {
        kind: object_type.kind.clone(),
        description: object_type.description.clone(),
        properties: object_type
            .properties
            .iter()
            .map(to_proto_property_def)
            .collect(),
        is_builtin: object_type.is_builtin,
        implements: object_type.implements.clone(),
    }
}

fn to_proto_interface(interface: &schema::InterfaceDef) -> InterfaceDef {
    InterfaceDef {
        name: interface.name.clone(),
        description: interface.description.clone(),
        properties: interface
            .properties
            .iter()
            .map(to_proto_property_def)
            .collect(),
        is_builtin: interface.is_builtin,
    }
}

fn to_proto_property_def(property: &schema::PropertyDef) -> PropertyDef {
    PropertyDef {
        name: property.name.clone(),
        r#type: property.prop_type.as_str().to_string(),
        required: property.required,
        description: property.description.clone(),
        enum_values: property.enum_values.clone(),
        link_kind: property.link_kind.clone(),
        compute_expr: property.compute_expr.clone(),
        classification: schema::normalize_property_classification(&property.classification)
            .to_string(),
        struct_fields: property
            .struct_fields
            .iter()
            .map(to_proto_struct_field_def)
            .collect(),
    }
}

fn to_proto_struct_field_def(field: &schema::StructFieldDef) -> StructFieldDef {
    StructFieldDef {
        name: field.name.clone(),
        r#type: field.prop_type.as_str().to_string(),
        required: field.required,
        description: field.description.clone(),
        enum_values: field.enum_values.clone(),
    }
}

fn from_proto_schema_type(object_type: &ObjectType) -> Result<schema::ObjectType, Status> {
    let properties = object_type
        .properties
        .iter()
        .map(from_proto_property_def)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(schema::ObjectType {
        kind: object_type.kind.clone(),
        description: object_type.description.clone(),
        properties,
        is_builtin: object_type.is_builtin,
        implements: object_type.implements.clone(),
    })
}

fn from_proto_interface(interface: &InterfaceDef) -> Result<schema::InterfaceDef, Status> {
    let properties = interface
        .properties
        .iter()
        .map(from_proto_property_def)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(schema::InterfaceDef {
        name: interface.name.clone(),
        description: interface.description.clone(),
        properties,
        is_builtin: interface.is_builtin,
    })
}

fn from_proto_property_def(property: &PropertyDef) -> Result<schema::PropertyDef, Status> {
    let prop_type = schema::PropertyType::parse(&property.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown property type: {}", property.r#type))
    })?;
    Ok(schema::PropertyDef {
        name: property.name.clone(),
        prop_type,
        required: property.required,
        description: property.description.clone(),
        enum_values: property.enum_values.clone(),
        link_kind: property.link_kind.clone(),
        compute_expr: property.compute_expr.clone(),
        classification: schema::normalize_property_classification(&property.classification)
            .to_string(),
        struct_fields: property
            .struct_fields
            .iter()
            .map(from_proto_struct_field_def)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn from_proto_struct_field_def(field: &StructFieldDef) -> Result<schema::StructFieldDef, Status> {
    let prop_type = schema::PropertyType::parse(&field.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown struct field type: {}", field.r#type))
    })?;
    Ok(schema::StructFieldDef {
        name: field.name.clone(),
        prop_type,
        required: field.required,
        description: field.description.clone(),
        enum_values: field.enum_values.clone(),
    })
}

fn schema_object_id(kind: &str) -> String {
    format!("schema:{kind}")
}

fn interface_object_id(name: &str) -> String {
    format!("interface:{name}")
}

fn action_object_id(name: &str) -> String {
    format!("action:{name}")
}

/// Internal governance object kinds that must never be created, mutated, read,
/// or listed through the generic object CRUD RPCs. They hold policy, held-action
/// params (potentially sensitive), and blast-radius counters, and are managed
/// only through their dedicated RPCs + server-internal DB paths. Exposing them
/// via CRUD would leak held params and let callers forge policy or tamper with
/// blast-radius counters.
const RESERVED_GOVERNANCE_KINDS: &[&str] = &[
    action_policy::ACTION_POLICY_KIND,
    action_policy::BLAST_RADIUS_KIND,
    action_approval::ACTION_APPROVAL_KIND,
    crate::domain::KIND_CAPABILITY,
    crate::domain::KIND_EXTERNAL_EVIDENCE,
];

fn is_reserved_governance_kind(kind: &str) -> bool {
    RESERVED_GOVERNANCE_KINDS.contains(&kind)
}

/// Resolve the namespace used for action-policy scope resolution: prefer the
/// namespace of an existing target object, falling back to a `namespace` param
/// (used by `create_object` before the object exists).
fn action_policy_namespace(
    db: &SekaiDb,
    target_ids: &[String],
    params: &std::collections::HashMap<String, String>,
) -> String {
    for id in target_ids {
        if let Ok(Some(object)) = db.get_object(id) {
            if object.kind == "namespace" {
                let namespace = object
                    .external_id
                    .strip_prefix("namespace:")
                    .map(str::trim)
                    .filter(|namespace| !namespace.is_empty())
                    .unwrap_or_else(|| object.name.trim());
                if !namespace.is_empty() {
                    return namespace.to_string();
                }
            }
            if !object.namespace.trim().is_empty() {
                return object.namespace;
            }
        }
    }
    params
        .get("namespace")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
}

fn action_budget_subject(action_risk: &str, namespace: &str, actor: &str) -> String {
    let base = format!("action:{action_risk}");
    if namespace.trim().is_empty() {
        return base;
    }
    if actor.trim().is_empty() {
        return format!("{base}/project:{}", namespace.trim());
    }
    format!("{base}/project:{}/agent:{}", namespace.trim(), actor.trim())
}

/// Pin the policy that rendered an action decision as a replayable
/// attestation and bind it into the audit decision's evidence. The returned
/// record must be persisted atomically with the decision via
/// `record_decision_with_attestation`. No policy (implicit allow) means
/// there is nothing to attest.
#[allow(clippy::too_many_arguments)]
fn attest_action_decision(
    policy: Option<&action_policy::ActionPolicy>,
    decision_id: &str,
    action_name: &str,
    actor: &str,
    risk: RiskClass,
    namespace: &str,
    decision: ActionDecision,
    evidence: &mut HashMap<String, String>,
) -> Option<attestation::PolicyAttestation> {
    let policy = policy?;
    let record = attestation::build_action_attestation(attestation::ActionAttestationInput {
        decision_id,
        policy,
        action: action_name,
        actor,
        risk,
        namespace,
        decision,
        created: now_millis(),
    });
    evidence.insert(
        attestation::EVIDENCE_ATTESTATION_ID.into(),
        record.id.clone(),
    );
    evidence.insert(
        attestation::EVIDENCE_ATTESTATION_HASH.into(),
        record.content_hash.clone(),
    );
    Some(record)
}

fn to_proto_attestation(a: &attestation::PolicyAttestation) -> PolicyAttestation {
    PolicyAttestation {
        id: a.id.clone(),
        decision_id: a.decision_id.clone(),
        policy_kind: a.policy_kind.clone(),
        policy_scope: a.policy_scope.clone(),
        policy_version: a.policy_version.clone(),
        policy_snapshot: a.policy_snapshot.clone(),
        inputs: a.inputs.clone(),
        decision: a.decision.clone(),
        content_hash: a.content_hash.clone(),
        created: a.created,
    }
}

fn to_proto_action_approval(approval: &action_approval::ActionApproval) -> ActionApproval {
    ActionApproval {
        id: approval.id.clone(),
        status: approval.status.as_str().to_string(),
        actor: approval.actor.clone(),
        action: approval.action.clone(),
        params: approval.redacted_params(),
        work_unit: approval.work_unit.clone(),
        policy_scope: approval.policy_scope.clone(),
        risk_class: approval.risk_class.clone(),
        target_id: approval.target_id.clone(),
        created: approval.created,
        updated: approval.updated,
        decided_by: approval.decided_by.clone(),
        outcome: approval.outcome.clone(),
    }
}

fn to_proto_action_policy(policy: &action_policy::ActionPolicy) -> ActionPolicy {
    ActionPolicy {
        scope: policy.scope.clone(),
        default_decision: policy.default_decision.as_str().to_string(),
        action_overrides: policy
            .action_overrides
            .iter()
            .map(|(name, decision)| (name.clone(), decision.as_str().to_string()))
            .collect(),
        risk_overrides: policy
            .risk_overrides
            .iter()
            .map(|(risk, decision)| (risk.as_str().to_string(), decision.as_str().to_string()))
            .collect(),
        max_mutations_per_work_unit: policy.max_mutations_per_work_unit.unwrap_or(0),
        max_deletes_per_work_unit: policy.max_deletes_per_work_unit.unwrap_or(0),
    }
}

fn from_proto_action_policy(policy: &ActionPolicy) -> Result<action_policy::ActionPolicy, Status> {
    let scope = policy.scope.trim();
    if scope.is_empty() {
        return Err(Status::invalid_argument("policy scope required"));
    }
    let default_decision = if policy.default_decision.trim().is_empty() {
        ActionDecision::Allow
    } else {
        ActionDecision::parse(&policy.default_decision)
            .ok_or_else(|| Status::invalid_argument("invalid default_decision"))?
    };
    let mut action_overrides = HashMap::new();
    for (name, decision) in &policy.action_overrides {
        let decision = ActionDecision::parse(decision).ok_or_else(|| {
            Status::invalid_argument(format!("invalid decision for action {name}"))
        })?;
        action_overrides.insert(name.clone(), decision);
    }
    let mut risk_overrides = HashMap::new();
    for (risk, decision) in &policy.risk_overrides {
        let parsed_risk = action::RiskClass::parse(risk)
            .ok_or_else(|| Status::invalid_argument(format!("invalid risk class {risk}")))?;
        let decision = ActionDecision::parse(decision)
            .ok_or_else(|| Status::invalid_argument(format!("invalid decision for risk {risk}")))?;
        risk_overrides.insert(parsed_risk, decision);
    }
    Ok(action_policy::ActionPolicy {
        scope: scope.to_string(),
        default_decision,
        action_overrides,
        risk_overrides,
        max_mutations_per_work_unit: (policy.max_mutations_per_work_unit > 0)
            .then_some(policy.max_mutations_per_work_unit),
        max_deletes_per_work_unit: (policy.max_deletes_per_work_unit > 0)
            .then_some(policy.max_deletes_per_work_unit),
    })
}

fn to_proto_action_type(action_type: &action::ActionTypeDef) -> ActionTypeDef {
    ActionTypeDef {
        name: action_type.name.clone(),
        description: action_type.description.clone(),
        params: action_type
            .params
            .iter()
            .map(to_proto_action_param)
            .collect(),
        ops: action_type.ops.iter().map(to_proto_action_op).collect(),
        target_kind: action_type.target_kind.clone(),
        created: action_type.created,
    }
}

fn to_proto_action_param(param: &action::ActionParamDef) -> ActionParamDef {
    ActionParamDef {
        name: param.name.clone(),
        r#type: param.param_type.as_str().to_string(),
        required: param.required,
        enum_values: param.enum_values.clone(),
    }
}

fn to_proto_action_op(op: &action::ActionOp) -> ActionOp {
    ActionOp {
        op: op.op.clone(),
        property: op.property.clone(),
        value_from: op.value_from.clone(),
        relation: op.relation.clone(),
    }
}

fn from_proto_action_type(action_type: &ActionTypeDef) -> Result<action::ActionTypeDef, Status> {
    let params = action_type
        .params
        .iter()
        .map(from_proto_action_param)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(action::ActionTypeDef {
        name: action_type.name.clone(),
        description: action_type.description.clone(),
        params,
        ops: action_type.ops.iter().map(from_proto_action_op).collect(),
        target_kind: action_type.target_kind.clone(),
        created: action_type.created,
    })
}

fn from_proto_action_param(param: &ActionParamDef) -> Result<action::ActionParamDef, Status> {
    let param_type = schema::PropertyType::parse(&param.r#type).ok_or_else(|| {
        Status::invalid_argument(format!("unknown action param type: {}", param.r#type))
    })?;
    Ok(action::ActionParamDef {
        name: param.name.clone(),
        param_type,
        required: param.required,
        enum_values: param.enum_values.clone(),
    })
}

fn from_proto_action_op(op: &ActionOp) -> action::ActionOp {
    action::ActionOp {
        op: op.op.clone(),
        property: op.property.clone(),
        value_from: op.value_from.clone(),
        relation: op.relation.clone(),
    }
}

fn validate_action_type_against_schema(
    action_type: &action::ActionTypeDef,
    schema: &SchemaRegistry,
) -> Result<(), Status> {
    action::validate_action_type_against_schema(action_type, schema)
        .map_err(Status::invalid_argument)
}

fn validate_computed_property_functions(
    db: &SekaiDb,
    object_type: &schema::ObjectType,
) -> Result<(), Status> {
    for property in &object_type.properties {
        if property.prop_type != schema::PropertyType::Computed || property.compute_expr.is_empty()
        {
            continue;
        }
        if db
            .get_function(&property.compute_expr)
            .map_err(Status::internal)?
            .is_none()
        {
            return Err(Status::invalid_argument(format!(
                "computed property {} references unknown function {}",
                property.name, property.compute_expr
            )));
        }
    }
    Ok(())
}

fn to_proto_dataset(d: &dataset::Dataset) -> Dataset {
    Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| ColumnDef {
                name: c.name.clone(),
                r#type: c.col_type.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}

fn from_proto_dataset(d: &Dataset) -> dataset::Dataset {
    dataset::Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| dataset::ColumnDef {
                name: c.name.clone(),
                col_type: c.r#type.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}

fn from_proto_row_filters(filters: &[RowFilter]) -> Vec<dataset::RowFilter> {
    filters
        .iter()
        .map(|f| dataset::RowFilter {
            column: f.column.clone(),
            op: f.op.clone(),
            value: f.value.clone(),
        })
        .collect()
}

fn to_proto_virtual_table(vt: &dataset::VirtualTable) -> VirtualTable {
    VirtualTable {
        id: vt.id.clone(),
        name: vt.name.clone(),
        dataset_id: vt.dataset_id.clone(),
        filters: vt
            .filters
            .iter()
            .map(|f| RowFilter {
                column: f.column.clone(),
                op: f.op.clone(),
                value: f.value.clone(),
            })
            .collect(),
        columns: vt.columns.clone(),
        created: vt.created,
    }
}

fn from_proto_virtual_table(vt: &VirtualTable) -> dataset::VirtualTable {
    dataset::VirtualTable {
        id: vt.id.clone(),
        name: vt.name.clone(),
        dataset_id: vt.dataset_id.clone(),
        filters: from_proto_row_filters(&vt.filters),
        columns: vt.columns.clone(),
        created: vt.created,
    }
}

fn to_proto_function(f: &function::Function) -> Function {
    Function {
        name: f.name.clone(),
        description: f.description.clone(),
        params: f
            .params
            .iter()
            .map(|p| FuncParam {
                name: p.name.clone(),
                r#type: p.param_type.clone(),
                required: p.required,
            })
            .collect(),
        pipeline: f
            .pipeline
            .iter()
            .map(|s| PipelineStep {
                op: s.op.clone(),
                kind: s.kind.clone(),
                property: s.property.clone(),
                value: s.value.clone(),
                relation: s.relation.clone(),
                dir: s.dir.clone(),
                func: s.func.clone(),
                field: s.field.clone(),
                r#as: s.alias.clone(),
            })
            .collect(),
        created: f.created,
    }
}

fn from_proto_function(f: &Function) -> function::Function {
    function::Function {
        name: f.name.clone(),
        description: f.description.clone(),
        params: f
            .params
            .iter()
            .map(|p| function::FuncParam {
                name: p.name.clone(),
                param_type: p.r#type.clone(),
                required: p.required,
            })
            .collect(),
        pipeline: f
            .pipeline
            .iter()
            .map(|s| function::PipelineStep {
                op: s.op.clone(),
                kind: s.kind.clone(),
                property: s.property.clone(),
                value: s.value.clone(),
                relation: s.relation.clone(),
                dir: s.dir.clone(),
                func: s.func.clone(),
                field: s.field.clone(),
                alias: s.r#as.clone(),
            })
            .collect(),
        created: f.created,
    }
}

fn to_proto_grant(g: &security::Grant) -> Grant {
    Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role: g.role.as_str().to_string(),
        created: g.created,
    }
}

fn to_proto_contention_scope(scope: &coordination::ContentionScope) -> ContentionScope {
    ContentionScope {
        id: scope.id.clone(),
        name: scope.name.clone(),
        parent_scope_id: scope.parent_scope_id.clone(),
        max_concurrency: scope.max_concurrency,
        admission_policy: scope.admission_policy.clone(),
        heartbeat_ttl_seconds: scope.heartbeat_ttl_seconds,
        timeout_seconds: scope.timeout_seconds,
        owner_principal: scope.owner_principal.clone(),
        created: scope.created,
        updated: scope.updated,
    }
}

fn from_proto_contention_scope(scope: &ContentionScope) -> coordination::ContentionScope {
    coordination::ContentionScope {
        id: scope.id.clone(),
        name: scope.name.clone(),
        parent_scope_id: scope.parent_scope_id.clone(),
        max_concurrency: scope.max_concurrency,
        admission_policy: scope.admission_policy.clone(),
        heartbeat_ttl_seconds: scope.heartbeat_ttl_seconds,
        timeout_seconds: scope.timeout_seconds,
        owner_principal: scope.owner_principal.clone(),
        created: scope.created,
        updated: scope.updated,
    }
}

fn to_proto_work_unit(work_unit: &coordination::WorkUnit) -> WorkUnit {
    WorkUnit {
        id: work_unit.id.clone(),
        kind: work_unit.kind.clone(),
        actor: work_unit.actor.clone(),
        target_object_id: work_unit.target_object_id.clone(),
        status: work_unit.status.clone(),
        requested_spec: work_unit.requested_spec.clone(),
        scope_id: work_unit.scope_id.clone(),
        priority: work_unit.priority,
        timeout_seconds: work_unit.timeout_seconds,
        heartbeat_ttl_seconds: work_unit.heartbeat_ttl_seconds,
        created_at: work_unit.created_at,
        admitted_at: work_unit.admitted_at,
        started_at: work_unit.started_at,
        finished_at: work_unit.finished_at,
        last_heartbeat_at: work_unit.last_heartbeat_at,
        failure_reason: work_unit.failure_reason.clone(),
        cancel_reason: work_unit.cancel_reason.clone(),
        owner_principal: work_unit.owner_principal.clone(),
        creator_principal: work_unit.creator_principal.clone(),
        idempotency_key: work_unit.idempotency_key.clone(),
        updated_at: work_unit.updated_at,
    }
}

fn from_proto_work_unit(work_unit: &WorkUnit) -> coordination::WorkUnit {
    coordination::WorkUnit {
        id: work_unit.id.clone(),
        kind: work_unit.kind.clone(),
        actor: work_unit.actor.clone(),
        target_object_id: work_unit.target_object_id.clone(),
        status: work_unit.status.clone(),
        requested_spec: work_unit.requested_spec.clone(),
        scope_id: work_unit.scope_id.clone(),
        priority: work_unit.priority,
        timeout_seconds: work_unit.timeout_seconds,
        heartbeat_ttl_seconds: work_unit.heartbeat_ttl_seconds,
        created_at: work_unit.created_at,
        admitted_at: work_unit.admitted_at,
        started_at: work_unit.started_at,
        finished_at: work_unit.finished_at,
        last_heartbeat_at: work_unit.last_heartbeat_at,
        failure_reason: work_unit.failure_reason.clone(),
        cancel_reason: work_unit.cancel_reason.clone(),
        owner_principal: work_unit.owner_principal.clone(),
        creator_principal: work_unit.creator_principal.clone(),
        idempotency_key: work_unit.idempotency_key.clone(),
        updated_at: work_unit.updated_at,
    }
}

fn to_proto_reservation(reservation: &coordination::Reservation) -> Reservation {
    Reservation {
        id: reservation.id.clone(),
        work_unit_id: reservation.work_unit_id.clone(),
        scope_id: reservation.scope_id.clone(),
        status: reservation.status.clone(),
        lease_owner: reservation.lease_owner.clone(),
        leased_at: reservation.leased_at,
        expires_at: reservation.expires_at,
        released_at: reservation.released_at,
        created_at: reservation.created_at,
    }
}

fn to_proto_run_event(event: &coordination::RunEvent) -> RunEvent {
    RunEvent {
        id: event.id.clone(),
        work_unit_id: event.work_unit_id.clone(),
        event_type: event.event_type.clone(),
        message: event.message.clone(),
        evidence: event.evidence.clone(),
        created_at: event.created_at,
    }
}

fn from_proto_work_unit_filter(filter: &WorkUnitFilter) -> coordination::WorkUnitFilter {
    coordination::WorkUnitFilter {
        status: if filter.status.is_empty() {
            None
        } else {
            Some(filter.status.clone())
        },
        actor: if filter.actor.is_empty() {
            None
        } else {
            Some(filter.actor.clone())
        },
        scope_id: if filter.scope_id.is_empty() {
            None
        } else {
            Some(filter.scope_id.clone())
        },
        target_object_id: if filter.target_object_id.is_empty() {
            None
        } else {
            Some(filter.target_object_id.clone())
        },
        owner_principal: if filter.owner_principal.is_empty() {
            None
        } else {
            Some(filter.owner_principal.clone())
        },
        statuses: filter.statuses.clone(),
        created_after: filter.created_after,
        updated_after: filter.updated_after,
        creator_principal: if filter.creator_principal.is_empty() {
            None
        } else {
            Some(filter.creator_principal.clone())
        },
        page_token: if filter.page_token.is_empty() {
            None
        } else {
            Some(filter.page_token.clone())
        },
        limit: filter.limit,
        offset: filter.offset,
    }
}

fn to_proto_snapshot(snapshot: &coordination::CoordinationSnapshot) -> CoordinationSnapshot {
    CoordinationSnapshot {
        pending_count: snapshot.pending_count,
        running_count: snapshot.running_count,
        stale_count: snapshot.stale_count,
        active_reservation_count: snapshot.active_reservation_count,
        oldest_pending_age_ms: snapshot.oldest_pending_age_ms,
        oldest_running_age_ms: snapshot.oldest_running_age_ms,
        stale_reservation_count: snapshot.stale_reservation_count,
        blocked_scopes: snapshot
            .blocked_scopes
            .iter()
            .map(|scope| ScopeBlockage {
                scope_id: scope.scope_id.clone(),
                scope_name: scope.scope_name.clone(),
                reason: scope.reason.clone(),
                pending_count: scope.pending_count,
                active_count: scope.active_count,
            })
            .collect(),
    }
}

fn dedup_principal(principals: &[String]) -> String {
    principals.first().cloned().unwrap_or_default()
}

fn trim_page<T>(items: &mut Vec<T>, limit: i32) {
    if limit > 0 && items.len() > limit as usize {
        items.truncate(limit as usize);
    }
}

fn initialize_work_unit_for_create(work_unit: &mut coordination::WorkUnit, principal: &str) {
    if work_unit.owner_principal.is_empty() {
        work_unit.owner_principal = principal.into();
    }
    if work_unit.creator_principal.is_empty() {
        work_unit.creator_principal = principal.into();
    }
    work_unit.status = coordination::WORK_UNIT_STATUS_PENDING.into();
    work_unit.admitted_at = 0;
    work_unit.started_at = 0;
    work_unit.finished_at = 0;
    work_unit.last_heartbeat_at = 0;
    work_unit.failure_reason.clear();
    work_unit.cancel_reason.clear();
    work_unit.updated_at = work_unit.created_at;
}

fn aggregate_reconcile_summary(
    summary: &mut coordination::ReconcileSummary,
    next: coordination::ReconcileSummary,
) {
    summary.work_units_reconciled += next.work_units_reconciled;
    summary.reservations_released += next.reservations_released;
    summary.details.extend(next.details);
}

fn reconcile_owned_scope(
    db: &SekaiDb,
    now_ms: i64,
    scope_id: String,
    dry_run: bool,
    limit: i32,
    summary: &mut coordination::ReconcileSummary,
) -> Result<(), Status> {
    if limit > 0 && summary.work_units_reconciled >= limit {
        return Ok(());
    }
    let remaining = if limit > 0 {
        limit - summary.work_units_reconciled
    } else {
        0
    };
    let next = db
        .reconcile_work_units(
            now_ms,
            &coordination::ReconcileFilter {
                dry_run,
                work_unit_id: None,
                scope_id: Some(scope_id),
                limit: remaining,
            },
        )
        .map_err(Status::internal)?;
    aggregate_reconcile_summary(summary, next);
    Ok(())
}

fn from_proto_grant(g: &Grant) -> Result<security::Grant, Status> {
    let role = security::Role::parse(&g.role).ok_or(Status::invalid_argument("invalid role"))?;
    Ok(security::Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role,
        created: g.created,
    })
}

fn from_proto_context_root(root: ContextRoot) -> Result<retrieval::RetrievalRoot, Status> {
    let configured = [
        !root.object_id.is_empty(),
        !root.external_id.is_empty(),
        !root.link_id.is_empty(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count();
    if configured != 1 {
        return Err(Status::invalid_argument(
            "each context root must set exactly one of object_id, external_id, or link_id",
        ));
    }
    if !root.object_id.is_empty() {
        Ok(retrieval::RetrievalRoot::Object(root.object_id))
    } else if !root.external_id.is_empty() {
        Ok(retrieval::RetrievalRoot::External(root.external_id))
    } else {
        Ok(retrieval::RetrievalRoot::Link(root.link_id))
    }
}

fn map_retrieval_error(error: retrieval::RetrievalError) -> Status {
    match error {
        retrieval::RetrievalError::InvalidArgument(message) => Status::invalid_argument(message),
        retrieval::RetrievalError::Storage(message) => Status::internal(message),
    }
}

#[tonic::async_trait]
impl SekaiService for SekaiServiceImpl {
    async fn create_object(
        &self,
        req: Request<CreateObjectRequest>,
    ) -> Result<Response<CreateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let obj = req
            .into_inner()
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if obj.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        check_write(&self.security, &obj.id, &principals)?;
        let domain_obj = from_proto_obj(&obj);
        if is_reserved_governance_kind(&domain_obj.kind) {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        self.require_schema_kind_loaded(&domain_obj.kind)?;
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        schema
            .validate(&domain_obj)
            .map_err(Status::invalid_argument)?;
        ensure_restricted_create_properties_allowed(
            &schema,
            &self.security,
            &principals,
            &domain_obj,
        )?;
        drop(schema);
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .create_object_with_audit(&domain_obj, actor)
            .map_err(Status::internal)?;
        let domain_obj = self.resolve_computed_for_response(domain_obj, &principals)?;
        Ok(Response::new(CreateObjectResponse {
            object: Some(to_proto_obj(&domain_obj)),
        }))
    }
    async fn get_object(
        &self,
        req: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let id = req.into_inner().id;
        check_read(&self.security, &id, &principals)?;
        let obj = self
            .db
            .get_object(&id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        if is_reserved_governance_kind(&obj.kind) {
            return Err(Status::not_found("not found"));
        }
        let obj = self.resolve_computed_for_response(obj, &principals)?;
        Ok(Response::new(GetObjectResponse {
            object: Some(to_proto_obj(&obj)),
        }))
    }
    async fn update_object(
        &self,
        req: Request<UpdateObjectRequest>,
    ) -> Result<Response<UpdateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let obj = req
            .into_inner()
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if obj.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        check_write(&self.security, &obj.id, &principals)?;
        let mut domain_obj = from_proto_obj(&obj);
        if is_reserved_governance_kind(&domain_obj.kind)
            || self
                .db
                .get_object(&obj.id)
                .map_err(Status::internal)?
                .is_some_and(|existing| is_reserved_governance_kind(&existing.kind))
        {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        self.require_schema_kind_loaded(&domain_obj.kind)?;
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        preserve_redacted_restricted_properties(
            &self.db,
            &schema,
            &self.security,
            &principals,
            &mut domain_obj,
        )?;
        schema
            .validate(&domain_obj)
            .map_err(Status::invalid_argument)?;
        drop(schema);
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .update_object_with_audit(&domain_obj, actor)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        let domain_obj = self.resolve_computed_for_response(domain_obj, &principals)?;
        Ok(Response::new(UpdateObjectResponse {
            object: Some(to_proto_obj(&domain_obj)),
        }))
    }
    async fn delete_object(
        &self,
        req: Request<DeleteObjectRequest>,
    ) -> Result<Response<DeleteObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let id = req.into_inner().id;
        check_write(&self.security, &id, &principals)?;
        if self
            .db
            .get_object(&id)
            .map_err(Status::internal)?
            .is_some_and(|existing| is_reserved_governance_kind(&existing.kind))
        {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        let actor = principals.first().map(String::as_str).unwrap_or_default();
        self.db
            .delete_object_with_audit(&id, actor)
            .map_err(Status::internal)?;
        Ok(Response::new(DeleteObjectResponse {}))
    }
    async fn list_objects(
        &self,
        req: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let filter = parse_list_filter(req.into_inner().filter.unwrap_or_default())?;
        // Never expose internal governance objects through generic listing.
        if filter
            .kind
            .as_deref()
            .is_some_and(is_reserved_governance_kind)
        {
            return Ok(Response::new(ListObjectsResponse {
                objects: Vec::new(),
                total: 0,
            }));
        }
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            let mut queried_properties = filter
                .property_filters
                .iter()
                .map(|property_filter| property_filter.key.clone())
                .collect::<Vec<_>>();
            if let Some(order_property) = queried_order_property(&filter.order_by) {
                queried_properties.push(order_property);
            }
            ensure_property_query_allowed(
                &schema,
                &principals,
                filter.kind.as_deref().unwrap_or_default(),
                queried_properties,
            )?;
        }
        // The API now defaults paging at 100 rows when no limit is provided;
        // DB callers using list_objects(&filter) remain unchanged.
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        // Query visibility in SQL so list pagination and totals honor grants
        // consistently across callers.
        let (objects, total) = self
            .db
            .list_objects_with_total_for_principals(
                &filter,
                &principal_refs,
                RESERVED_GOVERNANCE_KINDS,
            )
            .map_err(Status::internal)?;
        let objects = self.resolve_computed_for_responses(objects, &principals)?;
        Ok(Response::new(ListObjectsResponse {
            objects: objects.iter().map(to_proto_obj).collect(),
            total,
        }))
    }
    async fn find_by_external_id(
        &self,
        req: Request<FindByExternalIdRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let external_id = req.into_inner().external_id;
        let obj = self
            .db
            .find_by_external_id(&external_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        if is_reserved_governance_kind(&obj.kind) {
            return Err(Status::not_found("not found"));
        }
        check_read(&self.security, &obj.id, &principals)?;
        let obj = self.resolve_computed_for_response(obj, &principals)?;
        Ok(Response::new(GetObjectResponse {
            object: Some(to_proto_obj(&obj)),
        }))
    }
    async fn find_by_property(
        &self,
        req: Request<FindByPropertyRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        if is_reserved_governance_kind(&r.kind) {
            return Ok(Response::new(ListObjectsResponse {
                objects: Vec::new(),
                total: 0,
            }));
        }
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_property_query_allowed(&schema, &principals, &r.kind, [r.key.clone()])?;
        }
        let objs = self
            .db
            .find_by_property(&r.kind, &r.key, &r.value)
            .map_err(Status::internal)?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        let filtered = self.security.filter_objects(&objs, &refs);
        let filtered = self
            .resolve_computed_for_responses(filtered.into_iter().cloned().collect(), &principals)?;
        Ok(Response::new(ListObjectsResponse {
            objects: filtered.iter().map(to_proto_obj).collect(),
            total: filtered.len() as i32,
        }))
    }
    async fn create_object_set(
        &self,
        req: Request<CreateObjectSetRequest>,
    ) -> Result<Response<CreateObjectSetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let owner = principals.first().cloned().unwrap_or_default();
        let domain_set = to_domain_object_set(
            req.into_inner()
                .object_set
                .ok_or(Status::invalid_argument("object_set required"))?,
            owner.as_str(),
        )?;
        if domain_set
            .filter
            .kind
            .as_deref()
            .is_some_and(is_reserved_governance_kind)
        {
            return Err(Status::permission_denied(
                "reserved governance kind; use the dedicated action RPCs",
            ));
        }
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_list_filter_query_allowed(&schema, &principals, &domain_set.filter)?;
        }
        self.db.create_object_set(&domain_set).map_err(|e| {
            let duplicate_name = e.starts_with("UNIQUE constraint failed:")
                && e.contains("sekai_object_sets.owner_principal")
                && e.contains("sekai_object_sets.name");
            let duplicate_id =
                e.starts_with("UNIQUE constraint failed:") && e.contains("sekai_object_sets.id");
            if duplicate_name || duplicate_id {
                Status::already_exists("object set already exists")
            } else {
                Status::internal(e)
            }
        })?;
        Ok(Response::new(CreateObjectSetResponse {
            object_set: Some(to_proto_object_set(&domain_set)),
        }))
    }
    async fn list_object_sets(
        &self,
        req: Request<ListObjectSetsRequest>,
    ) -> Result<Response<ListObjectSetsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let sets = self
            .db
            .list_object_sets_for_principals(&principal_refs)
            .map_err(Status::internal)?
            .into_iter()
            .collect::<Vec<_>>();
        Ok(Response::new(ListObjectSetsResponse {
            object_sets: sets.iter().map(to_proto_object_set).collect(),
        }))
    }
    async fn delete_object_set(
        &self,
        req: Request<DeleteObjectSetRequest>,
    ) -> Result<Response<DeleteObjectSetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        if id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        if self
            .db
            .delete_object_set_for_principals(&id, &principal_refs)
            .map_err(Status::internal)?
        {
            return Ok(Response::new(DeleteObjectSetResponse {}));
        }
        Err(Status::not_found("not found"))
    }
    async fn resolve_object_set(
        &self,
        req: Request<ResolveObjectSetRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let set = self
            .db
            .get_object_set(&inner.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        if !principal_matches(&set.owner_principal, &principals) {
            return Err(Status::not_found("not found"));
        }
        let mut filter = set.filter.clone();
        let (limit, _) = read_limit_offset(inner.limit, 0)?;
        if inner.limit > 0 || filter.limit <= 0 {
            filter.limit = limit;
        }
        if let Some(offset) = inner.offset {
            if offset < 0 {
                return Err(Status::invalid_argument("offset must be >= 0"));
            }
            filter.offset = offset;
        }
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_list_filter_query_allowed(&schema, &principals, &filter)?;
        }
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let (objects, total) = self
            .db
            .list_objects_with_total_for_principals(
                &filter,
                &principal_refs,
                RESERVED_GOVERNANCE_KINDS,
            )
            .map_err(Status::internal)?;
        let objects = self.resolve_computed_for_responses(objects, &principals)?;
        Ok(Response::new(ListObjectsResponse {
            objects: objects.iter().map(to_proto_obj).collect(),
            total,
        }))
    }
    async fn create_link(
        &self,
        req: Request<CreateLinkRequest>,
    ) -> Result<Response<CreateLinkResponse>, Status> {
        let l = req
            .into_inner()
            .link
            .ok_or(Status::invalid_argument("link required"))?;
        let dl = domain::Link {
            id: l.id.clone(),
            from_id: l.from_id.clone(),
            to_id: l.to_id.clone(),
            relation: l.relation.clone(),
            created: l.created,
        };
        self.db.create_link(&dl).map_err(Status::internal)?;
        Ok(Response::new(CreateLinkResponse { link: Some(l) }))
    }
    async fn delete_link(
        &self,
        req: Request<DeleteLinkRequest>,
    ) -> Result<Response<DeleteLinkResponse>, Status> {
        self.db
            .delete_link(&req.into_inner().id)
            .map_err(Status::internal)?;
        Ok(Response::new(DeleteLinkResponse {}))
    }
    async fn get_links(
        &self,
        req: Request<GetLinksRequest>,
    ) -> Result<Response<GetLinksResponse>, Status> {
        let r = req.into_inner();
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let links = self
            .db
            .get_links(&r.object_id, &r.relation, &dir)
            .map_err(Status::internal)?;
        Ok(Response::new(GetLinksResponse {
            links: links.iter().map(to_proto_link).collect(),
        }))
    }
    async fn get_linked_objects(
        &self,
        req: Request<GetLinkedObjectsRequest>,
    ) -> Result<Response<GetLinkedObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let objs = self
            .db
            .get_linked_objects(&r.object_id, &r.relation, &dir)
            .map_err(Status::internal)?;
        let objs = self.resolve_computed_for_responses(objs, &principals)?;
        Ok(Response::new(GetLinkedObjectsResponse {
            objects: objs.iter().map(to_proto_obj).collect(),
        }))
    }
    async fn traverse(
        &self,
        req: Request<TraverseRequest>,
    ) -> Result<Response<TraverseResponse>, Status> {
        let principals = caller_principals(&req);
        let q = req
            .into_inner()
            .query
            .ok_or(Status::invalid_argument("query required"))?;
        let gq = crate::sekai::query::GraphQuery {
            start_id: q.start_id,
            start_external_id: q.start_external_id,
            relations: q.relations,
            direction: if q.direction == "incoming" {
                domain::Direction::Incoming
            } else {
                domain::Direction::Outgoing
            },
            max_depth: q.max_depth,
            kind_filter: q.kind_filter,
            interface_filter: q.interface_filter,
            property_filter: q.property_filter,
        };
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        let queried_properties = gq.property_filter.keys().cloned().collect::<Vec<_>>();
        if gq.kind_filter.is_empty() {
            ensure_property_query_allowed(&schema, &principals, "", queried_properties)?;
        } else {
            for kind in &gq.kind_filter {
                ensure_property_query_allowed(
                    &schema,
                    &principals,
                    kind,
                    queried_properties.clone(),
                )?;
            }
        }
        let mut res = crate::sekai::query::traverse(&self.db, &gq, Some(&schema))
            .map_err(Status::internal)?;
        drop(schema);
        res.objects = self.resolve_computed_for_responses(res.objects, &principals)?;
        Ok(Response::new(TraverseResponse {
            result: Some(GraphResult {
                objects: res.objects.iter().map(to_proto_obj).collect(),
                links: res.links.iter().map(to_proto_link).collect(),
            }),
        }))
    }
    async fn retrieve_context(
        &self,
        req: Request<RetrieveContextRequest>,
    ) -> Result<Response<RetrieveContextResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let roots = inner
            .roots
            .into_iter()
            .map(from_proto_context_root)
            .collect::<Result<Vec<_>, _>>()?;
        let direction =
            retrieval::RetrievalDirection::parse(&inner.direction).map_err(map_retrieval_error)?;
        let query = retrieval::RetrievalQuery {
            roots,
            relations: inner.relations,
            direction,
            max_depth: inner.max_depth,
            max_objects: inner.max_objects,
            max_links: inner.max_links,
            kind_filter: inner.kind_filter,
        };
        let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
        let mut result = retrieval::retrieve(
            &self.db,
            &query,
            |object| self.security.can_access(&object.id, &principal_refs),
            |object| is_reserved_governance_kind(&object.kind),
        )
        .map_err(map_retrieval_error)?;
        for candidate in &mut result.candidates {
            candidate.object =
                self.resolve_computed_for_response(candidate.object.clone(), &principals)?;
        }

        Ok(Response::new(RetrieveContextResponse {
            candidates: result
                .candidates
                .iter()
                .map(|candidate| ContextCandidate {
                    object: Some(to_proto_obj(&candidate.object)),
                    depth: candidate.depth,
                    via_relation: candidate.via_relation.clone(),
                    affinity: candidate.affinity,
                })
                .collect(),
            links: result.links.iter().map(to_proto_link).collect(),
            truncated: result.truncated,
            unresolved_roots: result.unresolved_roots,
            denied_objects: result.denied_objects,
            truncated_objects: result.truncated_objects,
            truncated_links: result.truncated_links,
        }))
    }
    async fn list_schema_types(
        &self,
        req: Request<ListSchemaTypesRequest>,
    ) -> Result<Response<ListSchemaTypesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let types = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .all()
            .iter()
            .filter(|object_type| {
                check_read(
                    &self.security,
                    &schema_object_id(&object_type.kind),
                    &principals,
                )
                .is_ok()
            })
            .map(to_proto_schema_type)
            .collect();
        Ok(Response::new(ListSchemaTypesResponse { types }))
    }
    async fn create_schema_type(
        &self,
        req: Request<CreateSchemaTypeRequest>,
    ) -> Result<Response<CreateSchemaTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let object_type = req
            .into_inner()
            .r#type
            .ok_or(Status::invalid_argument("schema type required"))?;
        let parsed = from_proto_schema_type(&object_type)?;
        check_schema_admin(&self.security, &parsed.kind, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            schema::validate_object_type_definition(&parsed, registry.get(&parsed.kind), &registry)
                .map_err(Status::invalid_argument)?;
        }
        validate_computed_property_functions(&self.db, &parsed)?;
        self.db
            .upsert_object_type(&parsed)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .register(parsed.clone());
        self.schema_load_errors
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(&parsed.kind);
        Ok(Response::new(CreateSchemaTypeResponse {
            r#type: Some(to_proto_schema_type(&parsed)),
        }))
    }
    async fn delete_schema_type(
        &self,
        req: Request<DeleteSchemaTypeRequest>,
    ) -> Result<Response<DeleteSchemaTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let kind = req.into_inner().kind;
        if kind.trim().is_empty() {
            return Err(Status::invalid_argument("kind required"));
        }
        check_schema_admin(&self.security, &kind, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            if registry
                .get(&kind)
                .map(|object_type| object_type.is_builtin)
                .unwrap_or(false)
            {
                return Err(Status::invalid_argument(
                    "cannot delete builtin schema type",
                ));
            }
        }
        self.db
            .delete_object_type(&kind)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(&kind);
        self.schema_load_errors
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove(&kind);
        Ok(Response::new(DeleteSchemaTypeResponse {}))
    }

    async fn list_interfaces(
        &self,
        req: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let interfaces = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .all_interfaces()
            .iter()
            .filter(|interface| {
                check_read(
                    &self.security,
                    &interface_object_id(&interface.name),
                    &principals,
                )
                .is_ok()
            })
            .map(to_proto_interface)
            .collect();
        Ok(Response::new(ListInterfacesResponse { interfaces }))
    }

    async fn create_interface(
        &self,
        req: Request<CreateInterfaceRequest>,
    ) -> Result<Response<CreateInterfaceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let interface = req
            .into_inner()
            .interface
            .ok_or(Status::invalid_argument("interface required"))?;
        let parsed = from_proto_interface(&interface)?;
        check_interface_admin(&self.security, &parsed.name, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            schema::validate_interface_definition(&parsed, registry.get_interface(&parsed.name))
                .map_err(Status::invalid_argument)?;
            let mut updated_registry = registry.clone();
            updated_registry.register_interface(parsed.clone());
            for object_type in updated_registry.all() {
                if object_type
                    .implements
                    .iter()
                    .any(|interface| interface == &parsed.name)
                {
                    schema::validate_object_type_definition(
                        &object_type,
                        updated_registry.get(&object_type.kind),
                        &updated_registry,
                    )
                    .map_err(Status::invalid_argument)?;
                }
            }
        }
        self.db
            .upsert_interface(&parsed)
            .map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .register_interface(parsed.clone());
        Ok(Response::new(CreateInterfaceResponse {
            interface: Some(to_proto_interface(&parsed)),
        }))
    }

    async fn delete_interface(
        &self,
        req: Request<DeleteInterfaceRequest>,
    ) -> Result<Response<DeleteInterfaceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("interface name required"));
        }
        check_interface_admin(&self.security, &name, &principals)?;
        {
            let registry = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            if registry
                .get_interface(&name)
                .map(|interface| interface.is_builtin)
                .unwrap_or(false)
            {
                return Err(Status::invalid_argument("cannot delete builtin interface"));
            }
            if registry.all().iter().any(|object_type| {
                object_type
                    .implements
                    .iter()
                    .any(|interface| interface == &name)
            }) {
                return Err(Status::failed_precondition(
                    "cannot delete interface while schema types implement it",
                ));
            }
        }
        self.db.delete_interface(&name).map_err(Status::internal)?;
        self.schema
            .write()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .remove_interface(&name);
        Ok(Response::new(DeleteInterfaceResponse {}))
    }

    async fn create_action_type(
        &self,
        req: Request<CreateActionTypeRequest>,
    ) -> Result<Response<CreateActionTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let action_type = req
            .into_inner()
            .action_type
            .ok_or(Status::invalid_argument("action_type required"))?;
        let parsed = from_proto_action_type(&action_type)?;
        check_action_admin(&self.security, &parsed.name, &principals)?;
        {
            action::validate_action_type_definition(
                &parsed,
                ActionExecutor::new().has_action(&parsed.name),
            )
            .map_err(Status::invalid_argument)?;
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            validate_action_type_against_schema(&parsed, &schema)?;
        }
        let stored = self
            .db
            .upsert_action_type(&parsed)
            .map_err(Status::internal)?;
        self.actions
            .write()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .register_action_type(stored.clone())
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateActionTypeResponse {
            action_type: Some(to_proto_action_type(&stored)),
        }))
    }

    async fn list_action_types(
        &self,
        req: Request<ListActionTypesRequest>,
    ) -> Result<Response<ListActionTypesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let action_types = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .list_action_types()
            .iter()
            .filter(|action_type| {
                check_read(
                    &self.security,
                    &action_object_id(&action_type.name),
                    &principals,
                )
                .is_ok()
            })
            .map(to_proto_action_type)
            .collect();
        Ok(Response::new(ListActionTypesResponse { action_types }))
    }

    async fn delete_action_type(
        &self,
        req: Request<DeleteActionTypeRequest>,
    ) -> Result<Response<DeleteActionTypeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let name = req.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("name required"));
        }
        check_action_admin(&self.security, &name, &principals)?;
        if self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .has_action(&name)
            && ActionExecutor::new().has_action(&name)
        {
            return Err(Status::invalid_argument("cannot delete builtin action"));
        }
        self.db
            .delete_action_type(&name)
            .map_err(Status::internal)?;
        self.actions
            .write()
            .map_err(|_| Status::internal("action registry unavailable"))?
            .remove_action_type(&name);
        Ok(Response::new(DeleteActionTypeResponse {}))
    }

    async fn execute_action(
        &self,
        req: Request<ExecuteActionRequest>,
    ) -> Result<Response<ExecuteActionResponse>, Status> {
        let principals = caller_principals(&req);
        let work_unit = work_unit_from_metadata(&req);
        let inner = req.into_inner();
        let dry_run = inner.dry_run;
        let r = inner
            .request
            .ok_or(Status::invalid_argument("request required"))?;
        let actions = self
            .actions
            .read()
            .map_err(|_| Status::internal("action registry unavailable"))?;
        let mask_missing_link = actions.masks_missing_link(&r.action);
        let sensitive_params = actions.sensitive_param_names(&r.action);
        let target_ids = actions
            .target_ids(&self.db, &r.action, &r.params)
            .map_err(|err| {
                if mask_missing_link && err == "link not found" {
                    Status::permission_denied("write denied")
                } else {
                    Status::invalid_argument(err)
                }
            })?;
        for target_id in &target_ids {
            check_write(&self.security, target_id, &principals)?;
        }
        let actor = principals.first().cloned().unwrap_or_default();
        // Governed-action policy gate (Plan 9, Phase A). Resolved by
        // agent-then-namespace scope; no policy == allow (backward compatible).
        let action_risk = actions.action_risk_class(&r.action);
        let policy_namespace = action_policy_namespace(&self.db, &target_ids, &r.params);
        let resolved_policy = self
            .db
            .resolve_action_policy(&actor, &policy_namespace, &policy_namespace)
            .map_err(Status::internal)?;
        let (decision, policy_scope) = match &resolved_policy {
            Some(policy) => (policy.decide(&r.action, action_risk), policy.scope.clone()),
            None => (ActionDecision::Allow, String::new()),
        };

        // Dry-run (Plan 9, Phase B): report the planned ops and the resolved
        // decision without executing or erroring, leaving the graph untouched.
        if dry_run {
            let planned_ops = actions
                .planned_ops(&r.action, &r.params)
                .map_err(Status::invalid_argument)?;
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("decision".into(), decision.as_str().into());
            evidence.insert("dry_run".into(), "true".into());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            if !policy_scope.is_empty() {
                evidence.insert("policy_scope".into(), policy_scope.clone());
            }
            let decision_id = uuid::Uuid::new_v4().to_string();
            let attested = attest_action_decision(
                resolved_policy.as_ref(),
                &decision_id,
                &r.action,
                &actor,
                action_risk,
                &policy_namespace,
                decision,
                &mut evidence,
            );
            self.db
                .record_decision_with_attestation(
                    &audit::Decision {
                        id: decision_id,
                        timestamp: now_millis(),
                        actor: actor.clone(),
                        action: r.action.clone(),
                        reason: "execute_action_dry_run".into(),
                        evidence,
                        target_id: target_ids.first().cloned().unwrap_or_default(),
                        outcome: format!(
                            "dry-run: {} planned op(s), decision={}",
                            planned_ops.len(),
                            decision.as_str()
                        ),
                    },
                    attested.as_ref(),
                )
                .map_err(Status::internal)?;
            return Ok(Response::new(ExecuteActionResponse {
                result: Some(ActionResult {
                    action: r.action,
                    message: format!("dry run: {} planned op(s)", planned_ops.len()),
                    dry_run: true,
                    planned_ops,
                    decision: decision.as_str().into(),
                    approval_id: String::new(),
                }),
            }));
        }

        if decision == ActionDecision::RequireApproval {
            // Phase B: hold the action for out-of-band approval instead of
            // executing. Persist the exact params so it can be resumed.
            let approval = action_approval::ActionApproval::pending(
                actor.clone(),
                r.action.clone(),
                r.params.clone(),
                work_unit.clone(),
                policy_scope.clone(),
                action_risk.as_str(),
                target_ids.first().cloned().unwrap_or_default(),
                now_millis(),
            );
            self.db
                .create_action_approval(&approval)
                .map_err(Status::internal)?;
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("policy_scope".into(), policy_scope.clone());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            evidence.insert("decision".into(), decision.as_str().into());
            evidence.insert("approval_id".into(), approval.id.clone());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            let decision_id = uuid::Uuid::new_v4().to_string();
            let attested = attest_action_decision(
                resolved_policy.as_ref(),
                &decision_id,
                &r.action,
                &actor,
                action_risk,
                &policy_namespace,
                decision,
                &mut evidence,
            );
            self.db
                .record_decision_with_attestation(
                    &audit::Decision {
                        id: decision_id,
                        timestamp: now_millis(),
                        actor: actor.clone(),
                        action: r.action.clone(),
                        reason: "action_approval_pending".into(),
                        evidence,
                        target_id: target_ids.first().cloned().unwrap_or_default(),
                        outcome: format!("held for approval: {}", approval.id),
                    },
                    attested.as_ref(),
                )
                .map_err(Status::internal)?;
            return Ok(Response::new(ExecuteActionResponse {
                result: Some(ActionResult {
                    action: r.action,
                    message: format!("action held for approval: {}", approval.id),
                    dry_run: false,
                    planned_ops: Vec::new(),
                    decision: decision.as_str().into(),
                    approval_id: approval.id,
                }),
            }));
        }

        if decision == ActionDecision::Deny {
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("policy_scope".into(), policy_scope.clone());
            evidence.insert("decision".into(), decision.as_str().into());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            let decision_id = uuid::Uuid::new_v4().to_string();
            let attested = attest_action_decision(
                resolved_policy.as_ref(),
                &decision_id,
                &r.action,
                &actor,
                action_risk,
                &policy_namespace,
                decision,
                &mut evidence,
            );
            self.db
                .record_decision_with_attestation(
                    &audit::Decision {
                        id: decision_id,
                        timestamp: now_millis(),
                        actor: actor.clone(),
                        action: r.action.clone(),
                        reason: "action_policy_denied".into(),
                        evidence,
                        target_id: target_ids.first().cloned().unwrap_or_default(),
                        outcome: format!("{} by action policy {}", decision.as_str(), policy_scope),
                    },
                    attested.as_ref(),
                )
                .map_err(Status::internal)?;
            return Err(Status::permission_denied(format!(
                "action {} denied by policy",
                r.action
            )));
        }

        // Blast-radius caps (Plan 9, Phase C): hard-stop runaway loops by
        // capping mutations/deletes per work unit. Only enforced when a policy
        // sets a cap and the call carries a work-unit attribution.
        let blast_caps = resolved_policy.as_ref().and_then(|policy| {
            match (
                policy.max_mutations_per_work_unit,
                policy.max_deletes_per_work_unit,
            ) {
                (None, None) => None,
                caps => Some(caps),
            }
        });
        let (op_mutations, op_deletes) = actions.action_op_counts(&r.action, &r.params);
        if !work_unit.is_empty()
            && let Some((max_mutations, max_deletes)) = blast_caps
        {
            let (used_mutations, used_deletes) = self
                .db
                .get_blast_radius(&work_unit)
                .map_err(Status::internal)?;
            let exceeds = |cap: Option<u32>, used: u32, add: u32| {
                cap.is_some_and(|cap| used.saturating_add(add) > cap)
            };
            if exceeds(max_deletes, used_deletes, op_deletes)
                || exceeds(max_mutations, used_mutations, op_mutations)
            {
                let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
                evidence.insert("risk_class".into(), action_risk.as_str().into());
                evidence.insert("policy_scope".into(), policy_scope.clone());
                evidence.insert("work_unit".into(), work_unit.clone());
                evidence.insert("used_mutations".into(), used_mutations.to_string());
                evidence.insert("used_deletes".into(), used_deletes.to_string());
                self.db
                    .record_decision(&audit::Decision {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: now_millis(),
                        actor: actor.clone(),
                        action: r.action.clone(),
                        reason: "action_blast_radius_exceeded".into(),
                        evidence,
                        target_id: target_ids.first().cloned().unwrap_or_default(),
                        outcome: format!("blast-radius cap exceeded for work unit {}", work_unit),
                    })
                    .map_err(Status::internal)?;
                return Err(Status::resource_exhausted(format!(
                    "blast-radius cap exceeded for work unit {}",
                    work_unit
                )));
            }
        }

        // Action-class budget (Plan 10, Phase A): meter effectful actions against
        // a hierarchical `action:<risk_class>` scope rooted at project and then
        // actor. No limit == allow.
        let budget_subject = action_budget_subject(action_risk.as_str(), &policy_namespace, &actor);
        if let Some(budget) = &self.budget
            && let Err(err) = budget.check(&budget_subject, 1)
        {
            let mut evidence = redact_action_evidence(&r.params, &sensitive_params, None);
            evidence.insert("risk_class".into(), action_risk.as_str().into());
            evidence.insert("budget_subject".into(), budget_subject.clone());
            if !work_unit.is_empty() {
                evidence.insert("work_unit".into(), work_unit.clone());
            }
            self.db
                .record_decision(&audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now_millis(),
                    actor: actor.clone(),
                    action: r.action.clone(),
                    reason: "action_budget_exceeded".into(),
                    evidence,
                    target_id: target_ids.first().cloned().unwrap_or_default(),
                    outcome: err,
                })
                .map_err(Status::internal)?;
            return Err(Status::resource_exhausted(format!(
                "action budget exhausted for {}",
                budget_subject
            )));
        }
        let schema_kinds = actions
            .schema_kinds(&self.db, &r.action, &r.params)
            .map_err(Status::invalid_argument)?;
        for kind in schema_kinds {
            self.require_schema_kind_loaded(&kind)?;
        }
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?;
        actions
            .validate_action_schema(&r.action, &schema)
            .map_err(Status::invalid_argument)?;
        let schema_restricted_property =
            schema_restricted_action_property(&self.db, &schema, &r.params);
        let provisional_learning_grant = (r.action
            == crate::sekai::learning::RECORD_LEARNING_ACTION)
            .then(|| security::Grant {
                id: String::new(),
                object_id: r.params.get("id").cloned().unwrap_or_default(),
                principal: actor.clone(),
                role: security::Role::Admin,
                created: now_millis(),
            })
            .filter(|grant| !grant.object_id.is_empty());
        if let Some(grant) = &provisional_learning_grant {
            self.security.add_grant(grant);
        }
        let msg = match actions.execute(&self.db, &schema, &r.action, &r.params, &actor) {
            Ok(msg) => msg,
            Err(error) => {
                if let Some(grant) = &provisional_learning_grant {
                    self.security
                        .remove_grant(&grant.object_id, &grant.principal);
                }
                return Err(Status::invalid_argument(error));
            }
        };
        drop(actions);
        drop(schema);
        self.refresh_security_after_action(&r.action, &r.params, &actor)?;
        let mut evidence =
            redact_action_evidence(&r.params, &sensitive_params, schema_restricted_property);
        evidence.insert("risk_class".into(), action_risk.as_str().into());
        evidence.insert("decision".into(), decision.as_str().into());
        if !policy_scope.is_empty() {
            evidence.insert("policy_scope".into(), policy_scope.clone());
        }
        if !work_unit.is_empty() {
            evidence.insert("work_unit".into(), work_unit.clone());
        }
        let decision_id = uuid::Uuid::new_v4().to_string();
        let attested = attest_action_decision(
            resolved_policy.as_ref(),
            &decision_id,
            &r.action,
            &actor,
            action_risk,
            &policy_namespace,
            decision,
            &mut evidence,
        );
        self.db
            .record_decision_with_attestation(
                &audit::Decision {
                    id: decision_id,
                    timestamp: now_millis(),
                    actor,
                    action: r.action.clone(),
                    reason: "execute_action".into(),
                    evidence,
                    target_id: target_ids.first().cloned().unwrap_or_default(),
                    outcome: redact_action_outcome(
                        &r.action,
                        &r.params,
                        &msg,
                        schema_restricted_property,
                    ),
                },
                attested.as_ref(),
            )
            .map_err(Status::internal)?;
        // Record the effect against the work unit's blast-radius counters.
        if !work_unit.is_empty() && blast_caps.is_some() && (op_mutations > 0 || op_deletes > 0) {
            let _ = self
                .db
                .add_blast_radius(&work_unit, op_mutations, op_deletes);
        }
        // Record action-class budget usage (one unit per executed action).
        if let Some(budget) = &self.budget {
            budget.record(&budget_subject, 1);
        }
        Ok(Response::new(ExecuteActionResponse {
            result: Some(ActionResult {
                action: r.action,
                message: msg,
                dry_run: false,
                planned_ops: Vec::new(),
                decision: decision.as_str().into(),
                approval_id: String::new(),
            }),
        }))
    }
    async fn set_action_policy(
        &self,
        req: Request<SetActionPolicyRequest>,
    ) -> Result<Response<SetActionPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let policy = req
            .into_inner()
            .policy
            .ok_or(Status::invalid_argument("policy required"))?;
        let domain_policy = from_proto_action_policy(&policy)?;
        check_action_admin(&self.security, &domain_policy.scope, &principals)?;
        self.db
            .upsert_action_policy(&domain_policy)
            .map_err(Status::internal)?;
        Ok(Response::new(SetActionPolicyResponse {
            policy: Some(to_proto_action_policy(&domain_policy)),
        }))
    }

    async fn get_action_policy(
        &self,
        req: Request<GetActionPolicyRequest>,
    ) -> Result<Response<GetActionPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        check_action_admin(&self.security, &r.scope, &principals)?;
        let policy = self
            .db
            .get_action_policy(&r.scope)
            .map_err(Status::internal)?;
        Ok(Response::new(GetActionPolicyResponse {
            policy: policy.map(|policy| to_proto_action_policy(&policy)),
        }))
    }

    async fn list_action_policies(
        &self,
        req: Request<ListActionPoliciesRequest>,
    ) -> Result<Response<ListActionPoliciesResponse>, Status> {
        let principals = caller_principals(&req);
        check_action_admin(&self.security, "", &principals)?;
        let policies = self.db.list_action_policies().map_err(Status::internal)?;
        Ok(Response::new(ListActionPoliciesResponse {
            policies: policies.iter().map(to_proto_action_policy).collect(),
        }))
    }

    async fn approve_action(
        &self,
        req: Request<ApproveActionRequest>,
    ) -> Result<Response<ApproveActionResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let mut approval = self
            .db
            .get_action_approval(&r.approval_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("approval not found"))?;
        check_action_admin(&self.security, &approval.policy_scope, &principals)?;
        if approval.status != action_approval::ApprovalStatus::Pending {
            return Err(Status::failed_precondition(format!(
                "approval {} is already {}",
                approval.id,
                approval.status.as_str()
            )));
        }
        let approver = principals.first().cloned().unwrap_or_default();

        // Re-check policy at execution time: a tightened policy that now denies
        // the action must block the resume even though it was approved.
        let target_ids = {
            let actions = self
                .actions
                .read()
                .map_err(|_| Status::internal("action registry unavailable"))?;
            actions
                .target_ids(&self.db, &approval.action, &approval.params)
                .unwrap_or_default()
        };
        let namespace = action_policy_namespace(&self.db, &target_ids, &approval.params);
        let action_risk = {
            let actions = self
                .actions
                .read()
                .map_err(|_| Status::internal("action registry unavailable"))?;
            actions.action_risk_class(&approval.action)
        };
        let resolved_policy = self
            .db
            .resolve_action_policy(&approval.actor, &namespace, &namespace)
            .map_err(Status::internal)?;
        if let Some(policy) = &resolved_policy
            && policy.decide(&approval.action, action_risk) == ActionDecision::Deny
        {
            let mut evidence = HashMap::from([
                ("approval_id".to_string(), approval.id.clone()),
                ("policy_scope".to_string(), policy.scope.clone()),
                ("risk_class".to_string(), action_risk.as_str().into()),
                ("decision".to_string(), "deny".into()),
            ]);
            if !approval.work_unit.is_empty() {
                evidence.insert("work_unit".into(), approval.work_unit.clone());
            }
            let decision_id = uuid::Uuid::new_v4().to_string();
            let attested = attest_action_decision(
                Some(policy),
                &decision_id,
                &approval.action,
                &approval.actor,
                action_risk,
                &namespace,
                ActionDecision::Deny,
                &mut evidence,
            );
            self.db
                .record_decision_with_attestation(
                    &audit::Decision {
                        id: decision_id,
                        timestamp: now_millis(),
                        actor: approver,
                        action: approval.action.clone(),
                        reason: "action_approval_policy_denied".into(),
                        evidence,
                        target_id: approval.target_id.clone(),
                        outcome: "policy now denies the held action".into(),
                    },
                    attested.as_ref(),
                )
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "action policy now denies this approval",
            ));
        }

        // Resumed actions must still be metered like the direct path: enforce
        // per-work-unit blast-radius caps and the action-class budget so
        // approval is not a governance bypass (Plan 9, Phase C).
        let (op_mutations, op_deletes) = {
            let actions = self
                .actions
                .read()
                .map_err(|_| Status::internal("action registry unavailable"))?;
            actions.action_op_counts(&approval.action, &approval.params)
        };
        let blast_caps = resolved_policy.as_ref().and_then(|policy| {
            match (
                policy.max_mutations_per_work_unit,
                policy.max_deletes_per_work_unit,
            ) {
                (None, None) => None,
                caps => Some(caps),
            }
        });
        if !approval.work_unit.is_empty()
            && let Some((max_mutations, max_deletes)) = blast_caps
        {
            let (used_mutations, used_deletes) = self
                .db
                .get_blast_radius(&approval.work_unit)
                .map_err(Status::internal)?;
            let exceeds = |cap: Option<u32>, used: u32, add: u32| {
                cap.is_some_and(|cap| used.saturating_add(add) > cap)
            };
            if exceeds(max_deletes, used_deletes, op_deletes)
                || exceeds(max_mutations, used_mutations, op_mutations)
            {
                return Err(Status::resource_exhausted(format!(
                    "blast-radius cap exceeded for work unit {}",
                    approval.work_unit
                )));
            }
        }
        let budget_subject =
            action_budget_subject(action_risk.as_str(), &namespace, &approval.actor);
        if let Some(budget) = &self.budget
            && budget.check(&budget_subject, 1).is_err()
        {
            let mut evidence =
                HashMap::from([("budget_subject".to_string(), budget_subject.clone())]);
            evidence.insert("risk_class".to_string(), action_risk.as_str().into());
            evidence.insert("decision".to_string(), "deny".into());
            if !approval.work_unit.is_empty() {
                evidence.insert("work_unit".into(), approval.work_unit.clone());
            }
            self.db
                .record_decision(&audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now_millis(),
                    actor: approver,
                    action: approval.action.clone(),
                    reason: "action_budget_exceeded".into(),
                    evidence,
                    target_id: approval.target_id.clone(),
                    outcome: format!("action budget exhausted for {budget_subject}"),
                })
                .map_err(Status::internal)?;
            return Err(Status::resource_exhausted(format!(
                "action budget exhausted for {}",
                budget_subject
            )));
        }

        // Resume the effect, re-checking write access for the original proposer.
        let proposer = vec![approval.actor.clone()];
        let msg = self.run_action_effect(
            &approval.action,
            &approval.params,
            &approval.actor,
            &proposer,
        )?;

        // Record the effect against blast-radius counters and the action budget.
        if !approval.work_unit.is_empty()
            && blast_caps.is_some()
            && (op_mutations > 0 || op_deletes > 0)
        {
            let _ = self
                .db
                .add_blast_radius(&approval.work_unit, op_mutations, op_deletes);
        }
        if let Some(budget) = &self.budget {
            budget.record(&budget_subject, 1);
        }

        approval.status = action_approval::ApprovalStatus::Approved;
        approval.decided_by = principals.first().cloned().unwrap_or_default();
        approval.outcome = msg.clone();
        approval.updated = now_millis();
        self.db
            .update_action_approval(&approval)
            .map_err(Status::internal)?;
        // Attest the policy that permitted the resume, so the executed
        // outcome is as replayable as the hold decision was.
        let approval_policy_decision = resolved_policy
            .as_ref()
            .map(|policy| policy.decide(&approval.action, action_risk))
            .unwrap_or(ActionDecision::Allow);
        let mut evidence = HashMap::from([
            ("approval_id".to_string(), approval.id.clone()),
            ("risk_class".to_string(), action_risk.as_str().into()),
            (
                "decision".to_string(),
                approval_policy_decision.as_str().into(),
            ),
            ("approval_status".to_string(), "approved".into()),
        ]);
        if !approval.policy_scope.is_empty() {
            evidence.insert("policy_scope".into(), approval.policy_scope.clone());
        }
        if !approval.work_unit.is_empty() {
            evidence.insert("work_unit".into(), approval.work_unit.clone());
        }
        let decision_id = uuid::Uuid::new_v4().to_string();
        let attested = attest_action_decision(
            resolved_policy.as_ref(),
            &decision_id,
            &approval.action,
            &approval.actor,
            action_risk,
            &namespace,
            approval_policy_decision,
            &mut evidence,
        );
        self.db
            .record_decision_with_attestation(
                &audit::Decision {
                    id: decision_id,
                    timestamp: now_millis(),
                    actor: approval.decided_by.clone(),
                    action: approval.action.clone(),
                    reason: "action_approval_approved".into(),
                    evidence,
                    target_id: approval.target_id.clone(),
                    outcome: msg.clone(),
                },
                attested.as_ref(),
            )
            .map_err(Status::internal)?;

        Ok(Response::new(ApproveActionResponse {
            result: Some(ActionResult {
                action: approval.action.clone(),
                message: msg,
                dry_run: false,
                planned_ops: Vec::new(),
                decision: "approved".into(),
                approval_id: approval.id.clone(),
            }),
            approval: Some(to_proto_action_approval(&approval)),
        }))
    }

    async fn deny_action(
        &self,
        req: Request<DenyActionRequest>,
    ) -> Result<Response<DenyActionResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let mut approval = self
            .db
            .get_action_approval(&r.approval_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("approval not found"))?;
        check_action_admin(&self.security, &approval.policy_scope, &principals)?;
        if approval.status != action_approval::ApprovalStatus::Pending {
            return Err(Status::failed_precondition(format!(
                "approval {} is already {}",
                approval.id,
                approval.status.as_str()
            )));
        }
        approval.status = action_approval::ApprovalStatus::Denied;
        approval.decided_by = principals.first().cloned().unwrap_or_default();
        approval.outcome = if r.reason.trim().is_empty() {
            "denied".to_string()
        } else {
            r.reason.trim().to_string()
        };
        approval.updated = now_millis();
        self.db
            .update_action_approval(&approval)
            .map_err(Status::internal)?;
        let mut evidence = HashMap::from([
            ("approval_id".into(), approval.id.clone()),
            ("risk_class".into(), approval.risk_class.clone()),
            ("decision".into(), "deny".into()),
        ]);
        if !approval.policy_scope.is_empty() {
            evidence.insert("policy_scope".into(), approval.policy_scope.clone());
        }
        if !approval.work_unit.is_empty() {
            evidence.insert("work_unit".into(), approval.work_unit.clone());
        }
        self.db
            .record_decision(&audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now_millis(),
                actor: approval.decided_by.clone(),
                action: approval.action.clone(),
                reason: "action_approval_denied".into(),
                evidence,
                target_id: approval.target_id.clone(),
                outcome: approval.outcome.clone(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(DenyActionResponse {
            approval: Some(to_proto_action_approval(&approval)),
        }))
    }

    async fn list_pending_approvals(
        &self,
        req: Request<ListPendingApprovalsRequest>,
    ) -> Result<Response<ListPendingApprovalsResponse>, Status> {
        let principals = caller_principals(&req);
        check_action_admin(&self.security, "", &principals)?;
        let r = req.into_inner();
        let status = match r.status.trim().to_ascii_lowercase().as_str() {
            "" | "pending" => Some(action_approval::ApprovalStatus::Pending),
            "all" => None,
            other => Some(
                action_approval::ApprovalStatus::parse(other)
                    .ok_or_else(|| Status::invalid_argument("invalid status filter"))?,
            ),
        };
        let approvals = self
            .db
            .list_action_approvals(status)
            .map_err(Status::internal)?;
        Ok(Response::new(ListPendingApprovalsResponse {
            approvals: approvals.iter().map(to_proto_action_approval).collect(),
        }))
    }

    async fn get_lineage(
        &self,
        req: Request<GetLineageRequest>,
    ) -> Result<Response<GetLineageResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let res = crate::sekai::lineage::get_lineage(&self.db, &r.object_id, r.max_nodes as usize)
            .map_err(Status::internal)?;
        let objects = self.resolve_computed_for_responses(
            res.nodes.iter().map(|node| node.object.clone()).collect(),
            &principals,
        )?;
        let nodes = res
            .nodes
            .iter()
            .zip(objects.iter())
            .map(|(n, object)| LineageNode {
                object: Some(to_proto_obj(object)),
                role: n.role.clone(),
                ephemeral: n.ephemeral,
            })
            .collect();
        let edges = res
            .edges
            .iter()
            .map(|e| LineageEdge {
                from: e.from.clone(),
                to: e.to.clone(),
                relation: e.relation.clone(),
            })
            .collect();
        Ok(Response::new(GetLineageResponse {
            result: Some(LineageResult {
                nodes,
                edges,
                truncated: res.truncated,
            }),
        }))
    }
    async fn create_contention_scope(
        &self,
        req: Request<CreateContentionScopeRequest>,
    ) -> Result<Response<CreateContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let mut scope = inner
            .scope
            .ok_or(Status::invalid_argument("scope required"))
            .map(|scope| from_proto_contention_scope(&scope))?;
        let owner = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        if let Some(existing) = self
            .db
            .get_dedup_request(&inner.request_id, "create_contention_scope")
            .map_err(Status::internal)?
            .filter(|record| record.principal == owner)
        {
            let scope = self
                .db
                .get_contention_scope(&existing.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            return Ok(Response::new(CreateContentionScopeResponse {
                scope: Some(to_proto_contention_scope(&scope)),
            }));
        }
        if scope.owner_principal.is_empty() {
            scope.owner_principal = owner;
        }
        self.db
            .create_contention_scope(&scope)
            .map_err(Status::invalid_argument)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "create_contention_scope".into(),
                principal: dedup_principal(&principals),
                scope_id: scope.id.clone(),
                work_unit_id: String::new(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CreateContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn update_contention_scope(
        &self,
        req: Request<UpdateContentionScopeRequest>,
    ) -> Result<Response<UpdateContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let scope = inner
            .scope
            .ok_or(Status::invalid_argument("scope required"))
            .map(|scope| from_proto_contention_scope(&scope))?;
        let existing = self
            .db
            .get_contention_scope(&scope.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_write(&existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "update_contention_scope")
            .map_err(Status::internal)?
        {
            if record.scope_id == scope.id && record.principal == dedup_principal(&principals) {
                let scope = self
                    .db
                    .get_contention_scope(&scope.id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("scope not found"))?;
                return Ok(Response::new(UpdateContentionScopeResponse {
                    scope: Some(to_proto_contention_scope(&scope)),
                }));
            }
        }
        self.db
            .update_contention_scope(&scope)
            .map_err(Status::invalid_argument)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "update_contention_scope".into(),
                principal: dedup_principal(&principals),
                scope_id: scope.id.clone(),
                work_unit_id: String::new(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(UpdateContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn get_contention_scope(
        &self,
        req: Request<GetContentionScopeRequest>,
    ) -> Result<Response<GetContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let scope = self
            .db
            .get_contention_scope(&req.into_inner().id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_read(&scope, &principals)?;
        Ok(Response::new(GetContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn list_contention_scopes(
        &self,
        req: Request<ListContentionScopesRequest>,
    ) -> Result<Response<ListContentionScopesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let scopes = self
            .db
            .list_contention_scopes()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|scope| check_scope_read(scope, &principals).is_ok())
            .map(|scope| to_proto_contention_scope(&scope))
            .collect();
        Ok(Response::new(ListContentionScopesResponse { scopes }))
    }
    async fn create_work_unit(
        &self,
        req: Request<CreateWorkUnitRequest>,
    ) -> Result<Response<CreateWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let mut work_unit = inner
            .work_unit
            .ok_or(Status::invalid_argument("work_unit required"))
            .map(|work_unit| from_proto_work_unit(&work_unit))?;
        let principal = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        if let Some(existing) = self
            .db
            .get_dedup_request(&inner.request_id, "create_work_unit")
            .map_err(Status::internal)?
            .filter(|record| record.principal == principal)
        {
            let work_unit = self
                .db
                .get_work_unit(&existing.work_unit_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("work unit not found"))?;
            return Ok(Response::new(CreateWorkUnitResponse {
                work_unit: Some(to_proto_work_unit(&work_unit)),
            }));
        }
        if !work_unit.idempotency_key.is_empty() {
            if let Some(existing) = self
                .db
                .get_work_unit_by_idempotency_key(&work_unit.idempotency_key)
                .map_err(Status::internal)?
            {
                check_work_unit_read(&self.security, &existing, &principals)?;
                return Ok(Response::new(CreateWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&existing)),
                }));
            }
        }
        if !work_unit.target_object_id.is_empty() {
            check_write(&self.security, &work_unit.target_object_id, &principals)?;
        }
        let scope = self
            .db
            .get_contention_scope(&work_unit.scope_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_read(&scope, &principals)?;
        initialize_work_unit_for_create(&mut work_unit, &principal);
        self.db
            .create_work_unit(&work_unit)
            .map_err(Status::invalid_argument)?;
        let event = coordination::RunEvent {
            id: format!("evt:{}:created:{}", work_unit.id, work_unit.created_at),
            work_unit_id: work_unit.id.clone(),
            event_type: "created".into(),
            message: "work unit created".into(),
            evidence: std::collections::HashMap::from([(
                "scope_id".into(),
                work_unit.scope_id.clone(),
            )]),
            created_at: work_unit.created_at,
        };
        self.db.append_run_event(&event).map_err(Status::internal)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "create_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CreateWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn get_work_unit(
        &self,
        req: Request<GetWorkUnitRequest>,
    ) -> Result<Response<GetWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let work_unit = self
            .db
            .get_work_unit(&req.into_inner().id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_read(&self.security, &work_unit, &principals)?;
        Ok(Response::new(GetWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn list_work_units(
        &self,
        req: Request<ListWorkUnitsRequest>,
    ) -> Result<Response<ListWorkUnitsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let filter = req.into_inner().filter.unwrap_or_default();
        let limit = filter.limit;
        let mut work_units = self
            .db
            .list_work_units(&from_proto_work_unit_filter(&filter))
            .map_err(Status::internal)?
            .into_iter()
            .filter(|work_unit| {
                check_work_unit_read(&self.security, work_unit, &principals).is_ok()
            })
            .collect::<Vec<_>>();
        let next_page_token = if limit > 0 && work_units.len() > limit as usize {
            let next = work_units
                .get((limit as usize).saturating_sub(1))
                .map(|work_unit| coordination::make_page_token(work_unit.created_at, &work_unit.id))
                .unwrap_or_default();
            trim_page(&mut work_units, limit);
            next
        } else {
            String::new()
        };
        Ok(Response::new(ListWorkUnitsResponse {
            work_units: work_units.iter().map(to_proto_work_unit).collect(),
            next_page_token,
        }))
    }
    async fn try_admit_work_unit(
        &self,
        req: Request<TryAdmitWorkUnitRequest>,
    ) -> Result<Response<TryAdmitWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let work_unit = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &work_unit, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "try_admit_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id
                && record.principal == dedup_principal(&principals)
            {
                let current = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                let reservations = self
                    .db
                    .list_reservations(&coordination::ReservationFilter {
                        work_unit_id: Some(work_unit_id.clone()),
                        status: Some(coordination::RESERVATION_STATUS_ACTIVE.into()),
                        ..Default::default()
                    })
                    .map_err(Status::internal)?;
                return Ok(Response::new(TryAdmitWorkUnitResponse {
                    admitted: current.status == coordination::WORK_UNIT_STATUS_RUNNING,
                    queue_position: 0,
                    reason: String::new(),
                    work_unit: Some(to_proto_work_unit(&current)),
                    reservations: reservations.iter().map(to_proto_reservation).collect(),
                }));
            }
        }
        let owner = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        let result = self
            .db
            .try_admit_work_unit(&work_unit_id, &owner, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "try_admit_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: result.work_unit.scope_id.clone(),
                work_unit_id: result.work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(TryAdmitWorkUnitResponse {
            admitted: result.admitted,
            queue_position: result.queue_position,
            reason: result.reason,
            work_unit: Some(to_proto_work_unit(&result.work_unit)),
            reservations: result
                .reservations
                .iter()
                .map(to_proto_reservation)
                .collect(),
        }))
    }
    async fn heartbeat_work_unit(
        &self,
        req: Request<HeartbeatWorkUnitRequest>,
    ) -> Result<Response<HeartbeatWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "heartbeat_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(HeartbeatWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .heartbeat_work_unit(&work_unit_id, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "heartbeat_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(HeartbeatWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn complete_work_unit(
        &self,
        req: Request<CompleteWorkUnitRequest>,
    ) -> Result<Response<CompleteWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "complete_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(CompleteWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .complete_work_unit(&work_unit_id, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "complete_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CompleteWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn fail_work_unit(
        &self,
        req: Request<FailWorkUnitRequest>,
    ) -> Result<Response<FailWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "fail_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == inner.work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&inner.work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(FailWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .fail_work_unit(
                &inner.work_unit_id,
                &inner.failure_reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "fail_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(FailWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn cancel_work_unit(
        &self,
        req: Request<CancelWorkUnitRequest>,
    ) -> Result<Response<CancelWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "cancel_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == inner.work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&inner.work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(CancelWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .cancel_work_unit(
                &inner.work_unit_id,
                &inner.cancel_reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "cancel_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CancelWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn release_reservation(
        &self,
        req: Request<ReleaseReservationRequest>,
    ) -> Result<Response<ReleaseReservationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "release_reservation")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                return Ok(Response::new(ReleaseReservationResponse { released: 0 }));
            }
        }
        let released = self
            .db
            .release_reservations_for_work_unit(
                &work_unit_id,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::internal)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "release_reservation".into(),
                principal: dedup_principal(&principals),
                scope_id: existing.scope_id.clone(),
                work_unit_id: existing.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(ReleaseReservationResponse { released }))
    }
    async fn list_reservations(
        &self,
        req: Request<ListReservationsRequest>,
    ) -> Result<Response<ListReservationsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let reservations = self
            .db
            .list_reservations(&coordination::ReservationFilter {
                work_unit_id: if inner.work_unit_id.is_empty() {
                    None
                } else {
                    Some(inner.work_unit_id)
                },
                scope_id: if inner.scope_id.is_empty() {
                    None
                } else {
                    Some(inner.scope_id)
                },
                status: if inner.status.is_empty() {
                    None
                } else {
                    Some(inner.status)
                },
            })
            .map_err(Status::internal)?;
        let mut visible = Vec::new();
        for reservation in reservations {
            if let Some(work_unit) = self
                .db
                .get_work_unit(&reservation.work_unit_id)
                .map_err(Status::internal)?
            {
                if check_work_unit_read(&self.security, &work_unit, &principals).is_ok() {
                    visible.push(to_proto_reservation(&reservation));
                }
            }
        }
        Ok(Response::new(ListReservationsResponse {
            reservations: visible,
        }))
    }
    async fn list_run_events(
        &self,
        req: Request<ListRunEventsRequest>,
    ) -> Result<Response<ListRunEventsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_read(&self.security, &work_unit, &principals)?;
        let limit = inner.limit;
        let mut events = self
            .db
            .list_run_events(
                &inner.work_unit_id,
                inner.limit,
                inner.after,
                &inner.event_types,
                if inner.page_token.is_empty() {
                    None
                } else {
                    Some(inner.page_token.as_str())
                },
            )
            .map_err(Status::internal)?
            .into_iter()
            .collect::<Vec<_>>();
        let next_page_token = if limit > 0 && events.len() > limit as usize {
            let next = events
                .get((limit as usize).saturating_sub(1))
                .map(|event| coordination::make_page_token(event.created_at, &event.id))
                .unwrap_or_default();
            trim_page(&mut events, limit);
            next
        } else {
            String::new()
        };
        Ok(Response::new(ListRunEventsResponse {
            events: events.iter().map(to_proto_run_event).collect(),
            next_page_token,
        }))
    }
    async fn reconcile_work_units(
        &self,
        req: Request<ReconcileWorkUnitsRequest>,
    ) -> Result<Response<ReconcileWorkUnitsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let summary = if !inner.work_unit_id.is_empty() {
            let work_unit = self
                .db
                .get_work_unit(&inner.work_unit_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("work unit not found"))?;
            let scope = self
                .db
                .get_contention_scope(&work_unit.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            check_scope_write(&scope, &principals)?;
            if !inner.scope_id.is_empty() && inner.scope_id != work_unit.scope_id {
                return Ok(Response::new(ReconcileWorkUnitsResponse {
                    work_units_reconciled: 0,
                    reservations_released: 0,
                    details: Vec::new(),
                }));
            }
            self.db
                .reconcile_work_units(
                    now_ms,
                    &coordination::ReconcileFilter {
                        dry_run: inner.dry_run,
                        work_unit_id: Some(inner.work_unit_id),
                        scope_id: if inner.scope_id.is_empty() {
                            None
                        } else {
                            Some(inner.scope_id)
                        },
                        limit: inner.limit,
                    },
                )
                .map_err(Status::internal)?
        } else if !inner.scope_id.is_empty() {
            let scope = self
                .db
                .get_contention_scope(&inner.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            check_scope_write(&scope, &principals)?;
            self.db
                .reconcile_work_units(
                    now_ms,
                    &coordination::ReconcileFilter {
                        dry_run: inner.dry_run,
                        work_unit_id: None,
                        scope_id: Some(inner.scope_id),
                        limit: inner.limit,
                    },
                )
                .map_err(Status::internal)?
        } else {
            let mut owned_scope_ids: Vec<String> = self
                .db
                .list_contention_scopes()
                .map_err(Status::internal)?
                .into_iter()
                .filter(|scope| principal_matches(&scope.owner_principal, &principals))
                .map(|scope| scope.id)
                .collect();
            owned_scope_ids.sort();
            if owned_scope_ids.is_empty() {
                return Err(Status::permission_denied(
                    "reconcile requires scope ownership",
                ));
            }
            let mut summary = coordination::ReconcileSummary::default();
            for scope_id in owned_scope_ids {
                reconcile_owned_scope(
                    &self.db,
                    now_ms,
                    scope_id,
                    inner.dry_run,
                    inner.limit,
                    &mut summary,
                )?;
            }
            summary
        };
        Ok(Response::new(ReconcileWorkUnitsResponse {
            work_units_reconciled: summary.work_units_reconciled,
            reservations_released: summary.reservations_released,
            details: summary
                .details
                .iter()
                .map(|detail| ReconciliationDetail {
                    work_unit_id: detail.work_unit_id.clone(),
                    reservation_id: detail.reservation_id.clone(),
                    reason: detail.reason.clone(),
                    action: detail.action.clone(),
                })
                .collect(),
        }))
    }
    async fn get_coordination_snapshot(
        &self,
        req: Request<GetCoordinationSnapshotRequest>,
    ) -> Result<Response<GetCoordinationSnapshotResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let visible_scopes = self
            .db
            .list_contention_scopes()
            .map_err(Status::internal)?
            .into_iter()
            .any(|scope| principal_matches(&scope.owner_principal, &principals));
        if !visible_scopes {
            return Err(Status::permission_denied(
                "snapshot requires scope ownership",
            ));
        }
        let snapshot = self
            .db
            .coordination_snapshot(chrono::Utc::now().timestamp_millis())
            .map_err(Status::internal)?;
        Ok(Response::new(GetCoordinationSnapshotResponse {
            snapshot: Some(to_proto_snapshot(&snapshot)),
        }))
    }
    // --- Remaining RPCs return unimplemented for now (wired in detail later) ---
    async fn create_function(
        &self,
        req: Request<CreateFunctionRequest>,
    ) -> Result<Response<CreateFunctionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let function = req
            .into_inner()
            .function
            .ok_or(Status::invalid_argument("function required"))?;
        let parsed = from_proto_function(&function);
        self.db
            .create_function(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateFunctionResponse {
            function: Some(to_proto_function(&parsed)),
        }))
    }
    async fn list_functions(
        &self,
        req: Request<ListFunctionsRequest>,
    ) -> Result<Response<ListFunctionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let functions = self
            .db
            .list_functions()
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_function)
            .collect();
        Ok(Response::new(ListFunctionsResponse { functions }))
    }
    async fn execute_function(
        &self,
        req: Request<ExecuteFunctionRequest>,
    ) -> Result<Response<ExecuteFunctionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let function = self
            .db
            .get_function(&inner.name)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("function not found"))?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        {
            let schema = self
                .schema
                .read()
                .map_err(|_| Status::internal("schema registry unavailable"))?;
            ensure_function_allows_restricted_properties(&schema, &principals, &function)?;
        }
        let result = function::execute_with_filter(&self.db, &function, &inner.params, |object| {
            self.security.can_access(&object.id, &refs)
        })
        .map_err(Status::invalid_argument)?;
        let objects = self.resolve_computed_for_responses(result.objects, &principals)?;
        Ok(Response::new(ExecuteFunctionResponse {
            result: Some(FunctionResult {
                objects: objects.iter().map(to_proto_obj).collect(),
                aggregates: result.aggregates,
            }),
        }))
    }
    async fn create_dataset(
        &self,
        req: Request<CreateDatasetRequest>,
    ) -> Result<Response<CreateDatasetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let dataset = req
            .into_inner()
            .dataset
            .ok_or(Status::invalid_argument("dataset required"))?;
        let parsed = from_proto_dataset(&dataset);
        if !parsed.object_id.is_empty() {
            check_write(&self.security, &parsed.object_id, &principals)?;
        }
        self.db
            .create_dataset(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateDatasetResponse {
            dataset: Some(to_proto_dataset(&parsed)),
        }))
    }
    async fn list_datasets(
        &self,
        req: Request<ListDatasetsRequest>,
    ) -> Result<Response<ListDatasetsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let datasets = self
            .db
            .list_datasets()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|dataset| {
                dataset.object_id.is_empty()
                    || check_read(&self.security, &dataset.object_id, &principals).is_ok()
            })
            .collect::<Vec<_>>()
            .iter()
            .map(to_proto_dataset)
            .collect();
        Ok(Response::new(ListDatasetsResponse { datasets }))
    }
    async fn append_rows(
        &self,
        req: Request<AppendRowsRequest>,
    ) -> Result<Response<AppendRowsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let dataset = self
            .db
            .get_dataset(&inner.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        if !dataset.object_id.is_empty() {
            check_write(&self.security, &dataset.object_id, &principals)?;
        }
        let rows: Vec<_> = inner.rows.into_iter().map(|r| r.values).collect();
        let count = self
            .db
            .append_rows(&inner.dataset_id, &rows)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(AppendRowsResponse { count }))
    }
    async fn query_rows(
        &self,
        req: Request<QueryRowsRequest>,
    ) -> Result<Response<QueryRowsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let dataset = self
            .db
            .get_dataset(&inner.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        if !dataset.object_id.is_empty() {
            check_read(&self.security, &dataset.object_id, &principals)?;
        }
        let query = inner.query.unwrap_or_default();
        let rows = self
            .db
            .query_rows(
                &inner.dataset_id,
                &dataset::RowQuery {
                    filters: from_proto_row_filters(&query.filters),
                    columns: query.columns,
                    limit: query.limit,
                    offset: query.offset,
                },
            )
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(QueryRowsResponse {
            rows: rows.into_iter().map(|values| Row { values }).collect(),
        }))
    }
    async fn create_virtual_table(
        &self,
        req: Request<CreateVirtualTableRequest>,
    ) -> Result<Response<CreateVirtualTableResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let table = req
            .into_inner()
            .table
            .ok_or(Status::invalid_argument("table required"))?;
        let parsed = from_proto_virtual_table(&table);
        let dataset = self
            .db
            .get_dataset(&parsed.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        if !dataset.object_id.is_empty() {
            check_write(&self.security, &dataset.object_id, &principals)?;
        }
        self.db
            .create_virtual_table(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateVirtualTableResponse {
            table: Some(to_proto_virtual_table(&parsed)),
        }))
    }
    async fn list_virtual_tables(
        &self,
        req: Request<ListVirtualTablesRequest>,
    ) -> Result<Response<ListVirtualTablesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tables = self
            .db
            .list_virtual_tables()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|table| {
                self.db
                    .get_dataset(&table.dataset_id)
                    .ok()
                    .flatten()
                    .map(|dataset| {
                        dataset.object_id.is_empty()
                            || check_read(&self.security, &dataset.object_id, &principals).is_ok()
                    })
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>()
            .iter()
            .map(to_proto_virtual_table)
            .collect();
        Ok(Response::new(ListVirtualTablesResponse { tables }))
    }
    async fn create_grant(
        &self,
        req: Request<CreateGrantRequest>,
    ) -> Result<Response<CreateGrantResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let grant = req
            .into_inner()
            .grant
            .ok_or(Status::invalid_argument("grant required"))?;
        let parsed = from_proto_grant(&grant)?;
        check_write(&self.security, &parsed.object_id, &principals)?;
        self.db
            .create_grant(&parsed)
            .map_err(Status::invalid_argument)?;
        self.security.add_grant(&parsed);
        Ok(Response::new(CreateGrantResponse {
            grant: Some(to_proto_grant(&parsed)),
        }))
    }
    async fn delete_grant(
        &self,
        req: Request<DeleteGrantRequest>,
    ) -> Result<Response<DeleteGrantResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        let existing = self
            .db
            .get_grant(&id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("grant not found"))?;
        check_write(&self.security, &existing.object_id, &principals)?;
        let deleted = self.db.delete_grant(&id).map_err(Status::internal)?;
        if let Some(grant) = deleted {
            self.security
                .remove_grant(&grant.object_id, &grant.principal);
        }
        Ok(Response::new(DeleteGrantResponse {}))
    }
    async fn list_grants(
        &self,
        req: Request<ListGrantsRequest>,
    ) -> Result<Response<ListGrantsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let object_id = req.into_inner().object_id;
        check_write(&self.security, &object_id, &principals)?;
        let grants = self
            .db
            .list_grants(&object_id)
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_grant)
            .collect();
        Ok(Response::new(ListGrantsResponse { grants }))
    }
    async fn check_access(
        &self,
        req: Request<CheckAccessRequest>,
    ) -> Result<Response<CheckAccessResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_read(&self.security, &inner.object_id, &principals)?;
        let refs: Vec<&str> = inner.principals.iter().map(String::as_str).collect();
        Ok(Response::new(CheckAccessResponse {
            allowed: self.security.can_access(&inner.object_id, &refs),
        }))
    }
    async fn record_decision(
        &self,
        req: Request<RecordDecisionRequest>,
    ) -> Result<Response<RecordDecisionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let mut decision = req
            .into_inner()
            .decision
            .ok_or_else(|| Status::invalid_argument("decision required"))?;
        if decision.id.is_empty() {
            decision.id = uuid::Uuid::new_v4().to_string();
        }
        // Clamp to server time: a client-supplied future timestamp would sit
        // above every later entry in the ledger and pin the purgeable prefix
        // forever (retention would silently stop).
        let now = now_millis();
        if decision.timestamp <= 0 || decision.timestamp > now {
            decision.timestamp = now;
        }
        // Reserved keys: only the server-side attestation binding may claim
        // one, otherwise a caller could dress up an arbitrary decision as
        // policy-attested.
        decision
            .evidence
            .remove(attestation::EVIDENCE_ATTESTATION_ID);
        decision
            .evidence
            .remove(attestation::EVIDENCE_ATTESTATION_HASH);
        self.db
            .record_decision(&audit::Decision {
                id: decision.id.clone(),
                timestamp: decision.timestamp,
                actor: decision.actor.clone(),
                action: decision.action.clone(),
                reason: decision.reason.clone(),
                evidence: decision.evidence.clone(),
                target_id: decision.target_id.clone(),
                outcome: decision.outcome.clone(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(RecordDecisionResponse {
            decision: Some(decision),
        }))
    }
    async fn list_decisions(
        &self,
        req: Request<ListDecisionsRequest>,
    ) -> Result<Response<ListDecisionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let visible_limit = if inner.limit > 0 {
            inner.limit as usize
        } else {
            100
        };
        let batch_size = visible_limit.max(50).min(200);
        let max_scan = visible_limit.saturating_mul(10).max(200);
        let actor_filter = if inner.actor.is_empty() {
            None
        } else {
            Some(inner.actor.clone())
        };
        let action_filter = if inner.action.is_empty() {
            None
        } else {
            Some(inner.action.clone())
        };
        let mut decisions = Vec::new();
        let mut offset = 0;
        let mut scanned = 0usize;
        while decisions.len() < visible_limit && scanned < max_scan {
            let batch = self
                .db
                .list_decisions(&audit::DecisionFilter {
                    actor: actor_filter.clone(),
                    action: action_filter.clone(),
                    target_id: None,
                    after: inner.after,
                    limit: batch_size as i32,
                    offset,
                })
                .map_err(Status::internal)?;
            if batch.is_empty() {
                break;
            }
            scanned += batch.len();
            offset += batch.len() as i32;
            for decision in batch {
                if decision.target_id.is_empty()
                    || check_read(&self.security, &decision.target_id, &principals).is_err()
                {
                    continue;
                }
                decisions.push(Decision {
                    id: decision.id,
                    timestamp: decision.timestamp,
                    actor: decision.actor,
                    action: decision.action,
                    reason: decision.reason,
                    evidence: decision.evidence,
                    target_id: decision.target_id,
                    outcome: decision.outcome,
                });
                if decisions.len() >= visible_limit {
                    break;
                }
            }
        }
        if decisions.len() < visible_limit && scanned >= max_scan {
            return Err(Status::resource_exhausted(
                "decision visibility scan limit exceeded; refine filters",
            ));
        }
        Ok(Response::new(ListDecisionsResponse { decisions }))
    }
    async fn list_object_changes(
        &self,
        req: Request<ListObjectChangesRequest>,
    ) -> Result<Response<ListObjectChangesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_read(&self.security, &inner.object_id, &principals)?;
        let object = self
            .db
            .get_object(&inner.object_id)
            .map_err(Status::internal)?;
        let object_kind = match object.as_ref() {
            Some(object) => Some(object.kind.clone()),
            None => self
                .db
                .object_change_kind(&inner.object_id)
                .map_err(Status::internal)?,
        };
        let schema = self
            .schema
            .read()
            .map_err(|_| Status::internal("schema registry unavailable"))?
            .clone();
        let changes = self
            .db
            .list_object_changes(&inner.object_id, inner.limit, inner.offset)
            .map_err(Status::internal)?
            .into_iter()
            .map(|change| {
                if let Some(kind) = object_kind.as_deref() {
                    redact_object_change_values(
                        change,
                        &inner.object_id,
                        kind,
                        &schema,
                        &self.security,
                        &principals,
                    )
                } else {
                    ObjectChange {
                        id: change.id,
                        object_id: change.object_id,
                        field: change.field,
                        old_value: change.old_value,
                        new_value: change.new_value,
                        changed_by: change.changed_by,
                        timestamp: change.timestamp,
                    }
                }
            })
            .collect();
        Ok(Response::new(ListObjectChangesResponse { changes }))
    }

    async fn verify_audit_ledger(
        &self,
        req: Request<VerifyAuditLedgerRequest>,
    ) -> Result<Response<VerifyAuditLedgerResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        // The chain walk re-hashes every entry since the last purge anchor;
        // keep that off the async executor threads.
        let db = self.db.clone();
        let report = tokio::task::spawn_blocking(move || db.verify_ledger())
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .map_err(Status::internal)?;
        Ok(Response::new(VerifyAuditLedgerResponse {
            ok: report.ok,
            entries_checked: report.entries_checked,
            first_bad_seq: report.first_bad_seq,
            error: report.error,
            anchor_seq: report.anchor_seq,
            head_seq: report.head_seq,
            head_hash: report.head_hash,
        }))
    }

    async fn get_attestation(
        &self,
        req: Request<GetAttestationRequest>,
    ) -> Result<Response<GetAttestationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        if id.trim().is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        let attestation = self
            .db
            .get_attestation(&id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("attestation not found"))?;
        // Attestations embed the full policy snapshot; reading policy content
        // is admin-gated like get_action_policy / list_action_policies.
        check_action_admin(&self.security, &attestation.policy_scope, &principals)?;
        Ok(Response::new(GetAttestationResponse {
            attestation: Some(to_proto_attestation(&attestation)),
        }))
    }

    async fn list_attestations(
        &self,
        req: Request<ListAttestationsRequest>,
    ) -> Result<Response<ListAttestationsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let decision_id = (!inner.decision_id.trim().is_empty()).then_some(inner.decision_id);
        let policy_scope = (!inner.policy_scope.trim().is_empty()).then_some(inner.policy_scope);
        // Attestations embed full policy snapshots (admin-gated content).
        // With a scope filter the caller must be admin for that scope; without
        // one, only the scopes the caller administers are returned.
        if let Some(scope) = policy_scope.as_deref() {
            check_action_admin(&self.security, scope, &principals)?;
        }
        // Paginate over *visible* rows: scan the table in batches and apply
        // limit/offset after the admin filter, so partially-privileged
        // callers get stable pages (mirrors list_decisions). A scan cap
        // bounds the work when most rows are invisible to the caller.
        let visible_limit = if inner.limit > 0 {
            inner.limit as usize
        } else {
            100
        };
        let visible_offset = inner.offset.max(0) as usize;
        let batch_size = visible_limit.clamp(50, 200);
        let max_scan = (visible_offset + visible_limit).saturating_mul(10).max(200);
        let mut attestations = Vec::new();
        let mut scanned = 0usize;
        let mut skipped = 0usize;
        let mut scan_offset = 0i32;
        while attestations.len() < visible_limit && scanned < max_scan {
            let batch = self
                .db
                .list_attestations(
                    decision_id.as_deref(),
                    policy_scope.as_deref(),
                    batch_size as i32,
                    scan_offset,
                )
                .map_err(Status::internal)?;
            if batch.is_empty() {
                break;
            }
            scan_offset += batch.len() as i32;
            scanned += batch.len();
            for attestation in &batch {
                if check_action_admin(&self.security, &attestation.policy_scope, &principals)
                    .is_err()
                {
                    continue;
                }
                if skipped < visible_offset {
                    skipped += 1;
                    continue;
                }
                if attestations.len() < visible_limit {
                    attestations.push(to_proto_attestation(attestation));
                }
            }
        }
        // A short page from an exhausted scan budget must not read like the
        // end of the data (matches list_decisions).
        if attestations.len() < visible_limit && scanned >= max_scan {
            return Err(Status::resource_exhausted(
                "attestation visibility scan limit exceeded; refine filters",
            ));
        }
        Ok(Response::new(ListAttestationsResponse { attestations }))
    }

    async fn verify_attestation(
        &self,
        req: Request<VerifyAttestationRequest>,
    ) -> Result<Response<VerifyAttestationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        if id.trim().is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        // Verification results expose the replayed decision for a scope's
        // policy; gate like the other attestation reads.
        if let Some(attestation) = self.db.get_attestation(&id).map_err(Status::internal)? {
            check_action_admin(&self.security, &attestation.policy_scope, &principals)?;
        }
        let report = self.db.verify_attestation(&id).map_err(Status::internal)?;
        Ok(Response::new(VerifyAttestationResponse {
            ok: report.ok,
            found: report.found,
            hash_ok: report.hash_ok,
            replay_ok: report.replay_ok,
            replayed_decision: report.replayed_decision,
            decision_linked: report.decision_linked,
            error: report.error,
        }))
    }

    async fn export_assurance(
        &self,
        req: Request<ExportAssuranceRequest>,
    ) -> Result<Response<ExportAssuranceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        if inner.action.trim().is_empty() {
            return Err(Status::invalid_argument("action required"));
        }
        if inner.policy_scope.trim().is_empty() {
            return Err(Status::invalid_argument("policy_scope required"));
        }
        check_action_admin(&self.security, &inner.policy_scope, &principals)?;

        let limit = if inner.limit > 0 {
            inner.limit.min(200)
        } else {
            100
        };
        let decisions = self
            .db
            .list_decisions(&audit::DecisionFilter {
                actor: None,
                action: Some(inner.action),
                target_id: None,
                after: inner.after,
                limit,
                offset: 0,
            })
            .map_err(Status::internal)?;
        let mut records = Vec::with_capacity(decisions.len());
        for decision in decisions {
            if decision.target_id.is_empty()
                || check_read(&self.security, &decision.target_id, &principals).is_err()
            {
                continue;
            }
            let attestation = decision
                .evidence
                .get(attestation::EVIDENCE_ATTESTATION_ID)
                .map(String::as_str)
                .map(|id| self.db.get_attestation(id))
                .transpose()
                .map_err(Status::internal)?
                .flatten()
                .filter(|proof| proof.policy_scope == inner.policy_scope);
            let verification = if let Some(proof) = &attestation {
                let report = self
                    .db
                    .verify_attestation(&proof.id)
                    .map_err(Status::internal)?;
                Some(VerifyAttestationResponse {
                    ok: report.ok,
                    found: report.found,
                    hash_ok: report.hash_ok,
                    replay_ok: report.replay_ok,
                    replayed_decision: report.replayed_decision,
                    decision_linked: report.decision_linked,
                    error: report.error,
                })
            } else {
                Some(VerifyAttestationResponse {
                    ok: false,
                    found: false,
                    hash_ok: false,
                    replay_ok: false,
                    replayed_decision: String::new(),
                    decision_linked: false,
                    error: "no attestation for requested policy scope".into(),
                })
            };
            records.push(AssuranceRecord {
                decision: Some(Decision {
                    id: decision.id,
                    timestamp: decision.timestamp,
                    actor: decision.actor,
                    action: decision.action,
                    reason: decision.reason,
                    evidence: decision.evidence,
                    target_id: decision.target_id,
                    outcome: decision.outcome,
                }),
                attestation: attestation.as_ref().map(to_proto_attestation),
                verification,
            });
        }

        let db = self.db.clone();
        let ledger = tokio::task::spawn_blocking(move || db.verify_ledger())
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .map_err(Status::internal)?;
        Ok(Response::new(ExportAssuranceResponse {
            records,
            ledger: Some(VerifyAuditLedgerResponse {
                ok: ledger.ok,
                entries_checked: ledger.entries_checked,
                first_bad_seq: ledger.first_bad_seq,
                error: ledger.error,
                anchor_seq: ledger.anchor_seq,
                head_seq: ledger.head_seq,
                head_hash: ledger.head_hash,
            }),
        }))
    }

    async fn create_credential(
        &self,
        req: Request<CreateCredentialRequest>,
    ) -> Result<Response<CreateCredentialResponse>, Status> {
        require_credential_admin(&caller_principals(&req))?;
        let principal = validate_new_credential_principal(&req.into_inner().principal)?;
        if !self
            .db
            .list_credentials(Some(&principal), Some("active"))
            .map_err(Status::internal)?
            .is_empty()
        {
            return Err(Status::already_exists(format!(
                "active credential already exists for {principal:?}; rotate it instead"
            )));
        }
        let token = new_credential_token();
        let credential = self
            .db
            .create_principal_credential(
                &principal,
                &hash_gateway_key(&token),
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::internal)?;
        Ok(Response::new(CreateCredentialResponse {
            token,
            credential: Some(to_proto_credential(credential)),
        }))
    }

    async fn rotate_credential(
        &self,
        req: Request<RotateCredentialRequest>,
    ) -> Result<Response<RotateCredentialResponse>, Status> {
        require_credential_admin(&caller_principals(&req))?;
        let principal = validate_new_credential_principal(&req.into_inner().principal)?;
        if self
            .db
            .list_credentials(Some(&principal), Some("active"))
            .map_err(Status::internal)?
            .is_empty()
        {
            return Err(Status::not_found(format!(
                "no active credential for {principal:?}"
            )));
        }
        let token = new_credential_token();
        let credential = self
            .db
            .rotate_principal_credential(&principal, &hash_gateway_key(&token))
            .map_err(Status::internal)?;
        Ok(Response::new(RotateCredentialResponse {
            token,
            credential: Some(to_proto_credential(credential)),
        }))
    }

    async fn revoke_credential(
        &self,
        req: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        require_credential_admin(&caller_principals(&req))?;
        let principal = validate_credential_principal(&req.into_inner().principal)?;
        let credential = self
            .db
            .revoke_principal_credential(&principal)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found(format!("no active credential for {principal:?}")))?;
        Ok(Response::new(RevokeCredentialResponse {
            credential: Some(to_proto_credential(credential)),
        }))
    }

    async fn list_credentials(
        &self,
        req: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        require_credential_admin(&caller_principals(&req))?;
        let credentials = self
            .db
            .list_credentials(None, None)
            .map_err(Status::internal)?
            .into_iter()
            .map(to_proto_credential)
            .collect();
        Ok(Response::new(ListCredentialsResponse { credentials }))
    }

    async fn register_evidence_producer(
        &self,
        req: Request<RegisterEvidenceProducerRequest>,
    ) -> Result<Response<RegisterEvidenceProducerResponse>, Status> {
        let principals = caller_principals(&req);
        require_evidence_admin(&self.security, &principals)?;
        let capability = req
            .into_inner()
            .capability
            .ok_or_else(|| Status::invalid_argument("capability required"))?;
        let capability = from_proto_evidence_producer(capability)?;
        self.db
            .upsert_evidence_producer(&capability, now_millis())
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(RegisterEvidenceProducerResponse {}))
    }

    async fn register_evidence_schema(
        &self,
        req: Request<RegisterEvidenceSchemaRequest>,
    ) -> Result<Response<RegisterEvidenceSchemaResponse>, Status> {
        let principals = caller_principals(&req);
        require_evidence_admin(&self.security, &principals)?;
        let definition = req
            .into_inner()
            .definition
            .ok_or_else(|| Status::invalid_argument("definition required"))?;
        self.db
            .register_evidence_schema(
                &DomainEvidenceSchemaDefinition {
                    schema_id: definition.schema_id,
                    schema_version: definition.schema_version,
                    evidence_type: definition.evidence_type,
                    compatible_versions: definition.compatible_versions,
                },
                now_millis(),
            )
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(RegisterEvidenceSchemaResponse {}))
    }

    async fn submit_evidence(
        &self,
        req: Request<SubmitEvidenceRequest>,
    ) -> Result<Response<SubmitEvidenceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let envelope = req
            .into_inner()
            .envelope
            .ok_or_else(|| Status::invalid_argument("envelope required"))?;
        let envelope = from_proto_evidence_envelope(envelope)?;
        if !principals.contains(&envelope.producer_identity) {
            return Err(Status::permission_denied(
                "authenticated producer must match envelope attribution",
            ));
        }
        let result =
            self.admit_and_project_evidence(&envelope, &envelope.producer_identity, now_millis())?;
        Ok(Response::new(SubmitEvidenceResponse {
            result: Some(result),
        }))
    }

    async fn submit_evidence_batch(
        &self,
        req: Request<SubmitEvidenceBatchRequest>,
    ) -> Result<Response<SubmitEvidenceBatchResponse>, Status> {
        const MAX_BATCH: usize = 100;
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let envelopes = req.into_inner().envelopes;
        if envelopes.is_empty() || envelopes.len() > MAX_BATCH {
            return Err(Status::invalid_argument(
                "evidence batch must contain between 1 and 100 envelopes",
            ));
        }
        let envelopes = envelopes
            .into_iter()
            .map(from_proto_evidence_envelope)
            .collect::<Result<Vec<_>, _>>()?;
        if envelopes
            .iter()
            .any(|envelope| !principals.contains(&envelope.producer_identity))
        {
            return Err(Status::permission_denied(
                "authenticated producer must match every envelope attribution",
            ));
        }
        let mut results = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            results.push(self.admit_and_project_evidence(
                &envelope,
                &envelope.producer_identity,
                now_millis(),
            )?);
        }
        Ok(Response::new(SubmitEvidenceBatchResponse { results }))
    }

    async fn get_evidence_submission(
        &self,
        req: Request<GetEvidenceSubmissionRequest>,
    ) -> Result<Response<GetEvidenceSubmissionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let submission_id = req.into_inner().submission_id;
        let submission = self
            .db
            .get_evidence_submission(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("evidence submission not found"))?;
        if !can_operate_evidence_submission(&self.security, &submission, &principals) {
            return Err(Status::permission_denied("evidence access denied"));
        }
        let history = self
            .db
            .evidence_lifecycle_history(&submission_id)
            .map_err(Status::internal)?
            .into_iter()
            .map(|state| state.as_str().to_string())
            .collect();
        Ok(Response::new(GetEvidenceSubmissionResponse {
            submission: Some(to_proto_evidence_submission(&submission)),
            lifecycle_history: history,
        }))
    }

    async fn list_evidence_submissions(
        &self,
        req: Request<ListEvidenceSubmissionsRequest>,
    ) -> Result<Response<ListEvidenceSubmissionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let is_admin = require_evidence_admin(&self.security, &principals).is_ok();
        let request = req.into_inner();
        let producer_identity = if is_admin {
            optional_nonempty(request.producer_identity)
        } else {
            let requested = optional_nonempty(request.producer_identity);
            if requested
                .as_ref()
                .is_some_and(|producer| !principals.contains(producer))
            {
                return Err(Status::permission_denied("evidence access denied"));
            }
            requested.or_else(|| {
                principals
                    .iter()
                    .find(|principal| principal.as_str() != "anonymous")
                    .cloned()
            })
        };
        let lifecycle_state = if request.lifecycle_state.trim().is_empty() {
            None
        } else {
            Some(
                evidence_domain::EvidenceLifecycleState::parse(request.lifecycle_state.trim())
                    .ok_or_else(|| Status::invalid_argument("invalid lifecycle_state"))?,
            )
        };
        let submissions = self
            .db
            .list_evidence_submissions(&EvidenceSubmissionFilter {
                producer_identity,
                source_instance: optional_nonempty(request.source_instance),
                namespace: optional_nonempty(request.namespace),
                lifecycle_state,
                target_external_id: optional_nonempty(request.target_external_id),
                evidence_type: optional_nonempty(request.evidence_type),
                limit: request.limit,
                offset: request.offset,
            })
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_evidence_submission)
            .collect();
        Ok(Response::new(ListEvidenceSubmissionsResponse {
            submissions,
        }))
    }

    async fn replay_evidence_submission(
        &self,
        req: Request<ReplayEvidenceSubmissionRequest>,
    ) -> Result<Response<ReplayEvidenceSubmissionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let submission_id = req.into_inner().submission_id;
        let submission = self
            .db
            .get_evidence_submission(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("evidence submission not found"))?;
        if !can_operate_evidence_submission(&self.security, &submission, &principals) {
            return Err(Status::permission_denied("evidence replay denied"));
        }
        let projection = self
            .db
            .project_evidence_submission(&submission_id, now_millis())
            .map_err(Status::failed_precondition)?;
        if let Some(object_id) = projection.evidence_object_id.as_deref() {
            for grant in self.db.list_grants(object_id).map_err(Status::internal)? {
                self.security.add_grant(&grant);
            }
        }
        let current = self
            .db
            .get_evidence_submission(&submission_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::internal("evidence submission disappeared"))?;
        Ok(Response::new(ReplayEvidenceSubmissionResponse {
            result: Some(EvidenceSubmissionResult {
                submission: Some(to_proto_evidence_submission(&current)),
                admitted: current.lifecycle_state
                    != evidence_domain::EvidenceLifecycleState::Rejected,
                deduplicated: true,
                projected: projection.projected,
            }),
        }))
    }

    async fn retract_evidence(
        &self,
        req: Request<RetractEvidenceRequest>,
    ) -> Result<Response<RetractEvidenceResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let request = req.into_inner();
        let result = self.create_evidence_lifecycle_marker(
            request.submission_id,
            request.source_version,
            request.source_sequence,
            request.idempotency_key,
            request.observed_at_ms,
            evidence_domain::EvidenceIntent::Retract,
            &principals,
        )?;
        Ok(Response::new(RetractEvidenceResponse {
            result: Some(result),
        }))
    }

    async fn mark_evidence_stale(
        &self,
        req: Request<MarkEvidenceStaleRequest>,
    ) -> Result<Response<MarkEvidenceStaleResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let request = req.into_inner();
        let result = self.create_evidence_lifecycle_marker(
            request.submission_id,
            request.source_version,
            request.source_sequence,
            request.idempotency_key,
            request.observed_at_ms,
            evidence_domain::EvidenceIntent::MarkStale,
            &principals,
        )?;
        Ok(Response::new(MarkEvidenceStaleResponse {
            result: Some(result),
        }))
    }

    async fn get_provenance_report(
        &self,
        req: Request<GetProvenanceReportRequest>,
    ) -> Result<Response<GetProvenanceReportResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let work_unit_id = req.into_inner().work_unit_id.trim().to_string();
        if work_unit_id.is_empty() {
            return Err(Status::invalid_argument("work_unit_id required"));
        }
        check_read(&self.security, &work_unit_id, &principals)?;
        let report = crate::provenance::assemble_report(&self.db, &work_unit_id)
            .map_err(Status::internal)?;
        Ok(Response::new(GetProvenanceReportResponse {
            report: crate::provenance::render_text(&report),
        }))
    }
}

fn require_credential_admin(principals: &[String]) -> Result<(), Status> {
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
    {
        return Ok(());
    }
    Err(Status::permission_denied("credential admin required"))
}

fn validate_credential_principal(principal: &str) -> Result<String, Status> {
    let principal = principal.trim();
    if principal.is_empty()
        || !principal
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
    {
        return Err(Status::invalid_argument(
            "principal must match [a-zA-Z0-9._-]+",
        ));
    }
    Ok(principal.to_string())
}

fn validate_new_credential_principal(principal: &str) -> Result<String, Status> {
    let principal = validate_credential_principal(principal)?;
    if matches!(principal.as_str(), "root" | "local") {
        return Err(Status::invalid_argument(format!(
            "principal {principal:?} is reserved for control-plane authentication"
        )));
    }
    Ok(principal)
}

fn new_credential_token() -> String {
    format!(
        "sekai_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

fn to_proto_credential(credential: crate::db::sekai::PrincipalCredential) -> CredentialRecord {
    CredentialRecord {
        id: credential.id,
        principal: credential.principal,
        status: credential.status,
        created: credential.created,
        rotated_at: credential.rotated_at,
        revoked_at: credential.revoked_at,
    }
}

fn scoring_learning_id(namespace: &str, request_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"chisei.scoring.record_learning.v1");
    for value in [namespace, request_id] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    format!("learning:chisei.scoring:{encoded}")
}

fn bounded_knowledge_text(value: &str, max_chars: usize) -> String {
    let mut normalized = String::new();
    let mut chars: usize = 0;
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_whitespace() || character.is_control() {
            pending_space = !normalized.is_empty();
            continue;
        }
        if pending_space {
            if chars.saturating_add(1) >= max_chars {
                break;
            }
            normalized.push(' ');
            chars += 1;
        }
        pending_space = false;
        if chars >= max_chars {
            break;
        }
        normalized.push(character);
        chars += 1;
    }
    normalized
}

fn knowledge_source_request_id(request_id: &str) -> String {
    let trimmed = request_id.trim();
    if trimmed.chars().count() <= 256 && !trimmed.chars().any(char::is_control) {
        return trimmed.to_string();
    }
    let mut digest = Sha256::new();
    digest.update(b"chisei.scoring.source_request.v1");
    digest.update((request_id.len() as u64).to_be_bytes());
    digest.update(request_id.as_bytes());
    let encoded = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{encoded}")
}

#[async_trait::async_trait]
impl KnowledgeWriter for SekaiServiceImpl {
    async fn write_knowledge(
        &self,
        request: &KnowledgeWriteRequest,
    ) -> Result<KnowledgeWriteOutcome, String> {
        let namespace = request.namespace.trim();
        if namespace.is_empty() {
            return Err("knowledge write requires an observation namespace".into());
        }
        if request.request_id.trim().is_empty() {
            return Err("knowledge write requires a source request id".into());
        }

        let target = match self
            .db
            .find_by_external_id(&format!("namespace:{namespace}"))?
        {
            Some(target) if target.kind == "namespace" => target,
            Some(target) => {
                return Err(format!(
                    "namespace external id resolved to unexpected kind: {}",
                    target.kind
                ));
            }
            None => self
                .db
                .find_by_external_id(&format!("policy:{namespace}"))?
                .or(self
                    .db
                    .find_by_external_id(&format!("project:{namespace}"))?)
                .ok_or_else(|| format!("no governed target found for namespace: {namespace}"))?,
        };

        let learning_id = scoring_learning_id(namespace, &request.request_id);
        let passed = if request.passed { "true" } else { "false" };
        let mut reasoning = bounded_knowledge_text(&request.reasoning, 2_000);
        if reasoning.is_empty() {
            reasoning = format!(
                "The scoring judge recorded a {} outcome with score {}.",
                if request.passed { "passing" } else { "failing" },
                request.score.clamp(0, 100)
            );
        }
        let task_class = bounded_knowledge_text(&request.task_class, 128);
        let model = bounded_knowledge_text(&request.model, 256);
        let task_class = if task_class.is_empty() {
            "unclassified".to_string()
        } else {
            task_class
        };
        let model = if model.is_empty() {
            "unknown".to_string()
        } else {
            model
        };
        let title = format!(
            "Scored {task_class} task outcome: {}",
            if request.passed {
                "passed"
            } else {
                "needs correction"
            }
        );
        let prevention = if request.passed {
            format!("Preserve this evaluated behavior: {reasoning}")
        } else {
            format!("Before repeating this task, address: {reasoning}")
        };
        let params = HashMap::from([
            ("id".into(), learning_id.clone()),
            ("target_id".into(), target.id.clone()),
            ("title".into(), title),
            ("prevention".into(), prevention),
            ("reasoning".into(), reasoning),
            (
                "source_request_id".into(),
                knowledge_source_request_id(&request.request_id),
            ),
            ("score".into(), request.score.clamp(0, 100).to_string()),
            ("passed".into(), passed.into()),
            ("task_class".into(), task_class),
            ("model".into(), model),
            ("producer".into(), "chisei.scoring".into()),
            ("status".into(), "candidate".into()),
        ]);
        let mut rpc_request = Request::new(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
                params,
                actor: "chisei.scoring".into(),
            }),
            dry_run: false,
        });
        rpc_request.metadata_mut().insert(
            "x-principal",
            tonic::metadata::MetadataValue::from_static("chisei.scoring"),
        );
        rpc_request.metadata_mut().insert(
            "x-chisei-work-unit",
            tonic::metadata::MetadataValue::try_from(learning_id.as_str())
                .map_err(|error| format!("invalid knowledge work-unit metadata: {error}"))?,
        );

        match <Self as SekaiService>::execute_action(self, rpc_request).await {
            Ok(response) => {
                let result = response
                    .into_inner()
                    .result
                    .ok_or_else(|| "record_learning returned no action result".to_string())?;
                match result.decision.as_str() {
                    "allow" | "require_approval" => Ok(KnowledgeWriteOutcome::Accepted),
                    "deny" => Ok(KnowledgeWriteOutcome::PolicyDenied),
                    decision => Err(format!(
                        "record_learning returned unknown policy decision: {decision}"
                    )),
                }
            }
            Err(status)
                if status.code() == tonic::Code::PermissionDenied
                    && status.message().contains("denied by policy") =>
            {
                Ok(KnowledgeWriteOutcome::PolicyDenied)
            }
            Err(status) => Err(format!(
                "record_learning failed ({}): {}",
                status.code(),
                status.message()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        SekaiServiceImpl::new(db)
    }

    fn with_principal<T>(payload: T) -> Request<T> {
        with_named_principal(payload, "tester")
    }

    fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn widget_schema_type() -> ObjectType {
        ObjectType {
            kind: "widget".into(),
            description: "A widget".into(),
            properties: vec![
                PropertyDef {
                    name: "name".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                },
                PropertyDef {
                    name: "color".into(),
                    r#type: "enum".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec!["red".into(), "blue".into()],
                    link_kind: "".into(),
                    compute_expr: "".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                },
            ],
            is_builtin: false,
            implements: vec![],
        }
    }

    fn widget_object(id: &str, properties: HashMap<String, String>) -> Object {
        Object {
            id: id.into(),
            kind: "widget".into(),
            name: "widget".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties,
            created: 0,
            updated: 0,
        }
    }

    fn grant_schema_admin(svc: &SekaiServiceImpl) {
        let grant = security::Grant {
            id: format!("schema-admin-{}", uuid::Uuid::new_v4().simple()),
            object_id: "schema".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn grant_action_admin(svc: &SekaiServiceImpl) {
        let grant = security::Grant {
            id: format!("action-admin-{}", uuid::Uuid::new_v4().simple()),
            object_id: "action".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn assign_color_action() -> ActionTypeDef {
        ActionTypeDef {
            name: "assign_color".into(),
            description: "Assign a widget color".into(),
            params: vec![ActionParamDef {
                name: "color".into(),
                r#type: "enum".into(),
                required: true,
                enum_values: vec!["red".into(), "blue".into()],
            }],
            ops: vec![ActionOp {
                op: "set_property".into(),
                property: "color".into(),
                value_from: "color".into(),
                relation: "".into(),
            }],
            target_kind: "widget".into(),
            created: 0,
        }
    }

    fn grant_object_role(
        svc: &SekaiServiceImpl,
        object_id: &str,
        principal: &str,
        role: security::Role,
    ) {
        let grant = security::Grant {
            id: format!("grant-{}", uuid::Uuid::new_v4().simple()),
            object_id: object_id.into(),
            principal: principal.into(),
            role,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn seed_domain_object(svc: &SekaiServiceImpl, id: &str) {
        svc.db
            .create_object(&domain::Object {
                id: id.into(),
                kind: "namespace".into(),
                name: id.into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
    }

    fn seed_scoring_namespace(svc: &SekaiServiceImpl, namespace: &str) -> String {
        let id = format!("namespace-{namespace}");
        svc.db
            .create_object(&domain::Object {
                id: id.clone(),
                kind: "namespace".into(),
                name: namespace.into(),
                namespace: String::new(),
                external_id: format!("namespace:{namespace}"),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        id
    }

    fn scored_knowledge_request(namespace: &str, request_id: &str) -> KnowledgeWriteRequest {
        KnowledgeWriteRequest {
            request_id: request_id.into(),
            namespace: namespace.into(),
            task_class: "primary".into(),
            model: "claude-opus-4-8".into(),
            score: 84,
            passed: true,
            reasoning: "The implementation satisfies the requested behavior.".into(),
        }
    }

    #[tokio::test]
    async fn execute_action_denies_ungranted_principal_even_when_actor_claims_owner() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        grant_object_role(&svc, "obj-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "set_property".into(),
                        params: HashMap::from([
                            ("id".into(), "obj-1".into()),
                            ("key".into(), "status".into()),
                            ("value".into(), "done".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "bob",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    #[tokio::test]
    async fn execute_action_allows_granted_principal() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        grant_object_role(&svc, "obj-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: "bob".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");
    }

    #[tokio::test]
    async fn execute_action_records_decision_with_authenticated_actor() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        grant_object_role(&svc, "obj-1", "alice", security::Role::Editor);

        let mut request = with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "password".into()),
                        ("value".into(), "secret-value".into()),
                    ]),
                    actor: "mallory".into(),
                }),
                dry_run: false,
            },
            "alice",
        );
        request
            .metadata_mut()
            .insert("x-chisei-work-unit", "successful-work".parse().unwrap());
        svc.execute_action(request).await.unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "alice");
        assert_eq!(decisions[0].target_id, "obj-1");
        assert_eq!(decisions[0].reason, "execute_action");
        assert_eq!(decisions[0].evidence["key"], "[redacted]");
        assert_eq!(decisions[0].evidence["value"], "[redacted]");
        assert_eq!(decisions[0].evidence["work_unit"], "successful-work");
        assert_eq!(decisions[0].evidence["risk_class"], "write");
        assert_eq!(decisions[0].evidence["decision"], "allow");
        assert_eq!(decisions[0].outcome, "set obj-1.password = [redacted]");
    }

    #[tokio::test]
    async fn record_decision_clamps_future_timestamp() {
        let svc = service();
        let future = now_millis() + 86_400_000;
        let recorded = svc
            .record_decision(with_principal(RecordDecisionRequest {
                decision: Some(Decision {
                    id: String::new(),
                    timestamp: future,
                    actor: "tester".into(),
                    action: "act".into(),
                    reason: String::new(),
                    evidence: HashMap::new(),
                    target_id: String::new(),
                    outcome: "done".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        // A future timestamp would pin the ledger's purgeable prefix forever.
        assert!(recorded.timestamp < future);
        assert!(recorded.timestamp <= now_millis());
    }

    #[tokio::test]
    async fn record_decision_strips_reserved_attestation_evidence_keys() {
        let svc = service();
        let recorded = svc
            .record_decision(with_principal(RecordDecisionRequest {
                decision: Some(Decision {
                    id: String::new(),
                    timestamp: 0,
                    actor: "tester".into(),
                    action: "act".into(),
                    reason: String::new(),
                    evidence: HashMap::from([
                        ("attestation_id".into(), "forged".into()),
                        ("attestation_hash".into(), "forged".into()),
                        ("note".into(), "kept".into()),
                    ]),
                    target_id: String::new(),
                    outcome: "done".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        assert!(!recorded.evidence.contains_key("attestation_id"));
        assert!(!recorded.evidence.contains_key("attestation_hash"));
        assert_eq!(recorded.evidence["note"], "kept");
        let stored = svc.db.get_decision(&recorded.id).unwrap().unwrap();
        assert!(!stored.evidence.contains_key("attestation_id"));
        assert!(!stored.evidence.contains_key("attestation_hash"));
    }

    #[tokio::test]
    async fn verify_audit_ledger_reports_clean_chain() {
        let svc = service();
        for i in 0..3 {
            svc.record_decision(with_principal(RecordDecisionRequest {
                decision: Some(Decision {
                    id: format!("d{i}"),
                    timestamp: 0,
                    actor: "tester".into(),
                    action: "act".into(),
                    reason: String::new(),
                    evidence: HashMap::new(),
                    target_id: String::new(),
                    outcome: "done".into(),
                }),
            }))
            .await
            .unwrap();
        }
        let report = svc
            .verify_audit_ledger(with_principal(VerifyAuditLedgerRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(report.ok, "{}", report.error);
        assert_eq!(report.entries_checked, 3);
        assert_eq!(report.head_seq, 3);
        assert!(!report.head_hash.is_empty());
    }

    #[tokio::test]
    async fn execute_action_set_property_respects_schema() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "red".into()),
                ]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "set_property".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("key".into(), "color".into()),
                            ("value".into(), "green".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not in"));
        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "red");
        assert!(
            svc.db
                .list_decisions(&audit::DecisionFilter {
                    action: Some("set_property".into()),
                    ..Default::default()
                })
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn execute_action_create_object_accepts_schema_properties() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "create_object".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("kind".into(), "widget".into()),
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["name"], "spinner");
        assert_eq!(obj.properties["color"], "blue");
    }

    #[tokio::test]
    async fn struct_property_round_trips_through_create_update_and_list() {
        let svc = service();
        grant_schema_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "ai_result".into(),
            r#type: "struct".into(),
            required: false,
            description: "AI generated compound value".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![
                StructFieldDef {
                    name: "value".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "".into(),
                    enum_values: vec![],
                },
                StructFieldDef {
                    name: "confidence".into(),
                    r#type: "float".into(),
                    required: true,
                    description: "".into(),
                    enum_values: vec![],
                },
                StructFieldDef {
                    name: "generated_at".into(),
                    r#type: "timestamp".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                },
            ],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();

        let initial_value =
            r#"{"value":"approve","confidence":0.91,"source_objects":["widget:1"]}"#;
        let created = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-ai",
                    HashMap::from([
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                        ("ai_result".into(), initial_value.into()),
                    ]),
                )),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(created.properties["ai_result"], initial_value);

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "widget".into(),
                    limit: 10,
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects[0].properties["ai_result"], initial_value);

        let updated_value =
            r#"{"value":"reject","confidence":0.12,"generated_at":"2026-07-06T12:00:00Z"}"#;
        let mut updated = created;
        updated
            .properties
            .insert("ai_result".into(), updated_value.into());
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(updated),
        }))
        .await
        .unwrap();
        let stored = svc.db.get_object("widget-ai").unwrap().unwrap();
        assert_eq!(stored.properties["ai_result"], updated_value);

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-ai-invalid",
                    HashMap::from([
                        ("name".into(), "bad".into()),
                        ("color".into(), "blue".into()),
                        ("ai_result".into(), r#"{"value":"approve"}"#.into()),
                    ]),
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("confidence"));

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-ai-type-mismatch",
                    HashMap::from([
                        ("name".into(), "bad".into()),
                        ("color".into(), "blue".into()),
                        (
                            "ai_result".into(),
                            r#"{"value":"approve","confidence":"high"}"#.into(),
                        ),
                    ]),
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("expected float"));
    }

    #[tokio::test]
    async fn object_responses_redact_restricted_schema_properties() {
        let svc = service();
        grant_schema_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "secret_note".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "sensitive".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        let create_err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object(
                    "widget-denied",
                    HashMap::from([
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                        ("secret_note".into(), "launch code".into()),
                    ]),
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(create_err.code(), tonic::Code::PermissionDenied);

        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(widget_object(
                    "widget-secret",
                    HashMap::from([
                        ("name".into(), "spinner".into()),
                        ("color".into(), "blue".into()),
                        ("secret_note".into(), "launch code".into()),
                    ]),
                )),
            },
            "root",
        ))
        .await
        .unwrap();

        let got = svc
            .get_object(with_principal(GetObjectRequest {
                id: "widget-secret".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(got.properties["name"], "spinner");
        assert_eq!(got.properties["secret_note"], "[redacted]");

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "list_widgets".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![PipelineStep {
                    op: "filter".into(),
                    kind: "widget".into(),
                    property: "".into(),
                    value: "".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    r#as: "".into(),
                }],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        let function_result = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "list_widgets".into(),
                params: HashMap::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(
            function_result.objects[0].properties["secret_note"],
            "[redacted]"
        );

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "filter_secret_widgets".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![PipelineStep {
                    op: "filter".into(),
                    kind: "widget".into(),
                    property: "secret_note".into(),
                    value: "launch code".into(),
                    relation: "".into(),
                    dir: "".into(),
                    func: "".into(),
                    field: "".into(),
                    r#as: "".into(),
                }],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        let function_err = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "filter_secret_widgets".into(),
                params: HashMap::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(function_err.code(), tonic::Code::PermissionDenied);

        let lineage = svc
            .get_lineage(with_principal(GetLineageRequest {
                object_id: "widget-secret".into(),
                max_nodes: 10,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(
            lineage.nodes[0].object.as_ref().unwrap().properties["secret_note"],
            "[redacted]"
        );

        let find_err = svc
            .find_by_property(with_principal(FindByPropertyRequest {
                kind: "widget".into(),
                key: "secret_note".into(),
                value: "launch code".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(find_err.code(), tonic::Code::PermissionDenied);

        let list_err = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "widget".into(),
                    property_filters: vec![PropertyFilter {
                        key: "secret_note".into(),
                        op: "eq".into(),
                        value: "launch code".into(),
                    }],
                    limit: 10,
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(list_err.code(), tonic::Code::PermissionDenied);

        let object_set_err = svc
            .create_object_set(with_principal(CreateObjectSetRequest {
                object_set: Some(ObjectSet {
                    id: "secret-set".into(),
                    name: "secret set".into(),
                    description: String::new(),
                    filter: Some(ListFilter {
                        kind: "widget".into(),
                        property_filters: vec![PropertyFilter {
                            key: "secret_note".into(),
                            op: "eq".into(),
                            value: "launch code".into(),
                        }],
                        limit: 10,
                        ..Default::default()
                    }),
                    owner_principal: String::new(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(object_set_err.code(), tonic::Code::PermissionDenied);

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "widget".into(),
                    limit: 10,
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects[0].properties["secret_note"], "[redacted]");

        let mut update = got;
        update.name = "renamed".into();
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(update),
        }))
        .await
        .unwrap();
        let stored = svc.db.get_object("widget-secret").unwrap().unwrap();
        assert_eq!(stored.name, "renamed");
        assert_eq!(stored.properties["secret_note"], "launch code");

        let mut attempted_overwrite = stored.clone();
        attempted_overwrite
            .properties
            .insert("secret_note".into(), "attacker code".into());
        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(to_proto_obj(&attempted_overwrite)),
        }))
        .await
        .unwrap();
        let stored = svc.db.get_object("widget-secret").unwrap().unwrap();
        assert_eq!(stored.properties["secret_note"], "launch code");

        let mut changed_secret = stored.clone();
        changed_secret
            .properties
            .insert("secret_note".into(), "rotated code".into());
        svc.db
            .update_object_with_audit(&changed_secret, "root")
            .unwrap();
        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "widget-secret".into(),
                limit: 20,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .changes;
        let secret_change = changes
            .iter()
            .find(|change| change.field == "properties.secret_note")
            .unwrap();
        assert_eq!(secret_change.old_value, "[redacted]");
        assert_eq!(secret_change.new_value, "[redacted]");

        grant_object_role(&svc, "widget-secret", "tester", security::Role::Admin);
        let admin_view = svc
            .get_object(with_principal(GetObjectRequest {
                id: "widget-secret".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(admin_view.properties["secret_note"], "rotated code");

        grant_object_role(&svc, "widget-secret", "reader", security::Role::Viewer);
        svc.delete_object(with_principal(DeleteObjectRequest {
            id: "widget-secret".into(),
        }))
        .await
        .unwrap();
        let deleted_changes = svc
            .list_object_changes(with_named_principal(
                ListObjectChangesRequest {
                    object_id: "widget-secret".into(),
                    limit: 20,
                    offset: 0,
                },
                "reader",
            ))
            .await
            .unwrap()
            .into_inner()
            .changes;
        let deleted_secret_change = deleted_changes
            .iter()
            .find(|change| change.field == "properties.secret_note")
            .unwrap();
        assert_eq!(deleted_secret_change.old_value, "[redacted]");
        assert_eq!(deleted_secret_change.new_value, "[redacted]");
    }

    #[tokio::test]
    async fn action_audit_prefers_schema_classification_over_name_heuristic() {
        let svc = service();
        grant_schema_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "api_key_label".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        schema_type.properties.push(PropertyDef {
            name: "secret_note".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "sensitive".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "widget-audit".into(),
                kind: "widget".into(),
                name: "widget".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "blue".into()),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "widget-audit".into()),
                    ("key".into(), "api_key_label".into()),
                    ("value".into(), "public alias".into()),
                ]),
                actor: "".into(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "widget-audit".into()),
                    ("key".into(), "secret_note".into()),
                    ("value".into(), "launch code".into()),
                ]),
                actor: "".into(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        let public_decision = decisions
            .iter()
            .find(|decision| decision.outcome.contains("api_key_label"))
            .unwrap();
        let sensitive_decision = decisions
            .iter()
            .find(|decision| decision.outcome.contains("secret_note"))
            .unwrap();
        assert_eq!(public_decision.evidence["value"], "public alias");
        assert_eq!(
            public_decision.outcome,
            "set widget-audit.api_key_label = public alias"
        );
        assert_eq!(sensitive_decision.evidence["value"], "[redacted]");
        assert_eq!(
            sensitive_decision.outcome,
            "set widget-audit.secret_note = [redacted]"
        );
    }

    #[tokio::test]
    async fn user_defined_action_type_round_trip_and_execute() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let created = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(assign_color_action()),
            }))
            .await
            .unwrap()
            .into_inner()
            .action_type
            .unwrap();
        assert_eq!(created.name, "assign_color");
        assert!(created.created > 0);

        let listed = svc
            .list_action_types(with_principal(ListActionTypesRequest {}))
            .await
            .unwrap()
            .into_inner()
            .action_types;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "assign_color");

        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "red".into()),
                ]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "assign_color".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("color".into(), "blue".into()),
                    ]),
                    actor: "ignored".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "blue");
        let changes = svc.db.list_object_changes("widget-1", 10, 0).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "properties.color");
        assert_eq!(changes[0].changed_by, "alice");
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("assign_color".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "alice");
        assert_eq!(decisions[0].target_id, "widget-1");

        svc.delete_action_type(with_principal(DeleteActionTypeRequest {
            name: "assign_color".into(),
        }))
        .await
        .unwrap();
        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "red".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("unknown action"));
    }

    #[tokio::test]
    async fn user_defined_action_redacts_password_fixed_property_params() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "password".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "set_password".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "value".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "set_property".into(),
                    property: "password".into(),
                    value_from: "value".into(),
                    relation: "".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "spinner".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_password".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("value".into(), "secret-value".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_password".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].evidence["value"], "[redacted]");
    }

    #[tokio::test]
    async fn user_defined_action_validates_params_and_authorization() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(assign_color_action()),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "spinner".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let missing = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([("id".into(), "widget-1".into())]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::InvalidArgument);
        assert!(missing.message().contains("missing required param: color"));

        let bad_enum = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "green".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(bad_enum.code(), tonic::Code::InvalidArgument);
        assert!(bad_enum.message().contains("not in"));

        let denied = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "blue".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        assert!(
            !svc.db
                .get_object("widget-1")
                .unwrap()
                .unwrap()
                .properties
                .contains_key("color")
        );
    }

    #[tokio::test]
    async fn user_defined_action_rejects_undeclared_property_at_definition() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let mut action_type = assign_color_action();
        action_type.ops[0].property = "undeclared".into();

        let err = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(action_type),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not declared"));
    }

    #[tokio::test]
    async fn user_defined_action_revalidates_against_current_schema() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(assign_color_action()),
        }))
        .await
        .unwrap();
        let mut changed_schema = widget_schema_type();
        changed_schema
            .properties
            .retain(|property| property.name != "color");
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(changed_schema),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "spinner".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "blue".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not declared"));
        assert!(
            !svc.db
                .get_object("widget-1")
                .unwrap()
                .unwrap()
                .properties
                .contains_key("color")
        );
    }

    #[tokio::test]
    async fn user_defined_action_rejects_undeclared_create_object_kind() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();

        let err = svc
            .create_action_type(with_principal(CreateActionTypeRequest {
                action_type: Some(ActionTypeDef {
                    name: "spawn_typo".into(),
                    description: "".into(),
                    params: vec![ActionParamDef {
                        name: "child_name".into(),
                        r#type: "string".into(),
                        required: true,
                        enum_values: vec![],
                    }],
                    ops: vec![ActionOp {
                        op: "create_object".into(),
                        property: "widgte".into(),
                        value_from: "child_name".into(),
                        relation: "".into(),
                    }],
                    target_kind: "widget".into(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("not declared"));
    }

    #[tokio::test]
    async fn user_defined_action_rolls_back_when_later_op_fails_schema() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "size".into(),
            r#type: "enum".into(),
            required: false,
            description: "".into(),
            enum_values: vec!["small".into(), "large".into()],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(schema_type),
        }))
        .await
        .unwrap();
        let mut action_type = assign_color_action();
        action_type.name = "assign_color_and_size".into();
        action_type.params.push(ActionParamDef {
            name: "size".into(),
            r#type: "string".into(),
            required: true,
            enum_values: vec![],
        });
        action_type.ops.push(ActionOp {
            op: "set_property".into(),
            property: "size".into(),
            value_from: "size".into(),
            relation: "".into(),
        });
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(action_type),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([
                    ("name".into(), "spinner".into()),
                    ("color".into(), "red".into()),
                    ("size".into(), "small".into()),
                ]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "assign_color_and_size".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("color".into(), "blue".into()),
                            ("size".into(), "medium".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        let obj = svc.db.get_object("widget-1").unwrap().unwrap();
        assert_eq!(obj.properties["color"], "red");
        assert_eq!(obj.properties["size"], "small");
        assert!(
            svc.db
                .list_object_changes("widget-1", 10, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn user_defined_action_creates_object_and_link_transactionally() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        let action_type = ActionTypeDef {
            name: "spawn_child".into(),
            description: "Create a child widget and link target to sibling".into(),
            params: vec![
                ActionParamDef {
                    name: "child_name".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                },
                ActionParamDef {
                    name: "to_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                },
            ],
            ops: vec![
                ActionOp {
                    op: "create_object".into(),
                    property: "widget".into(),
                    value_from: "child_name".into(),
                    relation: "".into(),
                },
                ActionOp {
                    op: "create_link".into(),
                    property: "to_id".into(),
                    value_from: "".into(),
                    relation: "relates_to".into(),
                },
            ],
            target_kind: "widget".into(),
            created: 0,
        };
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(action_type),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "parent".into())]),
            )))
            .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-2",
                HashMap::from([("name".into(), "sibling".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "widget-2", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "spawn_child".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("child_name".into(), "child".into()),
                        ("to_id".into(), "widget-2".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        let children = svc.db.find_by_property("widget", "name", "child").unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].namespace, "");
        assert!(svc.db.get_link("widget-1->widget-2").unwrap().is_some());
        assert_eq!(
            svc.db.list_object_changes(&children[0].id, 10, 0).unwrap()[0].changed_by,
            "alice"
        );
    }

    #[tokio::test]
    async fn user_defined_action_create_link_requires_write_on_endpoint() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "link_widget".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "to_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "create_link".into(),
                    property: "to_id".into(),
                    value_from: "".into(),
                    relation: "relates_to".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "one".into())]),
            )))
            .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-2",
                HashMap::from([("name".into(), "two".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "widget-2", "bob", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "link_widget".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("to_id".into(), "widget-2".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_link("widget-1->widget-2").unwrap().is_none());
    }

    #[tokio::test]
    async fn user_defined_action_deletes_link_only_when_authorized_for_both_endpoints() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "unlink_widget".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "link_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "delete_link".into(),
                    property: "".into(),
                    value_from: "link_id".into(),
                    relation: "".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "one".into())]),
            )))
            .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-2",
                HashMap::from([("name".into(), "two".into())]),
            )))
            .unwrap();
        svc.db
            .create_link(&domain::Link {
                id: "link-1".into(),
                from_id: "widget-1".into(),
                to_id: "widget-2".into(),
                relation: "relates_to".into(),
                created: 0,
            })
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "widget-2", "alice", security::Role::Editor);

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "unlink_widget".into(),
                    params: HashMap::from([
                        ("id".into(), "widget-1".into()),
                        ("link_id".into(), "link-1".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "alice",
        ))
        .await
        .unwrap();

        assert!(svc.db.get_link("link-1").unwrap().is_none());
    }

    #[tokio::test]
    async fn user_defined_action_delete_link_hides_unknown_link() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "unlink_widget".into(),
                description: "".into(),
                params: vec![ActionParamDef {
                    name: "link_id".into(),
                    r#type: "string".into(),
                    required: true,
                    enum_values: vec![],
                }],
                ops: vec![ActionOp {
                    op: "delete_link".into(),
                    property: "".into(),
                    value_from: "link_id".into(),
                    relation: "".into(),
                }],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "unlink_widget".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("link_id".into(), "missing-link".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "write denied");
    }

    #[tokio::test]
    async fn user_defined_action_rolls_back_created_object_when_later_link_fails() {
        let svc = service();
        grant_schema_admin(&svc);
        grant_action_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.create_action_type(with_principal(CreateActionTypeRequest {
            action_type: Some(ActionTypeDef {
                name: "spawn_then_link_missing".into(),
                description: "".into(),
                params: vec![
                    ActionParamDef {
                        name: "child_name".into(),
                        r#type: "string".into(),
                        required: true,
                        enum_values: vec![],
                    },
                    ActionParamDef {
                        name: "to_id".into(),
                        r#type: "string".into(),
                        required: true,
                        enum_values: vec![],
                    },
                ],
                ops: vec![
                    ActionOp {
                        op: "create_object".into(),
                        property: "widget".into(),
                        value_from: "child_name".into(),
                        relation: "".into(),
                    },
                    ActionOp {
                        op: "create_link".into(),
                        property: "to_id".into(),
                        value_from: "".into(),
                        relation: "relates_to".into(),
                    },
                ],
                target_kind: "widget".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .create_object(&from_proto_obj(&widget_object(
                "widget-1",
                HashMap::from([("name".into(), "parent".into())]),
            )))
            .unwrap();
        grant_object_role(&svc, "widget-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "missing", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "spawn_then_link_missing".into(),
                        params: HashMap::from([
                            ("id".into(), "widget-1".into()),
                            ("child_name".into(), "child".into()),
                            ("to_id".into(), "missing".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("object not found"));
        assert!(
            svc.db
                .find_by_property("widget", "name", "child")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn execute_action_allows_local_principal_on_unrestricted_object() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");

        svc.execute_action(with_named_principal(
            ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "local".into()),
                    ]),
                    actor: "".into(),
                }),
                dry_run: false,
            },
            "local",
        ))
        .await
        .unwrap();

        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "local");
    }

    #[tokio::test]
    async fn execute_action_create_link_requires_write_on_both_endpoints() {
        let svc = service();
        seed_domain_object(&svc, "from-1");
        seed_domain_object(&svc, "to-1");
        grant_object_role(&svc, "from-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "to-1", "bob", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "create_link".into(),
                        params: HashMap::from([
                            ("from_id".into(), "from-1".into()),
                            ("to_id".into(), "to-1".into()),
                            ("relation".into(), "depends_on".into()),
                        ]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_link("from-1->to-1").unwrap().is_none());
    }

    #[tokio::test]
    async fn execute_action_delete_link_requires_write_on_both_endpoints() {
        let svc = service();
        seed_domain_object(&svc, "from-1");
        seed_domain_object(&svc, "to-1");
        svc.db
            .create_link(&domain::Link {
                id: "link-1".into(),
                from_id: "from-1".into(),
                to_id: "to-1".into(),
                relation: "depends_on".into(),
                created: 0,
            })
            .unwrap();
        grant_object_role(&svc, "from-1", "alice", security::Role::Editor);
        grant_object_role(&svc, "to-1", "bob", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "delete_link".into(),
                        params: HashMap::from([("id".into(), "link-1".into())]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "write denied");
        assert!(svc.db.get_link("link-1").unwrap().is_some());
    }

    #[tokio::test]
    async fn execute_action_delete_link_hides_unknown_link() {
        let svc = service();

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "delete_link".into(),
                        params: HashMap::from([("id".into(), "missing-link".into())]),
                        actor: "alice".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "write denied");
    }

    #[tokio::test]
    async fn dataset_rpc_round_trip() {
        let svc = service();
        let created = svc
            .create_dataset(with_principal(CreateDatasetRequest {
                dataset: Some(Dataset {
                    id: "ds1".into(),
                    name: "metrics".into(),
                    columns: vec![ColumnDef {
                        name: "value".into(),
                        r#type: "int".into(),
                    }],
                    object_id: "".into(),
                    created: 1,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.dataset.unwrap().id, "ds1");

        let rows = vec![
            Row {
                values: HashMap::from([("value".into(), "1".into())]),
            },
            Row {
                values: HashMap::from([("value".into(), "2".into())]),
            },
        ];
        let append = svc
            .append_rows(with_principal(AppendRowsRequest {
                dataset_id: "ds1".into(),
                rows,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(append.count, 2);

        let queried = svc
            .query_rows(with_principal(QueryRowsRequest {
                dataset_id: "ds1".into(),
                query: Some(RowQuery {
                    filters: vec![RowFilter {
                        column: "value".into(),
                        op: "gte".into(),
                        value: "2".into(),
                    }],
                    columns: vec![],
                    limit: 0,
                    offset: 0,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(queried.rows.len(), 1);
    }

    #[tokio::test]
    async fn function_rpc_round_trip() {
        let svc = service();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "c1".into(),
                kind: "component".into(),
                name: "comp".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([
                    ("language".into(), "rust".into()),
                    ("task_total".into(), "5".into()),
                ]),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "sum_tasks".into(),
                description: "".into(),
                params: vec![FuncParam {
                    name: "lang".into(),
                    r#type: "string".into(),
                    required: true,
                }],
                pipeline: vec![
                    PipelineStep {
                        op: "filter".into(),
                        kind: "component".into(),
                        property: "language".into(),
                        value: "$lang".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "sum".into(),
                        field: "task_total".into(),
                        r#as: "total".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();

        let executed = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "sum_tasks".into(),
                params: HashMap::from([("lang".into(), "rust".into())]),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(executed.result.unwrap().aggregates["total"], "5");
    }

    #[tokio::test]
    async fn computed_property_resolves_from_function_without_persisting() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "count_children".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![
                    PipelineStep {
                        op: "self".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "traverse".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "contains".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "count".into(),
                        field: "".into(),
                        r#as: "child_count".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "cluster".into(),
                description: "Cluster".into(),
                properties: vec![PropertyDef {
                    name: "child_count".into(),
                    r#type: "computed".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "count_children".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                }],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "cluster-1".into(),
                kind: "cluster".into(),
                name: "cluster".into(),
                namespace: "".into(),
                external_id: "cluster:one".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "component-1".into(),
                kind: "component".into(),
                name: "component".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();
        svc.create_link(with_principal(CreateLinkRequest {
            link: Some(Link {
                id: "cluster-component".into(),
                from_id: "cluster-1".into(),
                to_id: "component-1".into(),
                relation: "contains".into(),
                created: 0,
            }),
        }))
        .await
        .unwrap();

        let got = svc
            .get_object(with_principal(GetObjectRequest {
                id: "cluster-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(got.properties["child_count"], "1");

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "cluster".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects[0].properties["child_count"], "1");

        let stored = svc.db.get_object("cluster-1").unwrap().unwrap();
        assert!(!stored.properties.contains_key("child_count"));
    }

    #[tokio::test]
    async fn schema_type_rejects_unknown_computed_function() {
        let svc = service();
        grant_schema_admin(&svc);
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(ObjectType {
                    kind: "cluster".into(),
                    description: "Cluster".into(),
                    properties: vec![PropertyDef {
                        name: "child_count".into(),
                        r#type: "computed".into(),
                        required: false,
                        description: "".into(),
                        enum_values: vec![],
                        link_kind: "".into(),
                        compute_expr: "missing_function".into(),
                        classification: "public".into(),
                        struct_fields: vec![],
                    }],
                    is_builtin: false,
                    implements: vec![],
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("missing_function"));
    }

    #[tokio::test]
    async fn unresolved_computed_property_hides_stored_value() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "ambiguous_child_count".into(),
                description: "".into(),
                params: vec![],
                pipeline: vec![
                    PipelineStep {
                        op: "self".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "count".into(),
                        field: "".into(),
                        r#as: "first".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "count".into(),
                        field: "".into(),
                        r#as: "second".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "cluster".into(),
                description: "Cluster".into(),
                properties: vec![PropertyDef {
                    name: "child_count".into(),
                    r#type: "computed".into(),
                    required: false,
                    description: "".into(),
                    enum_values: vec![],
                    link_kind: "".into(),
                    compute_expr: "ambiguous_child_count".into(),
                    classification: "public".into(),
                    struct_fields: vec![],
                }],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "cluster-spoofed".into(),
                kind: "cluster".into(),
                name: "cluster".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([("child_count".into(), "spoofed".into())]),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        let got = svc
            .get_object(with_principal(GetObjectRequest {
                id: "cluster-spoofed".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert!(!got.properties.contains_key("child_count"));

        let stored = svc.db.get_object("cluster-spoofed").unwrap().unwrap();
        assert_eq!(stored.properties["child_count"], "spoofed");
    }

    #[tokio::test]
    async fn object_mutations_record_audit_changes() {
        let svc = service();
        svc.create_object(with_named_principal(
            CreateObjectRequest {
                object: Some(Object {
                    id: "audit-1".into(),
                    kind: "component".into(),
                    name: "api".into(),
                    namespace: "default".into(),
                    external_id: "component:api".into(),
                    properties: HashMap::from([("status".into(), "todo".into())]),
                    created: 1,
                    updated: 1,
                }),
            },
            "alice",
        ))
        .await
        .unwrap();

        svc.update_object(with_named_principal(
            UpdateObjectRequest {
                object: Some(Object {
                    id: "audit-1".into(),
                    kind: "component".into(),
                    name: "worker".into(),
                    namespace: "default".into(),
                    external_id: "component:api".into(),
                    properties: HashMap::from([("status".into(), "done".into())]),
                    created: 1,
                    updated: 2,
                }),
            },
            "alice",
        ))
        .await
        .unwrap();

        svc.delete_object(with_named_principal(
            DeleteObjectRequest {
                id: "audit-1".into(),
            },
            "alice",
        ))
        .await
        .unwrap();

        let changes = svc
            .list_object_changes(with_named_principal(
                ListObjectChangesRequest {
                    object_id: "audit-1".into(),
                    limit: 10,
                    offset: 0,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .changes;

        assert_eq!(changes.len(), 4);
        assert_eq!(
            changes
                .iter()
                .map(|change| change.field.as_str())
                .collect::<Vec<_>>(),
            vec!["_deleted", "properties.status", "name", "_created"]
        );
        assert!(changes.iter().all(|change| change.changed_by == "alice"));
        assert_eq!(changes[0].old_value, "component/worker");
        assert_eq!(changes[1].old_value, "todo");
        assert_eq!(changes[1].new_value, "done");
        assert_eq!(changes[2].old_value, "api");
        assert_eq!(changes[2].new_value, "worker");
    }

    #[tokio::test]
    async fn noop_update_does_not_record_audit_change() {
        let svc = service();
        let object = Object {
            id: "audit-noop".into(),
            kind: "component".into(),
            name: "api".into(),
            namespace: "default".into(),
            external_id: "component:api".into(),
            properties: HashMap::from([("status".into(), "todo".into())]),
            created: 1,
            updated: 1,
        };
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(object.clone()),
        }))
        .await
        .unwrap();

        svc.update_object(with_principal(UpdateObjectRequest {
            object: Some(object),
        }))
        .await
        .unwrap();

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "audit-noop".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .changes;

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "_created");
    }

    #[tokio::test]
    async fn audit_insert_failure_rolls_back_create() {
        let svc = service();
        svc.db
            .conn()
            .execute("DROP TABLE sekai_object_changes", [])
            .unwrap();

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "audit-fail-closed".into(),
                    kind: "component".into(),
                    name: "api".into(),
                    namespace: "default".into(),
                    external_id: "component:api".into(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                }),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(svc.db.get_object("audit-fail-closed").unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_fails_closed_when_delete_audit_insert_fails() {
        let svc = service();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "delete-audit-fail".into(),
                kind: "component".into(),
                name: "api".into(),
                namespace: "default".into(),
                external_id: "component:api".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();
        svc.db
            .conn()
            .execute("DROP TABLE sekai_object_changes", [])
            .unwrap();

        let err = svc
            .delete_object(with_principal(DeleteObjectRequest {
                id: "delete-audit-fail".into(),
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(svc.db.get_object("delete-audit-fail").unwrap().is_some());
    }

    #[tokio::test]
    async fn delete_object_remains_idempotent_when_missing() {
        let svc = service();

        svc.delete_object(with_principal(DeleteObjectRequest {
            id: "missing-object".into(),
        }))
        .await
        .unwrap();

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "missing-object".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .changes;

        assert!(changes.is_empty());
    }

    #[tokio::test]
    async fn schema_type_enforces_create_and_update() {
        let svc = service();
        grant_schema_admin(&svc);
        let created = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.r#type.unwrap().kind, "widget");

        let missing_required = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(widget_object("w1", HashMap::new())),
            }))
            .await
            .unwrap_err();
        assert_eq!(missing_required.code(), tonic::Code::InvalidArgument);
        assert!(missing_required.message().contains("name"));

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "w1",
                HashMap::from([
                    ("name".into(), "first".into()),
                    ("color".into(), "red".into()),
                ]),
            )),
        }))
        .await
        .unwrap();

        let invalid_update = svc
            .update_object(with_principal(UpdateObjectRequest {
                object: Some(widget_object(
                    "w1",
                    HashMap::from([
                        ("name".into(), "first".into()),
                        ("color".into(), "green".into()),
                    ]),
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(invalid_update.code(), tonic::Code::InvalidArgument);
        assert!(invalid_update.message().contains("color"));
    }

    #[tokio::test]
    async fn untyped_kind_still_writes_and_schema_types_list() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-1".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        let listed = svc
            .list_schema_types(with_principal(ListSchemaTypesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(
            listed
                .types
                .iter()
                .any(|object_type| object_type.kind == "widget" && !object_type.is_builtin)
        );
        assert!(
            listed
                .types
                .iter()
                .any(|object_type| object_type.kind == "namespace" && object_type.is_builtin)
        );
    }

    #[tokio::test]
    async fn list_schema_types_requires_principal() {
        let svc = service();
        let err = svc
            .list_schema_types(Request::new(ListSchemaTypesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn delete_schema_type_rejects_builtin() {
        let svc = service();
        grant_schema_admin(&svc);
        let err = svc
            .delete_schema_type(with_principal(DeleteSchemaTypeRequest {
                kind: "namespace".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("builtin"));
    }

    #[tokio::test]
    async fn create_schema_type_requires_schema_admin() {
        let svc = service();
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(widget_schema_type()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn interface_rpcs_enforce_auth_and_admin() {
        let svc = service();
        let err = svc
            .list_interfaces(Request::new(ListInterfacesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let interface = InterfaceDef {
            name: "Trackable".into(),
            description: "Trackable object".into(),
            properties: vec![],
            is_builtin: false,
        };
        let err = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(interface.clone()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        grant_object_role(&svc, "schema:Trackable", "tester", security::Role::Admin);
        let err = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(interface.clone()),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        grant_object_role(&svc, "interface:Trackable", "tester", security::Role::Admin);
        let created = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(interface),
            }))
            .await
            .unwrap()
            .into_inner()
            .interface
            .unwrap();
        assert_eq!(created.name, "Trackable");

        let listed = svc
            .list_interfaces(with_principal(ListInterfacesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(
            listed
                .interfaces
                .iter()
                .any(|interface| interface.name == "Trackable" && !interface.is_builtin)
        );

        svc.delete_interface(with_principal(DeleteInterfaceRequest {
            name: "Trackable".into(),
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn delete_interface_rejects_builtin() {
        let svc = service();
        grant_schema_admin(&svc);
        let err = svc
            .delete_interface(with_principal(DeleteInterfaceRequest {
                name: "RiskScored".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("builtin"));
    }

    #[tokio::test]
    async fn schema_type_implements_interface_and_list_filters_by_interface() {
        let svc = service();
        grant_schema_admin(&svc);
        let interface = InterfaceDef {
            name: "Trackable".into(),
            description: "Trackable object".into(),
            properties: vec![PropertyDef {
                name: "tracking_id".into(),
                r#type: "string".into(),
                required: true,
                description: "".into(),
                enum_values: vec![],
                link_kind: "".into(),
                compute_expr: "".into(),
                classification: "public".into(),
                struct_fields: vec![],
            }],
            is_builtin: false,
        };
        svc.create_interface(with_principal(CreateInterfaceRequest {
            interface: Some(interface),
        }))
        .await
        .unwrap();

        let mut invalid_type = widget_schema_type();
        invalid_type.implements = vec!["Trackable".into()];
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(invalid_type),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("tracking_id"));

        let mut optional_required_property = widget_schema_type();
        optional_required_property.implements = vec!["Trackable".into()];
        optional_required_property.properties.push(PropertyDef {
            name: "tracking_id".into(),
            r#type: "string".into(),
            required: false,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        let err = svc
            .create_schema_type(with_principal(CreateSchemaTypeRequest {
                r#type: Some(optional_required_property),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("must be required"));

        let mut valid_type = widget_schema_type();
        valid_type.implements = vec!["Trackable".into()];
        valid_type.properties.push(PropertyDef {
            name: "tracking_id".into(),
            r#type: "string".into(),
            required: true,
            description: "".into(),
            enum_values: vec![],
            link_kind: "".into(),
            compute_expr: "".into(),
            classification: "public".into(),
            struct_fields: vec![],
        });
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(valid_type),
        }))
        .await
        .unwrap();

        let incompatible_update = svc
            .create_interface(with_principal(CreateInterfaceRequest {
                interface: Some(InterfaceDef {
                    name: "Trackable".into(),
                    description: "Trackable object".into(),
                    properties: vec![
                        PropertyDef {
                            name: "tracking_id".into(),
                            r#type: "string".into(),
                            required: true,
                            description: "".into(),
                            enum_values: vec![],
                            link_kind: "".into(),
                            compute_expr: "".into(),
                            classification: "public".into(),
                            struct_fields: vec![],
                        },
                        PropertyDef {
                            name: "second_tracking_id".into(),
                            r#type: "string".into(),
                            required: true,
                            description: "".into(),
                            enum_values: vec![],
                            link_kind: "".into(),
                            compute_expr: "".into(),
                            classification: "public".into(),
                            struct_fields: vec![],
                        },
                    ],
                    is_builtin: false,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(incompatible_update.code(), tonic::Code::InvalidArgument);
        assert!(incompatible_update.message().contains("second_tracking_id"));

        let delete_referenced = svc
            .delete_interface(with_principal(DeleteInterfaceRequest {
                name: "Trackable".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(delete_referenced.code(), tonic::Code::FailedPrecondition);

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object(
                "tracked",
                HashMap::from([
                    ("name".into(), "tracked".into()),
                    ("tracking_id".into(), "trk-1".into()),
                ]),
            )),
        }))
        .await
        .unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-2".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    interface_filter: vec!["Trackable".into()],
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.total, 1);
        assert_eq!(listed.objects[0].id, "tracked");
    }

    #[tokio::test]
    async fn corrupt_schema_row_only_blocks_that_kind_until_repaired() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        {
            let conn = db.conn();
            conn.execute(
                "INSERT INTO sekai_object_types (kind, description, properties_json, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                ("broken", "Broken schema", "[", 1_i64),
            )
            .unwrap();
        }
        let svc = SekaiServiceImpl::new(db.clone());
        grant_schema_admin(&svc);

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-1".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "broken-1".into(),
                    kind: "broken".into(),
                    name: "broken".into(),
                    namespace: "".into(),
                    external_id: "".into(),
                    properties: HashMap::new(),
                    created: 0,
                    updated: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("broken"));

        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "broken".into(),
                description: "Repaired".into(),
                properties: vec![],
                is_builtin: false,
                implements: vec![],
            }),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "broken-2".into(),
                kind: "broken".into(),
                name: "broken".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn user_defined_action_blocks_when_target_schema_failed_to_load() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        db.migrate_schema_types().unwrap();
        {
            let conn = db.conn();
            conn.execute(
                "INSERT INTO sekai_object_types (kind, description, properties_json, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                ("broken", "Broken schema", "[", 1_i64),
            )
            .unwrap();
        }
        db.upsert_action_type(&action::ActionTypeDef {
            name: "touch_broken".into(),
            description: "".into(),
            params: vec![action::ActionParamDef {
                name: "value".into(),
                param_type: schema::PropertyType::String,
                required: true,
                enum_values: vec![],
            }],
            ops: vec![action::ActionOp {
                op: "set_property".into(),
                property: "status".into(),
                value_from: "value".into(),
                relation: "".into(),
            }],
            target_kind: "broken".into(),
            created: 1,
        })
        .unwrap();
        let svc = SekaiServiceImpl::new(db.clone());
        svc.db
            .create_object(&domain::Object {
                id: "broken-1".into(),
                kind: "broken".into(),
                name: "broken".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        grant_object_role(&svc, "broken-1", "alice", security::Role::Editor);

        let err = svc
            .execute_action(with_named_principal(
                ExecuteActionRequest {
                    request: Some(ActionRequest {
                        action: "touch_broken".into(),
                        params: HashMap::from([
                            ("id".into(), "broken-1".into()),
                            ("value".into(), "done".into()),
                        ]),
                        actor: "".into(),
                    }),
                    dry_run: false,
                },
                "alice",
            ))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("broken"));
        assert!(
            !svc.db
                .get_object("broken-1")
                .unwrap()
                .unwrap()
                .properties
                .contains_key("status")
        );
    }

    #[tokio::test]
    async fn schema_table_read_failure_blocks_object_writes() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        {
            let conn = db.conn();
            conn.execute("DROP TABLE sekai_object_types", []).unwrap();
            conn.execute(
                "CREATE TABLE sekai_object_types (kind TEXT PRIMARY KEY)",
                [],
            )
            .unwrap();
        }
        let svc = SekaiServiceImpl::new(db.clone());

        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "loose-1".into(),
                    kind: "loose".into(),
                    name: "loose".into(),
                    namespace: "".into(),
                    external_id: "".into(),
                    properties: HashMap::new(),
                    created: 0,
                    updated: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(err.message().contains("schema registry unavailable"));

        {
            let conn = db.conn();
            conn.execute("DROP TABLE sekai_object_types", []).unwrap();
        }
        db.migrate_all().unwrap();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "loose-2".into(),
                kind: "loose".into(),
                name: "loose".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn malformed_object_row_returns_internal_and_next_request_succeeds() {
        let svc = service();
        {
            let conn = svc.db.conn();
            conn.execute(
                "INSERT INTO sekai_objects
                 (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                ("good", "widget", "good", "", "", "{}", 1000_i64, 1000_i64),
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sekai_objects
                 (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (
                    "bad",
                    "widget",
                    "bad",
                    "",
                    "",
                    "{}",
                    "not-an-integer",
                    1000_i64,
                ),
            )
            .unwrap();
        }

        let err = svc
            .get_object(with_principal(GetObjectRequest { id: "bad".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);

        let good = svc
            .get_object(with_principal(GetObjectRequest { id: "good".into() }))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert_eq!(good.id, "good");
    }

    #[tokio::test]
    async fn delete_schema_type_removes_enforcement() {
        let svc = service();
        grant_schema_admin(&svc);
        svc.create_schema_type(with_principal(CreateSchemaTypeRequest {
            r#type: Some(widget_schema_type()),
        }))
        .await
        .unwrap();
        svc.delete_schema_type(with_principal(DeleteSchemaTypeRequest {
            kind: "widget".into(),
        }))
        .await
        .unwrap();

        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(widget_object("w1", HashMap::new())),
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn grant_and_audit_rpcs_round_trip() {
        let svc = service();
        let admin_grant = security::Grant {
            id: "admin".into(),
            object_id: "o1".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&admin_grant).unwrap();
        svc.security.add_grant(&admin_grant);
        svc.db
            .record_decision(&audit::Decision {
                id: "d1".into(),
                timestamp: 10,
                actor: "tester".into(),
                action: "create".into(),
                reason: "".into(),
                evidence: HashMap::new(),
                target_id: "o1".into(),
                outcome: "ok".into(),
            })
            .unwrap();
        svc.db
            .record_object_change(&audit::ObjectChange {
                id: "c1".into(),
                object_id: "o1".into(),
                field: "name".into(),
                old_value: "a".into(),
                new_value: "b".into(),
                changed_by: "tester".into(),
                timestamp: 11,
            })
            .unwrap();

        let created = svc
            .create_grant(with_principal(CreateGrantRequest {
                grant: Some(Grant {
                    id: "g1".into(),
                    object_id: "o1".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 1,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.grant.unwrap().principal, "alice");

        let access = svc
            .check_access(with_principal(CheckAccessRequest {
                object_id: "o1".into(),
                principals: vec!["alice".into()],
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(access.allowed);

        let recorded = svc
            .record_decision(with_principal(RecordDecisionRequest {
                decision: Some(Decision {
                    id: "".into(),
                    timestamp: 0,
                    actor: "tester".into(),
                    action: "gateway.budget_denied".into(),
                    reason: "budget exceeded".into(),
                    evidence: HashMap::from([("user_id".into(), "agent:codex-app".into())]),
                    target_id: "o1".into(),
                    outcome: "denied".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        assert!(!recorded.id.is_empty());
        assert!(recorded.timestamp > 0);

        let listed = svc
            .list_decisions(with_principal(ListDecisionsRequest {
                actor: "tester".into(),
                action: "".into(),
                after: 0,
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.decisions.len(), 2);

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "o1".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(changes.changes.len(), 1);
    }

    #[tokio::test]
    async fn coordination_rpcs_round_trip() {
        let svc = service();
        let scope = svc
            .create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: "req-scope-1".into(),
                scope: Some(ContentionScope {
                    id: "scope-1".into(),
                    name: "build".into(),
                    parent_scope_id: String::new(),
                    max_concurrency: 1,
                    admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                    heartbeat_ttl_seconds: 30,
                    timeout_seconds: 60,
                    owner_principal: String::new(),
                    created: 100,
                    updated: 100,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .scope
            .unwrap();
        assert_eq!(scope.owner_principal, "tester");

        let work_unit = svc
            .create_work_unit(with_principal(CreateWorkUnitRequest {
                work_unit: Some(WorkUnit {
                    id: "wu-1".into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: "cargo test -q".into(),
                    scope_id: "scope-1".into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at: 101,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "idem-wu-1".into(),
                    updated_at: 101,
                }),
                request_id: "req-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(work_unit.owner_principal, "tester");

        let admitted = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-admit-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(admitted.admitted);
        assert_eq!(admitted.reservations.len(), 1);

        let reservations = svc
            .list_reservations(with_principal(ListReservationsRequest {
                work_unit_id: "wu-1".into(),
                scope_id: String::new(),
                status: coordination::RESERVATION_STATUS_ACTIVE.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reservations.reservations.len(), 1);

        let heartbeat = svc
            .heartbeat_work_unit(with_principal(HeartbeatWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-heartbeat-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert!(heartbeat.last_heartbeat_at > 0);

        let completed = svc
            .complete_work_unit(with_principal(CompleteWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-complete-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(completed.status, coordination::WORK_UNIT_STATUS_COMPLETED);

        let events = svc
            .list_run_events(with_principal(ListRunEventsRequest {
                work_unit_id: "wu-1".into(),
                limit: 20,
                after: 0,
                event_types: vec![],
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == "created")
        );
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == "admitted")
        );
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == coordination::WORK_UNIT_STATUS_COMPLETED)
        );
    }

    #[tokio::test]
    async fn coordination_hierarchy_blocks_siblings_and_snapshot_reports_contention() {
        let svc = service();
        for scope in [
            ContentionScope {
                id: "root".into(),
                name: "gradle".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 100,
                updated: 100,
            },
            ContentionScope {
                id: "child-a".into(),
                name: "gradle/a".into(),
                parent_scope_id: "root".into(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 101,
                updated: 101,
            },
            ContentionScope {
                id: "child-b".into(),
                name: "gradle/b".into(),
                parent_scope_id: "root".into(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 102,
                updated: 102,
            },
        ] {
            svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: format!("req-scope-{}", scope.id),
                scope: Some(scope),
            }))
            .await
            .unwrap();
        }
        for (id, scope_id, created_at) in [("wu-a", "child-a", 200), ("wu-b", "child-b", 201)] {
            svc.create_work_unit(with_principal(CreateWorkUnitRequest {
                work_unit: Some(WorkUnit {
                    id: id.into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: format!("run {}", id),
                    scope_id: scope_id.into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: format!("idem-{}", id),
                    updated_at: created_at,
                }),
                request_id: format!("req-{}", id),
            }))
            .await
            .unwrap();
        }

        let admitted = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-a".into(),
                request_id: "req-admit-wu-a".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(admitted.admitted);

        let blocked = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-b".into(),
                request_id: "req-admit-wu-b".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!blocked.admitted);
        assert!(blocked.reason.contains("saturated"));

        let snapshot = svc
            .get_coordination_snapshot(with_principal(GetCoordinationSnapshotRequest {}))
            .await
            .unwrap()
            .into_inner()
            .snapshot
            .unwrap();
        assert_eq!(snapshot.pending_count, 1);
        assert_eq!(snapshot.running_count, 1);
        assert!(!snapshot.blocked_scopes.is_empty());
    }

    #[tokio::test]
    async fn coordination_create_and_transition_requests_are_idempotent() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-idem".into(),
            scope: Some(ContentionScope {
                id: "scope-idem".into(),
                name: "idem".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();

        let create = CreateWorkUnitRequest {
            request_id: "req-create-idem".into(),
            work_unit: Some(WorkUnit {
                id: "wu-idem".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "echo hi".into(),
                scope_id: "scope-idem".into(),
                priority: 0,
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at: 2,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "idem-key-1".into(),
                updated_at: 2,
            }),
        };
        let first = svc
            .create_work_unit(with_principal(create.clone()))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        let second = svc
            .create_work_unit(with_principal(create))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(first.id, second.id);

        let admit = TryAdmitWorkUnitRequest {
            work_unit_id: "wu-idem".into(),
            request_id: "req-admit-idem".into(),
        };
        let first_admit = svc
            .try_admit_work_unit(with_principal(admit.clone()))
            .await
            .unwrap()
            .into_inner();
        let second_admit = svc
            .try_admit_work_unit(with_principal(admit))
            .await
            .unwrap()
            .into_inner();
        assert!(first_admit.admitted);
        assert!(second_admit.admitted);

        let complete = CompleteWorkUnitRequest {
            work_unit_id: "wu-idem".into(),
            request_id: "req-complete-idem".into(),
        };
        let first_complete = svc
            .complete_work_unit(with_principal(complete.clone()))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        let second_complete = svc
            .complete_work_unit(with_principal(complete))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(
            first_complete.status,
            coordination::WORK_UNIT_STATUS_COMPLETED
        );
        assert_eq!(second_complete.status, first_complete.status);
    }

    #[tokio::test]
    async fn coordination_filters_paginates_and_dry_run_reconciles() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-filter".into(),
            scope: Some(ContentionScope {
                id: "scope-filter".into(),
                name: "filter".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 10,
                updated: 10,
            }),
        }))
        .await
        .unwrap();

        for (id, key, created_at) in [("wu-f1", "filter-1", 11), ("wu-f2", "filter-2", 12)] {
            svc.create_work_unit(with_principal(CreateWorkUnitRequest {
                request_id: format!("req-create-{}", id),
                work_unit: Some(WorkUnit {
                    id: id.into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: format!("spec {}", id),
                    scope_id: "scope-filter".into(),
                    priority: 0,
                    timeout_seconds: 1,
                    heartbeat_ttl_seconds: 1,
                    created_at,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: key.into(),
                    updated_at: created_at,
                }),
            }))
            .await
            .unwrap();
        }
        svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
            work_unit_id: "wu-f1".into(),
            request_id: "req-admit-f1".into(),
        }))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-f1").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-f1"],
            )
            .unwrap();

        let first_page = svc
            .list_work_units(with_principal(ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-filter".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![
                        coordination::WORK_UNIT_STATUS_PENDING.into(),
                        coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    ],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: String::new(),
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first_page.work_units.len(), 1);
        assert!(!first_page.next_page_token.is_empty());

        let second_page = svc
            .list_work_units(with_principal(ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-filter".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![
                        coordination::WORK_UNIT_STATUS_PENDING.into(),
                        coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    ],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: first_page.next_page_token,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second_page.work_units.len(), 1);

        let reconcile = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: true,
                work_unit_id: "wu-f1".into(),
                scope_id: String::new(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!reconcile.details.is_empty());

        let still_running = svc
            .get_work_unit(with_principal(GetWorkUnitRequest { id: "wu-f1".into() }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn create_work_unit_ignores_client_supplied_lifecycle_state() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-sanitize".into(),
            scope: Some(ContentionScope {
                id: "scope-sanitize".into(),
                name: "sanitize".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();

        let created = svc
            .create_work_unit(with_principal(CreateWorkUnitRequest {
                request_id: "req-create-sanitize".into(),
                work_unit: Some(WorkUnit {
                    id: "wu-sanitize".into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    requested_spec: "echo hi".into(),
                    scope_id: "scope-sanitize".into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at: 5,
                    admitted_at: 99,
                    started_at: 99,
                    finished_at: 99,
                    last_heartbeat_at: 99,
                    failure_reason: "boom".into(),
                    cancel_reason: "stop".into(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "sanitize-1".into(),
                    updated_at: 77,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();

        assert_eq!(created.status, coordination::WORK_UNIT_STATUS_PENDING);
        assert_eq!(created.admitted_at, 0);
        assert_eq!(created.started_at, 0);
        assert_eq!(created.finished_at, 0);
        assert_eq!(created.last_heartbeat_at, 0);
        assert!(created.failure_reason.is_empty());
        assert!(created.cancel_reason.is_empty());
        assert_eq!(created.updated_at, created.created_at);
    }

    #[tokio::test]
    async fn reconcile_requires_scope_ownership_for_target_scope() {
        let svc = service();
        for (scope_id, owner, created) in [("scope-a", "tester", 1), ("scope-b", "other", 2)] {
            svc.create_contention_scope(with_named_principal(
                CreateContentionScopeRequest {
                    request_id: format!("req-{}", scope_id),
                    scope: Some(ContentionScope {
                        id: scope_id.into(),
                        name: scope_id.into(),
                        parent_scope_id: String::new(),
                        max_concurrency: 1,
                        admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                        heartbeat_ttl_seconds: 1,
                        timeout_seconds: 1,
                        owner_principal: String::new(),
                        created,
                        updated: created,
                    }),
                },
                owner,
            ))
            .await
            .unwrap();
        }

        svc.create_work_unit(with_named_principal(
            CreateWorkUnitRequest {
                request_id: "req-wu-other".into(),
                work_unit: Some(WorkUnit {
                    id: "wu-other".into(),
                    kind: "build".into(),
                    actor: "other".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: "run".into(),
                    scope_id: "scope-b".into(),
                    priority: 0,
                    timeout_seconds: 1,
                    heartbeat_ttl_seconds: 1,
                    created_at: 10,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "other-1".into(),
                    updated_at: 10,
                }),
            },
            "other",
        ))
        .await
        .unwrap();
        svc.try_admit_work_unit(with_named_principal(
            TryAdmitWorkUnitRequest {
                work_unit_id: "wu-other".into(),
                request_id: "req-admit-other".into(),
            },
            "other",
        ))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-other").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-other"],
            )
            .unwrap();

        let denied = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: false,
                work_unit_id: String::new(),
                scope_id: "scope-b".into(),
                limit: 10,
            }))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let still_running = svc
            .get_work_unit(with_named_principal(
                GetWorkUnitRequest {
                    id: "wu-other".into(),
                },
                "other",
            ))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn reconcile_with_mismatched_scope_and_work_unit_returns_empty() {
        let svc = service();
        for scope in [
            ContentionScope {
                id: "scope-one".into(),
                name: "scope-one".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            },
            ContentionScope {
                id: "scope-two".into(),
                name: "scope-two".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 2,
                updated: 2,
            },
        ] {
            svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: format!("req-{}", scope.id),
                scope: Some(scope),
            }))
            .await
            .unwrap();
        }

        svc.create_work_unit(with_principal(CreateWorkUnitRequest {
            request_id: "req-wu-mismatch".into(),
            work_unit: Some(WorkUnit {
                id: "wu-mismatch".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "run".into(),
                scope_id: "scope-one".into(),
                priority: 0,
                timeout_seconds: 1,
                heartbeat_ttl_seconds: 1,
                created_at: 10,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "mismatch-1".into(),
                updated_at: 10,
            }),
        }))
        .await
        .unwrap();
        svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
            work_unit_id: "wu-mismatch".into(),
            request_id: "req-admit-mismatch".into(),
        }))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-mismatch").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-mismatch"],
            )
            .unwrap();

        let reconcile = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: false,
                work_unit_id: "wu-mismatch".into(),
                scope_id: "scope-two".into(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reconcile.work_units_reconciled, 0);
        assert_eq!(reconcile.reservations_released, 0);
        assert!(reconcile.details.is_empty());

        let still_running = svc
            .get_work_unit(with_principal(GetWorkUnitRequest {
                id: "wu-mismatch".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn list_objects_enforces_limit_and_returns_total() {
        let svc = service();
        for i in 0..1105 {
            let object = domain::Object {
                id: format!("obj-{i}"),
                kind: "query-demo".into(),
                name: format!("object-{i}"),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "backend".into())]),
                created: i64::from(i),
                updated: i64::from(i),
            };
            svc.db.create_object(&object).unwrap();
        }

        let response = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        order_by: "name".into(),
                        limit: 2000,
                        offset: 0,
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.total, 1105);
        assert_eq!(response.objects.len(), 1000);
    }

    #[tokio::test]
    async fn list_objects_omits_filter_uses_defaults() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "default-filter".into(),
                kind: "query-demo".into(),
                name: "default-filter".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "backend".into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();

        let response = svc
            .list_objects(with_named_principal(
                ListObjectsRequest { filter: None },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.total, 1);
        assert_eq!(response.objects.len(), 1);
        assert_eq!(response.objects[0].id, "default-filter");
    }

    #[tokio::test]
    async fn list_objects_rejects_unknown_property_operator() {
        let svc = service();
        let err = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        property_filters: vec![PropertyFilter {
                            key: "team".into(),
                            op: "nope".into(),
                            value: "backend".into(),
                        }],
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn list_objects_rejects_invalid_property_key() {
        let svc = service();
        let err = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        property_filters: vec![PropertyFilter {
                            key: "team.name".into(),
                            op: "eq".into(),
                            value: "backend".into(),
                        }],
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn object_sets_resolve_like_inline_filter_and_owner_only_access() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "owner-visible".into(),
                kind: "query-demo".into(),
                name: "owner-visible".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "alpha".into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        grant_object_role(&svc, "owner-visible", "alice", security::Role::Viewer);

        svc.db
            .create_object(&domain::Object {
                id: "other-visible".into(),
                kind: "query-demo".into(),
                name: "other-visible".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::from([("team".into(), "alpha".into())]),
                created: 2,
                updated: 2,
            })
            .unwrap();
        grant_object_role(&svc, "other-visible", "bob", security::Role::Viewer);

        let inline = svc
            .list_objects(with_named_principal(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "query-demo".into(),
                        property_filters: vec![PropertyFilter {
                            key: "team".into(),
                            op: "eq".into(),
                            value: "alpha".into(),
                        }],
                        ..Default::default()
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        let created_set = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "alpha-set".into(),
                        description: "only alpha objects".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            property_filters: vec![PropertyFilter {
                                key: "team".into(),
                                op: "eq".into(),
                                value: "alpha".into(),
                            }],
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        let set_id = created_set.object_set.unwrap().id;

        let resolved_by_owner = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: set_id.clone(),
                    limit: 10,
                    offset: Some(0),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        let resolved_owner_ids = resolved_by_owner
            .objects
            .iter()
            .map(|obj| obj.id.clone())
            .collect::<Vec<_>>();

        assert_eq!(inline.total, 1);
        assert_eq!(resolved_by_owner.total, inline.total);
        assert_eq!(resolved_owner_ids, vec!["owner-visible"]);

        let err = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: set_id,
                    limit: 10,
                    offset: Some(0),
                },
                "bob",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn delete_object_set_prevents_future_resolve() {
        let svc = service();
        let created = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "temp".into(),
                        description: "temp set".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object_set
            .unwrap();

        svc.delete_object_set(with_named_principal(
            DeleteObjectSetRequest {
                id: created.id.clone(),
            },
            "alice",
        ))
        .await
        .unwrap();

        let err = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: created.id,
                    limit: 10,
                    offset: Some(0),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn create_object_set_rejects_duplicate_name_for_same_owner() {
        let svc = service();
        let payload = CreateObjectSetRequest {
            object_set: Some(ObjectSet {
                id: String::new(),
                name: "dup-name".into(),
                description: "first".into(),
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    ..Default::default()
                }),
                owner_principal: String::new(),
                created: 0,
            }),
        };

        svc.create_object_set(with_named_principal(payload.clone(), "alice"))
            .await
            .unwrap();

        let err = svc
            .create_object_set(with_named_principal(payload, "alice"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn create_object_set_rejects_duplicate_id_for_same_owner() {
        let svc = service();
        let first = CreateObjectSetRequest {
            object_set: Some(ObjectSet {
                id: "fixed-id".into(),
                name: "first-id".into(),
                description: "first".into(),
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    ..Default::default()
                }),
                owner_principal: String::new(),
                created: 0,
            }),
        };
        svc.create_object_set(with_named_principal(first.clone(), "alice"))
            .await
            .unwrap();

        let second = CreateObjectSetRequest {
            object_set: Some(ObjectSet {
                id: "fixed-id".into(),
                name: "second-id".into(),
                description: "second".into(),
                filter: Some(ListFilter {
                    kind: "query-demo".into(),
                    ..Default::default()
                }),
                owner_principal: String::new(),
                created: 0,
            }),
        };

        let err = svc
            .create_object_set(with_named_principal(second, "alice"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn create_object_set_rejects_blank_name() {
        let svc = service();
        let err = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "  ".into(),
                        description: "blank".into(),
                        filter: Some(ListFilter::default()),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn create_object_set_rejects_invalid_property_key() {
        let svc = service();
        let err = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "invalid-key".into(),
                        description: "invalid filter".into(),
                        filter: Some(ListFilter {
                            property_filters: vec![PropertyFilter {
                                key: "team.name".into(),
                                op: "eq".into(),
                                value: "backend".into(),
                            }],
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn resolve_object_set_offset_zero_overrides_stored_offset() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "first".into(),
                kind: "query-demo".into(),
                name: "first".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "second".into(),
                kind: "query-demo".into(),
                name: "second".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 2,
                updated: 2,
            })
            .unwrap();

        let created = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "offset-set".into(),
                        description: "offset override".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            order_by: "name".into(),
                            limit: 1,
                            offset: 1,
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object_set
            .unwrap();

        let response = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: created.id,
                    limit: 1,
                    offset: Some(0),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.objects.len(), 1);
        assert_eq!(response.objects[0].id, "first");
    }

    #[tokio::test]
    async fn resolve_object_set_omitted_offset_uses_stored_offset() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "first".into(),
                kind: "query-demo".into(),
                name: "first".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_object(&domain::Object {
                id: "second".into(),
                kind: "query-demo".into(),
                name: "second".into(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 2,
                updated: 2,
            })
            .unwrap();

        let created = svc
            .create_object_set(with_named_principal(
                CreateObjectSetRequest {
                    object_set: Some(ObjectSet {
                        id: String::new(),
                        name: "stored-offset-set".into(),
                        description: "stored offset".into(),
                        filter: Some(ListFilter {
                            kind: "query-demo".into(),
                            order_by: "name".into(),
                            limit: 1,
                            offset: 1,
                            ..Default::default()
                        }),
                        owner_principal: String::new(),
                        created: 0,
                    }),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner()
            .object_set
            .unwrap();

        let response = svc
            .resolve_object_set(with_named_principal(
                ResolveObjectSetRequest {
                    id: created.id,
                    limit: 1,
                    offset: None,
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.objects.len(), 1);
        assert_eq!(response.objects[0].id, "second");
    }

    #[tokio::test]
    async fn action_policy_set_get_list_round_trip() {
        let svc = service();
        grant_action_admin(&svc);

        let policy = ActionPolicy {
            scope: "agent:codex-app".into(),
            default_decision: "allow".into(),
            action_overrides: HashMap::from([("delete_link".to_string(), "deny".to_string())]),
            risk_overrides: HashMap::from([(
                "destructive".to_string(),
                "require_approval".to_string(),
            )]),
            max_mutations_per_work_unit: 0,
            max_deletes_per_work_unit: 5,
        };

        let stored = svc
            .set_action_policy(with_principal(SetActionPolicyRequest {
                policy: Some(policy.clone()),
            }))
            .await
            .unwrap()
            .into_inner()
            .policy
            .unwrap();
        assert_eq!(stored.scope, "agent:codex-app");
        assert_eq!(stored.action_overrides.get("delete_link").unwrap(), "deny");

        let fetched = svc
            .get_action_policy(with_principal(GetActionPolicyRequest {
                scope: "agent:codex-app".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .policy
            .unwrap();
        assert_eq!(fetched.default_decision, "allow");
        assert_eq!(
            fetched.risk_overrides.get("destructive").unwrap(),
            "require_approval"
        );
        assert_eq!(fetched.max_deletes_per_work_unit, 5);

        let listed = svc
            .list_action_policies(with_principal(ListActionPoliciesRequest {}))
            .await
            .unwrap()
            .into_inner()
            .policies;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].scope, "agent:codex-app");
    }

    #[tokio::test]
    async fn action_policy_set_requires_action_admin() {
        let svc = service();
        // No action-admin grant for "tester".
        let err = svc
            .set_action_policy(with_principal(SetActionPolicyRequest {
                policy: Some(ActionPolicy {
                    scope: "agent:codex-app".into(),
                    default_decision: "deny".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        // Nothing was persisted.
        assert!(
            svc.db
                .get_action_policy("agent:codex-app")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn action_policy_set_rejects_invalid_decision() {
        let svc = service();
        grant_action_admin(&svc);
        let err = svc
            .set_action_policy(with_principal(SetActionPolicyRequest {
                policy: Some(ActionPolicy {
                    scope: "agent:codex-app".into(),
                    default_decision: "maybe".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn scoring_writer_records_private_typed_learning_and_retries_idempotently() {
        let svc = service();
        let namespace_id = seed_scoring_namespace(&svc, "acme");
        let request = scored_knowledge_request("acme", "request-42");
        let learning_id = scoring_learning_id("acme", "request-42");

        assert_eq!(
            svc.write_knowledge(&request).await.unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
        let learning = svc.db.get_object(&learning_id).unwrap().unwrap();
        assert_eq!(learning.kind, domain::KIND_LEARNING);
        assert_eq!(learning.namespace, "acme");
        assert_eq!(learning.name, "Scored learning");
        assert_eq!(learning.properties["producer"], "chisei.scoring");
        assert_eq!(learning.properties["status"], "candidate");
        assert_eq!(
            learning.properties["title"],
            "Scored primary task outcome: passed"
        );
        assert!(
            learning.properties["prevention"]
                .contains("The implementation satisfies the requested behavior.")
        );
        assert_eq!(learning.properties["source_request_id"], "request-42");
        let long_source = knowledge_source_request_id(&"x".repeat(300));
        assert!(long_source.starts_with("sha256:"));
        assert_eq!(long_source.chars().count(), 71);

        let link = svc
            .db
            .get_link(&format!("{learning_id}->{namespace_id}"))
            .unwrap()
            .unwrap();
        assert_eq!(link.from_id, learning_id);
        assert_eq!(link.to_id, namespace_id);
        assert_eq!(link.relation, domain::REL_TOUCHES);

        let grants = svc.db.list_grants(&learning.id).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].principal, "chisei.scoring");
        assert_eq!(grants[0].role, security::Role::Admin);

        // The action inserted the fallback ACL directly in its transaction. The service refreshes
        // its in-process checker before returning, so the learning is never left world-readable.
        let denied = svc
            .get_object(with_named_principal(
                GetObjectRequest {
                    id: learning.id.clone(),
                },
                "unrelated",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        // The same namespace/request pair produces the same id and the action's exact-retry path
        // does not duplicate the object, link, or grant.
        assert_eq!(
            svc.write_knowledge(&request).await.unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
        let learnings = svc
            .db
            .list_objects(&domain::ListFilter {
                kind: Some(domain::KIND_LEARNING.into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(learnings.len(), 1);
        assert_eq!(svc.db.list_grants(&learning.id).unwrap().len(), 1);

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some(crate::sekai::learning::RECORD_LEARNING_ACTION.into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 2);
        for field in [
            "title",
            "prevention",
            "reasoning",
            "source_request_id",
            "score",
            "passed",
            "task_class",
            "model",
            "producer",
            "status",
        ] {
            assert_eq!(decisions[0].evidence[field], "[redacted]");
        }
    }

    #[tokio::test]
    async fn scoring_writer_uses_a_project_target_when_namespace_object_is_absent() {
        let svc = service();
        svc.db
            .create_object(&domain::Object {
                id: "project-acme".into(),
                kind: "project".into(),
                name: "acme".into(),
                namespace: "acme".into(),
                external_id: "project:acme".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        let request = scored_knowledge_request("acme", "project-request");
        let learning_id = scoring_learning_id("acme", "project-request");

        assert_eq!(
            svc.write_knowledge(&request).await.unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
        assert!(svc.db.get_object(&learning_id).unwrap().is_some());
        assert!(
            svc.db
                .get_link(&format!("{learning_id}->project-acme"))
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn scoring_writer_uses_an_explicit_service_grant_for_protected_targets() {
        let svc = service();
        let target_id = seed_scoring_namespace(&svc, "acme");
        grant_object_role(&svc, &target_id, "namespace-owner", security::Role::Admin);
        let request = scored_knowledge_request("acme", "protected-request");

        assert!(svc.write_knowledge(&request).await.is_err());

        grant_object_role(&svc, &target_id, "chisei.scoring", security::Role::Editor);
        assert_eq!(
            svc.write_knowledge(&request).await.unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
    }

    #[tokio::test]
    async fn scoring_writer_obeys_namespace_deny_and_approval_policies() {
        let denied_svc = service();
        seed_scoring_namespace(&denied_svc, "denied");
        denied_svc
            .db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "denied".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::from([(
                    crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
                    action_policy::ActionDecision::Deny,
                )]),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let denied_request = scored_knowledge_request("denied", "request-denied");
        let denied_id = scoring_learning_id("denied", "request-denied");

        assert_eq!(
            denied_svc.write_knowledge(&denied_request).await.unwrap(),
            KnowledgeWriteOutcome::PolicyDenied
        );
        assert!(denied_svc.db.get_object(&denied_id).unwrap().is_none());
        let denied_decisions = denied_svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some(crate::sekai::learning::RECORD_LEARNING_ACTION.into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(denied_decisions.len(), 1);
        assert_eq!(denied_decisions[0].reason, "action_policy_denied");
        assert_eq!(denied_decisions[0].evidence["policy_scope"], "denied");

        let approval_svc = service();
        seed_scoring_namespace(&approval_svc, "approval");
        approval_svc
            .db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "approval".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::from([(
                    crate::sekai::learning::RECORD_LEARNING_ACTION.into(),
                    action_policy::ActionDecision::RequireApproval,
                )]),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let approval_request = scored_knowledge_request("approval", "request-approval");
        let approval_id = scoring_learning_id("approval", "request-approval");

        assert_eq!(
            approval_svc
                .write_knowledge(&approval_request)
                .await
                .unwrap(),
            KnowledgeWriteOutcome::Accepted
        );
        assert!(approval_svc.db.get_object(&approval_id).unwrap().is_none());
        let pending = approval_svc
            .db
            .list_action_approvals(Some(action_approval::ApprovalStatus::Pending))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].action,
            crate::sekai::learning::RECORD_LEARNING_ACTION
        );
        assert_eq!(pending[0].params["id"], approval_id);
        assert_eq!(pending[0].work_unit, approval_id);
    }

    #[tokio::test]
    async fn execute_action_denied_by_policy_is_blocked_and_audited() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Deny destructive ops for this agent scope.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::from([(
                    action::RiskClass::Destructive,
                    action_policy::ActionDecision::Deny,
                )]),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        // Create a link then attempt to delete it (destructive).
        svc.db
            .create_link(&domain::Link {
                id: "obj-1->obj-1".into(),
                from_id: "obj-1".into(),
                to_id: "obj-1".into(),
                relation: "self".into(),
                created: 0,
            })
            .unwrap();

        let mut request = with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "delete_link".into(),
                params: HashMap::from([("id".into(), "obj-1->obj-1".into())]),
                actor: String::new(),
            }),
            dry_run: false,
        });
        request
            .metadata_mut()
            .insert("x-chisei-work-unit", "denied-action-work".parse().unwrap());
        let err = svc.execute_action(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // Link still exists (no mutation).
        assert!(svc.db.get_link("obj-1->obj-1").unwrap().is_some());

        // Denial was audited.
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("delete_link".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "action_policy_denied");
        assert_eq!(decisions[0].evidence["risk_class"], "destructive");
        assert_eq!(decisions[0].evidence["decision"], "deny");
        assert_eq!(decisions[0].evidence["policy_scope"], "agent:tester");
        assert_eq!(decisions[0].evidence["work_unit"], "denied-action-work");

        // The denial carries a verifiable attestation of the policy applied.
        // Attestation reads expose the policy snapshot, so they are gated on
        // action admin like direct policy reads.
        let attestation_id = decisions[0].evidence["attestation_id"].clone();
        let denied = svc
            .get_attestation(with_principal(GetAttestationRequest {
                id: attestation_id.clone(),
            }))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        let hidden = svc
            .list_attestations(with_principal(ListAttestationsRequest {
                decision_id: String::new(),
                policy_scope: String::new(),
                limit: 0,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .attestations;
        assert!(hidden.is_empty());

        grant_action_admin(&svc);
        let listed = svc
            .list_attestations(with_principal(ListAttestationsRequest {
                decision_id: decisions[0].id.clone(),
                policy_scope: String::new(),
                limit: 0,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .attestations;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, attestation_id);
        assert_eq!(listed[0].decision, "deny");
        assert_eq!(listed[0].policy_scope, "agent:tester");
        assert_eq!(listed[0].inputs["action"], "delete_link");
        assert_eq!(listed[0].inputs["risk_class"], "destructive");

        let report = svc
            .verify_attestation(with_principal(VerifyAttestationRequest {
                id: attestation_id,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(report.ok, "{}", report.error);
        assert!(report.hash_ok);
        assert!(report.replay_ok);
        assert!(report.decision_linked);
        assert_eq!(report.replayed_decision, "deny");

        let export = svc
            .export_assurance(with_principal(ExportAssuranceRequest {
                action: "delete_link".into(),
                policy_scope: "agent:tester".into(),
                after: 0,
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(export.records.len(), 1);
        assert_eq!(
            export.records[0].decision.as_ref().unwrap().action,
            "delete_link"
        );
        assert_eq!(
            export.records[0].attestation.as_ref().unwrap().policy_scope,
            "agent:tester"
        );
        assert!(export.records[0].verification.as_ref().unwrap().ok);
        assert!(export.ledger.as_ref().unwrap().ok);
    }

    #[tokio::test]
    async fn list_attestations_paginates_over_visible_rows_only() {
        let svc = service();
        // tester administers scope-a only; scope-b attestations stay hidden.
        let grant = security::Grant {
            id: "scope-a-admin".into(),
            object_id: action_object_id("scope-a"),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);

        for (scope, created) in [
            ("scope-a", 300),
            ("scope-b", 250),
            ("scope-a", 200),
            ("scope-b", 150),
            ("scope-a", 100),
        ] {
            let attestation =
                attestation::build_action_attestation(attestation::ActionAttestationInput {
                    decision_id: &format!("dec-{scope}-{created}"),
                    policy: &action_policy::ActionPolicy::allow_all(scope),
                    action: "set_property",
                    actor: "tester",
                    risk: action::RiskClass::Write,
                    namespace: "default",
                    decision: action_policy::ActionDecision::Allow,
                    created,
                });
            svc.db.insert_attestation(&attestation).unwrap();
        }

        // limit/offset apply to visible rows: skipping 1 of the 3 visible
        // scope-a rows (created DESC) yields the 200 and 100 entries, even
        // though hidden scope-b rows are interleaved in the raw table order.
        let page = svc
            .list_attestations(with_principal(ListAttestationsRequest {
                decision_id: String::new(),
                policy_scope: String::new(),
                limit: 2,
                offset: 1,
            }))
            .await
            .unwrap()
            .into_inner()
            .attestations;
        assert_eq!(page.len(), 2);
        assert!(page.iter().all(|a| a.policy_scope == "scope-a"));
        assert_eq!(page[0].created, 200);
        assert_eq!(page[1].created, 100);
    }

    #[tokio::test]
    async fn execute_action_without_policy_records_no_attestation() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "ok".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert!(!decisions[0].evidence.contains_key("attestation_id"));
        assert!(
            svc.db
                .list_attestations(None, None, 10, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn execute_action_allowed_by_policy_executes() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Deny only destructive; writes (set_property) are allowed.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::from([(
                    action::RiskClass::Destructive,
                    action_policy::ActionDecision::Deny,
                )]),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "done".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");
    }

    #[tokio::test]
    async fn execute_action_without_policy_is_allowed_backward_compatible() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // A deny-all policy for a *different* agent must not affect this caller.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:someone-else".into(),
                default_decision: action_policy::ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "done".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");
    }

    #[tokio::test]
    async fn execute_action_require_approval_holds_and_returns_pending() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        let mut req = Request::new(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "done".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        });
        req.metadata_mut().insert(
            "x-principal",
            tonic::metadata::MetadataValue::try_from("tester").unwrap(),
        );
        req.metadata_mut().insert(
            "x-chisei-work-unit",
            tonic::metadata::MetadataValue::try_from("wu-1").unwrap(),
        );

        let result = svc
            .execute_action(req)
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(result.decision, "require_approval");
        assert!(!result.approval_id.is_empty());

        // No mutation happened.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));

        // A pending approval was persisted with work-unit + exact params.
        let pending = svc
            .db
            .list_action_approvals(Some(action_approval::ApprovalStatus::Pending))
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, result.approval_id);
        assert_eq!(pending[0].action, "set_property");
        assert_eq!(pending[0].work_unit, "wu-1");
        assert_eq!(pending[0].params["value"], "done");

        // The hold was audited.
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "action_approval_pending");
    }

    #[tokio::test]
    async fn execute_action_dry_run_reports_plan_without_mutating() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");

        let result = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();

        assert!(result.dry_run);
        assert_eq!(result.decision, "allow");
        assert_eq!(result.planned_ops, vec!["set_property obj-1.status"]);

        // No mutation happened.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));

        // A dry-run decision was audited.
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "execute_action_dry_run");
        assert_eq!(decisions[0].evidence["dry_run"], "true");
    }

    #[tokio::test]
    async fn execute_action_dry_run_surfaces_deny_without_erroring() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        // Dry-run returns the plan + decision even though the policy denies.
        let result = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(result.dry_run);
        assert_eq!(result.decision, "deny");
        assert_eq!(result.planned_ops.len(), 1);
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    fn hold_set_property(svc: &SekaiServiceImpl) -> String {
        // Set a require-approval policy and hold a set_property action.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let approval = action_approval::ActionApproval::pending(
            "tester",
            "set_property",
            HashMap::from([
                ("id".to_string(), "obj-1".to_string()),
                ("key".to_string(), "status".to_string()),
                ("value".to_string(), "done".to_string()),
            ]),
            "wu-1",
            "agent:tester",
            "write",
            "obj-1",
            1000,
        );
        svc.db.create_action_approval(&approval).unwrap();
        approval.id
    }

    #[tokio::test]
    async fn approve_action_resumes_execution_and_audits() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        let response = svc
            .approve_action(with_principal(ApproveActionRequest {
                approval_id: id.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.result.unwrap().decision, "approved");
        assert_eq!(response.approval.unwrap().status, "approved");

        // The held action executed.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "done");

        // Approval recorded + no longer pending.
        assert!(
            svc.db
                .list_action_approvals(Some(action_approval::ApprovalStatus::Pending))
                .unwrap()
                .is_empty()
        );
        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        let approved = decisions
            .iter()
            .find(|d| d.reason == "action_approval_approved")
            .unwrap();
        assert_eq!(approved.evidence["work_unit"], "wu-1");
        assert_eq!(approved.evidence["risk_class"], "write");
        assert_eq!(approved.evidence["decision"], "require_approval");
        assert_eq!(approved.evidence["approval_status"], "approved");
        assert!(decisions.iter().any(|d| d.reason == "execute_action"));
    }

    #[tokio::test]
    async fn deny_action_drops_hold_without_executing() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        let approval = svc
            .deny_action(with_principal(DenyActionRequest {
                approval_id: id,
                reason: "not now".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .approval
            .unwrap();
        assert_eq!(approval.status, "denied");
        assert_eq!(approval.outcome, "not now");

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        let denied = decisions
            .iter()
            .find(|decision| decision.reason == "action_approval_denied")
            .unwrap();
        assert_eq!(denied.evidence["work_unit"], "wu-1");
        assert_eq!(denied.evidence["risk_class"], "write");
        assert_eq!(denied.evidence["decision"], "deny");

        // No mutation.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    #[tokio::test]
    async fn approve_action_rechecks_policy_and_blocks_when_now_denied() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        // Tighten the policy to deny before approving.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Deny,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        let err = svc
            .approve_action(with_principal(ApproveActionRequest { approval_id: id }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        // Still not executed.
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert!(!obj.properties.contains_key("status"));
    }

    #[tokio::test]
    async fn approve_action_requires_admin() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);
        let err = svc
            .approve_action(with_principal(ApproveActionRequest { approval_id: id }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn list_pending_approvals_filters_by_status() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        let id = hold_set_property(&svc);

        let pending = svc
            .list_pending_approvals(with_principal(ListPendingApprovalsRequest {
                status: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .approvals;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        // Sensitive params would be redacted; here plain values pass through.
        assert_eq!(pending[0].params["value"], "done");
    }

    fn work_unit_request(
        action: &str,
        params: HashMap<String, String>,
        wu: &str,
    ) -> Request<ExecuteActionRequest> {
        let mut req = Request::new(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: action.into(),
                params,
                actor: String::new(),
            }),
            dry_run: false,
        });
        req.metadata_mut().insert(
            "x-principal",
            tonic::metadata::MetadataValue::try_from("tester").unwrap(),
        );
        req.metadata_mut().insert(
            "x-chisei-work-unit",
            tonic::metadata::MetadataValue::try_from(wu).unwrap(),
        );
        req
    }

    #[tokio::test]
    async fn blast_radius_delete_cap_hard_stops_after_limit() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Allow everything but cap deletes at 1 per work unit.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: Some(1),
            })
            .unwrap();
        for link_id in ["obj-1->a", "obj-1->b"] {
            svc.db
                .create_link(&domain::Link {
                    id: link_id.into(),
                    from_id: "obj-1".into(),
                    to_id: "obj-1".into(),
                    relation: "self".into(),
                    created: 0,
                })
                .unwrap();
        }

        // First delete within cap succeeds.
        svc.execute_action(work_unit_request(
            "delete_link",
            HashMap::from([("id".into(), "obj-1->a".into())]),
            "wu-1",
        ))
        .await
        .unwrap();

        // Second delete exceeds the cap and is hard-stopped.
        let err = svc
            .execute_action(work_unit_request(
                "delete_link",
                HashMap::from([("id".into(), "obj-1->b".into())]),
                "wu-1",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        // The second link still exists.
        assert!(svc.db.get_link("obj-1->b").unwrap().is_some());

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("delete_link".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|d| d.reason == "action_blast_radius_exceeded")
        );
    }

    #[tokio::test]
    async fn blast_radius_counters_are_scoped_per_work_unit() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: Some(1),
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        // First mutation on wu-1 succeeds.
        svc.execute_action(work_unit_request(
            "set_property",
            HashMap::from([
                ("id".into(), "obj-1".into()),
                ("key".into(), "status".into()),
                ("value".into(), "a".into()),
            ]),
            "wu-1",
        ))
        .await
        .unwrap();

        // Second mutation on wu-1 exceeds the cap.
        let err = svc
            .execute_action(work_unit_request(
                "set_property",
                HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "b".into()),
                ]),
                "wu-1",
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // A different work unit has its own counter and succeeds.
        svc.execute_action(work_unit_request(
            "set_property",
            HashMap::from([
                ("id".into(), "obj-1".into()),
                ("key".into(), "status".into()),
                ("value".into(), "c".into()),
            ]),
            "wu-2",
        ))
        .await
        .unwrap();
        let obj = svc.db.get_object("obj-1").unwrap().unwrap();
        assert_eq!(obj.properties["status"], "c");
    }

    #[tokio::test]
    async fn action_class_budget_denies_when_exhausted() {
        use crate::chisei::budget::{BudgetTracker, PeriodType};
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let budget = Arc::new(BudgetTracker::new(db.clone()));
        // Allow 1 write action, then deny.
        budget
            .set_limit("action:write", 1, PeriodType::Daily)
            .unwrap();
        let svc = SekaiServiceImpl::with_budget(db, budget.clone());
        seed_domain_object(&svc, "obj-1");

        // First write consumes the budget.
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: "set_property".into(),
                params: HashMap::from([
                    ("id".into(), "obj-1".into()),
                    ("key".into(), "status".into()),
                    ("value".into(), "a".into()),
                ]),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();

        // Second write is denied by the exhausted budget.
        let err = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "b".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);

        // Usage reflects exactly one recorded action.
        assert_eq!(budget.get_usage("action:write").tokens_used, 1);

        let decisions = svc
            .db
            .list_decisions(&audit::DecisionFilter {
                action: Some("set_property".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|d| d.reason == "action_budget_exceeded")
        );
    }

    #[tokio::test]
    async fn governed_tool_call_is_policy_checked_via_execute_action() {
        use crate::sekai::tool_bridge::ToolCall;

        let svc = service();
        seed_domain_object(&svc, "obj-1");
        // Deny destructive tool-calls for this agent.
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::Allow,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::from([(
                    action::RiskClass::Destructive,
                    action_policy::ActionDecision::Deny,
                )]),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        svc.db
            .create_link(&domain::Link {
                id: "obj-1->obj-1".into(),
                from_id: "obj-1".into(),
                to_id: "obj-1".into(),
                relation: "self".into(),
                created: 0,
            })
            .unwrap();

        // An allowed write tool-call funnels through ExecuteAction and runs.
        let write_call = ToolCall::from_json_arguments(
            "set_property",
            r#"{"id":"obj-1","key":"status","value":"done"}"#,
        )
        .unwrap();
        svc.execute_action(with_principal(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: write_call.action_name().to_string(),
                params: write_call.to_action_params().unwrap(),
                actor: String::new(),
            }),
            dry_run: false,
        }))
        .await
        .unwrap();
        assert_eq!(
            svc.db.get_object("obj-1").unwrap().unwrap().properties["status"],
            "done"
        );

        // A destructive tool-call is denied by policy at the same boundary.
        let delete_call =
            ToolCall::from_json_arguments("delete_link", r#"{"id":"obj-1->obj-1"}"#).unwrap();
        let err = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: delete_call.action_name().to_string(),
                    params: delete_call.to_action_params().unwrap(),
                    actor: String::new(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(svc.db.get_link("obj-1->obj-1").unwrap().is_some());
    }

    #[tokio::test]
    async fn reserved_governance_objects_are_hidden_from_generic_crud() {
        let svc = service();
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy::allow_all("agent:tester"))
            .unwrap();

        // CreateObject cannot forge a governance kind (policy escalation guard).
        let err = svc
            .create_object(with_principal(CreateObjectRequest {
                object: Some(Object {
                    id: "forged".into(),
                    kind: "action_policy".into(),
                    name: "forged".into(),
                    namespace: String::new(),
                    external_id: "action_policy:agent:tester".into(),
                    properties: HashMap::from([("default_decision".into(), "allow".into())]),
                    created: 0,
                    updated: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // find_by_external_id hides the governance object.
        let err = svc
            .find_by_external_id(with_principal(FindByExternalIdRequest {
                external_id: "action_policy:agent:tester".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // ListObjects filtered by the reserved kind returns nothing.
        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "action_policy".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects.len(), 0);
        assert_eq!(listed.total, 0);
    }

    #[tokio::test]
    async fn held_approval_params_not_readable_via_get_object() {
        let svc = service();
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: None,
                max_deletes_per_work_unit: None,
            })
            .unwrap();
        let result = svc
            .execute_action(with_principal(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("api_key".into(), "super-secret".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), "done".into()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        let approval_id = result.approval_id;
        assert!(!approval_id.is_empty());

        // The stored approval object (raw params incl. the secret) is not
        // reachable through the generic GetObject RPC.
        let err = svc
            .get_object(with_principal(GetObjectRequest {
                id: approval_id.clone(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Nor via a broad ListObjects for the reserved kind.
        let listed = svc
            .list_objects(with_principal(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: "action_approval".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.objects.len(), 0);
    }

    #[tokio::test]
    async fn blast_radius_object_not_writable_via_update_object() {
        let svc = service();
        svc.db.add_blast_radius("wu-1", 1, 0).unwrap();
        let err = svc
            .update_object(with_principal(UpdateObjectRequest {
                object: Some(Object {
                    id: "blast-radius-wu-1".into(),
                    kind: "widget".into(),
                    name: "tamper".into(),
                    namespace: String::new(),
                    external_id: String::new(),
                    properties: HashMap::from([("mutations".into(), "0".into())]),
                    created: 0,
                    updated: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(svc.db.get_blast_radius("wu-1").unwrap(), (1, 0));
    }

    #[tokio::test]
    async fn approved_action_is_metered_against_blast_radius() {
        let svc = service();
        grant_action_admin(&svc);
        seed_domain_object(&svc, "obj-1");
        svc.db
            .upsert_action_policy(&action_policy::ActionPolicy {
                scope: "agent:tester".into(),
                default_decision: action_policy::ActionDecision::RequireApproval,
                action_overrides: HashMap::new(),
                risk_overrides: HashMap::new(),
                max_mutations_per_work_unit: Some(1),
                max_deletes_per_work_unit: None,
            })
            .unwrap();

        let mut ids = Vec::new();
        for value in ["a", "b"] {
            let mut req = Request::new(ExecuteActionRequest {
                request: Some(ActionRequest {
                    action: "set_property".into(),
                    params: HashMap::from([
                        ("id".into(), "obj-1".into()),
                        ("key".into(), "status".into()),
                        ("value".into(), value.to_string()),
                    ]),
                    actor: String::new(),
                }),
                dry_run: false,
            });
            req.metadata_mut().insert(
                "x-principal",
                tonic::metadata::MetadataValue::try_from("tester").unwrap(),
            );
            req.metadata_mut().insert(
                "x-chisei-work-unit",
                tonic::metadata::MetadataValue::try_from("wu-1").unwrap(),
            );
            let result = svc
                .execute_action(req)
                .await
                .unwrap()
                .into_inner()
                .result
                .unwrap();
            ids.push(result.approval_id);
        }

        // First approval executes and consumes the single-mutation cap.
        svc.approve_action(with_principal(ApproveActionRequest {
            approval_id: ids[0].clone(),
        }))
        .await
        .unwrap();

        // Second approval is hard-stopped by the per-work-unit blast-radius cap.
        let err = svc
            .approve_action(with_principal(ApproveActionRequest {
                approval_id: ids[1].clone(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn object_sets_cannot_read_or_target_reserved_governance_kinds() {
        let svc = service();
        // A held approval object carrying a secret param.
        let approval = action_approval::ActionApproval::pending(
            "tester",
            "rotate_key",
            HashMap::from([
                ("id".to_string(), "obj-1".to_string()),
                ("api_key".to_string(), "super-secret".to_string()),
            ]),
            "wu-1",
            "agent:tester",
            "destructive",
            "obj-1",
            0,
        );
        svc.db.create_action_approval(&approval).unwrap();

        // CreateObjectSet must reject a saved filter targeting a reserved kind.
        let err = svc
            .create_object_set(with_principal(CreateObjectSetRequest {
                object_set: Some(ObjectSet {
                    id: "leaky-set".into(),
                    name: "leaky".into(),
                    description: String::new(),
                    filter: Some(ListFilter {
                        kind: "action_approval".into(),
                        ..Default::default()
                    }),
                    owner_principal: "tester".into(),
                    created: 0,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // Even a set persisted out-of-band (e.g. legacy) resolves to nothing,
        // because the visibility query now excludes reserved kinds.
        svc.db
            .create_object_set(&domain::ObjectSet {
                id: "legacy-leaky-set".into(),
                name: "legacy".into(),
                description: String::new(),
                filter: domain::ListFilter {
                    kind: Some("action_approval".into()),
                    ..Default::default()
                },
                owner_principal: "tester".into(),
                created: 0,
            })
            .unwrap();
        let resolved = svc
            .resolve_object_set(with_principal(ResolveObjectSetRequest {
                id: "legacy-leaky-set".into(),
                limit: 10,
                offset: Some(0),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resolved.objects.len(), 0);
        assert_eq!(resolved.total, 0);
    }

    #[tokio::test]
    async fn retrieve_context_enforces_graph_visibility_and_response_redaction() {
        let svc = service();
        let mut schema_type = widget_schema_type();
        schema_type.properties.push(PropertyDef {
            name: "secret_note".into(),
            r#type: "string".into(),
            required: false,
            description: String::new(),
            enum_values: Vec::new(),
            link_kind: String::new(),
            compute_expr: String::new(),
            classification: "sensitive".into(),
            struct_fields: Vec::new(),
        });
        svc.create_schema_type(with_named_principal(
            CreateSchemaTypeRequest {
                r#type: Some(schema_type),
            },
            "root",
        ))
        .await
        .unwrap();

        for (id, external_id, secret) in [
            ("context-root", "widget:context-root", true),
            ("context-allowed", "widget:context-allowed", false),
            ("context-denied", "widget:context-denied", false),
            ("behind-denied", "widget:behind-denied", false),
            ("behind-governance", "widget:behind-governance", false),
        ] {
            let mut properties = HashMap::from([("name".into(), id.into())]);
            if secret {
                properties.insert("secret_note".into(), "launch code".into());
            }
            let mut object = widget_object(id, properties);
            object.external_id = external_id.into();
            svc.create_object(with_named_principal(
                CreateObjectRequest {
                    object: Some(object),
                },
                "root",
            ))
            .await
            .unwrap();
        }
        svc.db
            .create_object(&domain::Object {
                id: "internal-policy".into(),
                kind: action_policy::ACTION_POLICY_KIND.into(),
                name: "internal".into(),
                namespace: String::new(),
                external_id: "policy:internal".into(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        for link in [
            domain::Link {
                id: "context-visible-link".into(),
                from_id: "context-root".into(),
                to_id: "context-allowed".into(),
                relation: "contains".into(),
                created: 0,
            },
            domain::Link {
                id: "context-denied-link".into(),
                from_id: "context-root".into(),
                to_id: "context-denied".into(),
                relation: "contains".into(),
                created: 0,
            },
            domain::Link {
                id: "context-behind-denied-link".into(),
                from_id: "context-denied".into(),
                to_id: "behind-denied".into(),
                relation: "contains".into(),
                created: 0,
            },
            domain::Link {
                id: "context-governance-link".into(),
                from_id: "context-root".into(),
                to_id: "internal-policy".into(),
                relation: "contains".into(),
                created: 0,
            },
            domain::Link {
                id: "context-behind-governance-link".into(),
                from_id: "internal-policy".into(),
                to_id: "behind-governance".into(),
                relation: "contains".into(),
                created: 0,
            },
        ] {
            svc.db.create_link(&link).unwrap();
        }
        let denied_grant = security::Grant {
            id: "context-denied-grant".into(),
            object_id: "context-denied".into(),
            principal: "bob".into(),
            role: security::Role::Viewer,
            created: 0,
        };
        svc.db.create_grant(&denied_grant).unwrap();
        svc.security.add_grant(&denied_grant);

        let response = svc
            .retrieve_context(with_named_principal(
                RetrieveContextRequest {
                    roots: vec![ContextRoot {
                        external_id: "widget:context-root".into(),
                        ..Default::default()
                    }],
                    relations: vec!["contains".into()],
                    direction: "outgoing".into(),
                    max_depth: 3,
                    max_objects: 20,
                    max_links: 20,
                    kind_filter: Vec::new(),
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();

        let candidate_ids = response
            .candidates
            .iter()
            .map(|candidate| candidate.object.as_ref().unwrap().id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(candidate_ids, vec!["context-root", "context-allowed"]);
        assert_eq!(response.candidates[0].depth, 0);
        assert_eq!(
            response.candidates[0].object.as_ref().unwrap().properties["secret_note"],
            REDACTED_VALUE
        );
        assert_eq!(response.denied_objects, 2);
        assert_eq!(response.links.len(), 1);
        assert_eq!(response.links[0].id, "context-visible-link");
        assert!(!response.truncated);

        let denied_root = svc
            .retrieve_context(with_named_principal(
                RetrieveContextRequest {
                    roots: vec![ContextRoot {
                        object_id: "context-denied".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(denied_root.candidates.is_empty());
        assert_eq!(denied_root.denied_objects, 1);
    }

    #[tokio::test]
    async fn retrieve_context_rejects_ambiguous_roots() {
        let err = service()
            .retrieve_context(with_principal(RetrieveContextRequest {
                roots: vec![ContextRoot {
                    object_id: "one".into(),
                    external_id: "two".into(),
                    link_id: String::new(),
                }],
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn retrieve_context_requires_an_authenticated_principal() {
        let err = service()
            .retrieve_context(Request::new(RetrieveContextRequest {
                roots: vec![ContextRoot {
                    object_id: "one".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn credential_rpcs_manage_credentials_without_exposing_hashes() {
        let svc = service();
        let created = svc
            .create_credential(with_named_principal(
                CreateCredentialRequest {
                    principal: "agent-a".into(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(created.token.starts_with("sekai_"));
        assert_eq!(created.credential.unwrap().principal, "agent-a");

        let rotated = svc
            .rotate_credential(with_named_principal(
                RotateCredentialRequest {
                    principal: "agent-a".into(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_ne!(rotated.token, created.token);

        let listed = svc
            .list_credentials(with_named_principal(ListCredentialsRequest {}, "local"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.credentials.len(), 2);
        assert_eq!(
            listed
                .credentials
                .iter()
                .filter(|credential| credential.status == "active")
                .count(),
            1
        );

        let revoked = svc
            .revoke_credential(with_named_principal(
                RevokeCredentialRequest {
                    principal: "agent-a".into(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner()
            .credential
            .unwrap();
        assert_eq!(revoked.status, "revoked");
    }

    #[tokio::test]
    async fn credential_rpcs_require_control_plane_admin() {
        let error = service()
            .list_credentials(with_named_principal(ListCredentialsRequest {}, "tester"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn credential_rpcs_reject_privileged_principal_names() {
        for principal in ["root", "local"] {
            let error = service()
                .create_credential(with_named_principal(
                    CreateCredentialRequest {
                        principal: principal.into(),
                    },
                    "local",
                ))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn provenance_report_is_served_without_direct_database_access() {
        let response = service()
            .get_provenance_report(with_named_principal(
                GetProvenanceReportRequest {
                    work_unit_id: "work-unit-1".into(),
                },
                "local",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(response.report.contains("work-unit-1"));
    }

    async fn configured_evidence_service(with_target: bool) -> SekaiServiceImpl {
        let svc = service();
        svc.register_evidence_producer(with_named_principal(
            RegisterEvidenceProducerRequest {
                capability: Some(EvidenceProducerCapability {
                    producer_identity: "producer:checks".into(),
                    config_version: 1,
                    source_instances: vec!["checks-primary".into()],
                    namespaces: vec!["acme".into()],
                    evidence_types: vec!["verification.result".into()],
                    target_kinds: vec!["service".into()],
                    classification_ceiling: "confidential".into(),
                    allowed_intents: vec!["upsert".into(), "retract".into(), "mark_stale".into()],
                    allow_operation_attachment: false,
                    replay_window_ms: 60_000,
                    max_clock_skew_ms: 1_000,
                    max_payload_bytes: 4_096,
                    max_relationships: 8,
                    rate_limit_per_minute: 100,
                    revoked: false,
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        svc.register_evidence_schema(with_named_principal(
            RegisterEvidenceSchemaRequest {
                definition: Some(EvidenceSchemaDefinition {
                    schema_id: "verification.result".into(),
                    schema_version: "1.0.0".into(),
                    evidence_type: "verification.result".into(),
                    compatible_versions: vec![],
                }),
            },
            "local",
        ))
        .await
        .unwrap();
        if with_target {
            svc.db
                .create_object(&domain::Object {
                    id: "service-1".into(),
                    kind: "service".into(),
                    name: "payments".into(),
                    namespace: "acme".into(),
                    external_id: "service:payments".into(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                })
                .unwrap();
        }
        svc
    }

    fn proto_evidence(record: &str, sequence: i64) -> EvidenceEnvelope {
        let content = serde_json::json!({"result": "passed", "sequence": sequence});
        EvidenceEnvelope {
            contract_version: evidence_domain::EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "verification_system".into(),
            source_instance: "checks-primary".into(),
            source_record_id: record.into(),
            source_version: format!("v{sequence}"),
            source_sequence: sequence,
            namespace: "acme".into(),
            target_external_id: "service:payments".into(),
            target_kind: "service".into(),
            evidence_type: "verification.result".into(),
            signal: "verification".into(),
            schema_id: "verification.result".into(),
            schema_version: "1.0.0".into(),
            schema_compatibility: "exact".into(),
            observed_at_ms: now_millis(),
            collected_at_ms: now_millis(),
            expires_at_ms: None,
            content_json: serde_json::to_vec(&content).unwrap(),
            relationships: vec![],
            producer_identity: "producer:checks".into(),
            confidence_bps: 9_000,
            classification: "internal".into(),
            provenance: HashMap::new(),
            idempotency_key: format!("delivery-{record}-{sequence}"),
            content_digest: crate::sekai::evidence_store::canonical_content_digest(&content)
                .unwrap(),
            intent: "upsert".into(),
            causality: None,
        }
    }

    #[tokio::test]
    async fn evidence_control_plane_authenticates_and_filters_inspection() {
        let svc = configured_evidence_service(true).await;
        let submitted = svc
            .submit_evidence(with_named_principal(
                SubmitEvidenceRequest {
                    envelope: Some(proto_evidence("run-1", 1)),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(submitted.admitted);
        assert!(submitted.projected);
        let submission = submitted.submission.unwrap();
        assert_eq!(submission.lifecycle_state, "available");

        let inspected = svc
            .get_evidence_submission(with_named_principal(
                GetEvidenceSubmissionRequest {
                    submission_id: submission.id.clone(),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(inspected.lifecycle_history.last().unwrap(), "available");
        let denied = svc
            .get_evidence_submission(with_named_principal(
                GetEvidenceSubmissionRequest {
                    submission_id: submission.id,
                },
                "producer:other",
            ))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let listed = svc
            .list_evidence_submissions(with_named_principal(
                ListEvidenceSubmissionsRequest {
                    producer_identity: String::new(),
                    source_instance: "checks-primary".into(),
                    namespace: "acme".into(),
                    lifecycle_state: "available".into(),
                    target_external_id: "service:payments".into(),
                    evidence_type: "verification.result".into(),
                    limit: 10,
                    offset: 0,
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.submissions.len(), 1);
    }

    #[tokio::test]
    async fn evidence_batch_is_bounded_before_mutation() {
        let svc = configured_evidence_service(true).await;
        let error = svc
            .submit_evidence_batch(with_named_principal(
                SubmitEvidenceBatchRequest {
                    envelopes: (0..101)
                        .map(|sequence| proto_evidence("batch", sequence))
                        .collect(),
                },
                "producer:checks",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            svc.db
                .list_evidence_submissions(&EvidenceSubmissionFilter::default())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn evidence_replay_and_retraction_preserve_lifecycle_history() {
        let svc = configured_evidence_service(false).await;
        let submitted = svc
            .submit_evidence(with_named_principal(
                SubmitEvidenceRequest {
                    envelope: Some(proto_evidence("run-1", 1)),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        let submission_id = submitted.submission.unwrap().id;
        assert!(!submitted.projected);
        svc.db
            .create_object(&domain::Object {
                id: "service-1".into(),
                kind: "service".into(),
                name: "payments".into(),
                namespace: "acme".into(),
                external_id: "service:payments".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        let replayed = svc
            .replay_evidence_submission(with_named_principal(
                ReplayEvidenceSubmissionRequest {
                    submission_id: submission_id.clone(),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(replayed.projected);
        assert_eq!(replayed.submission.unwrap().lifecycle_state, "available");

        let retracted = svc
            .retract_evidence(with_named_principal(
                RetractEvidenceRequest {
                    submission_id: submission_id.clone(),
                    source_version: "v2".into(),
                    source_sequence: 2,
                    idempotency_key: "retract-run-1".into(),
                    observed_at_ms: now_millis(),
                },
                "producer:checks",
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(retracted.projected);
        assert_eq!(
            svc.db
                .get_evidence_submission(&submission_id)
                .unwrap()
                .unwrap()
                .lifecycle_state,
            evidence_domain::EvidenceLifecycleState::Retracted
        );
    }

    #[test]
    fn reserved_governance_kinds_are_exclusion_safe() {
        // Every reserved kind must be ASCII alphanumeric/underscore so the
        // static SQL exclusion covers it; a kind with special characters would
        // fail the query closed rather than silently re-opening the leak.
        for kind in RESERVED_GOVERNANCE_KINDS {
            assert!(
                !kind.is_empty() && kind.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "reserved governance kind {kind:?} is not exclusion-safe"
            );
        }
    }
}
