//! Governed Subject evaluation and situation-specific provenance lifecycle.

use super::*;

pub(super) struct ProvenanceExportOutcome {
    pub record: subject_provenance::ExportRecord,
    pub replayed: bool,
}

pub(super) struct GovernedSubjectLifecycle {
    db: Arc<RuntimeDb>,
    config: Config,
}

impl GovernedSubjectLifecycle {
    pub(super) fn new(db: Arc<RuntimeDb>, config: Config) -> Self {
        Self { db, config }
    }

    pub(super) fn evaluate(
        &self,
        actor: &str,
        envelope: subject::GovernedSubjectEnvelope,
        now_ms: i64,
    ) -> Result<subject::GovernedSubjectResult, Status> {
        require_namespace_write_access(&self.db, actor, &envelope.namespace)?;
        let fresh = subject::validate_envelope(&envelope, actor, now_ms)
            .map_err(Status::invalid_argument)?;
        if !matches!(actor, "root" | "local") {
            return Err(Status::permission_denied(
                "governed-subject conformance evaluation requires control-plane administration",
            ));
        }
        let binding_digest = subject::binding_digest(&envelope, actor);
        let operation_id = subject::operation_id(&envelope.namespace, actor, &envelope.request_id);
        if let Some(existing) = self
            .db
            .get_operation_receipt(&operation_id)
            .map_err(Status::internal)?
        {
            require_receipt_binding(&existing, &binding_digest)?;
            return result_from_receipt(&existing);
        }

        let receipt = build_receipt(
            envelope,
            actor,
            operation_id.clone(),
            binding_digest,
            fresh,
            now_ms,
        );
        if let Err(error) = self.db.insert_operation_receipt(&receipt) {
            if let Some(existing) = self
                .db
                .get_operation_receipt(&operation_id)
                .map_err(Status::internal)?
            {
                require_receipt_binding(
                    &existing,
                    receipt.events[0]
                        .attributes
                        .get("binding_digest")
                        .expect("receipt builder binds intent"),
                )?;
                return result_from_receipt(&existing);
            }
            return Err(Status::aborted(format!(
                "governed-subject receipt could not be committed: {error}"
            )));
        }
        result_from_receipt(&receipt)
    }

    pub(super) fn export_provenance(
        &self,
        binding: subject_provenance::ExportRequestBinding,
        now_ms: i64,
    ) -> Result<ProvenanceExportOutcome, Status> {
        let binding_digest =
            subject_provenance::binding_digest(&binding).map_err(Status::invalid_argument)?;
        if let Some(existing) = self
            .db
            .get_governed_subject_provenance_export(&binding.actor, &binding.export_id)
            .map_err(Status::internal)?
        {
            if existing.binding_digest != binding_digest {
                return Err(Status::already_exists(
                    "export_id is already bound to different governed-subject evidence",
                ));
            }
            require_namespace_access(&self.db, &binding.actor, &existing.namespace)?;
            validate_export_record(&existing, now_ms)?;
            return Ok(ProvenanceExportOutcome {
                record: existing,
                replayed: true,
            });
        }

        let receipt = self
            .db
            .get_operation_receipt(&binding.operation_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("governed-subject receipt not found"))?;
        require_namespace_write_access(&self.db, &binding.actor, &receipt.namespace)?;
        let (namespace, content_digest) = reconcile_receipt(&receipt, &binding, now_ms)?;
        let key_hex = self
            .config
            .governed_subject_provenance_signing_key
            .as_deref()
            .ok_or_else(|| {
                Status::failed_precondition("governed-subject provenance signing is not configured")
            })?;
        let signing_key = subject_provenance::signing_key_from_hex(key_hex)
            .map_err(Status::failed_precondition)?;
        if now_ms < self.config.governed_subject_provenance_key_not_before_ms
            || now_ms >= self.config.governed_subject_provenance_key_expires_at_ms
        {
            return Err(Status::failed_precondition(
                "governed-subject provenance signing key is not active",
            ));
        }
        let ttl_ms = self.config.governed_subject_provenance_ttl_ms;
        if ttl_ms <= 0 || ttl_ms > subject_provenance::MAX_ENVELOPE_TTL_MS {
            return Err(Status::failed_precondition(
                "governed-subject provenance TTL is invalid",
            ));
        }
        let expires_at_ms = now_ms
            .checked_add(ttl_ms)
            .unwrap_or(i64::MAX)
            .min(self.config.governed_subject_provenance_key_expires_at_ms);
        if expires_at_ms <= now_ms {
            return Err(Status::failed_precondition(
                "governed-subject provenance signing key expires too soon",
            ));
        }
        let envelope = subject_provenance::ProvenanceEnvelope::issue(
            &signing_key,
            binding.expected_subject_identity.clone(),
            content_digest,
            binding.expected_receipt_digest.clone(),
            binding.operation_id.clone(),
            now_ms,
            expires_at_ms,
        )
        .map_err(Status::internal)?;
        envelope
            .verify(&signing_key.verifying_key().to_bytes(), now_ms)
            .map_err(Status::internal)?;
        let record = subject_provenance::ExportRecord {
            binding_digest,
            namespace,
            envelope,
            public_key: base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().to_bytes()),
            created_at_ms: now_ms,
        };
        let (stored, inserted) = self
            .db
            .put_governed_subject_provenance_export(&binding.actor, &binding.export_id, &record)
            .map_err(map_export_persistence_error)?;
        validate_export_record(&stored, now_ms)?;
        Ok(ProvenanceExportOutcome {
            record: stored,
            replayed: !inserted,
        })
    }
}

fn require_receipt_binding(receipt: &OperationReceipt, binding_digest: &str) -> Result<(), Status> {
    let existing = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .and_then(|event| event.attributes.get("binding_digest"));
    if existing == Some(&binding_digest.to_string()) {
        Ok(())
    } else {
        Err(Status::already_exists(
            "request_id is already bound to different governed-subject evidence",
        ))
    }
}

fn build_receipt(
    envelope: subject::GovernedSubjectEnvelope,
    actor: &str,
    operation_id: String,
    binding_digest: String,
    fresh: bool,
    now_ms: i64,
) -> OperationReceipt {
    let (decision, failure_code) = subject::evaluation(&envelope.evaluation_profile, fresh);
    let references = envelope
        .references
        .iter()
        .map(|reference| GovernedReference {
            kind: reference.kind.clone(),
            reference: reference.reference.clone(),
            content_hash: Some(reference.content_digest.clone()),
            disclosed_fields: Vec::new(),
            omitted: true,
            omission_reason: Some("subject payload remains externally owned".into()),
        })
        .collect::<Vec<_>>();
    let event = |suffix: &str,
                 parent: Option<&str>,
                 kind: ReceiptEventKind,
                 attributes: BTreeMap<String, String>,
                 references: Vec<GovernedReference>| OperationReceiptEvent {
        event_id: format!("{operation_id}:{suffix}"),
        operation_id: operation_id.clone(),
        parent_event_id: parent.map(|value| format!("{operation_id}:{value}")),
        timestamp_ms: now_ms,
        kind,
        surface: kind.surface(),
        actor: actor.into(),
        references,
        attributes,
    };
    let mut intent = BTreeMap::from([
        ("request_id".into(), operation_id.clone()),
        ("lookup_request_id".into(), envelope.request_id.clone()),
        (
            "caller_scope".into(),
            subject::caller_scope(&envelope.namespace, actor),
        ),
        ("binding_digest".into(), binding_digest),
        ("subject_profile".into(), envelope.subject_profile.clone()),
        ("subject_identity".into(), envelope.subject_identity.clone()),
        ("content_digest".into(), envelope.content_digest.clone()),
        (
            "evaluation_profile".into(),
            envelope.evaluation_profile.clone(),
        ),
        (
            "reference_count".into(),
            envelope.references.len().to_string(),
        ),
    ]);
    for reference in &envelope.references {
        intent.insert(
            format!("reference_observed_at_ms.{}", reference.kind),
            reference.observed_at_ms.to_string(),
        );
    }
    let mut outcome = BTreeMap::from([
        ("decision".into(), decision.into()),
        ("fresh".into(), fresh.to_string()),
    ]);
    if let Some(code) = failure_code {
        outcome.insert("failure_code".into(), code.into());
        outcome.insert(
            "failure_message".into(),
            match code {
                "stale_evidence" => "governed evidence is stale",
                "evaluation_unavailable" => "governed evaluation is unavailable",
                "evaluation_timeout" => "governed evaluation timed out",
                _ => "governed evaluation failed",
            }
            .into(),
        );
    }
    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.clone(),
        parent_operation_id: None,
        namespace: envelope.namespace,
        operation_class: "governed_subject_evaluation".into(),
        initiating_actor: actor.into(),
        schema_version: subject::RECEIPT_SCHEMA_VERSION.into(),
        policy_version: envelope.evaluation_profile,
        started_at_ms: now_ms,
        completed_at_ms: Some(now_ms),
        events: vec![
            event(
                "intent",
                None,
                ReceiptEventKind::IntentRecorded,
                intent,
                references,
            ),
            event(
                "policy",
                Some("intent"),
                ReceiptEventKind::PolicyDecided,
                BTreeMap::from([
                    ("decision".into(), decision.into()),
                    (
                        "profile_registry".into(),
                        "chisei.governed-subject-registry/v1".into(),
                    ),
                ]),
                Vec::new(),
            ),
            event(
                "route",
                Some("policy"),
                ReceiptEventKind::RouteSelected,
                BTreeMap::from([("route".into(), "registered_profile".into())]),
                Vec::new(),
            ),
            event(
                "budget",
                Some("route"),
                ReceiptEventKind::BudgetDecided,
                BTreeMap::from([("budget_effect".into(), "none".into())]),
                Vec::new(),
            ),
            event(
                "outcome",
                Some("budget"),
                ReceiptEventKind::OutcomeRecorded,
                outcome,
                Vec::new(),
            ),
        ],
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    }
}

pub(super) fn result_from_receipt(
    receipt: &OperationReceipt,
) -> Result<subject::GovernedSubjectResult, Status> {
    let intent = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .ok_or_else(|| Status::internal("governed-subject receipt has no intent"))?;
    let outcome = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        .ok_or_else(|| Status::internal("governed-subject receipt has no outcome"))?;
    let references = intent
        .references
        .iter()
        .map(|reference| {
            let observed_at_ms = intent
                .attributes
                .get(&format!("reference_observed_at_ms.{}", reference.kind))
                .ok_or_else(|| Status::internal("governed-subject receipt lost evidence time"))?
                .parse()
                .map_err(|_| {
                    Status::internal("governed-subject receipt has invalid evidence time")
                })?;
            Ok(subject::GovernedSubjectReference {
                kind: reference.kind.clone(),
                reference: reference.reference.clone(),
                content_digest: reference.content_hash.clone().unwrap_or_default(),
                observed_at_ms,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let bytes = serde_json::to_vec(receipt).map_err(|error| Status::internal(error.to_string()))?;
    Ok(subject::GovernedSubjectResult {
        version: subject::RESULT_VERSION.into(),
        decision: outcome
            .attributes
            .get("decision")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        operation_id: receipt.operation_id.clone(),
        receipt_schema: receipt.schema_version.clone(),
        receipt_digest: format!("sha256:{:x}", sha2::Sha256::digest(bytes)),
        references,
        fresh: outcome
            .attributes
            .get("fresh")
            .is_some_and(|value| value == "true"),
        failure_code: outcome.attributes.get("failure_code").cloned(),
        failure_message: outcome.attributes.get("failure_message").cloned(),
    })
}

fn reconcile_receipt(
    receipt: &OperationReceipt,
    binding: &subject_provenance::ExportRequestBinding,
    now_ms: i64,
) -> Result<(String, String), Status> {
    if receipt.operation_id != binding.operation_id
        || receipt.operation_class != "governed_subject_evaluation"
        || receipt.schema_version != subject::RECEIPT_SCHEMA_VERSION
        || receipt.completed_at_ms.is_none()
    {
        return Err(Status::failed_precondition(
            "operation is not a complete governed-subject receipt",
        ));
    }
    let result = result_from_receipt(receipt).map_err(|_| {
        Status::data_loss("governed-subject receipt is incomplete or internally inconsistent")
    })?;
    if result.decision != "allow" || !result.fresh {
        return Err(Status::failed_precondition(
            "governed-subject receipt is not an authoritative allow",
        ));
    }
    let bytes = serde_json::to_vec(receipt)
        .map_err(|_| Status::data_loss("governed-subject receipt cannot be reconciled"))?;
    if format!("sha256:{:x}", sha2::Sha256::digest(bytes)) != binding.expected_receipt_digest {
        return Err(Status::failed_precondition(
            "governed-subject receipt digest does not match the requested export",
        ));
    }
    let intent = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .ok_or_else(|| Status::data_loss("governed-subject receipt intent is missing"))?;
    if intent.attributes.get("subject_identity") != Some(&binding.expected_subject_identity)
        || intent.attributes.get("content_digest") != Some(&binding.expected_subject_content_digest)
        || intent.attributes.get("subject_profile").map(String::as_str)
            != Some(subject::SOFTWARE_RELEASE_PROFILE)
    {
        return Err(Status::failed_precondition(
            "governed-subject identity does not match the requested software release",
        ));
    }
    let reference = |kind: &str| {
        intent
            .references
            .iter()
            .find(|reference| reference.kind == kind)
            .ok_or_else(|| {
                Status::data_loss("governed-subject receipt lacks required release evidence")
            })
    };
    if reference("manifest")?.content_hash.as_deref() != Some(&binding.expected_manifest_digest)
        || reference("artifact")?.content_hash.as_deref() != Some(&binding.expected_artifact_digest)
    {
        return Err(Status::failed_precondition(
            "governed-subject release evidence does not match the requested export",
        ));
    }
    if result.references.iter().any(|reference| {
        reference.observed_at_ms <= 0
            || reference.observed_at_ms > now_ms
            || now_ms - reference.observed_at_ms > subject::MAX_EVIDENCE_AGE_MS
    }) {
        return Err(Status::failed_precondition(
            "governed-subject release evidence is stale",
        ));
    }
    let content_digest = subject_provenance::release_content_digest(
        &binding.expected_manifest_digest,
        &binding.expected_artifact_digest,
    )
    .map_err(Status::invalid_argument)?;
    Ok((receipt.namespace.clone(), content_digest))
}

fn validate_export_record(
    record: &subject_provenance::ExportRecord,
    now_ms: i64,
) -> Result<(), Status> {
    record
        .envelope
        .validate(now_ms)
        .map_err(Status::failed_precondition)
}

fn map_export_persistence_error(error: String) -> Status {
    if error.contains("already bound") {
        Status::already_exists("export_id is already bound to different governed-subject evidence")
    } else {
        tracing::warn!(error = %error, "governed-subject provenance export persistence failed");
        Status::aborted("governed-subject provenance export could not be committed")
    }
}
