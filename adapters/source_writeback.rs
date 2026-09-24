//! Reusable source writeback adapter (#1085).
//!
//! Writes an approved change back to a source system of record through the
//! governed Action path, for any source the connector can address by key and
//! record version:
//!
//! 1. Chisei authorizes an external-action permit for the exact change.
//! 2. The executor verifies the permit against the trusted issuer key.
//! 3. `SubmitActionInstance` admits the Action, which materializes a pending
//!    `external_mutate` effect bound to the permit (`GetActionEffect`).
//! 4. The executor redeems the permit and applies the change through
//!    [`SourceSystem::apply`], conditioned on the record version the permit
//!    pinned. A changed record fails the write instead of overwriting it.
//! 5. Execution evidence records the outcome against the permit, and the
//!    operation receipt (`GetOperationReceipt`) carries the Action's identity.
//!
//! The executor holds the source credentials. Nothing credential-like enters
//! the Action parameters, the permit, the evidence, or object payloads; the
//! next ingest batch is how the plane learns the new record state.

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::VerifyingKey;
use sekai_chisei::chisei::external_permit::{HostContext, Permit};
use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::pb::chisei::chisei_service_server::ChiseiService;
use sekai_chisei::grpc::pb::chisei::{
    AuthorizeExternalActionRequest, ExternalActionPermit, ExternalActionRequest,
    RedeemExternalActionPermitRequest,
};
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    ActionEffect, EvidenceCausality, EvidenceEnvelope, EvidenceSchemaDefinition,
    GetActionEffectRequest, GovernedActionType, ListActionEffectsRequest,
    PutGovernedActionTypeRequest, RegisterEvidenceSchemaRequest, SubmitActionInstanceRequest,
    SubmitEvidenceRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::evidence::{
    EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceSignal,
};
use sekai_chisei::sekai::evidence_store::canonical_content_digest;
use sekai_chisei::sekai::execution_evidence::{
    EXECUTION_EVIDENCE_SCHEMA, EXECUTION_EVIDENCE_TYPE, ExecutionEvidence, ExecutionLifecycleState,
    verify_for_executor,
};
use sekai_chisei::sekai::governed_action_type::EFFECT_KIND_EXTERNAL_MUTATE;
use sha2::{Digest, Sha256};
use tonic::Request;
use tonic::metadata::MetadataValue;

/// A source system of record the executor can write to by key.
pub trait SourceSystem {
    /// Stable reference to one record, used in permits, evidence, and the
    /// Action's `source_id`. A key that does not resolve fails the writeback.
    fn resource(&self, key: &str) -> Result<String, String>;
    /// The record's current version.
    fn version(&self, key: &str) -> Result<String, String>;
    /// Applies `change` only while the record is still at
    /// `expected_version`, and returns the new version.
    fn apply(
        &self,
        key: &str,
        expected_version: &str,
        change: &BTreeMap<String, String>,
    ) -> Result<String, String>;
}

/// Identities one writeback profile runs under.
#[derive(Debug, Clone)]
pub struct WritebackProfile {
    pub namespace: String,
    pub action_type_id: String,
    pub action_type_version: String,
    /// External-action type the permit authorizes.
    pub external_action_type: String,
    pub parameter_schema: String,
    pub executor: String,
    pub harness: String,
    pub host_capability: String,
    /// Object kind the evidence targets.
    pub target_kind: String,
}

/// Trust anchors the executor verifies permits against.
pub struct PermitTrust<'a> {
    pub key: &'a VerifyingKey,
    pub issuer: &'a str,
    pub key_id: &'a str,
}

/// One requested change to one record.
#[derive(Debug, Clone)]
pub struct WritebackIntent {
    pub key: String,
    /// The record version the change was decided against.
    pub expected_version: String,
    pub change: BTreeMap<String, String>,
    pub operation_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone)]
pub struct WritebackOutcome {
    pub instance_id: String,
    pub operation_id: String,
    pub permit_id: String,
    pub effect: ActionEffect,
    pub new_version: String,
    /// The execution-evidence submission id. The source write above is
    /// committed either way, so a failed submission is reported here rather
    /// than hiding the committed version behind an error.
    pub evidence: Result<String, String>,
}

fn with_principal<T>(payload: T, principal: &str) -> Result<Request<T>, String> {
    let mut request = Request::new(payload);
    request.metadata_mut().insert(
        "x-principal",
        MetadataValue::try_from(principal).map_err(|error| error.to_string())?,
    );
    Ok(request)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Digest the permit binds: the record, the version, and the exact change.
pub fn arguments_digest(
    resource: &str,
    expected_version: &str,
    change: &BTreeMap<String, String>,
) -> String {
    let change = serde_json::to_string(change).expect("string map serializes");
    format!(
        "sha256:{:x}",
        Sha256::digest(format!("{resource}\n{expected_version}\n{change}\n").as_bytes())
    )
}

impl WritebackProfile {
    /// The governed Action type: a permit-backed `external_mutate` whose
    /// parameters are the permit, the record, and the change.
    pub fn governed_action_type(&self, created_by: &str) -> GovernedActionType {
        GovernedActionType {
            namespace: self.namespace.clone(),
            type_id: self.action_type_id.clone(),
            version: self.action_type_version.clone(),
            description: "Permit-backed source writeback".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"permit_id":{"type":"string"},"source_id":{"type":"string"},"change":{"type":"string"}},"required":["permit_id","source_id","change"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_EXTERNAL_MUTATE.into()],
            created_by: created_by.into(),
            enabled: true,
            ..Default::default()
        }
    }

    /// Registers the execution-evidence schema and the Action type.
    pub async fn bootstrap(&self, sekai: &SekaiServiceImpl, operator: &str) -> Result<(), String> {
        sekai
            .register_evidence_schema(with_principal(
                RegisterEvidenceSchemaRequest {
                    definition: Some(EvidenceSchemaDefinition {
                        schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
                        schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
                        evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
                        compatible_versions: vec![],
                    }),
                },
                operator,
            )?)
            .await
            .map_err(|error| error.message().to_string())?;
        sekai
            .put_governed_action_type(with_principal(
                PutGovernedActionTypeRequest {
                    r#type: Some(self.governed_action_type(operator)),
                    request_id: format!("put-{}", self.action_type_id),
                },
                operator,
            )?)
            .await
            .map_err(|error| error.message().to_string())?;
        Ok(())
    }

    /// The external-action authorization request for one intent.
    pub fn authorize_request(
        &self,
        actor: &str,
        resource: &str,
        intent: &WritebackIntent,
    ) -> AuthorizeExternalActionRequest {
        AuthorizeExternalActionRequest {
            request: Some(ExternalActionRequest {
                version: "external-action.request/v1".into(),
                operation_id: intent.operation_id.clone(),
                parent_operation_id: String::new(),
                attempt_id: format!("{}-attempt", intent.operation_id),
                request_id: format!("{}-request", intent.operation_id),
                actor: actor.into(),
                namespace: self.namespace.clone(),
                requesting_harness: self.harness.clone(),
                intended_executor: self.executor.clone(),
                action_type: self.external_action_type.clone(),
                parameter_schema: self.parameter_schema.clone(),
                canonical_arguments_digest: arguments_digest(
                    resource,
                    &intent.expected_version,
                    &intent.change,
                ),
                policy_summary: HashMap::new(),
                target_selectors: vec![format!("project:{}/{resource}", self.namespace)],
                immutable_preconditions: HashMap::from([(
                    "record_version".into(),
                    intent.expected_version.clone(),
                )]),
                risk_class: "write".into(),
                expected_effects: vec!["record_updated".into()],
                requested_invocation_count: 1,
                deadline_ms: now_ms() + 3_600_000,
                estimated_cost_micros: 0,
                estimated_volume: 1,
                affected_resource_count: 1,
                rollback_capability: "restore_record_version".into(),
                required_host_capabilities: vec![self.host_capability.clone()],
                idempotency_key: intent.idempotency_key.clone(),
                policy_project: self.namespace.clone(),
            }),
            offline: false,
        }
    }

    /// Runs one writeback end to end. `actor` requests the change; the
    /// profile's executor verifies, redeems, and applies it.
    pub async fn run(
        &self,
        sekai: &SekaiServiceImpl,
        chisei: &ChiseiServiceImpl,
        system: &dyn SourceSystem,
        actor: &str,
        trust: &PermitTrust<'_>,
        intent: &WritebackIntent,
    ) -> Result<WritebackOutcome, String> {
        let resource = system.resource(&intent.key)?;
        // A decision taken against an older record fails before a permit is
        // issued; the conditional write below still guards the race.
        if system.version(&intent.key)? != intent.expected_version {
            return Err("record version changed since the writeback was decided".into());
        }
        let authorized = chisei
            .authorize_external_action(with_principal(
                self.authorize_request(actor, &resource, intent),
                actor,
            )?)
            .await
            .map_err(|error| error.message().to_string())?
            .into_inner();
        let permit_proto = authorized
            .permit
            .ok_or("the writeback was not authorized")?;
        let permit = permit_from_proto(permit_proto.clone());
        // What the executor is about to do and observes right now, computed
        // independently of the permit, so verification and redemption compare
        // the authorized change against the one actually applied.
        let observe = |system: &dyn SourceSystem| -> Result<HostContext, String> {
            Ok(HostContext {
                executor: self.executor.clone(),
                requesting_harness: self.harness.clone(),
                canonical_arguments_digest: arguments_digest(
                    &resource,
                    &intent.expected_version,
                    &intent.change,
                ),
                target_selectors: vec![format!("project:{}/{resource}", self.namespace)],
                observed_preconditions: BTreeMap::from([(
                    "record_version".into(),
                    system.version(&intent.key)?,
                )]),
                host_capabilities: vec![self.host_capability.clone()],
            })
        };
        let host = observe(system)?;
        verify_for_executor(
            &permit,
            trust.key,
            trust.issuer,
            trust.key_id,
            &host,
            now_ms(),
        )?;

        let change_json =
            serde_json::to_string(&intent.change).map_err(|error| error.to_string())?;
        let instance = sekai
            .submit_action_instance(with_principal(
                SubmitActionInstanceRequest {
                    namespace: self.namespace.clone(),
                    type_id: self.action_type_id.clone(),
                    version: self.action_type_version.clone(),
                    parameters_json: serde_json::json!({
                        "permit_id": permit.permit_id,
                        "source_id": resource,
                        "change": change_json,
                    })
                    .to_string(),
                    idempotency_key: intent.idempotency_key.clone(),
                    evidence_submission_ids: vec![],
                    request_id: permit.operation_id.clone(),
                    ontology_digest: String::new(),
                },
                actor,
            )?)
            .await
            .map_err(|error| error.message().to_string())?
            .into_inner()
            .instance
            .ok_or("SubmitActionInstance returned no instance")?;
        if instance.status != "admitted" {
            return Err(format!("writeback Action was {}", instance.status));
        }
        let listed = sekai
            .list_action_effects(with_principal(
                ListActionEffectsRequest {
                    instance_id: instance.instance_id.clone(),
                    namespace: String::new(),
                    kind: EFFECT_KIND_EXTERNAL_MUTATE.into(),
                    status: String::new(),
                    limit: 8,
                },
                actor,
            )?)
            .await
            .map_err(|error| error.message().to_string())?
            .into_inner()
            .effects;
        let effect_id = listed
            .into_iter()
            .find(|effect| effect.kind == EFFECT_KIND_EXTERNAL_MUTATE)
            .map(|effect| effect.effect_id)
            .ok_or("the Action did not materialize an external_mutate effect")?;
        let effect = sekai
            .get_action_effect(with_principal(GetActionEffectRequest { effect_id }, actor)?)
            .await
            .map_err(|error| error.message().to_string())?
            .into_inner()
            .effect
            .ok_or("GetActionEffect returned no effect")?;
        if effect.status != "pending" {
            return Err(format!("writeback effect is {}", effect.status));
        }

        // Re-observed at redemption: a record that moved since authorization
        // no longer matches the permit's preconditions.
        let redeeming = observe(system)?;
        let redemption = chisei
            .redeem_external_action_permit(with_principal(
                RedeemExternalActionPermitRequest {
                    permit: Some(permit_proto),
                    executor: self.executor.clone(),
                    requesting_harness: self.harness.clone(),
                    canonical_arguments_digest: redeeming.canonical_arguments_digest,
                    target_selectors: redeeming.target_selectors,
                    observed_preconditions: redeeming.observed_preconditions.into_iter().collect(),
                    host_capabilities: redeeming.host_capabilities,
                    idempotency_key: format!("{}-redeem", intent.idempotency_key),
                    execution_id: format!("{}-exec", intent.operation_id),
                    invoked_at_ms: 0,
                },
                &self.executor,
            )?)
            .await
            .map_err(|error| error.message().to_string())?
            .into_inner()
            .redemption
            .ok_or("permit redemption returned no record")?;

        let applied = system.apply(&intent.key, &intent.expected_version, &intent.change);
        let (state, new_version) = match &applied {
            Ok(version) => (ExecutionLifecycleState::Completed, version.clone()),
            Err(_) => (ExecutionLifecycleState::Failed, String::new()),
        };
        let evidence = self
            .submit_evidence(
                sekai,
                &permit,
                &resource,
                &redemption.redemption_id,
                &format!("{}-exec", intent.operation_id),
                state,
                now_ms().max(redemption.redeemed_at_ms),
            )
            .await;
        if let Err(error) = applied {
            return Err(match evidence {
                Ok(_) => error,
                Err(evidence_error) => {
                    format!("{error}; execution evidence was not recorded: {evidence_error}")
                }
            });
        }
        Ok(WritebackOutcome {
            instance_id: instance.instance_id,
            operation_id: instance.operation_id,
            permit_id: permit.permit_id,
            effect,
            new_version,
            evidence,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn submit_evidence(
        &self,
        sekai: &SekaiServiceImpl,
        permit: &Permit,
        resource: &str,
        redemption_id: &str,
        execution_id: &str,
        state: ExecutionLifecycleState,
        observed_at_ms: i64,
    ) -> Result<String, String> {
        let report = ExecutionEvidence {
            version: EXECUTION_EVIDENCE_SCHEMA.into(),
            permit_id: permit.permit_id.clone(),
            redemption_id: redemption_id.into(),
            execution_id: execution_id.into(),
            host_identity: self.executor.clone(),
            lifecycle_state: state,
            observed_at_ms,
            started_at_ms: Some(observed_at_ms),
            finished_at_ms: state.is_terminal().then_some(observed_at_ms),
            enforced_preconditions: permit.immutable_preconditions.clone(),
            normalized_effects: vec!["record_updated".into()],
            affected_resource_references: vec![resource.into()],
            cost_micros: 0,
            resource_use: BTreeMap::new(),
            artifact_hashes: vec![],
            exit_classification: String::new(),
            error_classification: String::new(),
            compensation_evidence_hashes: vec![],
            host_schema_version: "host-evidence/v1".into(),
            host_software_version: "source-writeback/1.0".into(),
        };
        let content = serde_json::to_value(&report).map_err(|error| error.to_string())?;
        let envelope = EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "host_executor".into(),
            source_instance: format!("{}:writeback", self.executor),
            source_record_id: redemption_id.into(),
            source_version: format!("state-{}", state.as_str()),
            source_sequence: 1,
            namespace: self.namespace.clone(),
            target_external_id: resource.into(),
            target_kind: self.target_kind.clone(),
            evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
            signal: EvidenceSignal::Delivery.as_str().into(),
            schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
            schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
            schema_compatibility: "exact".into(),
            observed_at_ms,
            collected_at_ms: observed_at_ms,
            expires_at_ms: None,
            content_json: serde_json::to_vec(&content).map_err(|error| error.to_string())?,
            relationships: vec![],
            producer_identity: self.executor.clone(),
            confidence_bps: 8_000,
            classification: EvidenceClassification::Internal.as_str().into(),
            provenance: HashMap::new(),
            idempotency_key: format!("{redemption_id}-{}", state.as_str()),
            content_digest: canonical_content_digest(&content)?,
            intent: "upsert".into(),
            causality: Some(EvidenceCausality {
                operation_id: permit.operation_id.clone(),
                parent_operation_id: String::new(),
                attempt_id: String::new(),
                model_call_id: String::new(),
                subject_references: vec![resource.into()],
                trace_context: HashMap::new(),
            }),
        };
        let result = sekai
            .submit_evidence(with_principal(
                SubmitEvidenceRequest {
                    envelope: Some(envelope),
                },
                &self.executor,
            )?)
            .await
            .map_err(|error| error.message().to_string())?
            .into_inner()
            .result
            .ok_or("SubmitEvidence returned no result")?;
        if !result.admitted {
            return Err("execution evidence was not admitted".into());
        }
        Ok(result
            .submission
            .map(|submission| submission.id)
            .unwrap_or_default())
    }
}

fn permit_from_proto(value: ExternalActionPermit) -> Permit {
    Permit {
        version: value.version,
        permit_id: value.permit_id,
        authorization_id: value.authorization_id,
        request_digest: value.request_digest,
        issuer: value.issuer,
        subject_actor: value.subject_actor,
        namespace: value.namespace,
        operation_id: value.operation_id,
        requesting_harness: value.requesting_harness,
        executor: value.executor,
        action_type: value.action_type,
        parameter_schema: value.parameter_schema,
        canonical_arguments_digest: value.canonical_arguments_digest,
        target_selectors: value.target_selectors,
        immutable_preconditions: value.immutable_preconditions.into_iter().collect(),
        allowed_effects: value.allowed_effects,
        required_host_capabilities: value.required_host_capabilities,
        parent_chain: value.parent_chain,
        initiating_actor: value.initiating_actor,
        offline_revocation_unavailable: value.offline_revocation_unavailable,
        policy_scope: value.policy_scope,
        constraints: value.constraints,
        risk_class: value.risk_class,
        budget_micros: value.budget_micros,
        volume_limit: value.volume_limit,
        blast_radius_limit: value.blast_radius_limit,
        max_invocations: value.max_invocations,
        not_before_ms: value.not_before_ms,
        expires_at_ms: value.expires_at_ms,
        redemption_mode: value.redemption_mode,
        approval_identities: value.approval_identities,
        policy_version: value.policy_version,
        schema_version: value.schema_version,
        capability_version: value.capability_version,
        pricing_version: value.pricing_version,
        nonce: value.nonce,
        delegation_depth: value.delegation_depth,
        parent_permit_id: value.parent_permit_id,
        revocation_handle: value.revocation_handle,
        signature_algorithm: value.signature_algorithm,
        key_id: value.key_id,
        public_key: value.public_key,
        issued_at_ms: value.issued_at_ms,
        revocation_latency_ms: value.revocation_latency_ms,
        site_id: if value.site_id.trim().is_empty() {
            "local".into()
        } else {
            value.site_id
        },
        signed_digest: value.signed_digest,
        signature: value.signature,
    }
}
