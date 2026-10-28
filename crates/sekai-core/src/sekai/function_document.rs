//! LLM functions over a governed document rendition (#1326).
//!
//! Reference-platform analog: AIP Document Intelligence / Functions on objects bind
//! extracted text from a media reference (they do not re-OCR in the function).
//! Lineage is the media reference (document id + item digest). AIP Logic
//! Ontology edits apply automatically or are staged for human review via an
//! Action. Sekai binds an existing `extracted_text` rendition, checks the
//! caller-held text against the pinned digest (the plane stores no bytes),
//! stamps `derived_from` lineage, and resolves the namespace action policy for
//! every extraction: `deny` refuses, `require_approval` parks the Action at any
//! confidence unless a live auto-apply grant admits it, and `allow` writes
//! only at or above the function threshold (a threshold of 0 writes every
//! `allow` extraction). A write also passes the caller's object-write
//! authorization.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{Link, Object, REL_DERIVED_FROM, is_valid_property_key};
use crate::sekai::action::RiskClass;
use crate::sekai::action_instance::{
    ActionInstance, STATUS_ADMITTED, STATUS_PARKED, SUBMIT_POLICY_ACTION,
};
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use crate::sekai::action_policy::ActionDecision;
use crate::sekai::agent_autonomy;
use crate::sekai::document::{
    CONTENT_SCHEME_DIGEST, DOCUMENT_UNAVAILABLE, DocumentRetrieve, FIELD_CONTENT_REF,
    FIELD_METADATA, FIELD_RENDITIONS, RENDITION_EXTRACTED_TEXT, content_digest_for, is_expired,
    retrieve_document,
};
use crate::sekai::function::{
    Function, FunctionBudget, FunctionHost, FunctionInvocation, LLM_FUNCTION_REQUIRES_GATE,
    LlmStepHost, PipelineStep, invoke_with_llm, validate_function,
};
use crate::sekai::governed_action_type::{GovernedActionType, OBJECT_MUTATION_CREATE};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
use crate::sekai::object_security::PrincipalPolicyContext;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const EXTRACTED_TEXT_PARAM: &str = "extracted_text";
pub const LINEAGE_DOCUMENT_ID: &str = "lineage_document_id";
pub const LINEAGE_PARENT_CONTENT_DIGEST: &str = "lineage_parent_content_digest";
pub const LINEAGE_RENDITION_DIGEST: &str = "lineage_rendition_digest";
pub const DOCUMENT_OBJECT_KIND: &str = "document";
pub const CONFIDENCE_FIELD: &str = "confidence_micros";

/// Graph object id for a governed document's lineage stub.
pub fn document_lineage_object_id(namespace: &str, document_id: &str) -> String {
    format!("document:{namespace}:{document_id}")
}

#[derive(Debug, Clone)]
pub struct FunctionDocumentAction {
    pub type_id: String,
    pub version: String,
    pub ontology_digest: String,
    pub request_id: String,
    pub idempotency_key: String,
}

pub struct FunctionDocumentExtractRequest<'a> {
    pub db: &'a RuntimeDb,
    pub function: &'a Function,
    pub actor: &'a str,
    pub namespace: &'a str,
    pub document_id: &'a str,
    pub purpose: &'a str,
    pub extracted_text: &'a str,
    pub llm_host: &'a dyn LlmStepHost,
    pub host: FunctionHost,
    pub budget: FunctionBudget,
    pub now_ms: i64,
    pub object_kind: &'a str,
    pub action: FunctionDocumentAction,
    /// The caller's CreateObject authorization for the extracted object. Runs before a
    /// direct write; a parked extraction is authorized when its Action is granted.
    pub authorize_write: &'a dyn Fn(&Object) -> Result<(), String>,
}

#[derive(Debug, Clone)]
pub enum FunctionDocumentExtract {
    Written {
        object: Object,
        invocation: FunctionInvocation,
    },
    Parked {
        instance: Box<ActionInstance>,
        invocation: FunctionInvocation,
    },
}

/// Invoke an LLM function over a digest-checked `extracted_text` rendition.
pub fn extract_from_rendition(
    request: FunctionDocumentExtractRequest<'_>,
) -> Result<FunctionDocumentExtract, String> {
    let FunctionDocumentExtractRequest {
        db,
        function,
        actor,
        namespace,
        document_id,
        purpose,
        extracted_text,
        llm_host,
        host,
        budget,
        now_ms,
        object_kind,
        action,
        authorize_write,
    } = request;
    validate_function(function)?;
    let llm = llm_step(function)?;
    if !db.function_gate_approved(function)? {
        return Err(LLM_FUNCTION_REQUIRES_GATE.into());
    }
    if object_kind.trim().is_empty() {
        return Err("function document extract requires object_kind".into());
    }
    let view = retrieve_document(
        db,
        actor,
        &DocumentRetrieve {
            namespace: namespace.into(),
            document_id: document_id.into(),
            purpose: Some(purpose.into()),
            fields: vec![
                FIELD_CONTENT_REF.into(),
                FIELD_METADATA.into(),
                FIELD_RENDITIONS.into(),
            ],
            classification_ceiling: None,
        },
        now_ms,
    )?;
    let parent_content_digest = content_digest_for(
        view.content_ref
            .as_ref()
            .ok_or_else(|| DOCUMENT_UNAVAILABLE.to_string())?,
    )?;
    let classification = view
        .classification
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "function document extract requires document classification".to_string())?;
    let text_digest = digest_bytes(extracted_text.as_bytes());
    let rendition = view
        .renditions
        .as_ref()
        .and_then(|items| {
            items.iter().find(|item| {
                item.class == RENDITION_EXTRACTED_TEXT
                    && item.content_ref.scheme == CONTENT_SCHEME_DIGEST
                    && item.content_ref.digest == text_digest
            })
        })
        .ok_or_else(|| "extracted_text does not match the rendition digest".to_string())?;
    if rendition.parent_content_digest != parent_content_digest {
        return Err("extracted_text rendition parent digest does not match the document".into());
    }
    let params = HashMap::from([(EXTRACTED_TEXT_PARAM.into(), extracted_text.to_string())]);
    let invocation = invoke_with_llm(db, function, &params, |_| Ok(true), host, budget, llm_host)?;
    if !invocation.receipt.schema_error.is_empty() {
        return Err(format!(
            "function document extract schema: {}",
            invocation.receipt.schema_error
        ));
    }
    let structured = invocation
        .result
        .structured
        .as_ref()
        .ok_or_else(|| "function document extract produced no structured output".to_string())?;
    let object_id = structured
        .get("id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "function document extract output requires id".to_string())?;
    let confidence = structured
        .get(CONFIDENCE_FIELD)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| "function document extract output requires confidence_micros".to_string())?;
    if confidence > 1_000_000 {
        return Err("function document extract confidence_micros must be at most 1000000".into());
    }
    let mut properties = object_properties(structured)?;
    properties.insert(CONFIDENCE_FIELD.into(), confidence.to_string());
    properties.insert(OBJECT_CLASSIFICATION_PROPERTY.into(), classification.into());
    properties.insert(LINEAGE_DOCUMENT_ID.into(), document_id.into());
    properties.insert(
        LINEAGE_PARENT_CONTENT_DIGEST.into(),
        parent_content_digest.clone(),
    );
    properties.insert(
        LINEAGE_RENDITION_DIGEST.into(),
        rendition.content_ref.digest.clone(),
    );
    let object = Object {
        id: object_id.into(),
        kind: object_kind.into(),
        name: structured
            .get("name")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .unwrap_or(object_id)
            .into(),
        namespace: namespace.into(),
        external_id: String::new(),
        properties,
        created: now_ms,
        updated: now_ms,
    };
    let (type_def, decision) = extraction_policy(db, actor, namespace, &action)?;
    let agent = agent_autonomy::actor_is_agent(db, actor);
    match decision {
        ActionDecision::Deny => {
            return Err("function document extract denied by action policy".into());
        }
        ActionDecision::Allow if (confidence as u32) < llm.minimum_confidence_micros => {
            return Err(
                "function document extract below the confidence threshold requires require_approval"
                    .into(),
            );
        }
        ActionDecision::Allow if !agent => authorize_write(&object)?,
        ActionDecision::RequireApproval if !agent => {
            let instance =
                park_extraction(db, actor, namespace, now_ms, &type_def, &action, &object)?;
            return Ok(FunctionDocumentExtract::Parked {
                instance: Box::new(instance),
                invocation,
            });
        }
        _ => {
            // Authorize before admission so a grant that lands on this call
            // cannot write without the caller's object-write check.
            authorize_write(&object)?;
            let instance =
                park_extraction(db, actor, namespace, now_ms, &type_def, &action, &object)?;
            if instance.status == STATUS_ADMITTED {
                let written = db
                    .get_object(&object.id)
                    .map_err(|error| format!("function document extract auto-apply: {error}"))?
                    .ok_or_else(|| {
                        "function document extract auto-apply wrote no object".to_string()
                    })?;
                return Ok(FunctionDocumentExtract::Written {
                    object: written,
                    invocation,
                });
            }
            return Ok(FunctionDocumentExtract::Parked {
                instance: Box::new(instance),
                invocation,
            });
        }
    }
    persist_extracted_object(
        db,
        actor,
        &object,
        document_id,
        &parent_content_digest,
        classification,
        now_ms,
    )?;
    Ok(FunctionDocumentExtract::Written { object, invocation })
}

fn llm_step(function: &Function) -> Result<&crate::sekai::function::LlmStep, String> {
    if function
        .pipeline
        .iter()
        .any(|step| matches!(step, PipelineStep::Operator(_)))
    {
        return Err("function document extract requires an llm-only pipeline".into());
    }
    let llm = function
        .pipeline
        .iter()
        .find_map(|step| match step {
            PipelineStep::Llm(step) => Some(step),
            PipelineStep::Operator(_) => None,
        })
        .ok_or_else(|| "function document extract requires an llm step".to_string())?;
    if !llm
        .input_bindings
        .values()
        .any(|source| source == EXTRACTED_TEXT_PARAM)
    {
        return Err("function document extract requires an extracted_text binding".into());
    }
    Ok(llm)
}

fn object_properties(structured: &serde_json::Value) -> Result<HashMap<String, String>, String> {
    let object = structured
        .as_object()
        .ok_or_else(|| "function document extract output must be an object".to_string())?;
    let mut properties = HashMap::new();
    for (key, value) in object {
        if matches!(key.as_str(), "id" | "name" | CONFIDENCE_FIELD) {
            continue;
        }
        // `object_id` and `notify_delivery` are Action control parameters
        // when a low-confidence extraction parks.
        if key == OBJECT_CLASSIFICATION_PROPERTY
            || key.starts_with("lineage_")
            || matches!(key.as_str(), "object_id" | "notify_delivery")
        {
            return Err(format!(
                "function document extract property {key} is reserved"
            ));
        }
        if !is_valid_property_key(key) {
            return Err(format!(
                "function document extract property {key} is not a valid object key"
            ));
        }
        let stored = match value {
            serde_json::Value::String(value) => value.clone(),
            serde_json::Value::Number(value) => value.to_string(),
            serde_json::Value::Bool(value) => value.to_string(),
            _ => {
                return Err(format!(
                    "function document extract property {key} must be a string, number, or boolean"
                ));
            }
        };
        properties.insert(key.clone(), stored);
    }
    Ok(properties)
}

fn persist_extracted_object(
    db: &RuntimeDb,
    actor: &str,
    object: &Object,
    document_id: &str,
    parent_content_digest: &str,
    classification: &str,
    now_ms: i64,
) -> Result<(), String> {
    let lineage_id = ensure_document_lineage_object(
        db,
        actor,
        &object.namespace,
        document_id,
        parent_content_digest,
        classification,
        now_ms,
    )?;
    db.create_object_with_audit(object, actor)?;
    link_derived_from(db, object, lineage_id, now_ms)
}

fn link_derived_from(
    db: &RuntimeDb,
    object: &Object,
    lineage_id: String,
    now_ms: i64,
) -> Result<(), String> {
    let id = format!("link:{}:{lineage_id}", object.id);
    if db.get_link(&id)?.is_some() {
        return Ok(());
    }
    db.create_link(&Link {
        id,
        from_id: object.id.clone(),
        to_id: lineage_id,
        relation: REL_DERIVED_FROM.into(),
        created: now_ms,
    })
}

/// Document lineage an object claims through its `lineage_*` properties.
struct ClaimedLineage<'a> {
    document_id: &'a str,
    parent_content_digest: &'a str,
    rendition_digest: &'a str,
    classification: &'a str,
}

fn claimed_lineage(object: &Object) -> Result<Option<ClaimedLineage<'_>>, String> {
    let Some(document_id) = object.properties.get(LINEAGE_DOCUMENT_ID) else {
        return Ok(None);
    };
    let field = |key: &str| {
        object
            .properties
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("document lineage requires {key}"))
    };
    Ok(Some(ClaimedLineage {
        document_id,
        parent_content_digest: field(LINEAGE_PARENT_CONTENT_DIGEST)?,
        rendition_digest: field(LINEAGE_RENDITION_DIGEST)?,
        classification: field(OBJECT_CLASSIFICATION_PROPERTY)?,
    }))
}

/// Pre-write check for an object written through a governed Action that
/// claims document lineage, such as a granted parked extraction (#1383).
/// The claim must still match the live document, its classification, and
/// an `extracted_text` rendition, so a grant cannot write stale lineage.
/// Like the above-threshold path, this reads before the write commits: an
/// object derived from a document deleted in between is the same as one
/// written just before the delete, and a stub id taken in between leaves
/// the link to completion rather than widening the grant transaction.
pub fn validate_lineage_write(db: &RuntimeDb, object: &Object, now_ms: i64) -> Result<(), String> {
    let Some(claim) = claimed_lineage(object)? else {
        return Ok(());
    };
    let document = db
        .get_governed_document(&object.namespace, claim.document_id)?
        .filter(|document| document.deleted_at_ms == 0 && !is_expired(document, now_ms))
        .ok_or_else(|| DOCUMENT_UNAVAILABLE.to_string())?;
    if document.content_digest != claim.parent_content_digest
        || document.classification != claim.classification
    {
        return Err("document lineage does not match the document".into());
    }
    let rendition_matches = db
        .list_governed_renditions(&object.namespace, claim.document_id)?
        .iter()
        .any(|rendition| {
            rendition.class == RENDITION_EXTRACTED_TEXT
                && rendition.parent_content_digest == claim.parent_content_digest
                && rendition.content_ref.digest == claim.rendition_digest
        });
    if !rendition_matches {
        return Err("document lineage does not match an extracted_text rendition".into());
    }
    // Completion runs after the write commits, so refuse here what it could
    // never repair: an incompatible object holding the stub id.
    let lineage_id = document_lineage_object_id(&object.namespace, claim.document_id);
    if object.id == lineage_id {
        return Err("document lineage stub id is reserved".into());
    }
    if let Some(existing) = db.get_object(&lineage_id)? {
        check_lineage_stub(
            &existing,
            &object.namespace,
            claim.document_id,
            claim.parent_content_digest,
            claim.classification,
        )?;
    }
    Ok(())
}

/// Post-write completion for an object validated by
/// [`validate_lineage_write`]: ensures the document stub and the
/// `derived_from` link. Idempotent, so an admission replay finishes a link
/// an interrupted write skipped.
pub fn complete_lineage_write(
    db: &RuntimeDb,
    actor: &str,
    object: &Object,
    now_ms: i64,
) -> Result<(), String> {
    let Some(claim) = claimed_lineage(object)? else {
        return Ok(());
    };
    let lineage_id = ensure_document_lineage_object(
        db,
        actor,
        &object.namespace,
        claim.document_id,
        claim.parent_content_digest,
        claim.classification,
        now_ms,
    )?;
    link_derived_from(db, object, lineage_id, now_ms)
}

fn ensure_document_lineage_object(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    document_id: &str,
    parent_content_digest: &str,
    classification: &str,
    now_ms: i64,
) -> Result<String, String> {
    let lineage_id = document_lineage_object_id(namespace, document_id);
    match db.get_object(&lineage_id)? {
        Some(existing) => {
            check_lineage_stub(
                &existing,
                namespace,
                document_id,
                parent_content_digest,
                classification,
            )?;
        }
        None => {
            db.create_object_with_audit(
                &Object {
                    id: lineage_id.clone(),
                    kind: DOCUMENT_OBJECT_KIND.into(),
                    name: document_id.into(),
                    namespace: namespace.into(),
                    external_id: document_id.into(),
                    properties: HashMap::from([
                        (LINEAGE_DOCUMENT_ID.into(), document_id.into()),
                        (
                            LINEAGE_PARENT_CONTENT_DIGEST.into(),
                            parent_content_digest.into(),
                        ),
                        (OBJECT_CLASSIFICATION_PROPERTY.into(), classification.into()),
                    ]),
                    created: now_ms,
                    updated: now_ms,
                },
                actor,
            )?;
        }
    }
    Ok(lineage_id)
}

fn check_lineage_stub(
    existing: &Object,
    namespace: &str,
    document_id: &str,
    parent_content_digest: &str,
    classification: &str,
) -> Result<(), String> {
    let prop = |key: &str| existing.properties.get(key).map(String::as_str);
    if existing.kind != DOCUMENT_OBJECT_KIND
        || existing.namespace != namespace
        || prop(LINEAGE_DOCUMENT_ID) != Some(document_id)
        || prop(LINEAGE_PARENT_CONTENT_DIGEST) != Some(parent_content_digest)
        || prop(OBJECT_CLASSIFICATION_PROPERTY) != Some(classification)
    {
        return Err("function document extract lineage object does not match the document".into());
    }
    Ok(())
}

/// The namespace action-policy decision for submitting the extraction Action.
fn extraction_policy(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    action: &FunctionDocumentAction,
) -> Result<(GovernedActionType, ActionDecision), String> {
    let type_def =
        db.require_enabled_governed_action_type(namespace, &action.type_id, &action.version)?;
    let policy_project = if type_def.policy_scope.trim().is_empty() {
        namespace
    } else {
        type_def.policy_scope.as_str()
    };
    let decision = match db.resolve_action_policy(actor, namespace, policy_project)? {
        Some(policy) => policy.decide(SUBMIT_POLICY_ACTION, RiskClass::Write),
        None => ActionDecision::Allow,
    };
    Ok((type_def, decision))
}

fn park_extraction(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    now_ms: i64,
    type_def: &GovernedActionType,
    action: &FunctionDocumentAction,
    object: &Object,
) -> Result<ActionInstance, String> {
    // A grant writes the object through the type's own create mutation, so
    // refuse a type whose grant would write nothing or another kind.
    if type_def.object_kind.trim() != object.kind
        || type_def.object_mutation.trim() != OBJECT_MUTATION_CREATE
    {
        return Err(format!(
            "function document extract action must create {} objects on grant",
            object.kind
        ));
    }
    // Parameters are the object's own properties, so the granted create
    // writes the same object, classification and lineage included.
    let mut parameters = serde_json::Map::new();
    parameters.insert("object_id".into(), object.id.clone().into());
    parameters.insert("name".into(), object.name.clone().into());
    for (key, value) in &object.properties {
        parameters.insert(key.clone(), value.clone().into());
    }
    let confidence: u64 = object
        .properties
        .get(CONFIDENCE_FIELD)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "function document extract confidence_micros is missing".to_string())?;
    parameters.insert(CONFIDENCE_FIELD.into(), confidence.into());
    let parameters = serde_json::Value::Object(parameters);
    let outcome = ActionInstanceAdmission::new(db, None)
        .admit(
            ActionInstanceAdmissionRequest {
                namespace: namespace.into(),
                type_id: action.type_id.clone(),
                version: action.version.clone(),
                parameters_json: parameters.to_string(),
                idempotency_key: action.idempotency_key.clone(),
                evidence_submission_ids: Vec::new(),
                request_id: action.request_id.clone(),
                ontology_digest: action.ontology_digest.clone(),
                autonomous_envelope_id: String::new(),
                policy_context: PrincipalPolicyContext::default(),
                delegating_actor: None,
                budget_already_reserved: false,
                resource_tenant: String::new(),
                binding_markings: Vec::new(),
                source_object_id: String::new(),
                marking_gate: Default::default(),
                expected_object_revision: String::new(),
                offline: None,
            },
            actor,
            now_ms,
        )
        .map_err(|error| format!("function document extract action: {error:?}"))?;
    if outcome.instance.status != STATUS_PARKED && outcome.instance.status != STATUS_ADMITTED {
        return Err(format!(
            "function document extract expected parked or admitted action, got {}",
            outcome.instance.status
        ));
    }
    Ok(outcome.instance)
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::action_policy::ActionPolicy;
    use crate::sekai::document::{
        CONTENT_SCHEME_DIGEST, ContentReference, DOCUMENT_CONTRACT, DocumentRendition,
        GovernedDocument, TYPE_REVISION_V1, admit_document, attach_rendition,
    };
    use crate::sekai::function::{FuncParam, FunctionBudget, FunctionHost, LlmStep, PipelineStep};
    use crate::sekai::governed_action_type::EFFECT_KIND_NOTIFY;
    use crate::sekai::governed_action_type::{GovernedActionType, OBJECT_MUTATION_CREATE};
    use crate::sekai::markings::{
        PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY, PRINCIPAL_PROFILE_KIND,
        PRINCIPAL_PROFILE_SEALED_PROPERTY, principal_profile_external_id,
    };
    use crate::sekai::security::{Grant, Role};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const INVOICE_SCHEMA: &str = r#"{"type":"object","properties":{"id":{"type":"string"},"vendor":{"type":"string"},"confidence_micros":{"type":"integer"}},"required":["id","vendor","confidence_micros"],"additionalProperties":false}"#;
    const ONTOLOGY_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EXTRACTED: &str = "Invoice ACME 40.00";
    const EXTRACT_PARAMETER_SCHEMA: &str = r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"vendor":{"type":"string"},"confidence_micros":{"type":"integer","minimum":0,"maximum":1000000},"access_marking":{"type":"string"},"lineage_document_id":{"type":"string"},"lineage_parent_content_digest":{"type":"string"},"lineage_rendition_digest":{"type":"string"}},"required":["object_id","confidence_micros","access_marking","lineage_document_id","lineage_parent_content_digest","lineage_rendition_digest"],"additionalProperties":false}"#;

    struct RecordingHost {
        output: serde_json::Value,
        bound: Mutex<Option<serde_json::Value>>,
    }

    impl LlmStepHost for RecordingHost {
        fn complete(
            &self,
            _prompt_revision: &str,
            _model_route: &str,
            bound_inputs: &serde_json::Value,
            _output_schema: &str,
        ) -> Result<serde_json::Value, String> {
            *self.bound.lock().unwrap() = Some(bound_inputs.clone());
            Ok(self.output.clone())
        }
    }

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn pin_ceiling(runtime: &RuntimeDb, principal: &str, ceiling: &str) {
        let profile_id = format!("profile:{principal}");
        runtime
            .create_object(&Object {
                id: profile_id.clone(),
                kind: PRINCIPAL_PROFILE_KIND.into(),
                name: principal.into(),
                namespace: "records".into(),
                external_id: principal_profile_external_id(principal),
                properties: HashMap::from([
                    (
                        PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        ceiling.into(),
                    ),
                    (PRINCIPAL_PROFILE_SEALED_PROPERTY.into(), "true".into()),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        runtime
            .create_grant(&Grant {
                id: format!("grant:{principal}"),
                object_id: profile_id,
                principal: "root".into(),
                role: Role::Admin,
                created: 1,
                ..Default::default()
            })
            .unwrap();
    }

    fn content_ref(digest: &str, media: &str, len: u64) -> ContentReference {
        ContentReference {
            scheme: CONTENT_SCHEME_DIGEST.into(),
            digest: digest.into(),
            media_type: media.into(),
            byte_length: len,
        }
    }

    fn admit_invoice_document(runtime: &RuntimeDb) -> String {
        admit_invoice_document_for(runtime, "analyst")
    }

    fn admit_invoice_document_for(runtime: &RuntimeDb, owner: &str) -> String {
        pin_ceiling(runtime, owner, "internal");
        let parent = content_ref(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "application/pdf",
            128,
        );
        let document = GovernedDocument {
            contract_version: DOCUMENT_CONTRACT.into(),
            document_id: "doc:invoice".into(),
            namespace: "records".into(),
            owner: owner.into(),
            type_revision: TYPE_REVISION_V1.into(),
            purpose: "case-review".into(),
            classification: "internal".into(),
            title: "invoice".into(),
            metadata: BTreeMap::new(),
            content_digest: crate::sekai::document::content_digest_for(&parent).unwrap(),
            content_ref: parent.clone(),
            expires_at_ms: 0,
            hold_id: String::new(),
            hold_reason: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
            deleted_at_ms: 0,
        };
        let admitted = admit_document(runtime, owner, &document, 1_000).unwrap();
        let text_digest = digest_bytes(EXTRACTED.as_bytes());
        attach_rendition(
            runtime,
            owner,
            &DocumentRendition {
                namespace: "records".into(),
                document_id: "doc:invoice".into(),
                rendition_id: "rend:text".into(),
                class: RENDITION_EXTRACTED_TEXT.into(),
                parent_content_digest: admitted.content_digest.clone(),
                content_ref: content_ref(&text_digest, "text/plain", EXTRACTED.len() as u64),
                extractor_id: "extractor:text".into(),
                extractor_profile_digest:
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .into(),
                attached_by: String::new(),
                attached_at_ms: 0,
            },
            1_500,
        )
        .unwrap();
        text_digest
    }

    fn extract_function(threshold: u32) -> Function {
        Function {
            name: "extract-invoice".into(),
            description: "".into(),
            params: vec![FuncParam {
                name: EXTRACTED_TEXT_PARAM.into(),
                param_type: "string".into(),
                required: true,
            }],
            created: 0,
            pipeline: vec![PipelineStep::Llm(LlmStep {
                prompt_revision: "invoice/v1".into(),
                input_bindings: BTreeMap::from([("text".into(), EXTRACTED_TEXT_PARAM.into())]),
                output_schema: INVOICE_SCHEMA.into(),
                model_route: "native/scripted".into(),
                minimum_confidence_micros: threshold,
            })],
        }
    }

    fn seed_action(runtime: &RuntimeDb) {
        seed_action_creating(runtime, "invoice", OBJECT_MUTATION_CREATE);
    }

    fn seed_action_creating(runtime: &RuntimeDb, object_kind: &str, object_mutation: &str) {
        runtime
            .upsert_object_type(&crate::sekai::schema::ObjectType {
                kind: "invoice".into(),
                description: "Extracted invoice".into(),
                properties: vec![],
                is_builtin: false,
                implements: vec![],
            })
            .unwrap();
        runtime
            .put_governed_action_type(
                GovernedActionType {
                    namespace: "records".into(),
                    type_id: "function.extract_object".into(),
                    version: "1".into(),
                    description: "park a low-confidence extraction".into(),
                    parameter_schema_json: EXTRACT_PARAMETER_SCHEMA.into(),
                    allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
                    policy_scope: String::new(),
                    budget_scope: String::new(),
                    object_kind: object_kind.into(),
                    object_mutation: object_mutation.into(),
                    enabled: true,
                    created_by: String::new(),
                    created_at_ms: 0,
                    updated_at_ms: 0,
                    disabled_at_ms: 0,
                    ..Default::default()
                },
                "operator",
                1,
            )
            .unwrap();
        let mut policy = ActionPolicy::allow_all("records");
        policy.default_decision = crate::sekai::action_policy::ActionDecision::RequireApproval;
        runtime.upsert_action_policy(&policy).unwrap();
    }

    fn action() -> FunctionDocumentAction {
        FunctionDocumentAction {
            type_id: "function.extract_object".into(),
            version: "1".into(),
            ontology_digest: ONTOLOGY_DIGEST.into(),
            request_id: "operation-extract".into(),
            idempotency_key: "extract-1".into(),
        }
    }

    fn host() -> FunctionHost {
        FunctionHost {
            now_ms: 1_700_000_000_000,
            rng_seed: 7,
        }
    }

    fn set_policy(runtime: &RuntimeDb, decision: ActionDecision) {
        let mut policy = ActionPolicy::allow_all("records");
        policy.default_decision = decision;
        runtime.upsert_action_policy(&policy).unwrap();
    }

    fn extract(
        runtime: &RuntimeDb,
        function: &Function,
        text: &str,
        output: serde_json::Value,
    ) -> Result<(FunctionDocumentExtract, Option<serde_json::Value>), String> {
        extract_authorized(runtime, function, text, output, &|_| Ok(()))
    }

    fn extract_authorized(
        runtime: &RuntimeDb,
        function: &Function,
        text: &str,
        output: serde_json::Value,
        authorize_write: &dyn Fn(&Object) -> Result<(), String>,
    ) -> Result<(FunctionDocumentExtract, Option<serde_json::Value>), String> {
        if !runtime.function_gate_approved(function).unwrap() {
            runtime.publish_gated_function(function).unwrap();
        }
        extract_published(runtime, function, text, output, authorize_write)
    }

    fn extract_published(
        runtime: &RuntimeDb,
        function: &Function,
        text: &str,
        output: serde_json::Value,
        authorize_write: &dyn Fn(&Object) -> Result<(), String>,
    ) -> Result<(FunctionDocumentExtract, Option<serde_json::Value>), String> {
        extract_published_as(runtime, "analyst", function, text, output, authorize_write)
    }

    fn extract_published_as(
        runtime: &RuntimeDb,
        actor: &str,
        function: &Function,
        text: &str,
        output: serde_json::Value,
        authorize_write: &dyn Fn(&Object) -> Result<(), String>,
    ) -> Result<(FunctionDocumentExtract, Option<serde_json::Value>), String> {
        let llm = RecordingHost {
            output,
            bound: Mutex::new(None),
        };
        let result = extract_from_rendition(FunctionDocumentExtractRequest {
            db: runtime,
            function,
            actor,
            namespace: "records",
            document_id: "doc:invoice",
            purpose: "case-review",
            extracted_text: text,
            llm_host: &llm,
            host: host(),
            budget: FunctionBudget {
                max_time_ms: 5_000,
                ..FunctionBudget::default()
            },
            now_ms: 2_000,
            object_kind: "invoice",
            action: action(),
            authorize_write,
        })?;
        Ok((result, llm.bound.lock().unwrap().clone()))
    }

    #[test]
    fn extracts_an_invoice_object_with_lineage_to_the_document_digest() {
        let runtime = db();
        let text_digest = admit_invoice_document(&runtime);
        seed_action(&runtime);
        set_policy(&runtime, ActionDecision::Allow);
        let function = extract_function(800_000);
        let (result, bound) = extract(
            &runtime,
            &function,
            EXTRACTED,
            serde_json::json!({
                "id": "inv-1",
                "vendor": "ACME",
                "confidence_micros": 900_000
            }),
        )
        .unwrap();
        let FunctionDocumentExtract::Written { object, invocation } = result else {
            panic!("expected written object");
        };
        assert_eq!(object.id, "inv-1");
        assert_eq!(object.properties.get("vendor").unwrap(), "ACME");
        assert_eq!(
            object
                .properties
                .get(OBJECT_CLASSIFICATION_PROPERTY)
                .unwrap(),
            "internal"
        );
        assert_eq!(
            object.properties.get(LINEAGE_DOCUMENT_ID).unwrap(),
            "doc:invoice"
        );
        assert_eq!(
            object.properties.get(LINEAGE_RENDITION_DIGEST).unwrap(),
            &text_digest
        );
        let parent_pin = content_digest_for(&content_ref(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "application/pdf",
            128,
        ))
        .unwrap();
        assert_eq!(
            object
                .properties
                .get(LINEAGE_PARENT_CONTENT_DIGEST)
                .unwrap(),
            &parent_pin
        );
        assert_eq!(
            bound.unwrap()["text"],
            serde_json::Value::String(EXTRACTED.into())
        );
        assert!(invocation.receipt.input_digest.starts_with("sha256:"));
        let lineage = runtime.get_lineage("inv-1", 8).unwrap();
        let lineage_id = document_lineage_object_id("records", "doc:invoice");
        assert!(lineage.nodes.iter().any(|item| {
            item.object.id == lineage_id
                && item.object.kind == DOCUMENT_OBJECT_KIND
                && item
                    .object
                    .properties
                    .contains_key(LINEAGE_PARENT_CONTENT_DIGEST)
        }));
        assert_eq!(runtime.get_object("inv-1").unwrap().unwrap().id, "inv-1");
    }

    #[test]
    fn low_confidence_parks_a_require_approval_action() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        let function = extract_function(800_000);
        let (result, _) = extract(
            &runtime,
            &function,
            EXTRACTED,
            serde_json::json!({
                "id": "inv-low",
                "vendor": "ACME",
                "confidence_micros": 100_000
            }),
        )
        .unwrap();
        let FunctionDocumentExtract::Parked { instance, .. } = result else {
            panic!("expected parked action");
        };
        assert_eq!(instance.status, STATUS_PARKED);
        assert!(runtime.get_object("inv-low").unwrap().is_none());
        let parameters: serde_json::Value =
            serde_json::from_str(&instance.parameters_json).unwrap();
        assert_eq!(parameters["vendor"], "ACME");
        assert_eq!(parameters["confidence_micros"], 100_000);
        assert_eq!(parameters[OBJECT_CLASSIFICATION_PROPERTY], "internal");
        let inbox = runtime
            .list_action_instances("records", None, Some(STATUS_PARKED), 10)
            .unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].instance_id, instance.instance_id);
    }

    #[test]
    fn mismatched_extracted_text_fails_closed() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        let function = extract_function(800_000);
        let error = extract(
            &runtime,
            &function,
            "not the invoice",
            serde_json::json!({
                "id": "inv-1",
                "vendor": "ACME",
                "confidence_micros": 900_000
            }),
        )
        .unwrap_err();
        assert!(error.contains("does not match the rendition digest"));
    }

    #[test]
    fn oversized_confidence_fails_closed() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        let function = extract_function(800_000);
        let error = extract(
            &runtime,
            &function,
            EXTRACTED,
            serde_json::json!({
                "id": "inv-1",
                "vendor": "ACME",
                "confidence_micros": 1_000_001
            }),
        )
        .unwrap_err();
        assert!(error.contains("confidence_micros must be at most 1000000"));
        assert!(runtime.get_object("inv-1").unwrap().is_none());
    }

    #[test]
    fn model_access_marking_is_rejected() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        let mut function = extract_function(800_000);
        if let PipelineStep::Llm(step) = &mut function.pipeline[0] {
            step.output_schema = r#"{"type":"object","properties":{"id":{"type":"string"},"vendor":{"type":"string"},"confidence_micros":{"type":"integer"}},"required":["id","vendor","confidence_micros"],"additionalProperties":true}"#.into();
        }
        let error = extract(
            &runtime,
            &function,
            EXTRACTED,
            serde_json::json!({
                "id": "inv-1",
                "vendor": "ACME",
                "confidence_micros": 900_000,
                "access_marking": "public"
            }),
        )
        .unwrap_err();
        assert!(error.contains("reserved"));
        assert!(runtime.get_object("inv-1").unwrap().is_none());
    }

    #[test]
    fn operator_pipeline_is_rejected() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        let mut function = extract_function(800_000);
        function
            .pipeline
            .insert(0, PipelineStep::operator("filter", "invoice", "", "", ""));
        let error = extract(
            &runtime,
            &function,
            EXTRACTED,
            serde_json::json!({
                "id": "inv-1",
                "vendor": "ACME",
                "confidence_micros": 900_000
            }),
        )
        .unwrap_err();
        assert!(error.contains("llm-only pipeline"));
        assert!(runtime.get_object("inv-1").unwrap().is_none());
    }

    #[test]
    fn allow_policy_does_not_admit_a_low_confidence_extract() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        runtime
            .upsert_action_policy(&ActionPolicy::allow_all("records"))
            .unwrap();
        let error = extract(
            &runtime,
            &extract_function(800_000),
            EXTRACTED,
            serde_json::json!({
                "id": "inv-low",
                "vendor": "ACME",
                "confidence_micros": 100_000
            }),
        )
        .unwrap_err();
        assert!(error.contains("require_approval"));
        assert!(runtime.get_object("inv-low").unwrap().is_none());
        assert!(
            runtime
                .list_action_instances("records", None, None, 10)
                .unwrap()
                .is_empty()
        );
    }

    fn invoice_output(confidence: u64) -> serde_json::Value {
        serde_json::json!({"id": "inv-1", "vendor": "ACME", "confidence_micros": confidence})
    }

    #[test]
    fn deny_policy_refuses_an_above_threshold_extract() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        set_policy(&runtime, ActionDecision::Deny);
        let error = extract(
            &runtime,
            &extract_function(800_000),
            EXTRACTED,
            invoice_output(900_000),
        )
        .unwrap_err();
        assert!(error.contains("denied by action policy"), "{error}");
        assert!(runtime.get_object("inv-1").unwrap().is_none());
    }

    #[test]
    fn require_approval_parks_at_any_confidence_including_a_zero_threshold() {
        for threshold in [800_000, 0] {
            let runtime = db();
            admit_invoice_document(&runtime);
            seed_action(&runtime);
            let (result, _) = extract(
                &runtime,
                &extract_function(threshold),
                EXTRACTED,
                invoice_output(900_000),
            )
            .unwrap();
            assert!(
                matches!(result, FunctionDocumentExtract::Parked { .. }),
                "threshold {threshold} must park"
            );
            assert!(runtime.get_object("inv-1").unwrap().is_none());
        }
    }

    #[test]
    fn allowed_extract_is_refused_by_the_write_authorization() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        set_policy(&runtime, ActionDecision::Allow);
        let error = extract_authorized(
            &runtime,
            &extract_function(800_000),
            EXTRACTED,
            invoice_output(900_000),
            &|object| Err(format!("write denied for {}", object.id)),
        )
        .unwrap_err();
        assert_eq!(error, "write denied for inv-1");
        assert!(runtime.get_object("inv-1").unwrap().is_none());
    }

    #[test]
    fn extract_refuses_a_revision_that_was_not_published() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        set_policy(&runtime, ActionDecision::Allow);
        let unpublished = |function: &Function| {
            extract_published(
                &runtime,
                function,
                EXTRACTED,
                invoice_output(900_000),
                &|_| Ok(()),
            )
            .unwrap_err()
        };
        assert_eq!(
            unpublished(&extract_function(800_000)),
            LLM_FUNCTION_REQUIRES_GATE
        );
        runtime
            .publish_gated_function(&extract_function(800_000))
            .unwrap();
        assert_eq!(
            unpublished(&extract_function(500_000)),
            LLM_FUNCTION_REQUIRES_GATE
        );
        assert!(runtime.get_object("inv-1").unwrap().is_none());
    }

    fn grant(runtime: &RuntimeDb, instance_id: &str) -> ActionInstance {
        use crate::sekai::action_instance::DECISION_GRANT;
        use crate::sekai::action_instance_admission::ActionInstanceDecisionRequest;
        ActionInstanceAdmission::new(runtime, None)
            .decide(
                ActionInstanceDecisionRequest {
                    instance_id: instance_id.into(),
                    decision: DECISION_GRANT.into(),
                    reason: String::new(),
                    decider_principals: vec!["approver".into()],
                    decider_is_namespace_admin: true,
                    delegating_actor: None,
                    execution_claim: None,
                },
                "approver",
                3_000,
            )
            .unwrap()
            .instance
    }

    fn park_low_confidence(runtime: &RuntimeDb) -> Box<ActionInstance> {
        let (result, _) = extract(
            runtime,
            &extract_function(800_000),
            EXTRACTED,
            serde_json::json!({
                "id": "inv-low",
                "vendor": "ACME",
                "confidence_micros": 100_000
            }),
        )
        .unwrap();
        let FunctionDocumentExtract::Parked { instance, .. } = result else {
            panic!("expected parked action");
        };
        instance
    }

    fn earn_extract_auto_apply(runtime: &RuntimeDb, principal: &str) {
        use crate::sekai::action_instance::DECISION_GRANT;
        use crate::sekai::agent_autonomy::{
            AutonomyThreshold, GrantAutoApplyRequest, grant_auto_apply,
        };
        use crate::sekai::autonomous_envelope::{
            AutonomousEnvelope, AutonomousPins, ENVELOPE_CONTRACT, PROFILE_SIMULATE,
            PROFILE_VERSION, RECEIPT_CURRENT, STATUS_LIVE, admit_envelope, envelope_digest_for,
        };
        use ed25519_dalek::Signer;

        for (key, now) in [("a", 10i64), ("b", 20)] {
            runtime
                .put_action_instance(&ActionInstance {
                    instance_id: format!("inst-{key}"),
                    namespace: "records".into(),
                    type_id: "function.extract_object".into(),
                    version: "1".into(),
                    principal: principal.into(),
                    delegating_actor: None,
                    parameters_json: r#"{"object_id":"prior"}"#.into(),
                    request_digest: format!("sha256:{key}"),
                    idempotency_key: key.into(),
                    operation_id: format!("op-{key}"),
                    status: STATUS_ADMITTED.into(),
                    deny_reason: String::new(),
                    evidence_submission_ids: Vec::new(),
                    policy_decision: "require_approval".into(),
                    budget_decision: "not_configured".into(),
                    created_at_ms: now,
                    decided_at_ms: now,
                    system_one_fill_json: String::new(),
                    parked_object_digest: String::new(),
                    decided_by: "ops-admin".into(),
                    approval_decision: DECISION_GRANT.into(),
                    autonomous_envelope_id: String::new(),
                    review: Default::default(),
                    agent_action: false,
                    admission_tenant: String::new(),
                    resource_tenant: String::new(),
                    marking: String::new(),
                    conflict: None,
                    approval: None,
                    offline: None,
                    admission_lease: None,
                })
                .unwrap();
        }
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let digest = |tag: u8| format!("sha256:{tag:02x}{}", "ab".repeat(31));
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let mut envelope = AutonomousEnvelope {
            contract_version: ENVELOPE_CONTRACT.into(),
            envelope_id: "auto:extract".into(),
            namespace: "records".into(),
            owner: principal.into(),
            adapter_id: PROFILE_SIMULATE.into(),
            adapter_version: PROFILE_VERSION.into(),
            pins: AutonomousPins {
                state_digest: digest(1),
                policy_digest: digest(2),
                model_digest: digest(3),
                prompt_digest: digest(4),
                evidence_digest: digest(5),
                simulation_digest: digest(6),
                budget_digest: digest(7),
                lease_digest: digest(8),
            },
            signer_id: "signer:ops".into(),
            signer_digest: format!("sha256:{:x}", Sha256::digest(public_key)),
            public_key_hex: hex(&public_key),
            signature_hex: String::new(),
            envelope_digest: String::new(),
            receipt_digest: String::new(),
            receipt_status: RECEIPT_CURRENT.into(),
            status: STATUS_LIVE.into(),
            predecessor_id: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        };
        envelope.envelope_digest = envelope_digest_for(&envelope).unwrap();
        envelope.signature_hex = hex(&signing_key
            .sign(envelope.envelope_digest.as_bytes())
            .to_bytes());
        admit_envelope(runtime, principal, &envelope, 1_000).unwrap();
        grant_auto_apply(
            runtime,
            GrantAutoApplyRequest {
                actor: "ops-admin",
                namespace: "records",
                principal,
                type_id: "function.extract_object",
                envelope_id: "auto:extract",
                now_ms: 1_500,
                threshold: AutonomyThreshold {
                    min_reviews: 2,
                    min_unchanged_bps: 10_000,
                    max_incidents: 0,
                },
            },
        )
        .unwrap();
    }

    fn extract_as_agent(
        runtime: &RuntimeDb,
        authorize_write: &dyn Fn(&Object) -> Result<(), String>,
    ) -> Result<(FunctionDocumentExtract, Option<serde_json::Value>), String> {
        let function = extract_function(800_000);
        if !runtime.function_gate_approved(&function).unwrap() {
            runtime.publish_gated_function(&function).unwrap();
        }
        extract_published_as(
            runtime,
            "agent:extractor",
            &function,
            EXTRACTED,
            invoice_output(900_000),
            authorize_write,
        )
    }

    #[test]
    fn auto_apply_extract_returns_written() {
        let runtime = db();
        admit_invoice_document_for(&runtime, "agent:extractor");
        seed_action(&runtime);
        earn_extract_auto_apply(&runtime, "agent:extractor");
        let (result, _) = extract_as_agent(&runtime, &|_| Ok(())).unwrap();
        let FunctionDocumentExtract::Written { object, .. } = result else {
            panic!("expected written object after auto-apply");
        };
        assert_eq!(object.id, "inv-1");
        assert_eq!(
            runtime.get_object("inv-1").unwrap().unwrap().kind,
            "invoice"
        );
        let parked = runtime
            .list_action_instances("records", None, Some(STATUS_PARKED), 10)
            .unwrap();
        assert!(parked.is_empty());
    }

    #[test]
    fn auto_apply_extract_is_refused_by_the_write_authorization() {
        let runtime = db();
        admit_invoice_document_for(&runtime, "agent:extractor");
        seed_action(&runtime);
        earn_extract_auto_apply(&runtime, "agent:extractor");
        let error = extract_as_agent(&runtime, &|object| {
            Err(format!("write denied for {}", object.id))
        })
        .unwrap_err();
        assert!(error.contains("write denied for inv-1"), "{error}");
        assert!(runtime.get_object("inv-1").unwrap().is_none());
        assert!(
            runtime
                .list_action_instances("records", None, None, 10)
                .unwrap()
                .iter()
                .all(|instance| instance.principal != "agent:extractor"
                    || instance.idempotency_key != "extract-1")
        );
    }

    #[test]
    fn agent_extract_requires_write_authorization_before_parking() {
        let runtime = db();
        admit_invoice_document_for(&runtime, "agent:extractor");
        seed_action(&runtime);
        let error = extract_as_agent(&runtime, &|object| {
            Err(format!("write denied for {}", object.id))
        })
        .unwrap_err();
        assert!(error.contains("write denied for inv-1"), "{error}");
        assert!(runtime.get_object("inv-1").unwrap().is_none());
        assert!(
            runtime
                .list_action_instances("records", None, None, 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn allow_policy_parks_an_agent_without_a_grant() {
        let runtime = db();
        admit_invoice_document_for(&runtime, "agent:extractor");
        seed_action(&runtime);
        set_policy(&runtime, ActionDecision::Allow);
        let (result, _) = extract_as_agent(&runtime, &|_| Ok(())).unwrap();
        assert!(
            matches!(result, FunctionDocumentExtract::Parked { .. }),
            "agent Allow extract must park until auto-apply is granted"
        );
        assert!(runtime.get_object("inv-1").unwrap().is_none());
    }

    #[test]
    fn allow_policy_auto_apply_extract_returns_written() {
        let runtime = db();
        admit_invoice_document_for(&runtime, "agent:extractor");
        seed_action(&runtime);
        set_policy(&runtime, ActionDecision::Allow);
        earn_extract_auto_apply(&runtime, "agent:extractor");
        let (result, _) = extract_as_agent(&runtime, &|_| Ok(())).unwrap();
        let FunctionDocumentExtract::Written { object, .. } = result else {
            panic!("expected written object after Allow auto-apply");
        };
        assert_eq!(object.id, "inv-1");
        assert!(runtime.get_object("inv-1").unwrap().is_some());
    }

    #[test]
    fn granting_a_parked_extraction_writes_the_object_with_classification_and_lineage() {
        let runtime = db();
        let text_digest = admit_invoice_document(&runtime);
        seed_action(&runtime);
        let instance = park_low_confidence(&runtime);
        assert_eq!(grant(&runtime, &instance.instance_id).status, "admitted");

        let object = runtime.get_object("inv-low").unwrap().unwrap();
        assert_eq!(object.kind, "invoice");
        let props = &object.properties;
        assert_eq!(props["vendor"], "ACME");
        assert_eq!(props[CONFIDENCE_FIELD], "100000");
        assert_eq!(props[OBJECT_CLASSIFICATION_PROPERTY], "internal");
        assert_eq!(props[LINEAGE_DOCUMENT_ID], "doc:invoice");
        assert_eq!(props[LINEAGE_RENDITION_DIGEST], text_digest);
        assert!(!props.contains_key("properties_json"));
        let lineage_id = document_lineage_object_id("records", "doc:invoice");
        let lineage = runtime.get_lineage("inv-low", 8).unwrap();
        assert!(
            lineage
                .nodes
                .iter()
                .any(|item| item.object.id == lineage_id)
        );
        let link = runtime
            .get_link(&format!("link:inv-low:{lineage_id}"))
            .unwrap()
            .unwrap();
        assert_eq!(link.relation, REL_DERIVED_FROM);

        // A retried grant finishes a link an interrupted completion skipped.
        runtime.delete_link(&link.id).unwrap();
        assert_eq!(grant(&runtime, &instance.instance_id).status, "admitted");
        assert!(runtime.get_link(&link.id).unwrap().is_some());
    }

    #[test]
    fn extracted_action_control_keys_are_reserved() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        let mut function = extract_function(800_000);
        if let PipelineStep::Llm(step) = &mut function.pipeline[0] {
            step.output_schema = r#"{"type":"object","properties":{"id":{"type":"string"},"vendor":{"type":"string"},"confidence_micros":{"type":"integer"}},"required":["id","vendor","confidence_micros"],"additionalProperties":true}"#.into();
        }
        for key in ["object_id", "notify_delivery"] {
            let error = extract(
                &runtime,
                &function,
                EXTRACTED,
                serde_json::json!({
                    "id": "inv-low",
                    "vendor": "ACME",
                    "confidence_micros": 100_000,
                    key: "other"
                }),
            )
            .unwrap_err();
            assert!(error.contains("reserved"), "{key}: {error}");
        }
        assert!(
            runtime
                .list_action_instances("records", None, None, 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn grant_after_the_document_is_deleted_fails_closed_without_writing() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        let instance = park_low_confidence(&runtime);
        crate::sekai::document::delete_document(
            &runtime,
            "analyst",
            "records",
            "doc:invoice",
            2_500,
        )
        .unwrap();
        use crate::sekai::action_instance::DECISION_GRANT;
        use crate::sekai::action_instance_admission::ActionInstanceDecisionRequest;
        let result = ActionInstanceAdmission::new(&runtime, None).decide(
            ActionInstanceDecisionRequest {
                instance_id: instance.instance_id.clone(),
                decision: DECISION_GRANT.into(),
                reason: String::new(),
                decider_principals: vec!["approver".into()],
                decider_is_namespace_admin: true,
                delegating_actor: None,
                execution_claim: None,
            },
            "approver",
            3_000,
        );
        assert!(result.is_err(), "{result:?}");
        assert!(runtime.get_object("inv-low").unwrap().is_none());
    }

    #[test]
    fn grant_refuses_an_incompatible_lineage_stub_before_writing() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action(&runtime);
        let instance = park_low_confidence(&runtime);
        runtime
            .create_object(&Object {
                id: document_lineage_object_id("records", "doc:invoice"),
                kind: "invoice".into(),
                name: "squatter".into(),
                namespace: "records".into(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 2_500,
                updated: 2_500,
            })
            .unwrap();
        use crate::sekai::action_instance::DECISION_GRANT;
        use crate::sekai::action_instance_admission::ActionInstanceDecisionRequest;
        let result = ActionInstanceAdmission::new(&runtime, None).decide(
            ActionInstanceDecisionRequest {
                instance_id: instance.instance_id.clone(),
                decision: DECISION_GRANT.into(),
                reason: String::new(),
                decider_principals: vec!["approver".into()],
                decider_is_namespace_admin: true,
                delegating_actor: None,
                execution_claim: None,
            },
            "approver",
            3_000,
        );
        assert!(result.is_err(), "{result:?}");
        assert!(runtime.get_object("inv-low").unwrap().is_none());
    }

    #[test]
    fn park_refuses_a_type_whose_grant_writes_nothing() {
        let runtime = db();
        admit_invoice_document(&runtime);
        seed_action_creating(&runtime, "", "");
        let error = extract(
            &runtime,
            &extract_function(800_000),
            EXTRACTED,
            serde_json::json!({
                "id": "inv-low",
                "vendor": "ACME",
                "confidence_micros": 100_000
            }),
        )
        .unwrap_err();
        assert!(error.contains("must create invoice objects"), "{error}");
        assert!(
            runtime
                .list_action_instances("records", None, None, 10)
                .unwrap()
                .is_empty()
        );
    }
}
