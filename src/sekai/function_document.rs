//! LLM functions over a governed document rendition (#1326).
//!
//! Palantir analog: AIP Document Intelligence / Functions on objects bind
//! extracted text from a media reference (they do not re-OCR in the function).
//! Lineage is the media reference (document id + item digest). AIP Logic
//! Ontology edits apply automatically or are staged for human review via an
//! Action. Sekai binds an existing `extracted_text` rendition, checks the
//! caller-held text against the pinned digest (the plane stores no bytes),
//! stamps `derived_from` lineage, and parks a `require_approval` Action when
//! confidence is below the function threshold.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{Link, Object, REL_DERIVED_FROM, is_valid_property_key};
use crate::sekai::action::RiskClass;
use crate::sekai::action_instance::{ActionInstance, STATUS_PARKED, SUBMIT_POLICY_ACTION};
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionRequest,
};
use crate::sekai::action_policy::ActionDecision;
use crate::sekai::document::{
    CONTENT_SCHEME_DIGEST, DOCUMENT_UNAVAILABLE, DocumentRetrieve, FIELD_CONTENT_REF,
    FIELD_METADATA, FIELD_RENDITIONS, RENDITION_EXTRACTED_TEXT, content_digest_for,
    retrieve_document,
};
use crate::sekai::function::{
    Function, FunctionBudget, FunctionHost, FunctionInvocation, LlmStepHost, PipelineStep,
    invoke_with_llm, validate_function,
};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
use crate::sekai::object_security::PrincipalPolicyContext;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const EXTRACTED_TEXT_PARAM: &str = "extracted_text";
pub const LINEAGE_DOCUMENT_ID: &str = "lineage_document_id";
pub const LINEAGE_PARENT_CONTENT_DIGEST: &str = "lineage_parent_content_digest";
pub const LINEAGE_RENDITION_DIGEST: &str = "lineage_rendition_digest";
pub const DOCUMENT_OBJECT_KIND: &str = "document";
pub const CONFIDENCE_FIELD: &str = "confidence_micros";
const MAX_PROPERTIES_JSON_BYTES: usize = 1_024;

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
    } = request;
    validate_function(function)?;
    let llm = llm_step(function)?;
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
    if (confidence as u32) < llm.minimum_confidence_micros {
        let instance =
            park_extraction(db, actor, namespace, now_ms, &action, &object, &invocation)?;
        return Ok(FunctionDocumentExtract::Parked {
            instance: Box::new(instance),
            invocation,
        });
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
        if key == OBJECT_CLASSIFICATION_PROPERTY || key.starts_with("lineage_") {
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
    db.create_link(&Link {
        id: format!("link:{}:{lineage_id}", object.id),
        from_id: object.id.clone(),
        to_id: lineage_id,
        relation: REL_DERIVED_FROM.into(),
        created: now_ms,
    })?;
    Ok(())
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
            if existing.kind != DOCUMENT_OBJECT_KIND
                || existing.namespace != namespace
                || existing
                    .properties
                    .get(LINEAGE_DOCUMENT_ID)
                    .map(String::as_str)
                    != Some(document_id)
                || existing
                    .properties
                    .get(LINEAGE_PARENT_CONTENT_DIGEST)
                    .map(String::as_str)
                    != Some(parent_content_digest)
                || existing
                    .properties
                    .get(OBJECT_CLASSIFICATION_PROPERTY)
                    .map(String::as_str)
                    != Some(classification)
            {
                return Err(
                    "function document extract lineage object does not match the document".into(),
                );
            }
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

fn require_approval_policy(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    action: &FunctionDocumentAction,
) -> Result<(), String> {
    let type_def =
        db.require_enabled_governed_action_type(namespace, &action.type_id, &action.version)?;
    let policy_project = if type_def.policy_scope.trim().is_empty() {
        namespace
    } else {
        type_def.policy_scope.as_str()
    };
    let policy = db.resolve_action_policy(actor, namespace, policy_project)?;
    let decision = match policy {
        Some(policy) => policy.decide(SUBMIT_POLICY_ACTION, RiskClass::Write),
        None => ActionDecision::Allow,
    };
    if decision != ActionDecision::RequireApproval {
        return Err("function document extract requires require_approval".into());
    }
    Ok(())
}

fn park_extraction(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    now_ms: i64,
    action: &FunctionDocumentAction,
    object: &Object,
    invocation: &FunctionInvocation,
) -> Result<ActionInstance, String> {
    require_approval_policy(db, actor, namespace, action)?;
    let confidence: u32 = object
        .properties
        .get(CONFIDENCE_FIELD)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "function document extract confidence_micros is missing".to_string())?;
    let properties_json = serde_json::to_string(&BTreeMap::from_iter(
        object
            .properties
            .iter()
            .map(|(k, v)| (k.clone(), v.clone())),
    ))
    .map_err(|error| format!("function document extract properties_json: {error}"))?;
    if properties_json.len() > MAX_PROPERTIES_JSON_BYTES {
        return Err("function document extract properties_json exceeds parameter limit".into());
    }
    let parameters = serde_json::json!({
        "object_id": object.id,
        "name": object.name,
        "object_kind": object.kind,
        "confidence_micros": confidence,
        "lineage_document_id": object
            .properties
            .get(LINEAGE_DOCUMENT_ID)
            .cloned()
            .unwrap_or_default(),
        "lineage_parent_content_digest": object
            .properties
            .get(LINEAGE_PARENT_CONTENT_DIGEST)
            .cloned()
            .unwrap_or_default(),
        "lineage_rendition_digest": object
            .properties
            .get(LINEAGE_RENDITION_DIGEST)
            .cloned()
            .unwrap_or_default(),
        "properties_json": properties_json,
        "input_digest": invocation.receipt.input_digest,
    });
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
                budget_already_reserved: false,
            },
            actor,
            now_ms,
        )
        .map_err(|error| format!("function document extract action: {error:?}"))?;
    if outcome.instance.status != STATUS_PARKED {
        return Err(format!(
            "function document extract expected parked action, got {}",
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
    use crate::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
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
        pin_ceiling(runtime, "analyst", "internal");
        let parent = content_ref(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "application/pdf",
            128,
        );
        let document = GovernedDocument {
            contract_version: DOCUMENT_CONTRACT.into(),
            document_id: "doc:invoice".into(),
            namespace: "records".into(),
            owner: "analyst".into(),
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
        let admitted = admit_document(runtime, "analyst", &document, 1_000).unwrap();
        let text_digest = digest_bytes(EXTRACTED.as_bytes());
        attach_rendition(
            runtime,
            "analyst",
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
        runtime
            .put_governed_action_type(
                GovernedActionType {
                    namespace: "records".into(),
                    type_id: "function.extract_object".into(),
                    version: "1".into(),
                    description: "park a low-confidence extraction".into(),
                    parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"object_kind":{"type":"string"},"confidence_micros":{"type":"integer","minimum":0,"maximum":1000000},"lineage_document_id":{"type":"string"},"lineage_parent_content_digest":{"type":"string"},"lineage_rendition_digest":{"type":"string"},"properties_json":{"type":"string","maxLength":1024},"input_digest":{"type":"string"}},"required":["object_id","object_kind","confidence_micros","lineage_document_id","lineage_parent_content_digest","lineage_rendition_digest","properties_json"],"additionalProperties":false}"#.into(),
                    allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
                    policy_scope: String::new(),
                    budget_scope: String::new(),
                    object_kind: String::new(),
                    object_mutation: String::new(),
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

    fn extract(
        runtime: &RuntimeDb,
        function: &Function,
        text: &str,
        output: serde_json::Value,
    ) -> Result<(FunctionDocumentExtract, Option<serde_json::Value>), String> {
        let llm = RecordingHost {
            output,
            bound: Mutex::new(None),
        };
        let result = extract_from_rendition(FunctionDocumentExtractRequest {
            db: runtime,
            function,
            actor: "analyst",
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
        })?;
        Ok((result, llm.bound.lock().unwrap().clone()))
    }

    #[test]
    fn extracts_an_invoice_object_with_lineage_to_the_document_digest() {
        let runtime = db();
        let text_digest = admit_invoice_document(&runtime);
        seed_action(&runtime);
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
        assert_eq!(parameters["object_kind"], "invoice");
        assert_eq!(parameters["confidence_micros"], 100_000);
        assert!(
            parameters["properties_json"]
                .as_str()
                .unwrap()
                .contains("ACME")
        );
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
}
