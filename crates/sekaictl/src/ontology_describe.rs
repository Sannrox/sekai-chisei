//! `sekaictl ontology draft --describe` (#2298): model-proposed descriptions
//! and alternative names for a drafted tree, marked unreviewed.
//!
//! The model call is one governed execution: `PlanExecution`, then
//! `ExecutePlanStream`, so Chisei admits it under the namespace's policy,
//! route, budget and egress rules. The request carries only member ids,
//! property names, declared types and value-shape finding codes; sampled
//! counts, ratios, markings and source revisions stay out. Every proposed
//! text lands with its path in `unreviewed`, and the draft report records
//! the model, the prompt digest, and the request and plan ids.
//!
//! [`describe`] only changes the in-memory [`Draft`]. The caller writes the
//! tree afterwards, so any failure leaves the tree on disk untouched.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::ontology_draft::Draft;
use crate::ontology_export::{render, render_member};
use crate::ontology_product_cli::{execute_plan, plan_execution};
use sekai_admin_client::client::connect_sekai;
use sekai_core::sekai::definition_text::{
    self, ALTERNATIVE_NAMES, DESCRIPTION, PROPERTY_ALTERNATIVE_NAMES, PROPERTY_DESCRIPTIONS,
    UNREVIEWED,
};
use sekai_proto::chisei::ExecutionInput;
use sekai_proto::chisei::chisei_service_client::ChiseiServiceClient;

const REPORT_FILE: &str = "draft-report.json";
const TASK_TYPE: &str = "ontology_describe";
const MAX_TOKENS: i32 = 4096;

/// The instructions sent as the system prompt. Part of the prompt digest.
const SYSTEM_PROMPT: &str = "You write review drafts for a data model. For each object type, \
property and link type in the input, propose a one-sentence description and the alternative \
names people would use for it. The input holds only ids, property names, declared types and \
value-shape finding codes. Answer with one JSON object and nothing else, in this shape: \
{\"object_types\":{\"<id>\":{\"description\":\"...\",\"alternative_names\":[\"...\"],\
\"properties\":{\"<property>\":{\"description\":\"...\",\"alternative_names\":[\"...\"]}}}},\
\"link_types\":{\"<id>\":{\"description\":\"...\",\"alternative_names\":[\"...\"]}}}. \
Use only ids and property names from the input. Leave out a text you cannot propose. Each \
description is one sentence of at most 300 characters. Give at most 5 alternative names per item.";

/// Why `--describe` failed. Every variant leaves the tree untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DescribeError {
    /// Chisei refused to plan the call or planned it as not executable.
    NoModelRoute(String),
    /// The admitted call failed while executing.
    CallFailed(String),
    /// The answer did not parse, named a member or property the draft does
    /// not have, or held text the definition format refuses.
    InvalidProposal(String),
}

impl DescribeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoModelRoute(_) => "describe_no_model_route",
            Self::CallFailed(_) => "describe_call_failed",
            Self::InvalidProposal(_) => "describe_invalid_proposal",
        }
    }
}

impl fmt::Display for DescribeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (Self::NoModelRoute(detail) | Self::CallFailed(detail) | Self::InvalidProposal(detail)) =
            self;
        write!(f, "{}: {detail}", self.code())
    }
}

impl std::error::Error for DescribeError {}

/// What `draft-report.json` records about the call under `describe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DescribeRecord {
    pub model: String,
    pub prompt_digest: String,
    pub request_id: String,
    pub plan_id: String,
}

/// Proposes text for every member the draft owns, through one governed call
/// in `namespace`, and adds it to `draft` marked unreviewed.
pub async fn describe(
    target: &str,
    namespace: &str,
    draft: &mut Draft,
) -> Result<DescribeRecord, DescribeError> {
    let input = describe_input(draft).map_err(DescribeError::InvalidProposal)?;
    let spec = format!(
        "Drafted members:\n{}",
        serde_json::to_string_pretty(&input)
            .map_err(|e| DescribeError::InvalidProposal(e.to_string()))?
    );
    let prompt_digest = format!(
        "sha256:{:x}",
        Sha256::new()
            .chain_update(SYSTEM_PROMPT)
            .chain_update([0])
            .chain_update(&spec)
            .finalize()
    );
    let request_id = format!("ontology-describe-{}", uuid::Uuid::new_v4().simple());
    let mut client = ChiseiServiceClient::new(
        connect_sekai(target)
            .await
            .map_err(|error| DescribeError::NoModelRoute(error.to_string()))?,
    );
    let plan = plan_execution(
        &mut client,
        ExecutionInput {
            request_id: request_id.clone(),
            namespace: namespace.into(),
            spec,
            task_type: TASK_TYPE.into(),
            priority: 5,
            system: SYSTEM_PROMPT.into(),
            max_tokens: MAX_TOKENS,
            ..Default::default()
        },
    )
    .await
    .map_err(|status| DescribeError::NoModelRoute(status.message().to_string()))?;
    if !plan.executable {
        let why = if plan.warnings.is_empty() {
            "the plan is not executable".to_string()
        } else {
            plan.warnings.join("; ")
        };
        return Err(DescribeError::NoModelRoute(why));
    }
    let record = DescribeRecord {
        model: plan.resolved_model.clone(),
        prompt_digest,
        request_id,
        plan_id: plan.plan_id.clone(),
    };
    let response = execute_plan(&mut client, plan)
        .await
        .map_err(|error| DescribeError::CallFailed(error.to_string()))?;
    let proposals = parse_proposals(&response.content).map_err(DescribeError::InvalidProposal)?;
    apply(draft, &input, &proposals, &record).map_err(DescribeError::InvalidProposal)?;
    Ok(record)
}

/// The whole model input: names, declared types and finding codes only.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
struct DescribeInput {
    object_types: Vec<ObjectInput>,
    link_types: Vec<LinkInput>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ObjectInput {
    id: String,
    properties: Vec<PropertyInput>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct PropertyInput {
    name: String,
    #[serde(rename = "type")]
    declared_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    findings: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct LinkInput {
    id: String,
    from: String,
    to: String,
    columns: Vec<String>,
}

/// The parts of the drafted report this module reads.
#[derive(Deserialize)]
struct Report {
    members: Vec<ReportMember>,
    object_types: Vec<ReportKind>,
}

#[derive(Deserialize)]
struct ReportMember {
    id: String,
    kind: String,
    path: String,
}

#[derive(Deserialize)]
struct ReportKind {
    id: Option<String>,
    findings: Vec<ReportFinding>,
}

#[derive(Deserialize)]
struct ReportFinding {
    column: String,
    code: String,
}

fn report(draft: &Draft) -> Result<Report, String> {
    let body = draft
        .tree
        .get(REPORT_FILE)
        .ok_or("the draft has no report")?;
    serde_json::from_str(body).map_err(|error| format!("{REPORT_FILE}: {error}"))
}

fn member_body(draft: &Draft, path: &str) -> Result<Value, String> {
    let body = draft
        .tree
        .get(path)
        .ok_or_else(|| format!("{path}: missing from the draft"))?;
    serde_json::from_str(body).map_err(|error| format!("{path}: {error}"))
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

/// Reads the owned members of the draft into the model input. Built field
/// by field, so nothing else in a body or the report can reach the model.
fn describe_input(draft: &Draft) -> Result<DescribeInput, String> {
    let report = report(draft)?;
    let mut findings: BTreeMap<&str, BTreeMap<&str, Vec<String>>> = BTreeMap::new();
    for kind in &report.object_types {
        let Some(id) = kind.id.as_deref() else {
            continue;
        };
        let by_column = findings.entry(id).or_default();
        for finding in &kind.findings {
            by_column
                .entry(finding.column.as_str())
                .or_default()
                .push(finding.code.clone());
        }
    }
    let mut input = DescribeInput::default();
    for member in &report.members {
        let body = member_body(draft, &member.path)?;
        match member.kind.as_str() {
            "object_type" => {
                let types = body.get("property_types");
                let columns = findings.get(member.id.as_str());
                input.object_types.push(ObjectInput {
                    id: member.id.clone(),
                    properties: strings(&body["properties"])
                        .into_iter()
                        .map(|name| PropertyInput {
                            declared_type: types
                                .and_then(|types| types.get(&name))
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            findings: columns
                                .and_then(|columns| columns.get(name.as_str()))
                                .cloned()
                                .unwrap_or_default(),
                            name,
                        })
                        .collect(),
                });
            }
            "link_type" => input.link_types.push(LinkInput {
                id: member.id.clone(),
                from: body["from"].as_str().unwrap_or_default().into(),
                to: body["to"].as_str().unwrap_or_default().into(),
                columns: strings(&body["columns"]),
            }),
            other => return Err(format!("{}: unexpected member kind {other}", member.path)),
        }
    }
    Ok(input)
}

/// The model's answer, refused on any field outside this shape.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposals {
    #[serde(default)]
    object_types: BTreeMap<String, TypeText>,
    #[serde(default)]
    link_types: BTreeMap<String, Text>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypeText {
    description: Option<String>,
    #[serde(default)]
    alternative_names: Vec<String>,
    #[serde(default)]
    properties: BTreeMap<String, Text>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Text {
    description: Option<String>,
    #[serde(default)]
    alternative_names: Vec<String>,
}

/// Parses the answer, tolerating one surrounding Markdown code fence.
fn parse_proposals(content: &str) -> Result<Proposals, String> {
    let trimmed = content.trim();
    let json = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|rest| rest.strip_suffix("```"))
        .unwrap_or(trimmed);
    serde_json::from_str(json)
        .map_err(|error| format!("the answer is not the proposal JSON: {error}"))
}

/// Text after trimming; `None` when nothing is left.
fn description(text: &Option<String>) -> Option<Value> {
    text.as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| Value::String(text.into()))
}

/// Trimmed, non-empty names in first-seen order without repeats.
fn names(names: &[String]) -> Option<Value> {
    let mut seen = BTreeSet::new();
    let kept: Vec<Value> = names
        .iter()
        .map(|name| name.trim())
        .filter(|name| !name.is_empty() && seen.insert(*name))
        .map(|name| Value::String(name.into()))
        .collect();
    (!kept.is_empty()).then_some(Value::Array(kept))
}

/// Writes `value` under `field` (or under `field/property`) and records its
/// path as unreviewed.
fn propose(
    body: &mut Value,
    unreviewed: &mut BTreeSet<String>,
    field: &str,
    property: Option<&str>,
    value: Option<Value>,
) {
    let Some(value) = value else {
        return;
    };
    match property {
        None => {
            body[field] = value;
            unreviewed.insert(field.into());
        }
        Some(property) => {
            if !body[field].is_object() {
                body[field] = Value::Object(Default::default());
            }
            body[field][property] = value;
            unreviewed.insert(format!("{field}/{property}"));
        }
    }
}

/// Adds the proposals to the owned members and the record to the report.
/// Refuses a proposal for a member or property the draft does not have, and
/// any text the definition format refuses, before changing anything.
fn apply(
    draft: &mut Draft,
    input: &DescribeInput,
    proposals: &Proposals,
    record: &DescribeRecord,
) -> Result<(), String> {
    let objects: BTreeMap<&str, BTreeSet<&str>> = input
        .object_types
        .iter()
        .map(|object| {
            (
                object.id.as_str(),
                object
                    .properties
                    .iter()
                    .map(|property| property.name.as_str())
                    .collect(),
            )
        })
        .collect();
    let links: BTreeSet<&str> = input
        .link_types
        .iter()
        .map(|link| link.id.as_str())
        .collect();
    for (id, text) in &proposals.object_types {
        let properties = objects.get(id.as_str()).ok_or_else(|| {
            format!("proposal names object type {id:?}, which the draft does not hold")
        })?;
        if let Some(property) = text
            .properties
            .keys()
            .find(|p| !properties.contains(p.as_str()))
        {
            return Err(format!(
                "proposal names property {property:?} of {id:?}, which the draft does not hold"
            ));
        }
    }
    if let Some(id) = proposals
        .link_types
        .keys()
        .find(|id| !links.contains(id.as_str()))
    {
        return Err(format!(
            "proposal names link type {id:?}, which the draft does not hold"
        ));
    }

    let report = report(draft)?;
    let mut rewritten = Vec::new();
    for member in &report.members {
        let mut body = member_body(draft, &member.path)?;
        let mut unreviewed = BTreeSet::new();
        let (text, alternative_names, properties) = match member.kind.as_str() {
            "object_type" => match proposals.object_types.get(&member.id) {
                Some(text) => (
                    &text.description,
                    &text.alternative_names,
                    Some(&text.properties),
                ),
                None => continue,
            },
            _ => match proposals.link_types.get(&member.id) {
                Some(text) => (&text.description, &text.alternative_names, None),
                None => continue,
            },
        };
        propose(
            &mut body,
            &mut unreviewed,
            DESCRIPTION,
            None,
            description(text),
        );
        propose(
            &mut body,
            &mut unreviewed,
            ALTERNATIVE_NAMES,
            None,
            names(alternative_names),
        );
        for (property, text) in properties.into_iter().flatten() {
            propose(
                &mut body,
                &mut unreviewed,
                PROPERTY_DESCRIPTIONS,
                Some(property),
                description(&text.description),
            );
            propose(
                &mut body,
                &mut unreviewed,
                PROPERTY_ALTERNATIVE_NAMES,
                Some(property),
                names(&text.alternative_names),
            );
        }
        if unreviewed.is_empty() {
            continue;
        }
        body[UNREVIEWED] = unreviewed.into_iter().map(Value::String).collect();
        definition_text::validate(&member.kind, &body)
            .map_err(|error| format!("{}: {error}", member.path))?;
        rewritten.push((member.path.clone(), render_member(&member.kind, body)?));
    }

    let mut report_value: Value = serde_json::from_str(&draft.tree[REPORT_FILE])
        .map_err(|error| format!("{REPORT_FILE}: {error}"))?;
    report_value["describe"] = serde_json::to_value(record).map_err(|error| error.to_string())?;
    let report_body = render(&report_value)?;
    for (path, body) in rewritten {
        draft.tree.insert(path, body);
    }
    draft.tree.insert(REPORT_FILE.into(), report_body);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ontology_draft::draft_tree;
    use sekai_proto::chisei::chisei_service_server::{ChiseiService, ChiseiServiceServer};
    use sekai_proto::chisei::{
        ExecutePlanRequest, ExecutePlanStreamEvent, ExecutionPlan, PlanExecutionRequest,
        PlanExecutionResponse, PlannedChatResponse,
    };
    use sekai_source_sdk::{
        ColumnProfileHint, DiscoveredColumn, DiscoveredRecordKind, ReferenceBasis,
        ReferenceCandidate, ReferenceEvidence, SOURCE_DISCOVERY_VERSION, SourceDiscovery,
        ValueShapeCode, ValueShapeFinding,
    };
    use std::sync::{Arc, Mutex};
    use tonic::{Request, Response, Status};

    /// A Chisei plane that records every planned input and answers with a
    /// fixed plan and model reply.
    #[derive(Clone, Default)]
    struct FakeChisei {
        executable: bool,
        answer: String,
        planned: Arc<Mutex<Vec<ExecutionInput>>>,
    }

    #[tonic::async_trait]
    impl ChiseiService for FakeChisei {
        async fn plan_execution(
            &self,
            request: Request<PlanExecutionRequest>,
        ) -> Result<Response<PlanExecutionResponse>, Status> {
            let input = request.into_inner().input.unwrap();
            self.planned.lock().unwrap().push(input.clone());
            Ok(Response::new(PlanExecutionResponse {
                plan: Some(ExecutionPlan {
                    plan_id: "plan-1".into(),
                    input: Some(input),
                    resolved_model: "fake/describer".into(),
                    executable: self.executable,
                    warnings: if self.executable {
                        Vec::new()
                    } else {
                        vec!["no eligible route".into()]
                    },
                    ..Default::default()
                }),
            }))
        }

        async fn execute_plan_stream(
            &self,
            _request: Request<ExecutePlanRequest>,
        ) -> Result<Response<tonic::codegen::BoxStream<ExecutePlanStreamEvent>>, Status> {
            let event = ExecutePlanStreamEvent {
                response: Some(PlannedChatResponse {
                    content: self.answer.clone(),
                    ..Default::default()
                }),
                done: true,
                ..Default::default()
            };
            Ok(Response::new(Box::pin(tokio_stream::iter([Ok(event)]))))
        }
    }

    async fn serve(chisei: FakeChisei) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(ChiseiServiceServer::new(chisei))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        (format!("http://{address}"), server)
    }

    /// A shipment source whose discovery carries sample counts, ratios and a
    /// source revision with distinctive numbers, none of which may reach the
    /// model.
    fn shipments() -> SourceDiscovery {
        let column = |name: &str, data_type: &str| DiscoveredColumn {
            name: name.into(),
            data_type: data_type.into(),
            nullable: false,
            profile: Some(ColumnProfileHint {
                distinct_ratio_bp: 4321,
                null_ratio_bp: 1234,
                possibly_sensitive: false,
            }),
        };
        SourceDiscovery {
            contract_version: SOURCE_DISCOVERY_VERSION.into(),
            source: "ledger9".into(),
            record_kinds: vec![
                DiscoveredRecordKind {
                    record_kind: "customer".into(),
                    schema_revision: "rev-98765".into(),
                    columns: vec![column("id", "string")],
                    key_candidates: vec![vec!["id".into()]],
                    references: Vec::new(),
                    value_findings: Vec::new(),
                },
                DiscoveredRecordKind {
                    record_kind: "shipment".into(),
                    schema_revision: "rev-98765".into(),
                    columns: vec![
                        column("id", "string"),
                        column("cust_id", "string"),
                        column("shp_stat_cd", "string"),
                    ],
                    key_candidates: vec![vec!["id".into()]],
                    references: vec![ReferenceCandidate {
                        columns: vec!["cust_id".into()],
                        target_record_kind: "customer".into(),
                        target_key: vec!["id".into()],
                        basis: ReferenceBasis::Declared,
                        evidence: Some(ReferenceEvidence {
                            sampled: 7777,
                            matched: 6666,
                            null_ratio_bp: 0,
                            nullable: false,
                        }),
                    }],
                    value_findings: vec![ValueShapeFinding {
                        column: "shp_stat_cd".into(),
                        code: ValueShapeCode::NullableReference,
                        sampled: 7777,
                        matched: 5555,
                        formats: Vec::new(),
                    }],
                },
            ],
        }
    }

    const ANSWER: &str = r#"```json
{"object_types":{"shipment":{"description":"A parcel sent to a customer.","alternative_names":["parcel"," parcel ","consignment"],
"properties":{"shp_stat_cd":{"description":"Where the shipment is in delivery.","alternative_names":["shipment status"]}}}},
"link_types":{"shipment_cust_id_customer":{"description":"The customer a shipment goes to."}}}
```"#;

    #[tokio::test]
    async fn the_model_sees_only_names_types_and_codes_and_texts_land_unreviewed() {
        let chisei = FakeChisei {
            executable: true,
            answer: ANSWER.into(),
            ..Default::default()
        };
        let (target, server) = serve(chisei.clone()).await;
        let mut draft = draft_tree(&shipments(), None, &[]).unwrap();
        let record = describe(&target, "erp-team", &mut draft).await.unwrap();
        server.abort();

        let planned = chisei.planned.lock().unwrap().clone();
        assert_eq!(planned.len(), 1);
        let sent = &planned[0];
        assert_eq!(sent.namespace, "erp-team");
        assert!(sent.messages.is_empty() && sent.tools.is_empty());
        let input: Value =
            serde_json::from_str(sent.spec.strip_prefix("Drafted members:\n").unwrap()).unwrap();
        assert_eq!(
            input,
            serde_json::json!({
                "object_types": [
                    {"id": "customer", "properties": [{"name": "id", "type": "string"}]},
                    {"id": "shipment", "properties": [
                        {"name": "id", "type": "string"},
                        {"name": "cust_id", "type": "string"},
                        {"name": "shp_stat_cd", "type": "string", "findings": ["nullable_reference"]},
                    ]},
                ],
                "link_types": [{
                    "id": "shipment_cust_id_customer",
                    "from": "shipment",
                    "to": "customer",
                    "columns": ["cust_id"],
                }],
            })
        );
        let whole_request = format!("{}\n{}", sent.system, sent.spec);
        for sampled in ["7777", "6666", "5555", "4321", "1234", "98765", "ledger9"] {
            assert!(
                !whole_request.contains(sampled),
                "{sampled} reached the model"
            );
        }

        assert_eq!(record.model, "fake/describer");
        assert_eq!(record.plan_id, "plan-1");
        assert_eq!(record.request_id, sent.request_id);
        let report: Value = serde_json::from_str(&draft.tree[REPORT_FILE]).unwrap();
        assert_eq!(report["describe"], serde_json::to_value(&record).unwrap());

        let shipment: Value =
            serde_json::from_str(&draft.tree["object_type/shipment.json"]).unwrap();
        assert_eq!(shipment["description"], "A parcel sent to a customer.");
        assert_eq!(
            shipment["alternative_names"],
            serde_json::json!(["parcel", "consignment"])
        );
        assert_eq!(
            shipment["property_alternative_names"]["shp_stat_cd"],
            serde_json::json!(["shipment status"])
        );
        assert_eq!(
            shipment["unreviewed"],
            serde_json::json!([
                "alternative_names",
                "description",
                "property_alternative_names/shp_stat_cd",
                "property_descriptions/shp_stat_cd",
            ])
        );
        let link: Value =
            serde_json::from_str(&draft.tree["link_type/shipment_cust_id_customer.json"]).unwrap();
        assert_eq!(link["unreviewed"], serde_json::json!(["description"]));
        assert!(
            !draft.tree["object_type/customer.json"].contains("unreviewed"),
            "a member without a proposal is unchanged"
        );
    }

    #[tokio::test]
    async fn an_invented_member_or_a_prose_answer_changes_nothing() {
        let original = draft_tree(&shipments(), None, &[]).unwrap();
        for answer in [
            r#"{"object_types":{"invoice":{"description":"Made up."}}}"#,
            r#"{"object_types":{"shipment":{"properties":{"weight":{"description":"Made up."}}}}}"#,
            "Here are some ideas.",
        ] {
            let (target, server) = serve(FakeChisei {
                executable: true,
                answer: answer.into(),
                ..Default::default()
            })
            .await;
            let mut draft = original.clone();
            let error = describe(&target, "erp-team", &mut draft).await.unwrap_err();
            server.abort();
            assert_eq!(error.code(), "describe_invalid_proposal", "{error}");
            assert_eq!(draft, original, "{error}");
        }
    }

    fn read_tree(dir: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(path) = pending.pop() {
            for entry in std::fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let rel = path.strip_prefix(dir).unwrap().display().to_string();
                    files.insert(rel, std::fs::read(&path).unwrap());
                }
            }
        }
        files
    }

    #[tokio::test]
    async fn a_draft_without_describe_calls_no_model_and_a_refused_call_leaves_the_tree() {
        use crate::ontology_draft::{DraftOptions, run};
        let chisei = FakeChisei::default();
        let (target, server) = serve(chisei.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let discovery = dir.path().join("discovery.json");
        std::fs::write(&discovery, serde_json::to_vec(&shipments()).unwrap()).unwrap();
        let out = dir.path().join("tree");
        let options = DraftOptions {
            namespace: Some("erp-team"),
            ..Default::default()
        };
        run(&target, &discovery, &out, options).await.unwrap();
        assert!(chisei.planned.lock().unwrap().is_empty());
        let before = read_tree(&out);

        let error = run(
            &target,
            &discovery,
            &out,
            DraftOptions {
                update: true,
                describe: true,
                ..options
            },
        )
        .await
        .unwrap_err();
        server.abort();
        let error = error.downcast_ref::<DescribeError>().unwrap();
        assert_eq!(error.code(), "describe_no_model_route", "{error}");
        assert_eq!(chisei.planned.lock().unwrap().len(), 1);
        assert_eq!(read_tree(&out), before);
    }
}
