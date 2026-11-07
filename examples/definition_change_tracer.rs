//! Tracer fixture for the agent-driven definition-change path (#2096).
//!
//! An isolated in-memory plane runs the stable MCP draft-and-propose tools,
//! admits a source batch, validates a link, then has a second principal
//! approve and merge over gRPC. Approve and merge stay off MCP.
//!
//! ```bash
//! cargo run --locked --example definition_change_tracer
//! cargo test --locked --test definition_change_tracer_example
//! ```

use std::collections::BTreeMap;

use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    ApplySourceBatchRequest, ApproveDefinitionProposalRequest, EnsureTeamNamespaceRequest,
    MergeDefinitionProposalRequest, SourceBatch, SourceRecord,
};
use sekai_chisei::mcp_adapter::{InProcessSurface, handle_message};
use sekai_chisei::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_VERSION, SOURCE_GITHUB,
    SourceBatch as DomainBatch,
};
use sekai_source_sdk::{GitHubObjectFixture, translate_github_fixture};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tonic::Request;
use tonic::metadata::MetadataValue;

const DOMAIN_PACKAGE: &str = include_str!("definition-change-tracer/domain-v1.json");
const SOURCE_PACKAGE: &str = include_str!("definition-change-tracer/source-v1.json");
const HUMAN: &str = "root";
const CONNECTOR: &str = "connector.tracer";
const BRANCH_ID: &str = "tracer";
const PROPOSAL_ID: &str = "tracer-proposal";

#[derive(Debug, Deserialize)]
struct DomainPackage {
    contract_version: String,
    object_type: DomainObjectType,
    link: DomainLink,
}

#[derive(Debug, Deserialize)]
struct DomainObjectType {
    member_kind: String,
    member_id: String,
    definition: Value,
}

#[derive(Debug, Deserialize)]
struct DomainLink {
    relation: String,
}

#[derive(Debug, Deserialize)]
struct SourcePackage {
    contract_version: String,
    source: String,
    source_instance: String,
    records: Vec<SourceFixtureRecord>,
}

#[derive(Debug, Deserialize)]
struct SourceFixtureRecord {
    external_id: String,
    source_version: String,
    kind: String,
    title: String,
    state: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub contract_version: String,
    pub source_contract_version: String,
    pub namespace: String,
    pub agent_principal: String,
    pub human_principal: String,
    pub branch_id: String,
    pub parent_revision_digest: String,
    pub candidate_revision_digest: String,
    pub source_transaction_id: String,
    pub ingested_object_ids: Vec<String>,
    pub link_id: String,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub approval_actor: String,
    pub merge_receipt_id: String,
    pub agent_approve_denied: bool,
}

fn call(id: i64, name: &str, input: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": {"operation_id": format!("op-tracer-{id}"), "input": input}
        }
    })
}

fn output(reply: &Value) -> Result<&Value, String> {
    if reply["result"]["isError"] == true {
        return Err(format!("mcp tool error: {reply}"));
    }
    reply["result"]["structuredContent"]["output"]
        .as_object()
        .map(|_| &reply["result"]["structuredContent"]["output"])
        .ok_or_else(|| format!("mcp tool missing output: {reply}"))
}

fn with_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut request = Request::new(payload);
    request.metadata_mut().insert(
        "x-principal",
        MetadataValue::try_from(principal).expect("principal"),
    );
    request
}

fn source_batch(namespace: &str, package: &SourcePackage) -> Result<SourceBatch, String> {
    if package.source != SOURCE_GITHUB {
        return Err(format!("source {} is not github", package.source));
    }
    let records = package
        .records
        .iter()
        .map(|record| {
            let number = record.external_id.parse::<u64>().map_err(|_| {
                format!("external_id {} is not a GitHub number", record.external_id)
            })?;
            translate_github_fixture(
                GitHubObjectFixture {
                    repository: package.source_instance.clone(),
                    kind: record.kind.clone(),
                    number,
                    revision: record.source_version.clone(),
                    title: record.title.clone(),
                    state: record.state.clone(),
                    deleted: false,
                    observed_at_ms: 10,
                    properties: BTreeMap::new(),
                },
                &package.source_instance,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut domain = DomainBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: namespace.into(),
        producer_identity: CONNECTOR.into(),
        source: SOURCE_GITHUB.into(),
        source_instance: package.source_instance.clone(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        current_cursor: String::new(),
        proposed_next_cursor: "cursor:1".into(),
        idempotency_key: "tracer-ingest".into(),
        batch_digest: String::new(),
        collected_at_ms: 20,
        records,
        delivery: None,
    };
    domain.batch_digest = domain
        .canonical_digest()
        .map_err(|error| error.to_string())?;
    domain.validate().map_err(|error| error.to_string())?;
    Ok(SourceBatch {
        contract_version: domain.contract_version,
        namespace: domain.namespace,
        producer_identity: domain.producer_identity,
        source: domain.source,
        source_instance: domain.source_instance,
        family: domain.family,
        adapter_id: domain.adapter_id,
        adapter_version: domain.adapter_version,
        type_digest: domain.type_digest,
        current_cursor: domain.current_cursor,
        proposed_next_cursor: domain.proposed_next_cursor,
        idempotency_key: domain.idempotency_key,
        batch_digest: domain.batch_digest,
        collected_at_ms: domain.collected_at_ms,
        records: domain
            .records
            .into_iter()
            .map(|record| SourceRecord {
                source: record.source,
                source_instance: record.source_instance,
                external_id: record.external_id,
                source_version: record.source_version,
                type_name: record.type_name,
                display_name: record.display_name,
                payload_digest: record.payload_digest,
                properties: record.properties.into_iter().collect(),
                deleted: record.deleted,
                observed_at_ms: record.observed_at_ms,
                source_sequence: record.source_sequence,
            })
            .collect(),
        delivery: None,
    })
}

pub fn run() -> Result<Report, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(run_async())
}

async fn run_async() -> Result<Report, String> {
    let domain: DomainPackage =
        serde_json::from_str(DOMAIN_PACKAGE).map_err(|error| error.to_string())?;
    let source: SourcePackage =
        serde_json::from_str(SOURCE_PACKAGE).map_err(|error| error.to_string())?;
    let mut surface = InProcessSurface::synthetic()
        .await
        .map_err(|error| error.to_string())?;
    surface.experimental_rpcs = false;

    let created = handle_message(
        &surface,
        call(
            1,
            "sekai.definitions.branch.create",
            json!({
                "branchId": BRANCH_ID,
                "parentRevisionDigest": "",
                "idempotencyKey": "tracer-create"
            }),
        ),
    )
    .await
    .ok_or_else(|| "create branch returned no reply".to_string())?;
    let parent = output(&created)?["branch"]["headRevisionDigest"]
        .as_str()
        .ok_or_else(|| format!("create branch missing digest: {created}"))?
        .to_string();

    let edited = handle_message(
        &surface,
        call(
            2,
            "sekai.definitions.branch.edit",
            json!({
                "branchId": BRANCH_ID,
                "expectedHeadDigest": parent,
                "upserts": [{
                    "memberKind": domain.object_type.member_kind,
                    "memberId": domain.object_type.member_id,
                    "definitionJson": domain.object_type.definition.to_string(),
                    "memberDigest": ""
                }],
                "removals": [],
                "idempotencyKey": "tracer-edit"
            }),
        ),
    )
    .await
    .ok_or_else(|| "edit branch returned no reply".to_string())?;
    let candidate = output(&edited)?["revision"]["revisionDigest"]
        .as_str()
        .ok_or_else(|| format!("edit branch missing digest: {edited}"))?
        .to_string();

    surface
        .sekai
        .ensure_team_namespace(with_principal(
            EnsureTeamNamespaceRequest {
                namespace: surface.namespace.clone(),
                principal: CONNECTOR.into(),
                role: "editor".into(),
            },
            HUMAN,
        ))
        .await
        .map_err(|error| error.message().to_string())?;

    let ingested = surface
        .sekai
        .apply_source_batch(with_principal(
            ApplySourceBatchRequest {
                batch: Some(source_batch(&surface.namespace, &source)?),
            },
            CONNECTOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner()
        .result
        .ok_or_else(|| "ApplySourceBatch returned no result".to_string())?;
    let source_status = ingested
        .transaction
        .as_ref()
        .map(|transaction| transaction.status.as_str())
        .unwrap_or_default();
    if source_status != "COMMITTED" {
        return Err(format!("source batch status {source_status}"));
    }
    let source_transaction_id = ingested
        .transaction
        .as_ref()
        .map(|transaction| transaction.transaction_id.clone())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "source batch missing transaction id".to_string())?;
    let ingested_object_ids: Vec<String> = ingested
        .records
        .iter()
        .filter_map(|record| {
            record
                .object
                .as_ref()
                .map(|object| object.object_id.clone())
        })
        .collect();
    if ingested_object_ids.len() < 2 {
        return Err(format!(
            "expected two ingested objects, got {ingested_object_ids:?}"
        ));
    }

    let linked = handle_message(
        &surface,
        call(
            3,
            "sekai.links.create",
            json!({
                "from_id": ingested_object_ids[0],
                "to_id": ingested_object_ids[1],
                "relation": domain.link.relation
            }),
        ),
    )
    .await
    .ok_or_else(|| "create link returned no reply".to_string())?;
    let link_id = output(&linked)?["link"]["id"]
        .as_str()
        .ok_or_else(|| format!("create link missing id: {linked}"))?
        .to_string();
    let listed = handle_message(
        &surface,
        call(
            4,
            "sekai.links.get",
            json!({
                "object_id": ingested_object_ids[0],
                "relation": domain.link.relation
            }),
        ),
    )
    .await
    .ok_or_else(|| "get links returned no reply".to_string())?;
    let links = output(&listed)?["links"]
        .as_array()
        .ok_or_else(|| format!("get links missing array: {listed}"))?;
    if !links.iter().any(|link| link["id"] == link_id) {
        return Err(format!("created link {link_id} missing from {listed}"));
    }

    let diff = handle_message(
        &surface,
        call(
            5,
            "sekai.definitions.diff",
            json!({
                "fromRevisionDigest": parent,
                "toRevisionDigest": candidate
            }),
        ),
    )
    .await
    .ok_or_else(|| "diff returned no reply".to_string())?;
    output(&diff)?;
    let impact = handle_message(
        &surface,
        call(
            6,
            "sekai.definitions.impact",
            json!({
                "fromRevisionDigest": parent,
                "toRevisionDigest": candidate
            }),
        ),
    )
    .await
    .ok_or_else(|| "impact returned no reply".to_string())?;
    output(&impact)?;
    let proposed = handle_message(
        &surface,
        call(
            7,
            "sekai.definitions.proposal.create",
            json!({
                "branchId": BRANCH_ID,
                "proposalId": PROPOSAL_ID,
                "baseDigest": parent,
                "candidateDigest": candidate,
                "evalPlanDigests": [],
                "namedForeignDigests": [],
                "idempotencyKey": "tracer-propose"
            }),
        ),
    )
    .await
    .ok_or_else(|| "create proposal returned no reply".to_string())?;
    let proposal_digest = output(&proposed)?["proposal"]["proposalDigest"]
        .as_str()
        .ok_or_else(|| format!("create proposal missing digest: {proposed}"))?
        .to_string();

    let agent_denied = surface
        .sekai
        .approve_definition_proposal(with_principal(
            ApproveDefinitionProposalRequest {
                namespace: surface.namespace.clone(),
                proposal_id: PROPOSAL_ID.into(),
                idempotency_key: "tracer-approve-agent".into(),
            },
            &surface.principal,
        ))
        .await
        .err()
        .filter(|error| error.code() == tonic::Code::PermissionDenied)
        .is_some();
    if !agent_denied {
        return Err("creating agent was not refused on approve".into());
    }

    let approved = surface
        .sekai
        .approve_definition_proposal(with_principal(
            ApproveDefinitionProposalRequest {
                namespace: surface.namespace.clone(),
                proposal_id: PROPOSAL_ID.into(),
                idempotency_key: "tracer-approve-human".into(),
            },
            HUMAN,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner()
        .proposal
        .ok_or_else(|| "approve returned no proposal".to_string())?;
    let approval_actor = approved
        .approvals
        .first()
        .map(|approval| approval.actor.clone())
        .filter(|actor| !actor.is_empty())
        .ok_or_else(|| "approve left no actor on the proposal".to_string())?;

    let merged = surface
        .sekai
        .merge_definition_proposal(with_principal(
            MergeDefinitionProposalRequest {
                namespace: surface.namespace.clone(),
                proposal_id: PROPOSAL_ID.into(),
                expected_published_digest: parent.clone(),
                idempotency_key: "tracer-merge-human".into(),
            },
            HUMAN,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner();
    if merged.receipt_id.is_empty() {
        return Err("merge stored no receipt_id".into());
    }

    Ok(Report {
        contract_version: domain.contract_version,
        source_contract_version: source.contract_version,
        namespace: surface.namespace,
        agent_principal: surface.principal,
        human_principal: HUMAN.into(),
        branch_id: BRANCH_ID.into(),
        parent_revision_digest: parent,
        candidate_revision_digest: candidate,
        source_transaction_id,
        ingested_object_ids,
        link_id,
        proposal_id: PROPOSAL_ID.into(),
        proposal_digest,
        approval_actor,
        merge_receipt_id: merged.receipt_id,
        agent_approve_denied: agent_denied,
    })
}

#[allow(dead_code)]
pub fn main() {
    match run() {
        Ok(report) => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report is serializable")
        ),
        Err(error) => {
            eprintln!("definition-change tracer failed: {error}");
            std::process::exit(1);
        }
    }
}
