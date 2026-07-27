//! Product-loop CLI for ontology-first onboarding (#385 / research #383).
//!
//! Subcommands (under `sekaictl ontology`):
//! - `apply`  — create ontology classes/relations; ensure ObjectTypes when needed
//! - `seed`   — create objects and links under a namespace
//! - `run`    — plan + execute one governed operation (lookup-first friendly)
//! - `first-run` — apply → seed → lookup-first resolve → print receipt id
//!
//! All mutations go through public authenticated gRPC (same ACL/audit as native
//! clients). No second trust path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tonic::Request;

use crate::chisei::lookup_first;
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::{
    ExecutePlanRequest, ExecutionInput, GetOperationReceiptRequest, PlanExecutionRequest,
};
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    CreateLinkRequest, CreateObjectRequest, CreateOntologyClassRequest,
    CreateOntologyRelationRequest, CreateSchemaTypeRequest, Link, Object, ObjectType,
    OntologyClass, OntologyRelation,
};
use crate::sekai::schema::is_builtin_schema_kind;
use crate::sekai::semantic;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub const DOMAIN_DOC_VERSION: &str = "sekai.ontology-product/v1";
pub const SEED_DOC_VERSION: &str = "sekai.seed/v1";

pub fn usage() -> &'static str {
    "sekaictl ontology <inspect|apply|seed|run|first-run> ...\n  \
     sekaictl ontology apply --file <domain.json> [--target <url-or-socket>]\n  \
     sekaictl ontology seed --file <seed.json> [--target <url-or-socket>]\n  \
     sekaictl ontology run --namespace <ns> --task-type <capability> --spec <json-or-@file> [--target ...]\n  \
     sekaictl ontology first-run --domain <domain.json> --seed <seed.json> [--resolve-object <id>] [--target ...]\n  \
     sekaictl ontology inspect ...  (see inspect --help path)"
}

fn default_target() -> String {
    std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into())
}

fn require_flag(args: &[String], flag: &str) -> Result<String, String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .ok_or_else(|| format!("{flag} is required"))
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn target_from_args(args: &[String]) -> String {
    flag_value(args, "--target").unwrap_or_else(default_target)
}

// --- Documents ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainDocument {
    pub version: String,
    #[serde(default)]
    pub classes: Vec<DomainClass>,
    #[serde(default)]
    pub relations: Vec<DomainRelation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainClass {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Object kind used when seeding instances of this class. Empty = no kind bind.
    #[serde(default)]
    pub mapped_kind: String,
    /// When true (or when mapped_kind is non-empty and not builtin), create ObjectType first.
    #[serde(default)]
    pub ensure_kind: bool,
    #[serde(default)]
    pub kind_description: String,
    #[serde(default)]
    pub superclasses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainRelation {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub domain: String,
    pub range: String,
    #[serde(default)]
    pub mapped_relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedDocument {
    pub version: String,
    pub namespace: String,
    #[serde(default)]
    pub objects: Vec<SeedObject>,
    #[serde(default)]
    pub links: Vec<SeedLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedObject {
    pub id: String,
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub external_id: String,
    #[serde(default)]
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedLink {
    #[serde(default)]
    pub id: String,
    pub from: String,
    pub to: String,
    pub relation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    pub kinds_ensured: Vec<String>,
    pub classes_created: Vec<String>,
    pub relations_created: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedReport {
    pub objects_created: Vec<String>,
    pub links_created: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub request_id: String,
    pub plan_id: String,
    pub executable: bool,
    pub resolved_model: String,
    pub content_preview: String,
    pub provider: String,
    pub stop_reason: String,
}

pub fn load_domain_document(path: &Path) -> Result<DomainDocument, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read domain file: {e}"))?;
    parse_domain_document(&raw)
}

pub fn parse_domain_document(raw: &str) -> Result<DomainDocument, String> {
    let doc: DomainDocument =
        serde_json::from_str(raw).map_err(|e| format!("parse domain document: {e}"))?;
    validate_domain_document(&doc)?;
    Ok(doc)
}

pub fn validate_domain_document(doc: &DomainDocument) -> Result<(), String> {
    if doc.version != DOMAIN_DOC_VERSION {
        return Err(format!(
            "domain document version must be {DOMAIN_DOC_VERSION}, got {:?}",
            doc.version
        ));
    }
    if doc.classes.is_empty() && doc.relations.is_empty() {
        return Err("domain document must list at least one class or relation".into());
    }
    for class in &doc.classes {
        if class.name.trim().is_empty() {
            return Err("class name must not be empty".into());
        }
        if class.name.len() > 128 {
            return Err(format!("class name {:?} is too long", class.name));
        }
    }
    for rel in &doc.relations {
        if rel.name.trim().is_empty() {
            return Err("relation name must not be empty".into());
        }
        if rel.domain.trim().is_empty() || rel.range.trim().is_empty() {
            return Err(format!("relation {:?} requires domain and range", rel.name));
        }
    }
    Ok(())
}

pub fn load_seed_document(path: &Path) -> Result<SeedDocument, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read seed file: {e}"))?;
    parse_seed_document(&raw)
}

pub fn parse_seed_document(raw: &str) -> Result<SeedDocument, String> {
    let doc: SeedDocument =
        serde_json::from_str(raw).map_err(|e| format!("parse seed document: {e}"))?;
    validate_seed_document(&doc)?;
    Ok(doc)
}

pub fn validate_seed_document(doc: &SeedDocument) -> Result<(), String> {
    if doc.version != SEED_DOC_VERSION {
        return Err(format!(
            "seed document version must be {SEED_DOC_VERSION}, got {:?}",
            doc.version
        ));
    }
    if doc.namespace.trim().is_empty() {
        return Err("seed document namespace must not be empty".into());
    }
    if doc.objects.is_empty() {
        return Err("seed document must list at least one object".into());
    }
    for obj in &doc.objects {
        if obj.id.trim().is_empty() || obj.kind.trim().is_empty() || obj.name.trim().is_empty() {
            return Err("each seed object requires id, kind, and name".into());
        }
    }
    for link in &doc.links {
        if link.from.trim().is_empty()
            || link.to.trim().is_empty()
            || link.relation.trim().is_empty()
        {
            return Err("each seed link requires from, to, and relation".into());
        }
    }
    Ok(())
}

/// Whether apply should call CreateSchemaType for this class before the ontology class.
pub fn should_ensure_kind(class: &DomainClass) -> bool {
    let kind = class.mapped_kind.trim();
    if kind.is_empty() {
        return false;
    }
    if class.ensure_kind {
        return true;
    }
    // Ontology create requires mapped_kind schema to exist when set.
    // Builtins already exist; custom kinds need ensure.
    !is_builtin_schema_kind(kind)
}

// --- gRPC apply / seed / run --------------------------------------------------

pub async fn apply_domain(target: &str, doc: &DomainDocument) -> Result<ApplyReport, BoxErr> {
    let channel = connect_sekai(target).await?;
    let mut client = SekaiServiceClient::new(channel);
    let mut report = ApplyReport {
        kinds_ensured: Vec::new(),
        classes_created: Vec::new(),
        relations_created: Vec::new(),
    };

    // Superclasses first: sort so dependents follow dependents when possible.
    let mut classes = doc.classes.clone();
    classes.sort_by_key(|a| a.superclasses.len());

    for class in &classes {
        if should_ensure_kind(class) {
            let kind = class.mapped_kind.trim();
            let description = if class.kind_description.trim().is_empty() {
                format!("Object kind for ontology class {}", class.name)
            } else {
                class.kind_description.clone()
            };
            let response = client
                .create_schema_type(Request::new(CreateSchemaTypeRequest {
                    r#type: Some(ObjectType {
                        kind: kind.to_string(),
                        description,
                        properties: Vec::new(),
                        is_builtin: false,
                        implements: Vec::new(),
                    }),
                }))
                .await;
            match response {
                Ok(_) => report.kinds_ensured.push(kind.to_string()),
                Err(status) if status.code() == tonic::Code::AlreadyExists => {
                    // Idempotent re-apply.
                }
                Err(status)
                    if status.message().contains("already")
                        || status.message().contains("exists") =>
                {
                    // Some paths return invalid_argument for duplicates.
                }
                Err(status) => {
                    // If kind already registered, create_schema_type may still
                    // fail validation on replace; treat "already present" soft.
                    let msg = status.message().to_string();
                    if msg.contains("builtin") {
                        return Err(format!(
                            "ensure kind {kind:?} failed: {msg} (do not ensure_kind for builtins)"
                        )
                        .into());
                    }
                    // Retry path: list is expensive; re-attempt ontology after soft fail only when
                    // message indicates conflict. Otherwise surface.
                    if !msg.contains("duplicate") && !msg.contains("already") {
                        // Kind may already be loaded from a prior apply; continue and let
                        // ontology create fail closed if missing.
                        eprintln!("warning: ensure kind {kind:?}: {msg}");
                    }
                }
            }
        }

        let created = client
            .create_ontology_class(Request::new(CreateOntologyClassRequest {
                class: Some(OntologyClass {
                    name: class.name.clone(),
                    description: class.description.clone(),
                    superclasses: class.superclasses.clone(),
                    equivalent_classes: Vec::new(),
                    disjoint_classes: Vec::new(),
                    properties: Vec::new(),
                    is_builtin: false,
                    mapped_kind: class.mapped_kind.clone(),
                }),
            }))
            .await;
        match created {
            Ok(_) => report.classes_created.push(class.name.clone()),
            Err(status) => {
                let msg = status.message().to_string();
                if msg.contains("already") || msg.contains("exists") || msg.contains("duplicate") {
                    eprintln!("warning: class {:?} already present: {msg}", class.name);
                } else {
                    return Err(format!(
                        "create ontology class {:?}: {msg}. Hint: mapped_kind must exist as a schema type (apply ensures non-builtin kinds; builtins need no ensure).",
                        class.name
                    )
                    .into());
                }
            }
        }
    }

    for rel in &doc.relations {
        let created = client
            .create_ontology_relation(Request::new(CreateOntologyRelationRequest {
                relation: Some(OntologyRelation {
                    name: rel.name.clone(),
                    description: rel.description.clone(),
                    domain: rel.domain.clone(),
                    range: rel.range.clone(),
                    cardinality: None,
                    inverse: String::new(),
                    transitive: false,
                    is_builtin: false,
                    mapped_relation: if rel.mapped_relation.is_empty() {
                        rel.name.clone()
                    } else {
                        rel.mapped_relation.clone()
                    },
                }),
            }))
            .await;
        match created {
            Ok(_) => report.relations_created.push(rel.name.clone()),
            Err(status) => {
                let msg = status.message().to_string();
                if msg.contains("already") || msg.contains("exists") || msg.contains("duplicate") {
                    eprintln!("warning: relation {:?} already present: {msg}", rel.name);
                } else {
                    return Err(format!("create ontology relation {:?}: {msg}", rel.name).into());
                }
            }
        }
    }

    Ok(report)
}

pub async fn seed_graph(target: &str, doc: &SeedDocument) -> Result<SeedReport, BoxErr> {
    let channel = connect_sekai(target).await?;
    let mut client = SekaiServiceClient::new(channel);
    let mut report = SeedReport {
        objects_created: Vec::new(),
        links_created: Vec::new(),
    };

    for obj in &doc.objects {
        let created = client
            .create_object(Request::new(CreateObjectRequest {
                object: Some(Object {
                    id: obj.id.clone(),
                    kind: obj.kind.clone(),
                    name: obj.name.clone(),
                    namespace: doc.namespace.clone(),
                    external_id: obj.external_id.clone(),
                    properties: obj.properties.clone(),
                    created: 0,
                    updated: 0,
                }),
                lease_precondition: None,
            }))
            .await;
        match created {
            Ok(_) => report.objects_created.push(obj.id.clone()),
            Err(status) => {
                let msg = status.message().to_string();
                if msg.contains("already") || msg.contains("exists") || msg.contains("UNIQUE") {
                    eprintln!("warning: object {:?} already present: {msg}", obj.id);
                } else {
                    return Err(format!(
                        "create object {:?}: {msg}. Hint: kind must be a loaded schema type (use domain apply ensure_kind or a builtin kind such as component).",
                        obj.id
                    )
                    .into());
                }
            }
        }
    }

    for (idx, link) in doc.links.iter().enumerate() {
        let id = if link.id.trim().is_empty() {
            format!("link-{}-{}", link.relation, idx)
        } else {
            link.id.clone()
        };
        let created = client
            .create_link(Request::new(CreateLinkRequest {
                link: Some(Link {
                    id: id.clone(),
                    from_id: link.from.clone(),
                    to_id: link.to.clone(),
                    relation: link.relation.clone(),
                    created: 0,
                }),
                fail_if_exists: false,
            }))
            .await;
        match created {
            Ok(_) => report.links_created.push(id),
            Err(status) => {
                return Err(format!("create link {id:?}: {}", status.message()).into());
            }
        }
    }

    Ok(report)
}

pub async fn plan_and_execute(
    target: &str,
    namespace: &str,
    task_type: &str,
    spec: &str,
) -> Result<RunReport, BoxErr> {
    let channel = connect_sekai(target).await?;
    let mut client = ChiseiServiceClient::new(channel);
    let request_id = format!("product-loop-{}", uuid::Uuid::new_v4().simple());
    let input = ExecutionInput {
        request_id: request_id.clone(),
        namespace: namespace.to_string(),
        spec: spec.to_string(),
        preferred_model: String::new(),
        preferred_runtime: String::new(),
        task_type: task_type.to_string(),
        priority: 5,
        user_id: String::new(),
        estimated_tokens: 0,
        messages: Vec::new(),
        tools: Vec::new(),
        system: String::new(),
        max_tokens: 256,
        task_class: String::new(),
        logical_operation_id: String::new(),
        attempt_id: String::new(),
        route_override: String::new(),
    };

    let plan = client
        .plan_execution(Request::new(PlanExecutionRequest { input: Some(input) }))
        .await?
        .into_inner()
        .plan
        .ok_or("plan_execution returned empty plan")?;

    let plan_id = plan.plan_id.clone();
    let executable = plan.executable;
    let resolved_model = plan.resolved_model.clone();

    if !executable {
        return Ok(RunReport {
            request_id,
            plan_id,
            executable: false,
            resolved_model,
            content_preview: String::new(),
            provider: String::new(),
            stop_reason: "plan_not_executable".into(),
        });
    }

    let response = client
        .execute_plan(Request::new(ExecutePlanRequest { plan: Some(plan) }))
        .await?
        .into_inner();

    let (content, provider, stop_reason) = match response.response {
        Some(chat) => (chat.content, chat.provider, chat.stop_reason),
        None => (String::new(), String::new(), String::new()),
    };
    let preview: String = content.chars().take(240).collect();

    Ok(RunReport {
        request_id,
        plan_id,
        executable: true,
        resolved_model,
        content_preview: preview,
        provider,
        stop_reason,
    })
}

pub async fn fetch_receipt_json(target: &str, request_id: &str) -> Result<String, BoxErr> {
    let channel = connect_sekai(target).await?;
    let mut client = ChiseiServiceClient::new(channel);
    let response = client
        .get_operation_receipt(Request::new(GetOperationReceiptRequest {
            operation_id: String::new(),
            request_id: request_id.to_string(),
            caller_scope: String::new(),
            attempt: 0,
        }))
        .await?
        .into_inner();
    Ok(response.receipt_json)
}

// --- CLI entry ----------------------------------------------------------------

pub async fn run_ontology_product_command(args: Vec<String>) -> Result<(), BoxErr> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err(std::io::Error::other(usage()).into());
    };
    match sub {
        "apply" => {
            let rest = &args[1..];
            let file = require_flag(rest, "--file").map_err(std::io::Error::other)?;
            let target = target_from_args(rest);
            let doc = load_domain_document(Path::new(&file)).map_err(std::io::Error::other)?;
            let report = apply_domain(&target, &doc).await?;
            println!(
                "applied domain: kinds={} classes={} relations={}",
                report.kinds_ensured.len(),
                report.classes_created.len(),
                report.relations_created.len()
            );
            for k in &report.kinds_ensured {
                println!("  kind ensured: {k}");
            }
            for c in &report.classes_created {
                println!("  class: {c}");
            }
            for r in &report.relations_created {
                println!("  relation: {r}");
            }
            Ok(())
        }
        "seed" => {
            let rest = &args[1..];
            let file = require_flag(rest, "--file").map_err(std::io::Error::other)?;
            let target = target_from_args(rest);
            let doc = load_seed_document(Path::new(&file)).map_err(std::io::Error::other)?;
            let report = seed_graph(&target, &doc).await?;
            println!(
                "seeded namespace {:?}: objects={} links={}",
                doc.namespace,
                report.objects_created.len(),
                report.links_created.len()
            );
            for id in &report.objects_created {
                println!("  object: {id}");
            }
            for id in &report.links_created {
                println!("  link: {id}");
            }
            Ok(())
        }
        "run" => {
            let rest = &args[1..];
            let namespace = require_flag(rest, "--namespace").map_err(std::io::Error::other)?;
            let task_type = require_flag(rest, "--task-type").map_err(std::io::Error::other)?;
            let spec_arg = require_flag(rest, "--spec").map_err(std::io::Error::other)?;
            let target = target_from_args(rest);
            let spec = load_spec(&spec_arg).map_err(std::io::Error::other)?;
            let report = plan_and_execute(&target, &namespace, &task_type, &spec).await?;
            println!(
                "run request_id={} plan_id={} executable={} model={} provider={} stop={}",
                report.request_id,
                report.plan_id,
                report.executable,
                report.resolved_model,
                report.provider,
                report.stop_reason
            );
            if !report.content_preview.is_empty() {
                println!("content: {}", report.content_preview);
            }
            Ok(())
        }
        "first-run" => {
            let rest = &args[1..];
            let domain_path = require_flag(rest, "--domain").map_err(std::io::Error::other)?;
            let seed_path = require_flag(rest, "--seed").map_err(std::io::Error::other)?;
            let target = target_from_args(rest);
            let resolve_object = flag_value(rest, "--resolve-object");

            let domain =
                load_domain_document(Path::new(&domain_path)).map_err(std::io::Error::other)?;
            let seed = load_seed_document(Path::new(&seed_path)).map_err(std::io::Error::other)?;

            let apply = apply_domain(&target, &domain).await?;
            println!(
                "1/3 apply: kinds={} classes={} relations={}",
                apply.kinds_ensured.len(),
                apply.classes_created.len(),
                apply.relations_created.len()
            );

            let seeded = seed_graph(&target, &seed).await?;
            println!(
                "2/3 seed: objects={} links={}",
                seeded.objects_created.len(),
                seeded.links_created.len()
            );

            let object_id = resolve_object
                .or_else(|| seed.objects.first().map(|o| o.id.clone()))
                .ok_or_else(|| std::io::Error::other("seed has no objects to resolve"))?;
            let spec = serde_json::to_string(&lookup_first::ResolveRefInput {
                object_id: object_id.clone(),
                ..Default::default()
            })?;

            let run = plan_and_execute(
                &target,
                &seed.namespace,
                semantic::CAPABILITY_RESOLVE_REF,
                &spec,
            )
            .await?;
            println!(
                "3/3 run: request_id={} executable={} provider={} stop={}",
                run.request_id, run.executable, run.provider, run.stop_reason
            );
            if !run.content_preview.is_empty() {
                println!("content: {}", run.content_preview);
            }

            match fetch_receipt_json(&target, &run.request_id).await {
                Ok(json) if !json.is_empty() => {
                    println!(
                        "receipt: available for request_id={} (use: sekaictl receipt {} --request-id)",
                        run.request_id, run.request_id
                    );
                }
                Ok(_) => {
                    println!(
                        "receipt: empty or not yet visible; try sekaictl receipt {} --request-id",
                        run.request_id
                    );
                }
                Err(err) => {
                    eprintln!(
                        "receipt: fetch failed ({err}); try sekaictl receipt {} --request-id",
                        run.request_id
                    );
                }
            }
            Ok(())
        }
        "inspect" => Err(std::io::Error::other(
            "use sekaictl ontology inspect via the main dispatcher",
        )
        .into()),
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

fn load_spec(arg: &str) -> Result<String, String> {
    if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(PathBuf::from(path)).map_err(|e| format!("read --spec file: {e}"))
    } else {
        Ok(arg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DOMAIN: &str = r#"{
      "version": "sekai.ontology-product/v1",
      "classes": [
        {
          "name": "Service",
          "description": "A deployable service",
          "mapped_kind": "component"
        },
        {
          "name": "Incident",
          "description": "An operational incident",
          "mapped_kind": "incident",
          "ensure_kind": true,
          "kind_description": "Incident object kind"
        }
      ],
      "relations": [
        {
          "name": "affects",
          "domain": "Incident",
          "range": "Service",
          "description": "Incident affects service"
        }
      ]
    }"#;

    const SAMPLE_SEED: &str = r#"{
      "version": "sekai.seed/v1",
      "namespace": "demo",
      "objects": [
        {
          "id": "svc-api",
          "kind": "component",
          "name": "billing-api",
          "properties": { "tier": "prod" }
        },
        {
          "id": "inc-1",
          "kind": "incident",
          "name": "elevated latency"
        }
      ],
      "links": [
        {
          "from": "inc-1",
          "to": "svc-api",
          "relation": "affects"
        }
      ]
    }"#;

    #[test]
    fn parses_and_validates_domain_document() {
        let doc = parse_domain_document(SAMPLE_DOMAIN).unwrap();
        assert_eq!(doc.classes.len(), 2);
        assert_eq!(doc.relations.len(), 1);
        assert!(!should_ensure_kind(&doc.classes[0])); // builtin component
        assert!(should_ensure_kind(&doc.classes[1])); // custom incident
    }

    #[test]
    fn rejects_wrong_domain_version() {
        let err =
            parse_domain_document(r#"{"version":"v0","classes":[{"name":"A"}]}"#).unwrap_err();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn parses_and_validates_seed_document() {
        let doc = parse_seed_document(SAMPLE_SEED).unwrap();
        assert_eq!(doc.namespace, "demo");
        assert_eq!(doc.objects.len(), 2);
        assert_eq!(doc.links.len(), 1);
    }

    #[test]
    fn reject_empty_seed_objects() {
        let err =
            parse_seed_document(r#"{"version":"sekai.seed/v1","namespace":"demo","objects":[]}"#)
                .unwrap_err();
        assert!(err.contains("at least one object"), "{err}");
    }

    #[test]
    fn resolve_ref_spec_roundtrip() {
        let input = lookup_first::ResolveRefInput {
            object_id: "svc-api".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: lookup_first::ResolveRefInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.object_id, "svc-api");
        assert!(lookup_first::is_lookup_first_capability(
            semantic::CAPABILITY_RESOLVE_REF
        ));
    }

    #[test]
    fn product_loop_fixture_files_parse() {
        let domain_path = Path::new("tests/fixtures/product_loop/domain-v1.json");
        let seed_path = Path::new("tests/fixtures/product_loop/seed-v1.json");
        if domain_path.exists() {
            load_domain_document(domain_path).unwrap();
        }
        if seed_path.exists() {
            load_seed_document(seed_path).unwrap();
        }
    }
}
