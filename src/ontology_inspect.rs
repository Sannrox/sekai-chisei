use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use prost::Message;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::grpc::client::connect_sekai;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    ContextCandidate, ListOntologyClassesRequest, ListOntologyRelationsRequest, OntologyClass,
    OntologyRelation, RetrieveContextRequest,
};

const DEFAULT_TTL_SECONDS: i64 = 3_600;
const MAX_TTL_SECONDS: i64 = 86_400;

pub fn usage() -> &'static str {
    "sekaictl ontology inspect --root <object-id> --authorization-context <label> [--output <path>] [--ttl-seconds <1-86400>] [--target <url-or-socket>]"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectConfig {
    pub root: String,
    pub authorization_context: String,
    pub output: PathBuf,
    pub ttl_seconds: i64,
    pub target: String,
}

impl InspectConfig {
    pub fn from_env_and_args(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut root = None;
        let mut authorization_context = None;
        let mut output = PathBuf::from("ontology-inspection.html");
        let mut ttl_seconds = DEFAULT_TTL_SECONDS;
        let mut target = std::env::var("CHISEI_GRPC_URL")
            .or_else(|_| std::env::var("SEKAI_SOCKET"))
            .unwrap_or_else(|_| "./data/sekai.sock".into());
        let mut args = args.peekable();

        while let Some(arg) = args.next() {
            let value = |args: &mut std::iter::Peekable<_>, flag: &str| {
                args.next()
                    .ok_or_else(|| format!("{flag} requires a value"))
            };
            match arg.as_str() {
                "--root" => root = Some(value(&mut args, "--root")?),
                "--authorization-context" => {
                    authorization_context = Some(value(&mut args, "--authorization-context")?)
                }
                "--output" => output = PathBuf::from(value(&mut args, "--output")?),
                "--ttl-seconds" => {
                    ttl_seconds = value(&mut args, "--ttl-seconds")?
                        .parse()
                        .map_err(|_| "--ttl-seconds must be an integer".to_string())?;
                }
                "--target" => target = value(&mut args, "--target")?,
                _ => return Err(format!("unknown ontology inspect argument {arg:?}")),
            }
        }

        let root = required_non_secret(root, "--root")?;
        let authorization_context =
            required_non_secret(authorization_context, "--authorization-context")?;
        if !(1..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(format!(
                "--ttl-seconds must be between 1 and {MAX_TTL_SECONDS}"
            ));
        }
        if target.trim().is_empty() {
            return Err("--target must not be empty".into());
        }
        public_source(&target)?;

        Ok(Self {
            root,
            authorization_context,
            output,
            ttl_seconds,
            target,
        })
    }
}

fn public_source(target: &str) -> Result<String, String> {
    if target.starts_with("http://") {
        return Err(
            "ontology inspection refuses plaintext HTTP; use HTTPS or a Unix socket".into(),
        );
    }
    if !target.starts_with("https://") {
        return Ok(target.to_string());
    }
    let uri = target
        .parse::<http::Uri>()
        .map_err(|_| "--target must be a valid HTTP(S) URI or socket path".to_string())?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "--target URI is missing a scheme".to_string())?;
    let authority = uri
        .authority()
        .ok_or_else(|| "--target URI is missing an authority".to_string())?
        .as_str();
    if authority.contains('@') {
        return Err("--target must not contain user credentials".into());
    }
    Ok(format!("{scheme}://{authority}"))
}

fn required_non_secret(value: Option<String>, flag: &str) -> Result<String, String> {
    let value = value.ok_or_else(|| format!("{flag} is required"))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{flag} must not be empty"));
    }
    if value.len() > 256 {
        return Err(format!("{flag} must be at most 256 bytes"));
    }
    Ok(value.to_string())
}

pub async fn run_inspect(
    config: InspectConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_sekai(&config.target).await?;
    let mut client = SekaiServiceClient::new(channel);
    let classes_before = client
        .list_ontology_classes(ListOntologyClassesRequest {})
        .await?
        .into_inner()
        .classes;
    let relations_before = client
        .list_ontology_relations(ListOntologyRelationsRequest {})
        .await?
        .into_inner()
        .relations;
    let context = client
        .retrieve_context(inspection_context_request(&config.root))
        .await?
        .into_inner();
    ensure_complete_trace(
        context.truncated,
        context.unresolved_roots,
        context.candidates.is_empty(),
    )
    .map_err(std::io::Error::other)?;
    let classes = client
        .list_ontology_classes(ListOntologyClassesRequest {})
        .await?
        .into_inner()
        .classes;
    let relations = client
        .list_ontology_relations(ListOntologyRelationsRequest {})
        .await?
        .into_inner()
        .relations;
    let before_revision = authorized_ontology_revision(&classes_before, &relations_before);
    let authorized_snapshot_revision = authorized_ontology_revision(&classes, &relations);
    if before_revision != authorized_snapshot_revision {
        return Err(std::io::Error::other(
            "authorized ontology changed while generating the inspection; retry",
        )
        .into());
    }

    let snapshot_at = Utc::now();
    let snapshot = InspectionSnapshot::new(
        &config,
        snapshot_at,
        classes,
        relations,
        context.candidates,
        context.ontology_revision,
        authorized_snapshot_revision,
    );
    write_new_private(&config.output, render_html(&snapshot)?.as_bytes()).await?;
    Ok(())
}

fn ensure_complete_trace(
    truncated: bool,
    unresolved_roots: u32,
    candidates_empty: bool,
) -> Result<(), String> {
    if unresolved_roots != 0 || candidates_empty {
        return Err("selected context root is unavailable".into());
    }
    if truncated {
        Err("context trace exceeded inspection bounds; narrow the root or retry".into())
    } else {
        Ok(())
    }
}

async fn write_new_private(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::other("output path must name a file"))?;
    let temp_path = path.with_file_name(format!(
        ".{file_name}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let result = async {
        let mut output = options.open(&temp_path).await?;
        output.write_all(contents).await?;
        output.sync_all().await?;
        drop(output);
        tokio::fs::hard_link(&temp_path, path).await?;
        tokio::fs::remove_file(&temp_path).await
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temp_path).await;
    }
    result
}

fn authorized_ontology_revision(
    classes: &[OntologyClass],
    relations: &[OntologyRelation],
) -> String {
    let mut classes = classes.iter().collect::<Vec<_>>();
    classes.sort_by(|left, right| left.name.cmp(&right.name));
    let mut relations = relations.iter().collect::<Vec<_>>();
    relations.sort_by(|left, right| left.name.cmp(&right.name));
    let mut digest = Sha256::new();
    for class in classes {
        let bytes = class.encode_to_vec();
        digest.update(b"class\0");
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    for relation in relations {
        let bytes = relation.encode_to_vec();
        digest.update(b"relation\0");
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn inspection_context_request(root: &str) -> RetrieveContextRequest {
    RetrieveContextRequest {
        roots: vec![crate::grpc::pb::sekai::ContextRoot {
            object_id: root.to_string(),
            ..Default::default()
        }],
        reasoning_mode: "entailment".into(),
        max_depth: 2,
        max_objects: 50,
        max_links: 100,
        max_source_rows: 200,
        max_derived_rows: 100,
        max_derivation_steps: 12,
        max_time_ms: 500,
        max_explanation_bytes: 1_048_576,
        ..Default::default()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct InspectionSnapshot {
    format: &'static str,
    authorization_context: String,
    source: String,
    root: String,
    snapshot_at: String,
    expires_at: String,
    ontology_revision: String,
    authorized_snapshot_revision: String,
    classes: Vec<ClassView>,
    relations: Vec<RelationView>,
    trace: Vec<CandidateView>,
}

impl InspectionSnapshot {
    pub(crate) fn new(
        config: &InspectConfig,
        snapshot_at: DateTime<Utc>,
        classes: Vec<OntologyClass>,
        relations: Vec<OntologyRelation>,
        candidates: Vec<ContextCandidate>,
        ontology_revision: String,
        authorized_snapshot_revision: String,
    ) -> Self {
        Self {
            format: "sekai.ontology-inspection/v1",
            authorization_context: config.authorization_context.clone(),
            source: public_source(&config.target).unwrap_or_else(|_| "invalid source".into()),
            root: config.root.clone(),
            snapshot_at: snapshot_at.to_rfc3339(),
            expires_at: (snapshot_at + Duration::seconds(config.ttl_seconds)).to_rfc3339(),
            ontology_revision,
            authorized_snapshot_revision,
            classes: classes.into_iter().map(ClassView::from).collect(),
            relations: relations.into_iter().map(RelationView::from).collect(),
            trace: candidates.into_iter().map(CandidateView::from).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ClassView {
    name: String,
    description: String,
    superclasses: Vec<String>,
    equivalent_classes: Vec<String>,
    disjoint_classes: Vec<String>,
    mapped_kind: String,
    properties: Vec<PropertyView>,
}

impl From<OntologyClass> for ClassView {
    fn from(value: OntologyClass) -> Self {
        Self {
            name: value.name,
            description: value.description,
            superclasses: value.superclasses,
            equivalent_classes: value.equivalent_classes,
            disjoint_classes: value.disjoint_classes,
            mapped_kind: value.mapped_kind,
            properties: value
                .properties
                .into_iter()
                .map(PropertyView::from)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct PropertyView {
    name: String,
    property_type: String,
    required: bool,
    description: String,
}

impl From<crate::grpc::pb::sekai::OntologyProperty> for PropertyView {
    fn from(value: crate::grpc::pb::sekai::OntologyProperty) -> Self {
        Self {
            name: value.name,
            property_type: value.r#type,
            required: value.required,
            description: value.description,
        }
    }
}

#[derive(Debug, Serialize)]
struct RelationView {
    name: String,
    description: String,
    domain: String,
    range: String,
    inverse: String,
    transitive: bool,
    mapped_relation: String,
}

impl From<OntologyRelation> for RelationView {
    fn from(value: OntologyRelation) -> Self {
        Self {
            name: value.name,
            description: value.description,
            domain: value.domain,
            range: value.range,
            inverse: value.inverse,
            transitive: value.transitive,
            mapped_relation: value.mapped_relation,
        }
    }
}

#[derive(Debug, Serialize)]
struct CandidateView {
    object_id: String,
    kind: String,
    depth: u32,
    via_relation: String,
    derived: bool,
    source_fact_ids: Vec<String>,
    steps: Vec<StepView>,
}

impl From<ContextCandidate> for CandidateView {
    fn from(value: ContextCandidate) -> Self {
        let object = value.object.unwrap_or_default();
        let explanation = value.explanation.unwrap_or_default();
        Self {
            object_id: object.id,
            kind: object.kind,
            depth: value.depth,
            via_relation: value.via_relation,
            derived: explanation.derived,
            source_fact_ids: explanation.source_fact_ids,
            steps: explanation.steps.into_iter().map(StepView::from).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct StepView {
    kind: String,
    relation: String,
    from_id: String,
    to_id: String,
    source_fact_ids: Vec<String>,
    ontology_revision: String,
    rule: String,
}

impl From<crate::grpc::pb::sekai::ContextDerivationStep> for StepView {
    fn from(value: crate::grpc::pb::sekai::ContextDerivationStep) -> Self {
        Self {
            kind: value.kind,
            relation: value.relation,
            from_id: value.from_id,
            to_id: value.to_id,
            source_fact_ids: value.source_fact_ids,
            ontology_revision: value.ontology_revision,
            rule: value.rule,
        }
    }
}

pub(crate) fn render_html(snapshot: &InspectionSnapshot) -> Result<String, serde_json::Error> {
    let data = serde_json::to_string(snapshot)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    Ok(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>Sekai ontology inspection</title><style>
:root{{color-scheme:light dark;font:15px system-ui,sans-serif}}body{{max-width:1100px;margin:2rem auto;padding:0 1rem}}header{{border-bottom:1px solid #888;padding-bottom:1rem}}.warning{{padding:.75rem;border:2px solid #b66;background:#b662}}input{{width:100%;padding:.7rem;box-sizing:border-box}}section{{margin:2rem 0}}details{{border:1px solid #888;border-radius:6px;padding:.6rem;margin:.5rem 0}}summary{{cursor:pointer;font-weight:650}}code{{overflow-wrap:anywhere}}dl{{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1rem}}dt{{font-weight:650}}.derived{{color:#b85}}.empty{{opacity:.7}}
</style></head><body><header><h1>Ontology inspection</h1><div id="status" class="warning"></div><dl id="metadata"></dl></header>
<main><p>This is a read-only disclosed-data snapshot. Authorization is not rechecked after export.</p><label>Filter authorized snapshot <input id="filter" type="search" autocomplete="off"></label><section><h2>Classes <span id="class-count"></span></h2><div id="classes"></div></section><section><h2>Relations <span id="relation-count"></span></h2><div id="relations"></div></section><section><h2>Asserted and derived trace <span id="trace-count"></span></h2><div id="trace"></div></section></main>
<script id="inspection-data" type="application/json">{data}</script><script>
'use strict';const data=JSON.parse(document.getElementById('inspection-data').textContent);const el=(tag,text)=>{{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);return n}};const printable=v=>Array.isArray(v)?v.map(item=>typeof item==='object'?JSON.stringify(item):item).join(', '):v;const add=(p,t,v)=>{{const d=el('div');d.append(el('strong',t+': '),el('span',printable(v)||'—'));p.append(d)}};
const meta=document.getElementById('metadata');for(const [k,v] of [['Format',data.format],['Authorization context',data.authorization_context],['Source',data.source],['Root',data.root],['Snapshot',data.snapshot_at],['Expires',data.expires_at],['Authorized snapshot revision',data.authorized_snapshot_revision],['Entailment revision',data.ontology_revision]]){{meta.append(el('dt',k),el('dd',v||'—'))}}const expiresAt=Date.parse(data.expires_at);function updateStatus(){{const expired=Date.now()>=expiresAt;document.getElementById('status').textContent=expired?'EXPIRED — regenerate before relying on this snapshot':'ACTIVE UNTIL '+data.expires_at;return expired}}function scheduleStatus(){{if(!updateStatus())setTimeout(scheduleStatus,Math.max(1,expiresAt-Date.now()+1))}}scheduleStatus();document.addEventListener('visibilitychange',scheduleStatus);
function card(item,title,fields,derived){{const d=el('details');if(derived)d.className='derived';d.append(el('summary',title));for(const [label,key] of fields)add(d,label,item[key]);return d}}function render(){{const q=document.getElementById('filter').value.toLowerCase();const sets=[['classes',data.classes,'class-count',x=>card(x,x.name,[['Description','description'],['Superclasses','superclasses'],['Equivalent','equivalent_classes'],['Disjoint','disjoint_classes'],['Mapped kind','mapped_kind'],['Properties','properties']])],['relations',data.relations,'relation-count',x=>card(x,x.name,[['Description','description'],['Domain','domain'],['Range','range'],['Inverse','inverse'],['Transitive','transitive'],['Mapped relation','mapped_relation']])],['trace',data.trace,'trace-count',x=>{{const d=card(x,x.object_id+' · '+x.kind,[['Depth','depth'],['Via','via_relation'],['Derived','derived'],['Source facts','source_fact_ids']],x.derived);for(const s of x.steps)d.append(card(s,s.kind+' · '+s.rule,[['Relation','relation'],['From','from_id'],['To','to_id'],['Source facts','source_fact_ids'],['Ontology revision','ontology_revision']]));return d}}]];for(const [id,items,count,make] of sets){{const visible=items.filter(x=>JSON.stringify(x).toLowerCase().includes(q));const host=document.getElementById(id);host.replaceChildren(...visible.map(make));if(!visible.length)host.append(el('p','No matching authorized data.'));document.getElementById(count).textContent='('+visible.length+')'}}}}document.getElementById('filter').addEventListener('input',render);render();
</script></body></html>"#
    ))
}

#[cfg(test)]
fn snapshot_is_expired(expires_at: &str, at: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(expires_at)
        .map(|expires| at >= expires)
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::pb::sekai::{
        ContextDerivationStep, ContextExplanation, Object, OntologyProperty,
    };

    fn config() -> InspectConfig {
        InspectConfig {
            root: "root-1".into(),
            authorization_context: "operator-visible".into(),
            output: "ignored.html".into(),
            ttl_seconds: 60,
            target: "https://sekai.example".into(),
        }
    }

    #[test]
    fn config_rejects_missing_and_unbounded_values() {
        assert!(InspectConfig::from_env_and_args(Vec::new().into_iter()).is_err());
        let args = [
            "--root",
            "root",
            "--authorization-context",
            "ctx",
            "--ttl-seconds",
            "86401",
        ];
        assert!(InspectConfig::from_env_and_args(args.into_iter().map(str::to_string)).is_err());
        let args = [
            "--root",
            "root",
            "--authorization-context",
            "ctx",
            "--target",
            "http://127.0.0.1:50051",
        ];
        assert!(InspectConfig::from_env_and_args(args.into_iter().map(str::to_string)).is_err());
        let args = [
            "--root",
            "root",
            "--authorization-context",
            "ctx",
            "--target",
            "https://user:secret@sekai.example",
        ];
        assert!(InspectConfig::from_env_and_args(args.into_iter().map(str::to_string)).is_err());
    }

    #[test]
    fn rendering_is_self_contained_text_safe_and_marks_expiry() {
        let now = DateTime::parse_from_rfc3339("2026-07-22T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut cfg = config();
        cfg.authorization_context = "<img src=x onerror=alert(1)>".into();
        let snapshot = InspectionSnapshot::new(
            &cfg,
            now,
            vec![OntologyClass {
                name: "visible</script><script>alert(1)</script>".into(),
                properties: vec![OntologyProperty {
                    name: "display-name".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "Visible name".into(),
                }],
                ..Default::default()
            }],
            vec![],
            vec![ContextCandidate {
                object: Some(Object {
                    id: "visible-object".into(),
                    kind: "artifact".into(),
                    ..Default::default()
                }),
                explanation: Some(ContextExplanation {
                    derived: true,
                    source_fact_ids: vec!["fact-1".into()],
                    steps: vec![ContextDerivationStep {
                        kind: "derived".into(),
                        rule: "subclass".into(),
                        ontology_revision: "rev-1".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            "rev-1".into(),
            "authorized-rev-1".into(),
        );
        let html = render_html(&snapshot).unwrap();
        assert!(snapshot_is_expired(
            &snapshot.expires_at,
            now + Duration::seconds(61)
        ));
        assert!(html.contains("EXPIRED"));
        assert!(html.contains("Date.now()"));
        assert!(html.contains("setTimeout(scheduleStatus"));
        assert!(html.contains("visible-object"));
        assert!(html.contains("fact-1"));
        assert!(html.contains("display-name"));
        assert!(!html.contains("</script><script>alert(1)</script>"));
        assert!(!html.contains("onerror=alert(1)>"));
        assert!(!html.contains("localStorage"));
        assert!(!html.contains("serviceWorker"));
    }

    #[test]
    fn snapshot_contains_only_supplied_authorized_responses() {
        let now = Utc::now();
        let mut cfg = config();
        cfg.target = "https://sekai.example/path?token=do-not-export".into();
        let snapshot = InspectionSnapshot::new(
            &cfg,
            now,
            vec![OntologyClass {
                name: "visible-class".into(),
                ..Default::default()
            }],
            vec![OntologyRelation {
                name: "visible-relation".into(),
                ..Default::default()
            }],
            vec![],
            "revision".into(),
            "authorized-revision".into(),
        );
        assert!(!snapshot_is_expired(&snapshot.expires_at, now));
        let html = render_html(&snapshot).unwrap();
        assert!(html.contains("visible-class"));
        assert!(html.contains("visible-relation"));
        assert!(!html.contains("denied_objects"));
        assert!(!html.contains("SEKAI_AUTH_TOKEN"));
        assert!(!html.contains("do-not-export"));
    }

    #[test]
    fn authorized_revision_is_complete_stable_and_sensitive() {
        let class_a = OntologyClass {
            name: "A".into(),
            ..Default::default()
        };
        let class_b = OntologyClass {
            name: "B".into(),
            ..Default::default()
        };
        let first = authorized_ontology_revision(&[class_a.clone(), class_b.clone()], &[]);
        let reordered = authorized_ontology_revision(&[class_b.clone(), class_a.clone()], &[]);
        assert_eq!(first, reordered);
        let mut changed = class_b;
        changed.description = "changed outside any retrieval row cap".into();
        assert_ne!(
            first,
            authorized_ontology_revision(&[class_a, changed], &[])
        );
    }

    #[tokio::test]
    async fn private_output_is_complete_and_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("inspection.html");
        write_new_private(&output, b"complete artifact")
            .await
            .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"complete artifact");
        assert!(write_new_private(&output, b"replacement").await.is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"complete artifact");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn truncated_trace_fails_closed() {
        assert!(ensure_complete_trace(false, 0, false).is_ok());
        assert!(ensure_complete_trace(true, 0, false).is_err());
        assert_eq!(
            ensure_complete_trace(false, 1, true).unwrap_err(),
            "selected context root is unavailable"
        );
    }
}
