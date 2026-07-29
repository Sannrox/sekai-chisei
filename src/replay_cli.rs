use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

use crate::grpc::client::connect_sekai;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    GetLinksRequest, GetObjectRequest, Link, ListDecisionsRequest, ListObjectChangesRequest, Object,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const FORMAT: &str = "sekai.replay.v1";

pub fn usage() -> &'static str {
    "sekaictl admin assurance replay export <root-object-id> --output <file> [--terminal <file>] [--max-depth <1-10>]"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayExportConfig {
    pub root_object_id: String,
    pub output: PathBuf,
    pub terminal: Option<PathBuf>,
    pub max_depth: i32,
}

impl ReplayExportConfig {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut args = args.into_iter();
        let root_object_id = args.next().ok_or_else(|| usage().to_string())?;
        if root_object_id.trim().is_empty() || root_object_id.starts_with('-') {
            return Err(usage().to_string());
        }

        let mut output = None;
        let mut terminal = None;
        let mut max_depth = 8;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--output" => output = Some(PathBuf::from(next_value(&mut args, "--output")?)),
                "--terminal" => {
                    terminal = Some(PathBuf::from(next_value(&mut args, "--terminal")?))
                }
                "--max-depth" => {
                    max_depth = next_value(&mut args, "--max-depth")?
                        .parse::<i32>()
                        .map_err(|_| "--max-depth must be an integer".to_string())?;
                    if !(1..=10).contains(&max_depth) {
                        return Err("--max-depth must be between 1 and 10".into());
                    }
                }
                _ => {
                    return Err(format!(
                        "unknown replay export argument {arg:?}\n{}",
                        usage()
                    ));
                }
            }
        }

        Ok(Self {
            root_object_id,
            output: output.ok_or_else(|| "--output is required".to_string())?,
            terminal,
            max_depth,
        })
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[derive(Serialize)]
struct ReplayBundle {
    format: &'static str,
    exported_at_ms: i64,
    root_object_id: String,
    source: ReplaySource,
    timeline: Vec<TimelineEvent>,
    graph: ReplayGraph,
    terminal: Option<String>,
}

#[derive(Serialize)]
struct ReplaySource {
    control_plane_version: &'static str,
    traversal_max_depth: i32,
    graph_truncated: bool,
    timeline_truncated: bool,
    timeline_truncation_reasons: Vec<String>,
}

#[derive(Serialize)]
struct ReplayGraph {
    objects: Vec<ReplayObject>,
    links: Vec<ReplayLink>,
}

#[derive(Serialize)]
struct ReplayObject {
    id: String,
    kind: String,
    name: String,
    namespace: String,
    external_id: String,
    properties: BTreeMap<String, String>,
    created_at_ms: i64,
    updated_at_ms: i64,
}

#[derive(Serialize)]
struct ReplayLink {
    id: String,
    from: String,
    to: String,
    relation: String,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct TimelineEvent {
    id: String,
    timestamp_ms: i64,
    kind: String,
    subject_id: String,
    label: String,
    details: BTreeMap<String, String>,
}

pub async fn run_export(config: ReplayExportConfig) -> Result<(), BoxError> {
    let target = std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into());
    let channel = connect_sekai(&target).await?;
    let mut client = SekaiServiceClient::new(channel);
    let root = client
        .get_object(GetObjectRequest {
            id: config.root_object_id.clone(),
        })
        .await?
        .into_inner()
        .object
        .ok_or("replay root was not returned")?;
    let (objects, links, graph_truncated) =
        collect_graph(&mut client, root, config.max_depth).await?;

    let visible_ids = objects
        .iter()
        .map(|object| object.id.clone())
        .collect::<HashSet<_>>();
    let earliest = objects
        .iter()
        .map(|object| object.created)
        .min()
        .unwrap_or_default();
    let mut decisions = Vec::new();
    let mut decisions_truncated = false;
    for object_id in &visible_ids {
        let mut object_decisions = client
            .list_decisions(ListDecisionsRequest {
                after: earliest.saturating_sub(1),
                limit: 500,
                target_id: object_id.clone(),
                ..Default::default()
            })
            .await?
            .into_inner()
            .decisions;
        decisions_truncated |= object_decisions.len() == 500;
        decisions.append(&mut object_decisions);
    }

    let mut timeline = Vec::new();
    let mut changes_truncated = false;
    for object in &objects {
        timeline.push(TimelineEvent {
            id: format!("object:{}:created", object.id),
            timestamp_ms: object.created,
            kind: "object_created".into(),
            subject_id: object.id.clone(),
            label: format!("created {}", object.name),
            details: BTreeMap::from([("object_kind".into(), object.kind.clone())]),
        });
        let (changes, object_changes_truncated) =
            list_object_changes(&mut client, &object.id).await?;
        changes_truncated |= object_changes_truncated;
        timeline.extend(changes.into_iter().map(|change| {
            let field = change.field;
            TimelineEvent {
                id: change.id,
                timestamp_ms: change.timestamp,
                kind: "object_changed".into(),
                subject_id: change.object_id,
                label: format!("{field} changed"),
                details: BTreeMap::from([
                    ("field".into(), field.clone()),
                    (
                        "old_value".into(),
                        sanitize_field_value(&field, change.old_value),
                    ),
                    (
                        "new_value".into(),
                        sanitize_field_value(&field, change.new_value),
                    ),
                    ("changed_by".into(), change.changed_by),
                ]),
            }
        }));
    }
    timeline.extend(decisions.into_iter().map(|decision| {
        TimelineEvent {
            id: decision.id,
            timestamp_ms: decision.timestamp,
            kind: "decision".into(),
            subject_id: decision.target_id,
            label: format!("{}: {}", decision.action, decision.outcome),
            details: decision
                .evidence
                .into_iter()
                .map(|(key, value)| {
                    let value = sanitize_field_value(&key, value);
                    (key, value)
                })
                .chain([
                    ("actor".into(), decision.actor),
                    ("reason".into(), decision.reason),
                ])
                .collect(),
        }
    }));
    timeline.sort_by(|left, right| {
        left.timestamp_ms
            .cmp(&right.timestamp_ms)
            .then_with(|| left.id.cmp(&right.id))
    });

    let bundle = ReplayBundle {
        format: FORMAT,
        exported_at_ms: chrono::Utc::now().timestamp_millis(),
        root_object_id: config.root_object_id,
        source: ReplaySource {
            control_plane_version: env!("CARGO_PKG_VERSION"),
            traversal_max_depth: config.max_depth,
            graph_truncated,
            timeline_truncated: decisions_truncated || changes_truncated,
            timeline_truncation_reasons: [
                decisions_truncated.then(|| "decision_limit".into()),
                changes_truncated.then(|| "object_change_limit".into()),
            ]
            .into_iter()
            .flatten()
            .collect(),
        },
        timeline,
        graph: ReplayGraph {
            objects: objects
                .into_iter()
                .map(|object| ReplayObject {
                    id: object.id,
                    kind: object.kind,
                    name: object.name,
                    namespace: object.namespace,
                    external_id: object.external_id,
                    properties: object
                        .properties
                        .into_iter()
                        .map(|(key, value)| {
                            let value = sanitize_field_value(&key, value);
                            (key, value)
                        })
                        .collect(),
                    created_at_ms: object.created,
                    updated_at_ms: object.updated,
                })
                .collect(),
            links: links
                .into_iter()
                .map(|link| ReplayLink {
                    id: link.id,
                    from: link.from_id,
                    to: link.to_id,
                    relation: link.relation,
                    created_at_ms: link.created,
                })
                .collect(),
        },
        terminal: config
            .terminal
            .as_ref()
            .map(fs::read_to_string)
            .transpose()?
            .map(|terminal| sanitize_terminal(&terminal)),
    };

    let encoded = serde_json::to_vec_pretty(&bundle)?;
    if let Some(parent) = config
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&config.output, encoded)?;
    println!("exported {}", config.output.display());
    Ok(())
}

async fn list_object_changes(
    client: &mut SekaiServiceClient<crate::grpc::client::GatewayClient>,
    object_id: &str,
) -> Result<(Vec<crate::grpc::pb::sekai::ObjectChange>, bool), BoxError> {
    const PAGE_SIZE: i32 = 500;
    const MAX_CHANGES: usize = 10_000;
    let mut changes = Vec::new();
    let mut offset = 0;
    loop {
        let page = client
            .list_object_changes(ListObjectChangesRequest {
                object_id: object_id.into(),
                limit: PAGE_SIZE,
                offset,
            })
            .await?
            .into_inner()
            .changes;
        let page_len = page.len();
        changes.extend(page.into_iter().take(MAX_CHANGES - changes.len()));
        if page_len < PAGE_SIZE as usize {
            return Ok((changes, false));
        }
        if changes.len() >= MAX_CHANGES {
            return Ok((changes, true));
        }
        offset += PAGE_SIZE;
    }
}

fn sanitize_field_value(field: &str, value: String) -> String {
    let field = field.to_ascii_lowercase();
    if ["manifest", "plan", "workdir"]
        .iter()
        .any(|name| field == *name || field.ends_with(&format!(".{name}")))
    {
        return "[redacted structured payload]".into();
    }
    let normalized = field
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>();
    if [
        "secret",
        "token",
        "password",
        "passphrase",
        "credential",
        "apikey",
        "privatekey",
        "accesskey",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
    {
        return "[redacted sensitive value]".into();
    }
    value
}

fn sanitize_terminal(value: &str) -> String {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        vec![
            (
                Regex::new(r"(?i)(authorization:\s*bearer\s+)\S+").unwrap(),
                "${1}[REDACTED]",
            ),
            (
                Regex::new(
                    r"(?i)([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*=)[^\s]+",
                )
                .unwrap(),
                "${1}[REDACTED]",
            ),
            (
                Regex::new(r#"(?i)("(?:api[_-]?key|token|secret|password|credential)"\s*:\s*")[^"]+"#)
                    .unwrap(),
                "${1}[REDACTED]",
            ),
            (
                Regex::new(r#"/(?:Users|home|private/tmp)/[^\s"']+"#).unwrap(),
                "[REDACTED_PATH]",
            ),
        ]
    });
    patterns
        .iter()
        .fold(value.to_string(), |text, (pattern, replacement)| {
            pattern.replace_all(&text, *replacement).into_owned()
        })
}

async fn collect_graph(
    client: &mut SekaiServiceClient<crate::grpc::client::GatewayClient>,
    root: Object,
    max_depth: i32,
) -> Result<(Vec<Object>, Vec<Link>, bool), BoxError> {
    const MAX_OBJECTS: usize = 500;
    let mut objects = BTreeMap::from([(root.id.clone(), root.clone())]);
    let mut links = BTreeMap::new();
    let mut queue = VecDeque::from([(root, 0)]);
    let mut truncated = false;

    while let Some((object, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        for direction in ["outgoing", "incoming"] {
            let response = client
                .get_links(GetLinksRequest {
                    object_id: object.id.clone(),
                    relation: String::new(),
                    direction: direction.into(),
                })
                .await?
                .into_inner();
            for link in response.links {
                let target_id = if direction == "outgoing" {
                    link.to_id.clone()
                } else {
                    link.from_id.clone()
                };
                links.entry(link.id.clone()).or_insert(link);
                if objects.contains_key(&target_id) {
                    continue;
                }
                if objects.len() >= MAX_OBJECTS {
                    truncated = true;
                    continue;
                }
                match client
                    .get_object(GetObjectRequest {
                        id: target_id.clone(),
                    })
                    .await
                {
                    Ok(response) => {
                        if let Some(target) = response.into_inner().object {
                            objects.insert(target.id.clone(), target.clone());
                            queue.push_back((target, depth + 1));
                        }
                    }
                    Err(status)
                        if matches!(
                            status.code(),
                            tonic::Code::NotFound | tonic::Code::PermissionDenied
                        ) => {}
                    Err(status) => return Err(status.into()),
                }
            }
        }
    }

    links
        .retain(|_, link| objects.contains_key(&link.from_id) && objects.contains_key(&link.to_id));
    Ok((
        objects.into_values().collect(),
        links.into_values().collect(),
        truncated,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_export_arguments() {
        let config = ReplayExportConfig::from_args([
            "plan-1".into(),
            "--output".into(),
            "replay.json".into(),
            "--terminal".into(),
            "terminal.log".into(),
            "--max-depth".into(),
            "6".into(),
        ])
        .unwrap();
        assert_eq!(config.root_object_id, "plan-1");
        assert_eq!(config.output, PathBuf::from("replay.json"));
        assert_eq!(config.terminal, Some(PathBuf::from("terminal.log")));
        assert_eq!(config.max_depth, 6);
    }

    #[test]
    fn requires_output_and_bounded_depth() {
        assert!(ReplayExportConfig::from_args(["plan-1".into()]).is_err());
        assert!(
            ReplayExportConfig::from_args([
                "plan-1".into(),
                "--output".into(),
                "x.json".into(),
                "--max-depth".into(),
                "0".into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn redacts_structured_and_secret_properties() {
        assert_eq!(
            sanitize_field_value("properties.plan", "/private/path".into()),
            "[redacted structured payload]"
        );
        assert_eq!(
            sanitize_field_value("api_token", "value".into()),
            "[redacted sensitive value]"
        );
        assert_eq!(sanitize_field_value("status", "failed".into()), "failed");
        assert_eq!(
            sanitize_field_value("accessKeyId", "value".into()),
            "[redacted sensitive value]"
        );
        let terminal = sanitize_terminal(
            "authorization: Bearer abc\nOPENAI_API_KEY=sk-secret\n/home/alice/project\n",
        );
        assert!(!terminal.contains("abc"));
        assert!(!terminal.contains("sk-secret"));
        assert!(!terminal.contains("alice"));
    }
}
