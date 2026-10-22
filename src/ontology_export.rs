//! `sekaictl ontology export` (#1617): a namespace's published definitions as a
//! canonical file tree that can be reviewed in Git.
//!
//! The tree holds one file per member of the published definition revision, at
//! `<member_kind>/<member_id>.json`, plus `markings/lattice.json` when the
//! namespace has a classification lattice and `layout.json` naming the layout
//! version. Bodies are pretty-printed with sorted keys and a trailing newline.
//! Digests, the namespace, actors and times are left out, so exporting the same
//! definitions from any namespace gives byte-identical trees. Object data is
//! never read. Values under credential-shaped keys are replaced with
//! [`CREDENTIAL_PLACEHOLDER`], so a credential reference never reaches the tree.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Map, Value};
use tonic::{Code, Request};

use crate::grpc::client::connect_sekai;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    ClassificationLattice, GetClassificationLatticeRequest, GetDefinitionMemberRequest,
    GetPublishedDefinitionRevisionRequest,
};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Versions the file layout; it is a contract for tools that read the tree.
pub const LAYOUT_VERSION: &str = "sekai.ontology-export/v1";
pub const CREDENTIAL_PLACEHOLDER: &str = "[credential reference omitted]";

/// One published definition member as stored by the server.
pub struct ExportMember {
    pub kind: String,
    pub id: String,
    pub definition_json: String,
}

/// Relative path to file contents, in path order.
pub type Tree = BTreeMap<String, String>;

/// Builds the canonical tree. Fails on unreadable member JSON or on two ids whose
/// file names would collide on a case-insensitive file system.
pub fn build_tree(
    members: &[ExportMember],
    lattice: Option<&ClassificationLattice>,
) -> Result<Tree, String> {
    let mut tree = Tree::new();
    let mut folded = BTreeMap::new();
    let mut long_ids = Map::new();
    for member in members {
        let value: Value = serde_json::from_str(&member.definition_json)
            .map_err(|error| format!("{}/{}: {error}", member.kind, member.id))?;
        let path = format!("{}/{}.json", encode(&member.kind), file_stem(&member.id));
        if path.contains(HASHED_MARK) {
            long_ids.insert(path.clone(), Value::String(member.id.clone()));
        }
        if let Some(other) = folded.insert(path.to_lowercase(), path.clone()) {
            return Err(format!(
                "{path} and {other} differ only in case and cannot share a tree"
            ));
        }
        tree.insert(path, render(&omit_credentials(value))?);
    }
    if let Some(lattice) = lattice.filter(|lattice| !lattice.tokens.is_empty()) {
        tree.insert(
            "markings/lattice.json".into(),
            render(&lattice_value(lattice))?,
        );
    }
    let layout = if long_ids.is_empty() {
        serde_json::json!({ "layout_version": LAYOUT_VERSION })
    } else {
        serde_json::json!({ "layout_version": LAYOUT_VERSION, "long_ids": long_ids })
    };
    tree.insert("layout.json".into(), render(&layout)?);
    Ok(tree)
}

/// The lattice without its namespace or digest, in a stable order.
fn lattice_value(lattice: &ClassificationLattice) -> Value {
    let mut tokens = lattice.tokens.clone();
    tokens.sort();
    let mut parents: Vec<[String; 2]> = lattice
        .parents
        .iter()
        .map(|edge| [edge.child.clone(), edge.parent.clone()])
        .collect();
    parents.sort();
    let mut incomparable: Vec<[String; 2]> = lattice
        .incomparable
        .iter()
        .map(|pair| {
            let mut pair = [pair.left.clone(), pair.right.clone()];
            pair.sort();
            pair
        })
        .collect();
    incomparable.sort();
    serde_json::json!({
        "contract_version": lattice.contract_version,
        "tokens": tokens,
        "parents": parents,
        "incomparable": incomparable,
    })
}

/// Pretty JSON with sorted object keys at every depth and a trailing newline.
fn render(value: &Value) -> Result<String, String> {
    let mut text =
        serde_json::to_string_pretty(&sorted(value.clone())).map_err(|error| error.to_string())?;
    text.push('\n');
    Ok(text)
}

fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let entries: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(key, value)| (key, sorted(value)))
                .collect();
            Value::Object(entries.into_iter().collect::<Map<_, _>>())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// Keys whose string value is a credential or a reference to one. Matched on
/// whole underscore-separated words, so `max_tokens` or `tokens` stay readable.
fn credential_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace('-', "_");
    key.contains("api_key")
        || key.contains("private_key")
        || key.split('_').any(|word| {
            matches!(
                word,
                "token" | "secret" | "password" | "passwd" | "credential" | "apikey"
            )
        })
}

/// Redacts credential values: everything beneath a credential-shaped key. Governed
/// definitions name their properties in a `properties` array of strings, so a
/// property called `password` is a string in an array and keeps its name.
fn omit_credentials(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let value = if credential_key(&key) {
                        redact_strings(value)
                    } else {
                        omit_credentials(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(omit_credentials).collect()),
        other => other,
    }
}

/// Every string beneath a credential-shaped key, at any depth, becomes the placeholder.
fn redact_strings(value: Value) -> Value {
    match value {
        Value::String(_) => Value::String(CREDENTIAL_PLACEHOLDER.into()),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_strings).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, redact_strings(value)))
                .collect(),
        ),
        other => other,
    }
}

/// Longest encoded id used verbatim as a file name; longer ids are shortened.
const MAX_STEM: usize = 200;
const HASHED_MARK: &str = "~sha256-";

/// The file name stem for an id: its encoding, or, past [`MAX_STEM`] bytes, a prefix
/// plus a digest of the id. `layout.json` maps shortened paths back to their ids.
fn file_stem(id: &str) -> String {
    use sha2::{Digest, Sha256};
    let encoded = encode(id);
    if encoded.len() <= MAX_STEM {
        return encoded;
    }
    let digest = format!("{:x}", Sha256::digest(id.as_bytes()));
    let mut prefix = encoded[..120].to_string();
    // Never cut a percent escape in half.
    if let Some(position) = prefix.rfind('%')
        && prefix.len() - position < 3
    {
        prefix.truncate(position);
    }
    format!("{prefix}{HASHED_MARK}{}", &digest[..32])
}

/// Percent-encodes everything but ASCII letters, digits, `-` and `_`, so any id is
/// one safe path segment (no `.`, `..` or separators).
fn encode(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Creates a new directory beside `out` that this process owns: `create_dir`
/// fails rather than reuse an existing path, and on Unix only the owner may write
/// into it, so nothing else can plant files or symlinks in the staged tree.
fn create_staging(out: &Path) -> std::io::Result<std::path::PathBuf> {
    let parent = match out.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = out
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "export".into());
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..16u32 {
        let staging = parent.join(format!(
            ".{name}.partial-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        match builder.create(&staging) {
            Ok(()) => return Ok(staging),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::other(
        "could not create a staging directory",
    ))
}

fn write_tree(root: &Path, tree: &Tree) -> std::io::Result<()> {
    for (path, body) in tree {
        let path = root.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, body)?;
    }
    Ok(())
}

/// Fetches the namespace's published revision and lattice and writes the tree
/// into `out`, which must not exist or be empty. Returns the number of files.
pub async fn export(target: &str, namespace: &str, out: &Path) -> Result<usize, BoxErr> {
    if out.exists() && std::fs::read_dir(out)?.next().is_some() {
        return Err(std::io::Error::other(format!(
            "{} is not empty; export writes a fresh tree",
            out.display()
        ))
        .into());
    }
    let mut client = SekaiServiceClient::new(connect_sekai(target).await?);
    let revision = client
        .get_published_definition_revision(Request::new(GetPublishedDefinitionRevisionRequest {
            namespace: namespace.into(),
        }))
        .await?
        .into_inner()
        .revision
        .ok_or_else(|| std::io::Error::other("namespace has no published definition revision"))?;
    let mut members = Vec::with_capacity(revision.members.len());
    for member in &revision.members {
        let body = client
            .get_definition_member(Request::new(GetDefinitionMemberRequest {
                namespace: namespace.into(),
                revision_digest: revision.revision_digest.clone(),
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
            }))
            .await?
            .into_inner()
            .member
            .ok_or_else(|| std::io::Error::other("definition member missing from revision"))?;
        members.push(ExportMember {
            kind: body.member_kind,
            id: body.member_id,
            definition_json: body.definition_json,
        });
    }
    let lattice = match client
        .get_classification_lattice(Request::new(GetClassificationLatticeRequest {
            namespace: namespace.into(),
        }))
        .await
    {
        Ok(response) => response.into_inner().lattice,
        Err(status) if status.code() == Code::NotFound => None,
        Err(status) => return Err(status.into()),
    };
    let tree = build_tree(&members, lattice.as_ref()).map_err(std::io::Error::other)?;
    // Write into a fresh directory beside `out` and rename it into place, so a
    // failed export leaves no partial tree and can be retried.
    let staging = create_staging(out)?;
    let published = write_tree(&staging, &tree).and_then(|()| {
        if out.exists() {
            std::fs::remove_dir(out)?;
        }
        std::fs::rename(&staging, out)
    });
    if let Err(error) = published {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error.into());
    }
    Ok(tree.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::pb::sekai::{ClassificationIncomparablePair, ClassificationParentEdge};

    fn member(kind: &str, id: &str, json: &str) -> ExportMember {
        ExportMember {
            kind: kind.into(),
            id: id.into(),
            definition_json: json.into(),
        }
    }

    #[test]
    fn the_tree_is_canonical_and_independent_of_input_order() {
        let a = member("object_type", "incident", r#"{"z":1,"a":{"y":2,"b":3}}"#);
        let b = member("action_type", "close/now", r#"{"name":"close"}"#);
        let lattice = ClassificationLattice {
            contract_version: "v".into(),
            namespace: "one".into(),
            tokens: vec!["secret".into(), "public".into()],
            parents: vec![ClassificationParentEdge {
                child: "public".into(),
                parent: "secret".into(),
            }],
            incomparable: vec![ClassificationIncomparablePair {
                left: "x".into(),
                right: "a".into(),
            }],
            digest: "sha256:abc".into(),
        };
        let first = build_tree(&[a, b], Some(&lattice)).unwrap();
        let b = member("action_type", "close/now", r#"{"name":"close"}"#);
        let a = member("object_type", "incident", r#"{"a":{"b":3,"y":2},"z":1}"#);
        assert_eq!(first, build_tree(&[b, a], Some(&lattice)).unwrap());
        assert_eq!(
            first.keys().collect::<Vec<_>>(),
            [
                "action_type/close%2Fnow.json",
                "layout.json",
                "markings/lattice.json",
                "object_type/incident.json"
            ]
        );
        assert!(first["object_type/incident.json"].starts_with("{\n  \"a\": {\n    \"b\": 3"));
        assert!(!first["markings/lattice.json"].contains("sha256:abc"));
        assert!(!first["markings/lattice.json"].contains("\"one\""));
    }

    #[test]
    fn credential_values_never_reach_the_tree() {
        let tree = build_tree(
            &[member(
                "function",
                "sync",
                r#"{"source":{"credential_ref":"vault://prod/db","api-key":"k1","owner_token":"t"},"timeout":3}"#,
            )],
            None,
        )
        .unwrap();
        let body = &tree["function/sync.json"];
        for leaked in ["vault://prod/db", "k1", "\"t\""] {
            assert!(!body.contains(leaked), "{leaked} leaked: {body}");
        }
        assert_eq!(body.matches(CREDENTIAL_PLACEHOLDER).count(), 3);
        assert!(body.contains("\"timeout\": 3"));
    }

    #[test]
    fn schema_declarations_and_ordinary_settings_survive() {
        let tree = build_tree(
            &[member(
                "object_type",
                "account",
                r#"{"properties":["password","api_key"],"max_tokens":5,"api_key":"k2","source":{"properties":{"password":"k3"}}}"#,
            )],
            None,
        )
        .unwrap();
        let body = &tree["object_type/account.json"];
        assert!(
            body.contains("\"password\",") && body.contains("\"api_key\"\n"),
            "{body}"
        );
        let nested = build_tree(
            &[member(
                "function",
                "f",
                r#"{"secret":["s1"],"password":{"value":"s2"},"credential":{"type":"bearer","value":"s3"},"name":"f"}"#,
            )],
            None,
        )
        .unwrap();
        for leaked in ["s1", "s2", "s3"] {
            assert!(
                !nested["function/f.json"].contains(leaked),
                "{leaked} leaked"
            );
        }
        assert!(body.contains("\"max_tokens\": 5"), "{body}");
        assert!(!body.contains("k2") && !body.contains("k3"), "{body}");
    }

    #[test]
    fn long_ids_get_bounded_file_names_mapped_in_the_layout() {
        let id = "x".repeat(256);
        let tree = build_tree(&[member("object_type", &id, "{}")], None).unwrap();
        let path = tree
            .keys()
            .find(|path| path.starts_with("object_type/"))
            .unwrap()
            .clone();
        assert!(path.len() < 255, "{path}");
        let layout: Value = serde_json::from_str(&tree["layout.json"]).unwrap();
        assert_eq!(layout["long_ids"][&path], Value::String(id));
    }

    #[test]
    fn ids_are_single_safe_segments_and_case_collisions_are_refused() {
        assert_eq!(encode("../x.y"), "%2E%2E%2Fx%2Ey");
        let collide = build_tree(
            &[
                member("object_type", "Incident", "{}"),
                member("object_type", "incident", "{}"),
            ],
            None,
        );
        assert!(collide.unwrap_err().contains("differ only in case"));
    }
}
