//! `sekaictl ontology import` (#1618): applies a file tree written by
//! `sekaictl ontology export` to a namespace as one governed proposal.
//!
//! The tree is compared with the namespace's published definitions as export
//! would render them. A file that renders the same is sent with the server's
//! stored body, so redaction in the tree never overwrites a credential
//! reference; a changed or new file is sent as written and must not contain
//! the redaction placeholder. Published members the tree lacks become
//! removals. An unchanged tree opens nothing.
//!
//! The request names the published revision the tree was compared with, and
//! the server refuses it if another proposal merged since, so an import never
//! reverts a concurrent change. The server checks every grant before its first
//! write, so a refused import creates no branch. The proposal records the
//! source commit and goes through the normal review and merge gates; import
//! never merges. The response carries the lint findings the candidate
//! introduces (#1619), the same ones review sees; an unsuppressed error
//! finding blocks the merge. The marking
//! lattice (`markings/lattice.json`) is not imported: it is not governed by
//! proposals.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;
use tonic::Request;

use crate::grpc::client::connect_sekai;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    DefinitionMemberInput, DefinitionRevisionCompatibility, DefinitionRevisionDiff,
    ImportDefinitionTreeRequest, OntologyLintFinding,
};
use crate::ontology_export::{
    CREDENTIAL_PLACEHOLDER, LAYOUT_VERSION, Tree, build_tree, decode, is_hashed_stem, member_path,
    published_members,
};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// One definition file of the tree.
#[derive(Debug, PartialEq, Eq)]
pub struct TreeMember {
    pub kind: String,
    pub id: String,
    pub path: String,
    pub body: String,
}

/// The proposal an import opened, with what it changes and how compatible
/// that is with the published head.
#[derive(Debug)]
pub struct ImportProposal {
    pub proposal_id: String,
    pub preview: DefinitionRevisionDiff,
    pub compatibility: DefinitionRevisionCompatibility,
    /// What the candidate introduces under ontology lint (#1619); an error
    /// finding blocks the merge.
    pub lint_findings: Vec<OntologyLintFinding>,
    pub lint_complete: bool,
}

/// What an import did.
#[derive(Debug)]
pub enum ImportOutcome {
    /// The tree matches the published definitions; nothing was opened.
    Unchanged,
    Proposed(Box<ImportProposal>),
}

/// Reads the definition files of an exported tree. Refuses an unknown layout
/// version and any file name export would not write.
pub fn read_tree(dir: &Path) -> Result<Vec<TreeMember>, String> {
    if !plain(&dir.join("layout.json"), false)? {
        return Err("layout.json: not a regular file".into());
    }
    let layout: Value = serde_json::from_slice(
        &std::fs::read(dir.join("layout.json")).map_err(|error| format!("layout.json: {error}"))?,
    )
    .map_err(|error| format!("layout.json: {error}"))?;
    if layout["layout_version"] != LAYOUT_VERSION {
        return Err(format!(
            "layout.json: unsupported layout version {}",
            layout["layout_version"]
        ));
    }
    let long_ids = layout["long_ids"].as_object().cloned().unwrap_or_default();
    let mut members = Vec::new();
    for kind_entry in read_dir_sorted(dir)? {
        let kind_segment = file_name(&kind_entry)?;
        if kind_segment == "layout.json" || kind_segment == "markings" {
            continue;
        }
        // Links are refused, so a tree never makes import read a file
        // outside it.
        if !plain(&kind_entry, true)? {
            return Err(format!("{kind_segment}: not a definition kind directory"));
        }
        let kind = decode(&kind_segment)
            .ok_or_else(|| format!("{kind_segment}: not an exported kind name"))?;
        for file in read_dir_sorted(&kind_entry)? {
            let name = file_name(&file)?;
            let path = format!("{kind_segment}/{name}");
            let stem = name
                .strip_suffix(".json")
                .filter(|_| plain(&file, false).unwrap_or(false))
                .ok_or_else(|| format!("{path}: not a definition file"))?;
            let id = if is_hashed_stem(stem) {
                long_ids
                    .get(&path)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{path}: long id missing from layout.json"))?
            } else {
                decode(stem).ok_or_else(|| format!("{path}: not an exported id"))?
            };
            if member_path(&kind, &id) != path {
                return Err(format!("{path}: name does not match its id"));
            }
            let body =
                std::fs::read_to_string(&file).map_err(|error| format!("{path}: {error}"))?;
            members.push(TreeMember {
                kind: kind.clone(),
                id,
                path,
                body,
            });
        }
    }
    Ok(members)
}

/// The full member set to propose: unchanged files carry the stored body.
/// `None` when the tree matches what is published.
pub fn plan_members(
    tree: &[TreeMember],
    published: &[crate::ontology_export::ExportMember],
) -> Result<Option<Vec<DefinitionMemberInput>>, String> {
    let rendered: Tree = build_tree(published, None)?;
    let stored: BTreeMap<String, &str> = published
        .iter()
        .map(|member| {
            (
                member_path(&member.kind, &member.id),
                member.definition_json.as_str(),
            )
        })
        .collect();
    let mut changed = stored.len() != tree.len();
    let mut members = Vec::with_capacity(tree.len());
    for member in tree {
        let definition_json = match (rendered.get(&member.path), stored.get(&member.path)) {
            (Some(rendered), Some(stored)) if *rendered == member.body => (*stored).to_string(),
            _ => {
                changed = true;
                if member.body.contains(CREDENTIAL_PLACEHOLDER) {
                    return Err(format!(
                        "{}: changed definition still holds the redaction placeholder; \
                         write the credential reference before importing",
                        member.path
                    ));
                }
                member.body.clone()
            }
        };
        members.push(DefinitionMemberInput {
            member_kind: member.kind.clone(),
            member_id: member.id.clone(),
            definition_json,
            member_digest: String::new(),
        });
    }
    Ok(changed.then_some(members))
}

/// Imports the tree at `dir` into `namespace`, recording `source_commit`.
pub async fn import(
    target: &str,
    namespace: &str,
    dir: &Path,
    source_commit: &str,
) -> Result<ImportOutcome, BoxErr> {
    let tree = read_tree(dir).map_err(std::io::Error::other)?;
    let mut client = SekaiServiceClient::new(connect_sekai(target).await?);
    let (published_digest, published) = published_members(&mut client, namespace)
        .await?
        .unwrap_or_default();
    let Some(members) = plan_members(&tree, &published).map_err(std::io::Error::other)? else {
        return Ok(ImportOutcome::Unchanged);
    };
    // The same commit imported again replays the same proposal.
    let proposal_id = format!("import-{source_commit}");
    let response = client
        .import_definition_tree(Request::new(ImportDefinitionTreeRequest {
            namespace: namespace.into(),
            branch_id: proposal_id.clone(),
            proposal_id: proposal_id.clone(),
            members,
            source_commit: source_commit.into(),
            idempotency_key: proposal_id.clone(),
            // Unchanged files carry bodies from this revision; a newer head
            // is refused rather than silently reverted.
            expected_published_digest: published_digest,
        }))
        .await?
        .into_inner();
    Ok(ImportOutcome::Proposed(Box::new(ImportProposal {
        proposal_id,
        preview: response.preview.unwrap_or_default(),
        compatibility: response.compatibility.unwrap_or_default(),
        lint_findings: response.lint_findings,
        lint_complete: response.lint_complete,
    })))
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut entries = std::fs::read_dir(dir)
        .map_err(|error| format!("{}: {error}", dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{}: {error}", dir.display()))?;
    entries.sort();
    Ok(entries)
}

/// Whether `path` itself, not a link's target, is a directory (`dir`) or a
/// regular file.
fn plain(path: &Path, dir: bool) -> Result<bool, String> {
    let kind = std::fs::symlink_metadata(path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .file_type();
    Ok(if dir { kind.is_dir() } else { kind.is_file() })
}

fn file_name(path: &Path) -> Result<String, String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("{}: not a UTF-8 file name", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ontology_export::ExportMember;

    fn published(kind: &str, id: &str, json: &str) -> ExportMember {
        ExportMember {
            kind: kind.into(),
            id: id.into(),
            definition_json: json.into(),
        }
    }

    fn written(members: &[ExportMember]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, body) in build_tree(members, None).unwrap() {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        dir
    }

    #[test]
    fn an_exported_tree_reads_back_and_plans_nothing() {
        let members = [
            published("object_type", "incident", r#"{"name":"incident"}"#),
            published("function", "sync/feed", r#"{"name":"sync"}"#),
            published("object_type", &"x".repeat(256), "{}"),
        ];
        let tree = read_tree(written(&members).path()).unwrap();
        assert_eq!(tree.len(), 3);
        assert!(tree.iter().any(|member| member.id == "sync/feed"));
        assert!(tree.iter().any(|member| member.id == "x".repeat(256)));
        assert_eq!(plan_members(&tree, &members).unwrap(), None);
    }

    #[test]
    fn unchanged_files_keep_stored_bodies_and_changed_files_are_sent() {
        let members = [
            published(
                "object_type",
                "a",
                r#"{"name":"a","api_token":"ref:vault/a"}"#,
            ),
            published("object_type", "b", r#"{"name":"b"}"#),
        ];
        let dir = written(&members);
        std::fs::write(
            dir.path().join("object_type/b.json"),
            "{\n  \"name\": \"b2\"\n}\n",
        )
        .unwrap();
        let planned = plan_members(&read_tree(dir.path()).unwrap(), &members)
            .unwrap()
            .unwrap();
        let body = |id: &str| {
            planned
                .iter()
                .find(|member| member.member_id == id)
                .unwrap()
                .definition_json
                .clone()
        };
        assert_eq!(
            body("a"),
            members[0].definition_json,
            "redaction not written back"
        );
        assert_eq!(body("b"), "{\n  \"name\": \"b2\"\n}\n");
    }

    #[test]
    fn a_missing_file_is_a_removal_and_a_changed_placeholder_is_refused() {
        let members = [
            published(
                "object_type",
                "a",
                r#"{"name":"a","api_token":"ref:vault/a"}"#,
            ),
            published("object_type", "b", r#"{"name":"b"}"#),
        ];
        let dir = written(&members);
        std::fs::remove_file(dir.path().join("object_type/b.json")).unwrap();
        let planned = plan_members(&read_tree(dir.path()).unwrap(), &members)
            .unwrap()
            .unwrap();
        assert_eq!(planned.len(), 1);

        let body = std::fs::read_to_string(dir.path().join("object_type/a.json")).unwrap();
        std::fs::write(
            dir.path().join("object_type/a.json"),
            body.replace("\"a\"", "\"a2\""),
        )
        .unwrap();
        let error = plan_members(&read_tree(dir.path()).unwrap(), &members).unwrap_err();
        assert!(error.contains("redaction placeholder"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn links_in_the_tree_are_refused() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.json"), "{}").unwrap();
        let dir = written(&[published("object_type", "a", "{}")]);
        std::os::unix::fs::symlink(
            outside.path().join("secret.json"),
            dir.path().join("object_type/b.json"),
        )
        .unwrap();
        assert!(
            read_tree(dir.path())
                .unwrap_err()
                .contains("not a definition file")
        );

        let dir = written(&[published("object_type", "a", "{}")]);
        std::os::unix::fs::symlink(outside.path(), dir.path().join("function")).unwrap();
        assert!(
            read_tree(dir.path())
                .unwrap_err()
                .contains("not a definition kind")
        );
    }

    #[test]
    fn names_export_would_not_write_are_refused() {
        let dir = written(&[published("object_type", "a", "{}")]);
        std::fs::write(dir.path().join("object_type/%2e%2e.json"), "{}").unwrap();
        assert!(
            read_tree(dir.path())
                .unwrap_err()
                .contains("not an exported id")
        );
    }
}
