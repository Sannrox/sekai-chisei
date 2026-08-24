//! Governed definition branches with immutable, content-addressed history.
//!
//! A branch head is a compare-and-swap projection. Definition members and
//! revisions are immutable authority; changing a branch creates another
//! revision instead of rewriting the parent.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::sekai::json::contains_duplicate_object_keys;

pub const MEMBER_CONTRACT_VERSION: &str = "sekai.definition-member/v1";
pub const REVISION_CONTRACT_VERSION: &str = "sekai.definition-revision/v1";
pub const BRANCH_CONTRACT_VERSION: &str = "sekai.definition-branch/v1";
pub const MAX_DEFINITION_MEMBERS: usize = 4_096;
pub const MAX_DEFINITION_MEMBER_BYTES: usize = 256 * 1024;
pub const MAX_DEFINITION_ID_BYTES: usize = 256;
pub const MAX_DEFINITION_KIND_BYTES: usize = 64;

const KNOWN_MEMBER_KINDS: &[&str] = &[
    "action_type",
    "control",
    "interface_type",
    "link_type",
    "object_type",
    "ontology_class",
    "ontology_relation",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionMemberInput {
    pub member_kind: String,
    pub member_id: String,
    pub definition_json: String,
    #[serde(default)]
    pub member_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionMemberRef {
    pub member_kind: String,
    pub member_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionMember {
    pub contract_version: String,
    pub namespace: String,
    pub member_kind: String,
    pub member_id: String,
    pub definition_json: String,
    pub member_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionRevisionMember {
    pub member_kind: String,
    pub member_id: String,
    pub member_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionRevision {
    pub contract_version: String,
    pub namespace: String,
    pub revision_digest: String,
    pub parent_revision_digest: String,
    pub members: Vec<DefinitionRevisionMember>,
    pub published: bool,
    pub created_by: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionBranch {
    pub contract_version: String,
    pub namespace: String,
    pub branch_id: String,
    pub base_revision_digest: String,
    pub head_revision_digest: String,
    pub created_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateDefinitionBranch {
    pub namespace: String,
    pub branch_id: String,
    pub parent_revision_digest: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyDefinitionBranchEdit {
    pub namespace: String,
    pub branch_id: String,
    pub expected_head_digest: String,
    pub upserts: Vec<DefinitionMemberInput>,
    pub removals: Vec<DefinitionMemberRef>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionBranchEditResult {
    pub branch: DefinitionBranch,
    pub previous_head_digest: String,
    pub revision: DefinitionRevision,
    pub changed_member_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum DefinitionWriteResult {
    CreateBranch {
        branch: DefinitionBranch,
    },
    ApplyEdit {
        result: Box<DefinitionBranchEditResult>,
    },
    CreateProposal {
        proposal: crate::sekai::definition_proposal::DefinitionProposal,
    },
    ApproveProposal {
        proposal: crate::sekai::definition_proposal::DefinitionProposal,
    },
    RejectProposal {
        proposal: crate::sekai::definition_proposal::DefinitionProposal,
    },
    MergeProposal {
        result: Box<crate::sekai::definition_proposal::DefinitionMergeResult>,
    },
}

impl DefinitionMemberRef {
    pub fn validate(&self) -> Result<(), String> {
        validate_member_identity(&self.member_kind, &self.member_id)
    }

    fn key(&self) -> (&str, &str) {
        (&self.member_kind, &self.member_id)
    }
}

impl DefinitionMemberInput {
    pub fn prepare(&self, namespace: &str) -> Result<DefinitionMember, String> {
        validate_namespace(namespace)?;
        validate_member_identity(&self.member_kind, &self.member_id)?;
        if self.definition_json.len() > MAX_DEFINITION_MEMBER_BYTES {
            return Err("definition_json exceeds the supported size".into());
        }
        if contains_duplicate_object_keys(&self.definition_json)? {
            return Err("definition_json contains duplicate object keys".into());
        }
        let value: Value = serde_json::from_str(&self.definition_json)
            .map_err(|error| format!("definition_json must be valid JSON: {error}"))?;
        if !value.is_object() {
            return Err("definition_json must be a JSON object".into());
        }
        let canonical = crate::shomei::canonical_json_with_finite_numbers(&value)?;
        let definition_json =
            String::from_utf8(canonical).map_err(|_| "canonical definition_json is not UTF-8")?;
        let digest = member_digest(
            namespace,
            &self.member_kind,
            &self.member_id,
            definition_json.as_bytes(),
        );
        if !self.member_digest.is_empty() && self.member_digest != digest {
            return Err("member_digest does not match canonical definition content".into());
        }
        Ok(DefinitionMember {
            contract_version: MEMBER_CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            member_kind: self.member_kind.clone(),
            member_id: self.member_id.clone(),
            definition_json,
            member_digest: digest,
        })
    }
}

impl DefinitionMember {
    pub fn verify(&self) -> Result<(), String> {
        if self.contract_version != MEMBER_CONTRACT_VERSION {
            return Err("definition member contract version is unsupported".into());
        }
        let prepared = DefinitionMemberInput {
            member_kind: self.member_kind.clone(),
            member_id: self.member_id.clone(),
            definition_json: self.definition_json.clone(),
            member_digest: self.member_digest.clone(),
        }
        .prepare(&self.namespace)?;
        if prepared != *self {
            return Err("definition member content binding is invalid".into());
        }
        Ok(())
    }
}

impl CreateDefinitionBranch {
    pub fn validate(&self) -> Result<(), String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("branch_id", &self.branch_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("parent_revision_digest", &self.parent_revision_digest)?;
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )
    }

    pub fn request_digest(&self) -> Result<String, String> {
        self.validate()?;
        canonical_digest("create_definition_branch", self)
    }
}

impl ApplyDefinitionBranchEdit {
    pub fn prepare(
        &self,
    ) -> Result<(Vec<DefinitionMember>, Vec<DefinitionMemberRef>, String), String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("branch_id", &self.branch_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("expected_head_digest", &self.expected_head_digest)?;
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )?;
        if self.upserts.is_empty() && self.removals.is_empty() {
            return Err("at least one definition member change is required".into());
        }
        if self.upserts.len() + self.removals.len() > MAX_DEFINITION_MEMBERS {
            return Err("definition edit exceeds the supported member count".into());
        }

        let mut changed = BTreeSet::new();
        let mut upserts = Vec::with_capacity(self.upserts.len());
        for input in &self.upserts {
            let member = input.prepare(&self.namespace)?;
            if !changed.insert((member.member_kind.clone(), member.member_id.clone())) {
                return Err("definition edit contains a duplicate member change".into());
            }
            upserts.push(member);
        }
        let mut removals = Vec::with_capacity(self.removals.len());
        for member in &self.removals {
            member.validate()?;
            if !changed.insert((member.member_kind.clone(), member.member_id.clone())) {
                return Err("definition edit contains a duplicate member change".into());
            }
            removals.push(member.clone());
        }
        upserts.sort_by(|left, right| {
            (&left.member_kind, &left.member_id).cmp(&(&right.member_kind, &right.member_id))
        });
        removals.sort_by(|left, right| left.key().cmp(&right.key()));
        let request_digest = canonical_digest(
            "apply_definition_branch_edit",
            &PreparedEditDigestInput {
                namespace: &self.namespace,
                branch_id: &self.branch_id,
                expected_head_digest: &self.expected_head_digest,
                upserts: &upserts,
                removals: &removals,
            },
        )?;
        Ok((upserts, removals, request_digest))
    }
}

impl DefinitionRevision {
    pub fn verify(&self) -> Result<(), String> {
        if self.contract_version != REVISION_CONTRACT_VERSION {
            return Err("definition revision contract version is unsupported".into());
        }
        let prepared = prepare_revision(
            &self.namespace,
            &self.parent_revision_digest,
            self.members.clone(),
            self.published,
            &self.created_by,
            self.created_at_ms,
        )?;
        if prepared != *self {
            return Err("definition revision content binding is invalid".into());
        }
        Ok(())
    }
}

pub fn prepare_revision(
    namespace: &str,
    parent_revision_digest: &str,
    members: impl IntoIterator<Item = DefinitionRevisionMember>,
    published: bool,
    created_by: &str,
    created_at_ms: i64,
) -> Result<DefinitionRevision, String> {
    validate_namespace(namespace)?;
    if !parent_revision_digest.is_empty() {
        validate_digest("parent_revision_digest", parent_revision_digest)?;
    }
    validate_identifier("created_by", created_by, MAX_DEFINITION_ID_BYTES)?;
    if created_at_ms <= 0 {
        return Err("created_at_ms must be positive".into());
    }

    let mut by_identity = BTreeMap::new();
    for member in members {
        validate_member_identity(&member.member_kind, &member.member_id)?;
        validate_digest("member_digest", &member.member_digest)?;
        let key = (member.member_kind.clone(), member.member_id.clone());
        if by_identity.insert(key, member).is_some() {
            return Err("revision contains duplicate member identities".into());
        }
    }
    if by_identity.len() > MAX_DEFINITION_MEMBERS {
        return Err("revision exceeds the supported member count".into());
    }
    let members = by_identity.into_values().collect::<Vec<_>>();
    let digest_input = RevisionDigestInput {
        contract_version: REVISION_CONTRACT_VERSION,
        namespace,
        parent_revision_digest,
        members: &members,
    };
    let revision_digest = canonical_digest("definition_revision", &digest_input)?;
    Ok(DefinitionRevision {
        contract_version: REVISION_CONTRACT_VERSION.into(),
        namespace: namespace.into(),
        revision_digest,
        parent_revision_digest: parent_revision_digest.into(),
        members,
        published,
        created_by: created_by.into(),
        created_at_ms,
    })
}

pub fn apply_member_changes(
    parent: &DefinitionRevision,
    upserts: &[DefinitionMember],
    removals: &[DefinitionMemberRef],
    actor: &str,
    now_ms: i64,
) -> Result<DefinitionRevision, String> {
    let mut members = parent
        .members
        .iter()
        .cloned()
        .map(|member| {
            (
                (member.member_kind.clone(), member.member_id.clone()),
                member,
            )
        })
        .collect::<BTreeMap<_, _>>();
    for removal in removals {
        if members
            .remove(&(removal.member_kind.clone(), removal.member_id.clone()))
            .is_none()
        {
            return Err("definition_member_not_found: member is unavailable".into());
        }
    }
    for member in upserts {
        if member.namespace != parent.namespace {
            return Err("definition member namespace does not match parent revision".into());
        }
        members.insert(
            (member.member_kind.clone(), member.member_id.clone()),
            DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            },
        );
    }
    let resulting_members = members.into_values().collect::<Vec<_>>();
    if resulting_members == parent.members {
        return Err("definition_edit_no_change: edit does not change the parent revision".into());
    }
    prepare_revision(
        &parent.namespace,
        &parent.revision_digest,
        resulting_members,
        false,
        actor,
        now_ms,
    )
}

pub fn changed_member_digests(
    parent: &DefinitionRevision,
    upserts: &[DefinitionMember],
    removals: &[DefinitionMemberRef],
) -> Result<Vec<String>, String> {
    let parent_members = parent
        .members
        .iter()
        .map(|member| {
            (
                (member.member_kind.as_str(), member.member_id.as_str()),
                member.member_digest.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut changed = upserts
        .iter()
        .map(|member| member.member_digest.clone())
        .collect::<Vec<_>>();
    for removal in removals {
        let digest = parent_members
            .get(&(removal.member_kind.as_str(), removal.member_id.as_str()))
            .ok_or_else(|| "definition_member_not_found: member is unavailable".to_string())?;
        changed.push((*digest).to_string());
    }
    changed.sort();
    changed.dedup();
    Ok(changed)
}

pub fn validate_revision_members(
    revision: &DefinitionRevision,
    members: &[DefinitionMember],
) -> Result<(), String> {
    revision.verify()?;
    let mut supplied = Vec::with_capacity(members.len());
    for member in members {
        member.verify()?;
        if member.namespace != revision.namespace {
            return Err("definition member namespace does not match revision".into());
        }
        supplied.push(DefinitionRevisionMember {
            member_kind: member.member_kind.clone(),
            member_id: member.member_id.clone(),
            member_digest: member.member_digest.clone(),
        });
    }
    supplied.sort_by(|left, right| {
        (&left.member_kind, &left.member_id).cmp(&(&right.member_kind, &right.member_id))
    });
    if supplied != revision.members {
        return Err("definition revision member bodies are incomplete or inconsistent".into());
    }
    Ok(())
}

pub fn validate_digest(field: &str, digest: &str) -> Result<(), String> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(format!("{field} must use sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must use sha256:<64 lowercase hex>"));
    }
    Ok(())
}

pub(crate) fn validate_namespace(namespace: &str) -> Result<(), String> {
    validate_identifier("namespace", namespace, MAX_DEFINITION_ID_BYTES)
}

fn validate_member_identity(member_kind: &str, member_id: &str) -> Result<(), String> {
    validate_identifier("member_kind", member_kind, MAX_DEFINITION_KIND_BYTES)?;
    if !KNOWN_MEMBER_KINDS.contains(&member_kind) {
        return Err("member_kind is not supported by the branch contract".into());
    }
    validate_identifier("member_id", member_id, MAX_DEFINITION_ID_BYTES)
}

pub(crate) fn validate_identifier(
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(format!("canonical {field} required"));
    }
    Ok(())
}

#[derive(Serialize)]
struct RevisionDigestInput<'a> {
    contract_version: &'a str,
    namespace: &'a str,
    parent_revision_digest: &'a str,
    members: &'a [DefinitionRevisionMember],
}

#[derive(Serialize)]
struct PreparedEditDigestInput<'a> {
    namespace: &'a str,
    branch_id: &'a str,
    expected_head_digest: &'a str,
    upserts: &'a [DefinitionMember],
    removals: &'a [DefinitionMemberRef],
}

fn member_digest(namespace: &str, member_kind: &str, member_id: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MEMBER_CONTRACT_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(namespace.as_bytes());
    hasher.update(b"\n");
    hasher.update(member_kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(member_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(body);
    format!("sha256:{:x}", hasher.finalize())
}

pub(crate) fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, String> {
    let canonical = crate::shomei::canonical_json_with_finite_numbers(value)?;
    let mut hasher = Sha256::new();
    hasher.update(BRANCH_CONTRACT_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn input(json: &str) -> DefinitionMemberInput {
        DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
    }

    #[test]
    fn member_digest_is_stable_across_object_key_order() {
        let first = input(r#"{"name":"Ticket","properties":{"b":2,"a":1}}"#)
            .prepare("team-a")
            .unwrap();
        let second = input(r#"{"properties":{"a":1,"b":2},"name":"Ticket"}"#)
            .prepare("team-a")
            .unwrap();
        assert_eq!(first.member_digest, second.member_digest);
        assert_eq!(first.definition_json, second.definition_json);
    }

    #[test]
    fn member_digest_is_namespace_bound() {
        let first = input(r#"{"name":"Ticket"}"#).prepare("team-a").unwrap();
        let second = input(r#"{"name":"Ticket"}"#).prepare("team-b").unwrap();
        assert_ne!(first.member_digest, second.member_digest);
    }

    #[test]
    fn supplied_member_digest_must_match() {
        let mut member = input(r#"{"name":"Ticket"}"#);
        member.member_digest = digest('a');
        assert!(
            member
                .prepare("team-a")
                .unwrap_err()
                .contains("does not match")
        );
    }

    #[test]
    fn revision_digest_is_order_independent_and_parent_bound() {
        let ticket = input(r#"{"name":"Ticket"}"#).prepare("team-a").unwrap();
        let incident = DefinitionMemberInput {
            member_id: "Incident".into(),
            ..input(r#"{"name":"Incident"}"#)
        }
        .prepare("team-a")
        .unwrap();
        let refs = |members: Vec<DefinitionMember>| {
            members.into_iter().map(|member| DefinitionRevisionMember {
                member_kind: member.member_kind,
                member_id: member.member_id,
                member_digest: member.member_digest,
            })
        };
        let first = prepare_revision(
            "team-a",
            &digest('a'),
            refs(vec![ticket.clone(), incident.clone()]),
            false,
            "author",
            1,
        )
        .unwrap();
        let second = prepare_revision(
            "team-a",
            &digest('a'),
            refs(vec![incident, ticket]),
            false,
            "author",
            2,
        )
        .unwrap();
        let different_parent = prepare_revision(
            "team-a",
            &digest('b'),
            second.members.clone(),
            false,
            "author",
            2,
        )
        .unwrap();
        assert_eq!(first.revision_digest, second.revision_digest);
        assert_ne!(first.revision_digest, different_parent.revision_digest);
    }

    #[test]
    fn edit_rejects_duplicate_member_changes() {
        let request = ApplyDefinitionBranchEdit {
            namespace: "team-a".into(),
            branch_id: "feature".into(),
            expected_head_digest: digest('a'),
            upserts: vec![input(r#"{"name":"Ticket"}"#)],
            removals: vec![DefinitionMemberRef {
                member_kind: "object_type".into(),
                member_id: "Ticket".into(),
            }],
            idempotency_key: "request-1".into(),
        };
        assert!(request.prepare().unwrap_err().contains("duplicate"));
    }
}
