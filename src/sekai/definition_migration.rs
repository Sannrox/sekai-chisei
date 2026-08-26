//! Approved, checkpointed fact migration between definition revisions.
//!
//! Published definition rows stay immutable. Runtime objects of object-type
//! members are rebound from an ancestor revision to the current published
//! head. Unknown compatibility, stale parents, and unauthorized revisions
//! fail closed. Dry-run, execute, resume, and rollback share one result
//! identity.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::Object;
use crate::sekai::definition_branch::{
    DefinitionMember, DefinitionRevision, MAX_DEFINITION_ID_BYTES, validate_digest,
    validate_identifier, validate_namespace,
};
use crate::sekai::definition_diff::{
    DefinitionCompatibilityClass, DefinitionRevisionCompatibility,
    classify_definition_revision_compatibility,
};

pub const FACT_MIGRATION_CONTRACT_VERSION: &str = "sekai.fact-migration/v1";
pub const MODE_DRY_RUN: &str = "dry_run";
pub const MODE_EXECUTE: &str = "execute";
pub const MODE_ROLLBACK: &str = "rollback";
pub const STATUS_DRY_RUN_COMPLETE: &str = "dry_run_complete";
pub const STATUS_COMMITTED: &str = "committed";
pub const STATUS_BLOCKED: &str = "blocked";
pub const STATUS_ROLLED_BACK: &str = "rolled_back";
pub const STATUS_DENIED: &str = "denied";
pub const MAX_MIGRATION_OBJECTS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteFactMigration {
    pub namespace: String,
    pub migration_id: String,
    pub from_revision_digest: String,
    pub to_revision_digest: String,
    pub mode: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactMigrationBlock {
    pub object_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactMigrationObjectPlan {
    pub object_id: String,
    pub kind: String,
    pub outcome: String,
    pub stripped_properties: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactMigrationResult {
    pub contract_version: String,
    pub namespace: String,
    pub migration_id: String,
    pub from_revision_digest: String,
    pub to_revision_digest: String,
    pub compatibility_digest: String,
    pub compatibility_class: String,
    pub mode: String,
    pub status: String,
    pub checkpoint_object_id: String,
    pub affected_count: i32,
    pub migrated_count: i32,
    pub blocked_count: i32,
    pub blocked: Vec<FactMigrationBlock>,
    pub objects: Vec<FactMigrationObjectPlan>,
    pub actor: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub result_digest: String,
}

#[derive(Debug, Clone)]
pub struct PreparedObjectMigration {
    pub object: Object,
    pub outcome: String,
    pub stripped_properties: Vec<String>,
    pub after_properties: HashMap<String, String>,
}

impl ExecuteFactMigration {
    pub fn prepare(&self) -> Result<String, String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("migration_id", &self.migration_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("from_revision_digest", &self.from_revision_digest)?;
        validate_digest("to_revision_digest", &self.to_revision_digest)?;
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )?;
        if self.from_revision_digest == self.to_revision_digest {
            return Err("fact_migration_no_change: candidate must differ from parent".into());
        }
        match self.mode.as_str() {
            MODE_DRY_RUN | MODE_EXECUTE | MODE_ROLLBACK => {}
            _ => return Err("fact_migration_unsupported_mode: mode is unknown".into()),
        }
        canonical_digest(
            "execute_definition_fact_migration",
            &(
                &self.namespace,
                &self.migration_id,
                &self.from_revision_digest,
                &self.to_revision_digest,
                &self.mode,
            ),
        )
    }
}

pub fn require_published_candidate(
    published_digest: &str,
    to: &DefinitionRevision,
) -> Result<(), String> {
    if published_digest != to.revision_digest {
        return Err(
            "stale_published_definition_head: fact migration target must be the published head"
                .into(),
        );
    }
    Ok(())
}

pub fn require_ancestor(
    from: &DefinitionRevision,
    to: &DefinitionRevision,
    ancestors: &[DefinitionRevision],
) -> Result<(), String> {
    if from.namespace != to.namespace {
        return Err(
            "definition_revision_conflict: migrated revisions must share a namespace".into(),
        );
    }
    if to.parent_revision_digest == from.revision_digest {
        return Ok(());
    }
    let mut current = to.parent_revision_digest.clone();
    for _ in 0..4_096 {
        if current.is_empty() {
            break;
        }
        if current == from.revision_digest {
            return Ok(());
        }
        let Some(parent) = ancestors
            .iter()
            .find(|revision| revision.revision_digest == current)
        else {
            break;
        };
        current = parent.parent_revision_digest.clone();
    }
    Err("stale_definition_revision: from revision is not an ancestor of the published head".into())
}

pub fn plan_fact_migration(
    from: &DefinitionRevision,
    from_members: &[DefinitionMember],
    to: &DefinitionRevision,
    to_members: &[DefinitionMember],
    objects: &[Object],
    bindings: &BTreeMap<String, String>,
) -> Result<
    (
        DefinitionRevisionCompatibility,
        Vec<PreparedObjectMigration>,
    ),
    String,
> {
    let compatibility =
        classify_definition_revision_compatibility(from, from_members, to, to_members)?;
    if compatibility.class == DefinitionCompatibilityClass::Unknown.as_str() {
        return Err("fact_migration_unknown: unknown compatibility cannot migrate facts".into());
    }
    if objects.len() > MAX_MIGRATION_OBJECTS {
        return Err("fact_migration_limit: object set exceeds the supported ceiling".into());
    }
    let from_types = object_type_map(from_members)?;
    let to_types = object_type_map(to_members)?;
    let mut planned = Vec::new();
    for object in objects {
        if object.namespace != from.namespace {
            continue;
        }
        if !from_types.contains_key(&object.kind) {
            continue;
        }
        planned.push(plan_object(
            object,
            &from.revision_digest,
            &to.revision_digest,
            bindings.get(&object.id),
            from_types.get(&object.kind),
            to_types.get(&object.kind),
        )?);
    }
    planned.sort_by(|left, right| left.object.id.cmp(&right.object.id));
    Ok((compatibility, planned))
}

pub fn finish_migration_result(
    request: &ExecuteFactMigration,
    compatibility: &DefinitionRevisionCompatibility,
    planned: &[PreparedObjectMigration],
    actor: &str,
    now_ms: i64,
    executed: bool,
    rolled_back: bool,
) -> Result<FactMigrationResult, String> {
    let mut blocked = Vec::new();
    let mut objects = Vec::new();
    let mut migrated = 0i32;
    let mut checkpoint = String::new();
    for item in planned {
        objects.push(FactMigrationObjectPlan {
            object_id: item.object.id.clone(),
            kind: item.object.kind.clone(),
            outcome: item.outcome.clone(),
            stripped_properties: item.stripped_properties.clone(),
        });
        if item.outcome == "blocked" {
            blocked.push(FactMigrationBlock {
                object_id: item.object.id.clone(),
                reason_code: item
                    .stripped_properties
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "blocked_transform".into()),
            });
        } else if item.outcome == "migrate" {
            migrated += 1;
            checkpoint = item.object.id.clone();
        }
    }
    let blocked_count = blocked.len() as i32;
    let status = if rolled_back {
        STATUS_ROLLED_BACK
    } else if blocked_count > 0 && request.mode != MODE_DRY_RUN {
        STATUS_BLOCKED
    } else if request.mode == MODE_DRY_RUN {
        STATUS_DRY_RUN_COMPLETE
    } else if executed {
        STATUS_COMMITTED
    } else {
        STATUS_DENIED
    };
    let mut result = FactMigrationResult {
        contract_version: FACT_MIGRATION_CONTRACT_VERSION.into(),
        namespace: request.namespace.clone(),
        migration_id: request.migration_id.clone(),
        from_revision_digest: request.from_revision_digest.clone(),
        to_revision_digest: request.to_revision_digest.clone(),
        compatibility_digest: compatibility.compatibility_digest.clone(),
        compatibility_class: compatibility.class.clone(),
        mode: request.mode.clone(),
        status: status.into(),
        checkpoint_object_id: checkpoint,
        affected_count: planned.len() as i32,
        migrated_count: if request.mode == MODE_DRY_RUN {
            0
        } else {
            migrated
        },
        blocked_count,
        blocked,
        objects,
        actor: actor.into(),
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
        result_digest: String::new(),
    };
    result.result_digest = canonical_digest("fact_migration_result", &result)?;
    Ok(result)
}

fn plan_object(
    object: &Object,
    from_digest: &str,
    to_digest: &str,
    bound: Option<&String>,
    from_type: Option<&ObjectTypeShape>,
    to_type: Option<&ObjectTypeShape>,
) -> Result<PreparedObjectMigration, String> {
    if bound.is_some_and(|digest| digest == to_digest) {
        return Ok(PreparedObjectMigration {
            object: object.clone(),
            outcome: "skip".into(),
            stripped_properties: Vec::new(),
            after_properties: object.properties.clone(),
        });
    }
    if bound.is_some_and(|digest| digest != from_digest) {
        return Ok(blocked(object, "mixed_revision"));
    }
    let Some(_from_type) = from_type else {
        return Ok(blocked(object, "unknown_kind"));
    };
    let Some(to_type) = to_type else {
        return Ok(blocked(object, "removed_member"));
    };
    for required in &to_type.required {
        if !object.properties.contains_key(required) {
            return Ok(blocked(object, "missing_required"));
        }
    }
    let mut after = object.properties.clone();
    let mut stripped = Vec::new();
    after.retain(|key, _| {
        if to_type.properties.contains(key) || to_type.properties.is_empty() {
            true
        } else {
            stripped.push(key.clone());
            false
        }
    });
    stripped.sort();
    Ok(PreparedObjectMigration {
        object: object.clone(),
        outcome: "migrate".into(),
        stripped_properties: stripped,
        after_properties: after,
    })
}

fn blocked(object: &Object, reason: &str) -> PreparedObjectMigration {
    PreparedObjectMigration {
        object: object.clone(),
        outcome: "blocked".into(),
        stripped_properties: vec![reason.into()],
        after_properties: object.properties.clone(),
    }
}

struct ObjectTypeShape {
    properties: BTreeSet<String>,
    required: BTreeSet<String>,
}

fn object_type_map(
    members: &[DefinitionMember],
) -> Result<BTreeMap<String, ObjectTypeShape>, String> {
    let mut map = BTreeMap::new();
    for member in members {
        if member.member_kind != "object_type" {
            continue;
        }
        map.insert(member.member_id.clone(), object_type_shape(member)?);
    }
    Ok(map)
}

fn object_type_shape(member: &DefinitionMember) -> Result<ObjectTypeShape, String> {
    let value: serde_json::Value = serde_json::from_str(&member.definition_json).map_err(|_| {
        "unknown_definition_construct: definition_json must be an object".to_string()
    })?;
    Ok(ObjectTypeShape {
        properties: named_string_set(&value, "properties")?,
        required: named_string_set(&value, "required")?,
    })
}

fn named_string_set(value: &serde_json::Value, field: &str) -> Result<BTreeSet<String>, String> {
    let Some(found) = value.get(field) else {
        return Ok(BTreeSet::new());
    };
    let Some(items) = found.as_array() else {
        return Err(format!(
            "unknown_definition_construct: {field} must be an array"
        ));
    };
    let mut set = BTreeSet::new();
    for item in items {
        let Some(name) = item.as_str() else {
            return Err(format!(
                "unknown_definition_construct: {field} entries must be strings"
            ));
        };
        set.insert(name.to_string());
    }
    Ok(set)
}

fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, String> {
    let encoded = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(encoded);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(test)]
#[allow(clippy::cloned_ref_to_slice_refs)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };

    fn prepared(kind: &str, id: &str, json: &str) -> DefinitionMember {
        DefinitionMemberInput {
            member_kind: kind.into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare("acme")
        .unwrap()
    }

    fn revision(members: &[DefinitionMember], parent: &str, published: bool) -> DefinitionRevision {
        prepare_revision(
            "acme",
            parent,
            members.iter().map(|member| DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            }),
            published,
            "author",
            1,
        )
        .unwrap()
    }

    fn ticket(id: &str, properties: &[(&str, &str)]) -> Object {
        Object {
            id: id.into(),
            kind: "Ticket".into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: id.into(),
            properties: properties
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn dry_run_plans_compatible_rebind_and_strips_removed_properties() {
        let from_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title","secret"]}"#,
        );
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        );
        let from = revision(&[from_ticket.clone()], "", true);
        let to = revision(&[to_ticket.clone()], &from.revision_digest, true);
        let object = ticket("t1", &[("title", "hello"), ("secret", "hidden")]);
        let (compat, planned) = plan_fact_migration(
            &from,
            &[from_ticket],
            &to,
            &[to_ticket],
            &[object],
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(compat.class, "breaking");
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].outcome, "migrate");
        assert_eq!(planned[0].stripped_properties, ["secret"]);
        assert!(!planned[0].after_properties.contains_key("secret"));
        assert_eq!(planned[0].after_properties.get("title").unwrap(), "hello");
    }

    #[test]
    fn missing_required_and_removed_kind_block_transform() {
        let from_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        );
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title","severity"],"required":["severity"]}"#,
        );
        let from = revision(&[from_ticket.clone()], "", true);
        let to = revision(&[to_ticket.clone()], &from.revision_digest, true);
        let object = ticket("t1", &[("title", "hello")]);
        let (_, planned) = plan_fact_migration(
            &from,
            &[from_ticket.clone()],
            &to,
            &[to_ticket],
            &[object],
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(planned[0].outcome, "blocked");
        assert_eq!(planned[0].stripped_properties, ["missing_required"]);

        let empty_to = revision(&[], &from.revision_digest, true);
        let (_, planned) = plan_fact_migration(
            &from,
            &[from_ticket],
            &empty_to,
            &[],
            &[ticket("t1", &[("title", "hello")])],
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(planned[0].stripped_properties, ["removed_member"]);
    }

    #[test]
    fn mixed_revision_skips_already_migrated_and_blocks_foreign_bindings() {
        let from_ticket = prepared("object_type", "Ticket", r#"{"name":"Ticket"}"#);
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        );
        let from = revision(&[from_ticket.clone()], "", true);
        let to = revision(&[to_ticket.clone()], &from.revision_digest, true);
        let migrated = ticket("done", &[("title", "ok")]);
        let foreign = ticket("other", &[("title", "ok")]);
        let mut bindings = BTreeMap::new();
        bindings.insert(migrated.id.clone(), to.revision_digest.clone());
        bindings.insert(foreign.id.clone(), format!("sha256:{}", "ab".repeat(32)));
        let (_, planned) = plan_fact_migration(
            &from,
            &[from_ticket],
            &to,
            &[to_ticket],
            &[migrated, foreign],
            &bindings,
        )
        .unwrap();
        assert_eq!(planned[0].outcome, "skip");
        assert_eq!(planned[1].outcome, "blocked");
        assert_eq!(planned[1].stripped_properties, ["mixed_revision"]);
    }

    #[test]
    fn unknown_compatibility_fails_closed() {
        let from_ticket = prepared("object_type", "Ticket", r#"{"name":"Ticket"}"#);
        let to_ticket = prepared(
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","mystery":true}"#,
        );
        let from = revision(&[from_ticket.clone()], "", true);
        let to = revision(&[to_ticket.clone()], &from.revision_digest, true);
        let error = plan_fact_migration(
            &from,
            &[from_ticket],
            &to,
            &[to_ticket],
            &[ticket("t1", &[])],
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(
            error.contains("unknown")
                || error.contains("unknown_definition_construct")
                || error.contains("fact_migration_unknown")
        );
    }

    #[test]
    fn ancestor_and_published_head_checks_fail_closed() {
        let member = prepared("object_type", "Ticket", r#"{"name":"Ticket"}"#);
        let from = revision(&[member.clone()], "", true);
        let mid = revision(&[member.clone()], &from.revision_digest, true);
        let to = revision(&[member], &mid.revision_digest, true);
        require_ancestor(&from, &to, std::slice::from_ref(&mid)).unwrap();
        assert!(require_ancestor(&to, &from, &[]).is_err());
        assert!(require_published_candidate("other", &to).is_err());
        require_published_candidate(&to.revision_digest, &to).unwrap();
    }
}
