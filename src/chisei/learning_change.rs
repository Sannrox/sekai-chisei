//! Governed lineage for inspectable, reversible learned changes (#714).
//!
//! A recorded learning candidate becomes a `chisei.learning-change/v1` object
//! that binds baseline, candidate, and evidence digests. Approval and
//! activation are explicit. Rollback supersedes history without rewriting
//! source evidence.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::KIND_LEARNING;
use crate::sekai::audit::Decision;
use crate::shomei;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const CHANGE_CONTRACT: &str = "chisei.learning-change/v1";
pub const POSTGRES_UNAVAILABLE: &str =
    "learning changes are unavailable on the PostgreSQL community runtime";
pub const UNAVAILABLE: &str = "learning change is unavailable";
pub const PROPOSE_ACTION: &str = "learning.change_propose";
pub const APPROVE_ACTION: &str = "learning.change_approve";
pub const ACTIVATE_ACTION: &str = "learning.change_activate";
pub const ROLLBACK_ACTION: &str = "learning.change_rollback";
pub const RECONCILE_ACTION: &str = "learning.change_reconcile";

const STATUS_PROPOSED: &str = "proposed";
const STATUS_APPROVED: &str = "approved";
const STATUS_ACTIVE: &str = "active";
const STATUS_ROLLED_BACK: &str = "rolled_back";
const RECONCILE_NONE: &str = "none";
const RECONCILE_LEASE_LOST: &str = "lease_lost";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearningChangeApproval {
    pub approved_by: String,
    pub approved_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearningChangeLineageEntry {
    pub action: String,
    pub actor: String,
    pub at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_change_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearningChangeComparison {
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub evidence_digest: String,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearningChange {
    pub contract_version: String,
    pub change_id: String,
    pub namespace: String,
    pub learning_id: String,
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub evidence_digest: String,
    pub status: String,
    pub approval: Option<LearningChangeApproval>,
    #[serde(default)]
    pub lineage: Vec<LearningChangeLineageEntry>,
    pub reconciliation: String,
    pub write_authority: bool,
    pub permit_authority: bool,
    pub proposed_by: String,
    pub proposed_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ProposeLearningChange {
    pub namespace: String,
    pub learning_id: String,
    pub evidence_digest: String,
}

pub fn change_id_for(namespace: &str, learning_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CHANGE_CONTRACT.as_bytes());
    hasher.update(b"\n");
    hasher.update(namespace.as_bytes());
    hasher.update(b"\n");
    hasher.update(learning_id.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

pub fn propose_change(
    db: &RuntimeDb,
    actor: &str,
    request: &ProposeLearningChange,
    now_ms: i64,
) -> Result<LearningChange, String> {
    required("actor", actor)?;
    required("namespace", &request.namespace)?;
    required("learning id", &request.learning_id)?;
    validate_digest("evidence_digest", &request.evidence_digest)?;
    if now_ms < 0 {
        return Err("proposal timestamp must be non-negative".into());
    }

    let learning = visible_learning(db, &request.namespace, &request.learning_id)?;
    let candidate_digest = learning_digest(&learning)?;
    let baseline_digest = live_baseline_digest(db, &request.namespace, &request.learning_id)?;
    let change_id = change_id_for(&request.namespace, &request.learning_id);
    if let Some(mut existing) = db.get_learning_change(&change_id)? {
        if existing.namespace != request.namespace || existing.learning_id != request.learning_id {
            return Err(UNAVAILABLE.into());
        }
        deny_if_unusable(&existing)?;
        if existing.status == STATUS_ACTIVE {
            return Err(UNAVAILABLE.into());
        }
        if existing.candidate_digest == candidate_digest
            && existing.evidence_digest == request.evidence_digest
            && existing.baseline_digest == baseline_digest
            && existing.status == STATUS_PROPOSED
        {
            return Ok(existing);
        }
        existing.baseline_digest = baseline_digest;
        existing.candidate_digest = candidate_digest;
        existing.evidence_digest = request.evidence_digest.clone();
        existing.status = STATUS_PROPOSED.into();
        existing.approval = None;
        existing.lineage.push(LearningChangeLineageEntry {
            action: "propose".into(),
            actor: actor.into(),
            at_ms: now_ms,
            restored_change_id: None,
        });
        existing.updated_at_ms = now_ms;
        db.put_learning_change(&existing)?;
        audit(db, actor, PROPOSE_ACTION, "proposed", &existing, now_ms)?;
        return Ok(existing);
    }

    let record = LearningChange {
        contract_version: CHANGE_CONTRACT.into(),
        change_id,
        namespace: request.namespace.clone(),
        learning_id: request.learning_id.clone(),
        baseline_digest,
        candidate_digest,
        evidence_digest: request.evidence_digest.clone(),
        status: STATUS_PROPOSED.into(),
        approval: None,
        lineage: Vec::new(),
        reconciliation: RECONCILE_NONE.into(),
        write_authority: false,
        permit_authority: false,
        proposed_by: actor.into(),
        proposed_at_ms: now_ms,
        updated_at_ms: now_ms,
    };
    db.put_learning_change(&record)?;
    audit(db, actor, PROPOSE_ACTION, "proposed", &record, now_ms)?;
    Ok(record)
}

pub fn approve_change(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    learning_id: &str,
    now_ms: i64,
) -> Result<LearningChange, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("approval timestamp must be non-negative".into());
    }
    let mut record = get_change(db, namespace, learning_id)?;
    deny_if_unusable(&record)?;
    require_current_candidate(db, &record)?;
    if record.status == STATUS_APPROVED
        && record
            .approval
            .as_ref()
            .is_some_and(|item| item.approved_by == actor)
    {
        return Ok(record);
    }
    if record.status != STATUS_PROPOSED && record.status != STATUS_APPROVED {
        return Err(UNAVAILABLE.into());
    }
    record.status = STATUS_APPROVED.into();
    record.approval = Some(LearningChangeApproval {
        approved_by: actor.into(),
        approved_at_ms: now_ms,
    });
    record.updated_at_ms = now_ms;
    db.put_learning_change(&record)?;
    audit(db, actor, APPROVE_ACTION, "approved", &record, now_ms)?;
    Ok(record)
}

pub fn activate_change(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    learning_id: &str,
    now_ms: i64,
) -> Result<LearningChange, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("activation timestamp must be non-negative".into());
    }
    let mut record = get_change(db, namespace, learning_id)?;
    deny_if_unusable(&record)?;
    if record.status == STATUS_ACTIVE {
        return Ok(record);
    }
    require_current_candidate(db, &record)?;
    if record.status != STATUS_APPROVED || record.approval.is_none() {
        return Err(UNAVAILABLE.into());
    }
    record.status = STATUS_ACTIVE.into();
    record.lineage.push(LearningChangeLineageEntry {
        action: "activate".into(),
        actor: actor.into(),
        at_ms: now_ms,
        restored_change_id: None,
    });
    record.updated_at_ms = now_ms;
    set_learning_status(db, &record.learning_id, "active")?;
    db.put_learning_change(&record)?;
    audit(db, actor, ACTIVATE_ACTION, "activated", &record, now_ms)?;
    Ok(record)
}

pub fn rollback_change(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    learning_id: &str,
    now_ms: i64,
) -> Result<LearningChange, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("rollback timestamp must be non-negative".into());
    }
    let mut record = get_change(db, namespace, learning_id)?;
    deny_if_unusable(&record)?;
    if record.status == STATUS_ROLLED_BACK {
        return Ok(record);
    }
    if record.status != STATUS_ACTIVE {
        return Err(UNAVAILABLE.into());
    }
    record.status = STATUS_ROLLED_BACK.into();
    record.lineage.push(LearningChangeLineageEntry {
        action: "rollback".into(),
        actor: actor.into(),
        at_ms: now_ms,
        restored_change_id: None,
    });
    record.updated_at_ms = now_ms;
    set_learning_status(db, &record.learning_id, "candidate")?;
    db.put_learning_change(&record)?;
    audit(db, actor, ROLLBACK_ACTION, "rolled_back", &record, now_ms)?;
    Ok(record)
}

pub fn note_lease_loss(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    learning_id: &str,
    now_ms: i64,
) -> Result<LearningChange, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("reconciliation timestamp must be non-negative".into());
    }
    let mut record = get_change(db, namespace, learning_id)?;
    if record.reconciliation == RECONCILE_LEASE_LOST {
        return Ok(record);
    }
    record.reconciliation = RECONCILE_LEASE_LOST.into();
    record.updated_at_ms = now_ms;
    db.put_learning_change(&record)?;
    audit(db, actor, RECONCILE_ACTION, "lease_lost", &record, now_ms)?;
    Ok(record)
}

pub fn get_change(
    db: &RuntimeDb,
    namespace: &str,
    learning_id: &str,
) -> Result<LearningChange, String> {
    required("namespace", namespace)?;
    required("learning id", learning_id)?;
    let change_id = change_id_for(namespace, learning_id);
    let record = db
        .get_learning_change(&change_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())?;
    if record.namespace != namespace || record.learning_id != learning_id {
        return Err(UNAVAILABLE.into());
    }
    Ok(record)
}

pub fn list_changes(
    db: &RuntimeDb,
    namespace: Option<&str>,
) -> Result<Vec<LearningChange>, String> {
    db.list_learning_changes(namespace)
}

pub fn inspect_change(
    db: &RuntimeDb,
    namespace: &str,
    learning_id: &str,
) -> Result<LearningChangeComparison, String> {
    let record = get_change(db, namespace, learning_id)?;
    Ok(LearningChangeComparison {
        baseline_digest: record.baseline_digest.clone(),
        candidate_digest: record.candidate_digest.clone(),
        evidence_digest: record.evidence_digest.clone(),
        changed: record.baseline_digest != record.candidate_digest,
    })
}

fn visible_learning(
    db: &RuntimeDb,
    namespace: &str,
    learning_id: &str,
) -> Result<crate::domain::Object, String> {
    let learning = db
        .get_object(learning_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())?;
    if learning.kind != KIND_LEARNING || learning.namespace != namespace {
        return Err(UNAVAILABLE.into());
    }
    Ok(learning)
}

fn require_current_candidate(db: &RuntimeDb, record: &LearningChange) -> Result<(), String> {
    let learning = visible_learning(db, &record.namespace, &record.learning_id)?;
    let current = learning_digest(&learning)?;
    if current != record.candidate_digest {
        return Err(UNAVAILABLE.into());
    }
    Ok(())
}

fn deny_if_unusable(record: &LearningChange) -> Result<(), String> {
    if record.reconciliation != RECONCILE_NONE {
        return Err(UNAVAILABLE.into());
    }
    Ok(())
}

fn live_baseline_digest(
    db: &RuntimeDb,
    namespace: &str,
    learning_id: &str,
) -> Result<String, String> {
    let current = change_id_for(namespace, learning_id);
    Ok(db
        .list_learning_changes(Some(namespace))?
        .into_iter()
        .filter(|record| record.status == STATUS_ACTIVE && record.change_id != current)
        .map(|record| record.candidate_digest)
        .next()
        .unwrap_or_default())
}

fn set_learning_status(db: &RuntimeDb, learning_id: &str, status: &str) -> Result<(), String> {
    let mut learning = db
        .get_object(learning_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())?;
    learning.properties.insert("status".into(), status.into());
    learning.updated = learning.updated.saturating_add(1);
    db.update_object(&learning)
}

fn learning_digest(object: &crate::domain::Object) -> Result<String, String> {
    let mut properties = object.properties.clone();
    properties.remove("status");
    #[derive(Serialize)]
    struct Claim<'a> {
        object_id: &'a str,
        kind: &'a str,
        name: &'a str,
        namespace: &'a str,
        properties: &'a HashMap<String, String>,
    }
    digest_json(&Claim {
        object_id: &object.id,
        kind: &object.kind,
        name: &object.name,
        namespace: &object.namespace,
        properties: &properties,
    })
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, String> {
    let canonical =
        shomei::canonical_json_with_finite_numbers(value).map_err(|_| UNAVAILABLE.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn validate_digest(name: &str, value: &str) -> Result<(), String> {
    required(name, value)?;
    if !value.starts_with("sha256:") || value.len() != 71 {
        return Err(UNAVAILABLE.into());
    }
    if !value.as_bytes()[7..].iter().all(u8::is_ascii_hexdigit) {
        return Err(UNAVAILABLE.into());
    }
    Ok(())
}

fn audit(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    outcome: &str,
    record: &LearningChange,
    now_ms: i64,
) -> Result<(), String> {
    db.record_decision(&Decision {
        id: format!("{action}:{}:{now_ms}", record.change_id),
        timestamp: now_ms,
        actor: actor.into(),
        action: action.into(),
        reason: format!("recorded {CHANGE_CONTRACT} {outcome}"),
        evidence: HashMap::from([
            ("contract_version".into(), CHANGE_CONTRACT.into()),
            ("namespace".into(), record.namespace.clone()),
            ("learning_id".into(), record.learning_id.clone()),
            ("change_id".into(), record.change_id.clone()),
            ("status".into(), record.status.clone()),
            ("write_authority".into(), "false".into()),
            ("permit_authority".into(), "false".into()),
            ("data_class".into(), "internal".into()),
        ]),
        target_id: record.change_id.clone(),
        outcome: outcome.into(),
    })
}

fn required(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::learning::record_learning;
    use crate::sekai::schema::SchemaRegistry;
    use std::collections::HashMap;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn evidence() -> String {
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
    }

    fn record_candidate(db: &RuntimeDb) {
        db.create_object(&Object {
            id: "target-1".into(),
            kind: "component".into(),
            name: "checkout".into(),
            namespace: "payments".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        record_learning(
            db,
            &SchemaRegistry::new(),
            &HashMap::from([
                ("id".into(), "learning-1".into()),
                ("target_id".into(), "target-1".into()),
                ("title".into(), "Validate retries".into()),
                ("prevention".into(), "Check the prior record first".into()),
                (
                    "reasoning".into(),
                    "The retry repeated a side effect".into(),
                ),
                ("source_request_id".into(), "request-42".into()),
                ("score".into(), "72".into()),
                ("passed".into(), "false".into()),
                ("task_class".into(), "reasoning".into()),
                ("model".into(), "judge-model".into()),
                ("producer".into(), "scoring-job".into()),
                ("status".into(), "candidate".into()),
            ]),
            "worker-1",
        )
        .unwrap();
    }

    fn propose(db: &RuntimeDb, now_ms: i64) -> LearningChange {
        propose_change(
            db,
            "operator",
            &ProposeLearningChange {
                namespace: "payments".into(),
                learning_id: "learning-1".into(),
                evidence_digest: evidence(),
            },
            now_ms,
        )
        .unwrap()
    }

    #[test]
    fn inspects_approves_activates_and_rolls_back_without_rewriting_evidence() {
        let db = db();
        record_candidate(&db);
        let proposed = propose(&db, 1_000);
        assert_eq!(proposed.status, STATUS_PROPOSED);
        assert!(!proposed.write_authority);
        let replay = propose(&db, 1_100);
        assert_eq!(replay.change_id, proposed.change_id);
        assert_eq!(replay.proposed_at_ms, 1_000);

        let comparison = inspect_change(&db, "payments", "learning-1").unwrap();
        assert!(comparison.changed);
        assert_eq!(comparison.candidate_digest, proposed.candidate_digest);
        assert_eq!(comparison.evidence_digest, evidence());

        let approved = approve_change(&db, "reviewer", "payments", "learning-1", 2_000).unwrap();
        assert_eq!(approved.status, STATUS_APPROVED);
        let activated = activate_change(&db, "operator", "payments", "learning-1", 3_000).unwrap();
        assert_eq!(activated.status, STATUS_ACTIVE);
        assert_eq!(activated.lineage.len(), 1);
        let replay_activate =
            activate_change(&db, "operator", "payments", "learning-1", 3_100).unwrap();
        assert_eq!(replay_activate.status, STATUS_ACTIVE);
        assert_eq!(replay_activate.lineage.len(), 1);
        assert_eq!(replay_activate.updated_at_ms, 3_000);
        assert_eq!(
            db.get_object("learning-1").unwrap().unwrap().properties["status"],
            "active"
        );
        let title_before = db
            .get_object("learning-1")
            .unwrap()
            .unwrap()
            .properties
            .get("title")
            .cloned();

        let rolled = rollback_change(&db, "operator", "payments", "learning-1", 4_000).unwrap();
        assert_eq!(rolled.status, STATUS_ROLLED_BACK);
        assert_eq!(rolled.lineage.len(), 2);
        assert_eq!(rolled.lineage[1].action, "rollback");
        assert_eq!(
            db.get_object("learning-1").unwrap().unwrap().properties["status"],
            "candidate"
        );
        assert_eq!(
            db.get_object("learning-1")
                .unwrap()
                .unwrap()
                .properties
                .get("title"),
            title_before.as_ref()
        );

        let reproposed = propose(&db, 5_000);
        assert_eq!(reproposed.status, STATUS_PROPOSED);
        assert_eq!(reproposed.lineage.len(), 3);
        assert_eq!(reproposed.lineage[2].action, "propose");
        assert_eq!(reproposed.change_id, proposed.change_id);
    }

    #[test]
    fn stale_hidden_and_lease_loss_block_activation() {
        let db = db();
        record_candidate(&db);
        propose(&db, 1_000);
        approve_change(&db, "reviewer", "payments", "learning-1", 2_000).unwrap();

        let mut learning = db.get_object("learning-1").unwrap().unwrap();
        learning
            .properties
            .insert("title".into(), "changed after pin".into());
        db.update_object(&learning).unwrap();
        assert_eq!(
            activate_change(&db, "operator", "payments", "learning-1", 3_000).unwrap_err(),
            UNAVAILABLE
        );

        let missing = get_change(&db, "payments", "missing").unwrap_err();
        assert_eq!(missing, UNAVAILABLE);
        assert!(!missing.contains("missing"));
        assert_eq!(
            propose_change(
                &db,
                "operator",
                &ProposeLearningChange {
                    namespace: "other".into(),
                    learning_id: "learning-1".into(),
                    evidence_digest: evidence(),
                },
                3_100,
            )
            .unwrap_err(),
            UNAVAILABLE
        );

        let lost = RuntimeDb::memory();
        record_candidate(&lost);
        propose(&lost, 4_000);
        note_lease_loss(&lost, "operator", "payments", "learning-1", 4_100).unwrap();
        assert_eq!(
            approve_change(&lost, "reviewer", "payments", "learning-1", 4_200).unwrap_err(),
            UNAVAILABLE
        );
    }

    #[test]
    fn postgres_surface_is_explicitly_unavailable() {
        assert!(POSTGRES_UNAVAILABLE.contains("PostgreSQL"));
    }
}
