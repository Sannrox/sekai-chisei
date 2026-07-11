//! Policy attestations: replayable proofs of governed-action decisions.
//!
//! When the action-policy gate renders a decision, an attestation pins the
//! exact policy that authorized it: a canonical snapshot of the policy, a
//! version hash of that snapshot, the inputs (action, actor, risk class,
//! namespace), and the rendered decision. The attestation is bound to the
//! hash-chained audit decision through the decision's evidence
//! (`attestation_id` / `attestation_hash`), so altering an attestation after
//! the fact is detectable, and the decision can be re-derived at any time by
//! replaying the pinned snapshot against the recorded inputs.

use crate::db::sekai::SekaiDb;
use crate::sekai::action::RiskClass;
use crate::sekai::action_policy::{ActionDecision, ActionPolicy};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const ACTION_POLICY_KIND: &str = "action_policy";

/// Evidence keys that bind an audit decision to its attestation.
pub const EVIDENCE_ATTESTATION_ID: &str = "attestation_id";
pub const EVIDENCE_ATTESTATION_HASH: &str = "attestation_hash";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAttestation {
    pub id: String,
    /// The hash-chained audit decision this attestation authorizes.
    pub decision_id: String,
    /// Which policy engine rendered the decision (currently `action_policy`).
    pub policy_kind: String,
    pub policy_scope: String,
    /// Content hash of `policy_snapshot`: the policy version in effect.
    pub policy_version: String,
    /// Canonical JSON of the policy's property map, pinned at decision time.
    pub policy_snapshot: String,
    /// Decision inputs: action, actor, risk_class, namespace.
    pub inputs: HashMap<String, String>,
    /// The rendered decision: allow | deny | require_approval.
    pub decision: String,
    pub content_hash: String,
    pub created: i64,
}

/// Result of re-checking an attestation after the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationVerification {
    /// True when every individual check passed.
    pub ok: bool,
    pub found: bool,
    /// Stored content hash matches a recomputation over the stored fields.
    pub hash_ok: bool,
    /// Replaying the pinned policy snapshot against the recorded inputs
    /// re-derives the recorded decision.
    pub replay_ok: bool,
    /// What the replay produced (useful when it disagrees).
    pub replayed_decision: String,
    /// The linked audit decision exists and its evidence binds back to this
    /// attestation by id and content hash.
    pub decision_linked: bool,
    pub error: String,
}

/// Canonical JSON snapshot of a policy's property map (sorted keys).
pub fn snapshot_action_policy(policy: &ActionPolicy) -> String {
    let properties: BTreeMap<String, String> = policy.to_properties().into_iter().collect();
    serde_json::to_string(&properties).unwrap_or_default()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Version hash of a policy snapshot.
pub fn policy_version(snapshot: &str) -> String {
    sha256_hex(snapshot.as_bytes())
}

/// Content hash over every attestation field except the hash itself. Inputs
/// are sorted so the hash is independent of map iteration order.
pub fn attestation_content_hash(a: &PolicyAttestation) -> String {
    let inputs: BTreeMap<&str, &str> = a
        .inputs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let canonical = serde_json::to_vec(&(
        &a.id,
        &a.decision_id,
        &a.policy_kind,
        &a.policy_scope,
        &a.policy_version,
        &a.policy_snapshot,
        &inputs,
        &a.decision,
        a.created,
    ))
    .unwrap_or_default();
    sha256_hex(&canonical)
}

/// Build an attestation for an action-policy decision. The caller supplies
/// the audit decision id it will record so the two records cross-reference.
pub struct ActionAttestationInput<'a> {
    pub decision_id: &'a str,
    pub policy: &'a ActionPolicy,
    pub action: &'a str,
    pub actor: &'a str,
    pub risk: RiskClass,
    pub namespace: &'a str,
    pub decision: ActionDecision,
    pub created: i64,
}

pub fn build_action_attestation(input: ActionAttestationInput<'_>) -> PolicyAttestation {
    let snapshot = snapshot_action_policy(input.policy);
    let version = policy_version(&snapshot);
    let mut attestation = PolicyAttestation {
        id: uuid::Uuid::new_v4().to_string(),
        decision_id: input.decision_id.to_string(),
        policy_kind: ACTION_POLICY_KIND.to_string(),
        policy_scope: input.policy.scope.clone(),
        policy_version: version,
        policy_snapshot: snapshot,
        inputs: HashMap::from([
            ("action".to_string(), input.action.to_string()),
            ("actor".to_string(), input.actor.to_string()),
            ("risk_class".to_string(), input.risk.as_str().to_string()),
            ("namespace".to_string(), input.namespace.to_string()),
        ]),
        decision: input.decision.as_str().to_string(),
        content_hash: String::new(),
        created: input.created,
    };
    attestation.content_hash = attestation_content_hash(&attestation);
    attestation
}

impl SekaiDb {
    pub(crate) fn migrate_attestations(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_attestations (
                id TEXT PRIMARY KEY,
                decision_id TEXT NOT NULL,
                policy_kind TEXT NOT NULL,
                policy_scope TEXT NOT NULL DEFAULT '',
                policy_version TEXT NOT NULL,
                policy_snapshot TEXT NOT NULL,
                inputs TEXT NOT NULL DEFAULT '{}',
                decision TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                created INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_attestations_decision ON sekai_attestations(decision_id);
            CREATE INDEX IF NOT EXISTS idx_attestations_scope ON sekai_attestations(policy_scope, created);",
        )
        .map_err(|e| e.to_string())
    }

    pub fn insert_attestation(&self, a: &PolicyAttestation) -> Result<(), String> {
        let conn = self.conn();
        insert_attestation_row(&conn, a)
    }

    /// Insert the attestation (when present) and its chained audit decision
    /// in one transaction, so neither an orphan attestation nor an executed
    /// action without an audit record can result from a partial failure.
    pub fn record_decision_with_attestation(
        &self,
        decision: &crate::sekai::audit::Decision,
        attestation: Option<&PolicyAttestation>,
    ) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        if let Some(attestation) = attestation {
            insert_attestation_row(&tx, attestation)?;
        }
        crate::sekai::ledger::insert_chained_decision(&tx, decision)?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn get_attestation(&self, id: &str) -> Result<Option<PolicyAttestation>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT id,decision_id,policy_kind,policy_scope,policy_version,policy_snapshot,inputs,decision,content_hash,created \
             FROM sekai_attestations WHERE id = ?1",
            params![id],
            row_to_attestation,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_attestations(
        &self,
        decision_id: Option<&str>,
        policy_scope: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<PolicyAttestation>, String> {
        let conn = self.conn();
        let mut sql = "SELECT id,decision_id,policy_kind,policy_scope,policy_version,policy_snapshot,inputs,decision,content_hash,created \
             FROM sekai_attestations WHERE 1=1"
            .to_string();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(decision_id) = decision_id {
            sql.push_str(" AND decision_id = ?");
            params.push(Box::new(decision_id.to_string()));
        }
        if let Some(scope) = policy_scope {
            sql.push_str(" AND policy_scope = ?");
            params.push(Box::new(scope.to_string()));
        }
        sql.push_str(" ORDER BY created DESC, rowid DESC LIMIT ? OFFSET ?");
        params.push(Box::new(if limit > 0 { limit } else { 100 }));
        params.push(Box::new(offset.max(0)));

        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), row_to_attestation)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Re-check an attestation: content hash, policy-version hash, decision
    /// replay from the pinned snapshot, and the evidence link on the audit
    /// decision it claims to authorize.
    pub fn verify_attestation(&self, id: &str) -> Result<AttestationVerification, String> {
        let Some(attestation) = self.get_attestation(id)? else {
            return Ok(AttestationVerification {
                ok: false,
                found: false,
                hash_ok: false,
                replay_ok: false,
                replayed_decision: String::new(),
                decision_linked: false,
                error: format!("attestation {id} not found"),
            });
        };

        let mut errors = Vec::new();
        let hash_ok = attestation_content_hash(&attestation) == attestation.content_hash
            && policy_version(&attestation.policy_snapshot) == attestation.policy_version;
        if !hash_ok {
            errors.push("content or policy-version hash mismatch: record was altered".to_string());
        }

        let (replay_ok, replayed_decision) = replay_decision(&attestation);
        if !replay_ok {
            errors.push(format!(
                "replay produced '{replayed_decision}', recorded decision is '{}'",
                attestation.decision
            ));
        }

        let decision_linked = match self.get_decision(&attestation.decision_id)? {
            Some(decision) => {
                decision.evidence.get(EVIDENCE_ATTESTATION_ID) == Some(&attestation.id)
                    && decision.evidence.get(EVIDENCE_ATTESTATION_HASH)
                        == Some(&attestation.content_hash)
            }
            None => false,
        };
        if !decision_linked {
            errors.push(format!(
                "audit decision {} missing or does not bind this attestation",
                attestation.decision_id
            ));
        }

        Ok(AttestationVerification {
            ok: hash_ok && replay_ok && decision_linked,
            found: true,
            hash_ok,
            replay_ok,
            replayed_decision,
            decision_linked,
            error: errors.join("; "),
        })
    }
}

/// Re-derive the decision from the pinned snapshot and recorded inputs.
fn replay_decision(attestation: &PolicyAttestation) -> (bool, String) {
    let Ok(properties) =
        serde_json::from_str::<HashMap<String, String>>(&attestation.policy_snapshot)
    else {
        return (false, "unparseable policy snapshot".to_string());
    };
    let policy = ActionPolicy::from_properties(&attestation.policy_scope, &properties);
    let action = attestation
        .inputs
        .get("action")
        .map(String::as_str)
        .unwrap_or_default();
    let Some(risk) = attestation
        .inputs
        .get("risk_class")
        .and_then(|value| RiskClass::parse(value))
    else {
        return (false, "unparseable risk class input".to_string());
    };
    let replayed = policy.decide(action, risk).as_str().to_string();
    (replayed == attestation.decision, replayed)
}

fn insert_attestation_row(
    conn: &rusqlite::Connection,
    a: &PolicyAttestation,
) -> Result<(), String> {
    let inputs = serde_json::to_string(&a.inputs).unwrap_or_default();
    conn.execute(
        "INSERT INTO sekai_attestations (id,decision_id,policy_kind,policy_scope,policy_version,policy_snapshot,inputs,decision,content_hash,created) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            a.id,
            a.decision_id,
            a.policy_kind,
            a.policy_scope,
            a.policy_version,
            a.policy_snapshot,
            inputs,
            a.decision,
            a.content_hash,
            a.created
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn row_to_attestation(row: &rusqlite::Row<'_>) -> rusqlite::Result<PolicyAttestation> {
    let inputs_str: String = row.get(6)?;
    Ok(PolicyAttestation {
        id: row.get(0)?,
        decision_id: row.get(1)?,
        policy_kind: row.get(2)?,
        policy_scope: row.get(3)?,
        policy_version: row.get(4)?,
        policy_snapshot: row.get(5)?,
        inputs: serde_json::from_str(&inputs_str).unwrap_or_default(),
        decision: row.get(7)?,
        content_hash: row.get(8)?,
        created: row.get(9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::audit::Decision;

    fn policy() -> ActionPolicy {
        let mut policy = ActionPolicy::allow_all("agent:tester");
        policy
            .action_overrides
            .insert("delete_object".into(), ActionDecision::Deny);
        policy
            .risk_overrides
            .insert(RiskClass::Destructive, ActionDecision::RequireApproval);
        policy
    }

    fn attest(decision_id: &str) -> PolicyAttestation {
        build_action_attestation(ActionAttestationInput {
            decision_id,
            policy: &policy(),
            action: "delete_object",
            actor: "tester",
            risk: RiskClass::Destructive,
            namespace: "default",
            decision: ActionDecision::Deny,
            created: 1_000,
        })
    }

    fn record_linked_decision(db: &SekaiDb, attestation: &PolicyAttestation) {
        db.record_decision(&Decision {
            id: attestation.decision_id.clone(),
            timestamp: 1_000,
            actor: "tester".into(),
            action: "delete_object".into(),
            reason: "action_policy_denied".into(),
            evidence: std::collections::HashMap::from([
                (EVIDENCE_ATTESTATION_ID.into(), attestation.id.clone()),
                (
                    EVIDENCE_ATTESTATION_HASH.into(),
                    attestation.content_hash.clone(),
                ),
            ]),
            target_id: "obj-1".into(),
            outcome: "deny".into(),
        })
        .unwrap();
    }

    #[test]
    fn attestation_round_trip_and_verify() {
        let db = SekaiDb::new(":memory:").unwrap();
        let attestation = attest("dec-1");
        db.insert_attestation(&attestation).unwrap();
        record_linked_decision(&db, &attestation);

        let loaded = db.get_attestation(&attestation.id).unwrap().unwrap();
        assert_eq!(loaded, attestation);

        let report = db.verify_attestation(&attestation.id).unwrap();
        assert!(report.ok, "{}", report.error);
        assert!(report.hash_ok);
        assert!(report.replay_ok);
        assert!(report.decision_linked);
        assert_eq!(report.replayed_decision, "deny");
    }

    #[test]
    fn tampered_snapshot_fails_hash_and_replay() {
        let db = SekaiDb::new(":memory:").unwrap();
        let attestation = attest("dec-1");
        db.insert_attestation(&attestation).unwrap();
        record_linked_decision(&db, &attestation);
        {
            let conn = db.conn();
            // Rewrite the snapshot to an allow-everything policy.
            let permissive = snapshot_action_policy(&ActionPolicy::allow_all("agent:tester"));
            conn.execute(
                "UPDATE sekai_attestations SET policy_snapshot = ?1 WHERE id = ?2",
                params![permissive, attestation.id],
            )
            .unwrap();
        }
        let report = db.verify_attestation(&attestation.id).unwrap();
        assert!(!report.ok);
        assert!(!report.hash_ok);
        assert!(!report.replay_ok);
        assert_eq!(report.replayed_decision, "allow");
    }

    #[test]
    fn tampered_recorded_decision_fails_replay() {
        let db = SekaiDb::new(":memory:").unwrap();
        let attestation = attest("dec-1");
        db.insert_attestation(&attestation).unwrap();
        record_linked_decision(&db, &attestation);
        {
            let conn = db.conn();
            conn.execute(
                "UPDATE sekai_attestations SET decision = 'allow' WHERE id = ?1",
                params![attestation.id],
            )
            .unwrap();
        }
        let report = db.verify_attestation(&attestation.id).unwrap();
        assert!(!report.ok);
        assert!(!report.hash_ok); // decision is hashed
        assert!(!report.replay_ok);
    }

    #[test]
    fn missing_decision_link_is_reported() {
        let db = SekaiDb::new(":memory:").unwrap();
        let attestation = attest("dec-missing");
        db.insert_attestation(&attestation).unwrap();
        let report = db.verify_attestation(&attestation.id).unwrap();
        assert!(!report.ok);
        assert!(report.hash_ok);
        assert!(report.replay_ok);
        assert!(!report.decision_linked);
    }

    #[test]
    fn missing_attestation_is_reported() {
        let db = SekaiDb::new(":memory:").unwrap();
        let report = db.verify_attestation("nope").unwrap();
        assert!(!report.ok);
        assert!(!report.found);
    }

    #[test]
    fn list_filters_by_decision_and_scope() {
        let db = SekaiDb::new(":memory:").unwrap();
        let a1 = attest("dec-1");
        let a2 = attest("dec-2");
        db.insert_attestation(&a1).unwrap();
        db.insert_attestation(&a2).unwrap();

        let by_decision = db.list_attestations(Some("dec-1"), None, 10, 0).unwrap();
        assert_eq!(by_decision.len(), 1);
        assert_eq!(by_decision[0].id, a1.id);

        let by_scope = db
            .list_attestations(None, Some("agent:tester"), 10, 0)
            .unwrap();
        assert_eq!(by_scope.len(), 2);

        assert!(
            db.list_attestations(None, Some("other"), 10, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn purge_removes_attestations_with_their_decisions() {
        let db = SekaiDb::new(":memory:").unwrap();
        let old = attest("dec-old");
        let new = attest("dec-new");
        db.record_decision_with_attestation(
            &Decision {
                id: "dec-old".into(),
                timestamp: 100,
                actor: "tester".into(),
                action: "delete_object".into(),
                reason: "action_policy_denied".into(),
                evidence: std::collections::HashMap::new(),
                target_id: String::new(),
                outcome: "deny".into(),
            },
            Some(&old),
        )
        .unwrap();
        db.record_decision_with_attestation(
            &Decision {
                id: "dec-new".into(),
                timestamp: 500,
                actor: "tester".into(),
                action: "delete_object".into(),
                reason: "action_policy_denied".into(),
                evidence: std::collections::HashMap::new(),
                target_id: String::new(),
                outcome: "deny".into(),
            },
            Some(&new),
        )
        .unwrap();

        db.purge_old_records(300).unwrap();

        // The purged decision's attestation goes with it (no false tamper
        // signal for retired history); the surviving decision keeps its own.
        assert!(db.get_attestation(&old.id).unwrap().is_none());
        assert!(db.get_attestation(&new.id).unwrap().is_some());
        assert!(db.verify_ledger().unwrap().ok);
    }

    #[test]
    fn snapshot_is_deterministic() {
        assert_eq!(
            snapshot_action_policy(&policy()),
            snapshot_action_policy(&policy())
        );
    }
}
