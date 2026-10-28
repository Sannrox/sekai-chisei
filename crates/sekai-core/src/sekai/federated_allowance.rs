//! Per-tenant federated aggregate allowances (ADR 0134 §1, #1921).
//!
//! A tenant's admin opts in to federated aggregates by publishing an
//! [`Allowance`] for one object type. Allowances are an append-only history
//! per (namespace, object type), like export grants: publishing supersedes
//! the current allowance, withdrawing keeps it as a withdrawn record, and two
//! concurrent changes cannot both land because each takes the next sequence
//! number. Every history entry is mirrored to an audit decision, written
//! idempotently so a lost audit write is repaired by the next change. Off by
//! default: a namespace with no active allowance never takes part.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;
use crate::sekai::federated_aggregate::Allowance;

pub const ALLOWANCE_CHANGED: &str = "federated_allowance_changed";
const MAX_REASON: usize = 1024;

/// One entry of an allowance's history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowanceRecord {
    pub allowance: Allowance,
    /// Digest of `allowance`; a query records it to pin what it ran under.
    pub allowance_digest: String,
    pub published_by: String,
    pub published_at_ms: i64,
    pub reason: String,
    #[serde(default)]
    pub withdrawn_by: String,
    #[serde(default)]
    pub withdrawn_at_ms: i64,
    #[serde(default)]
    pub withdrawal_reason: String,
}

impl AllowanceRecord {
    pub fn active(&self) -> bool {
        self.withdrawn_by.is_empty()
    }
}

fn check_reason(reason: &str) -> Result<(), String> {
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > MAX_REASON {
        return Err(format!("reason must be 1 to {MAX_REASON} bytes"));
    }
    Ok(())
}

/// Publish `allowance`, superseding the active one for its namespace and
/// object type. Publishing the active allowance again returns it unchanged,
/// so a retry records nothing twice.
pub fn publish(
    db: &RuntimeDb,
    allowance: Allowance,
    reason: &str,
    actor: &str,
    now_ms: i64,
) -> Result<AllowanceRecord, String> {
    check_reason(reason)?;
    let allowance_digest = allowance.digest().map_err(|error| error.to_string())?;
    let (namespace, object_type) = (allowance.namespace.clone(), allowance.object_type.clone());
    mirror_history(db, &namespace, &object_type)?;
    let latest = db.latest_federated_allowance(&namespace, &object_type)?;
    if let Some((_, current)) = &latest
        && current.active()
        && current.allowance_digest == allowance_digest
    {
        return Ok(current.clone());
    }
    let record = AllowanceRecord {
        allowance,
        allowance_digest,
        published_by: actor.into(),
        published_at_ms: now_ms,
        reason: reason.trim().into(),
        withdrawn_by: String::new(),
        withdrawn_at_ms: 0,
        withdrawal_reason: String::new(),
    };
    record_change(db, latest.map_or(1, |(seq, _)| seq + 1), &record)?;
    Ok(record)
}

/// Withdraw the active allowance, keeping it as a withdrawn record.
/// Withdrawing a withdrawn or missing allowance changes nothing.
pub fn withdraw(
    db: &RuntimeDb,
    namespace: &str,
    object_type: &str,
    reason: &str,
    actor: &str,
    now_ms: i64,
) -> Result<Option<AllowanceRecord>, String> {
    check_reason(reason)?;
    mirror_history(db, namespace, object_type)?;
    let Some((seq, current)) = db.latest_federated_allowance(namespace, object_type)? else {
        return Ok(None);
    };
    if !current.active() {
        return Ok(Some(current));
    }
    let withdrawn = AllowanceRecord {
        withdrawn_by: actor.into(),
        withdrawn_at_ms: now_ms,
        withdrawal_reason: reason.trim().into(),
        ..current
    };
    record_change(db, seq + 1, &withdrawn)?;
    Ok(Some(withdrawn))
}

/// The active allowance of a namespace's object type, if any: what a
/// federated query consults to decide whether the tenant takes part.
pub fn current(
    db: &RuntimeDb,
    namespace: &str,
    object_type: &str,
) -> Result<Option<AllowanceRecord>, String> {
    Ok(db
        .latest_federated_allowance(namespace, object_type)?
        .map(|(_, record)| record)
        .filter(AllowanceRecord::active))
}

fn record_change(db: &RuntimeDb, seq: i64, record: &AllowanceRecord) -> Result<(), String> {
    if !db.insert_federated_allowance(seq, record)? {
        return Err(ALLOWANCE_CHANGED.into());
    }
    mirror(db, seq, record)
}

fn mirror_history(db: &RuntimeDb, namespace: &str, object_type: &str) -> Result<(), String> {
    for (seq, record) in db.federated_allowance_history(namespace, object_type)? {
        mirror(db, seq, &record)?;
    }
    Ok(())
}

/// A digest of the length-prefixed (namespace, object type, seq), so no two
/// history entries share a decision id.
fn decision_id(namespace: &str, object_type: &str, seq: i64) -> String {
    let mut hasher = Sha256::new();
    for part in [namespace, object_type] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(seq.to_be_bytes());
    format!("federated-allowance:{:x}", hasher.finalize())
}

fn mirror(db: &RuntimeDb, seq: i64, record: &AllowanceRecord) -> Result<(), String> {
    let (outcome, actor, at_ms) = if record.active() {
        ("published", &record.published_by, record.published_at_ms)
    } else {
        ("withdrawn", &record.withdrawn_by, record.withdrawn_at_ms)
    };
    let allowance = &record.allowance;
    db.record_decisions_idempotently(&[Decision {
        id: decision_id(&allowance.namespace, &allowance.object_type, seq),
        timestamp: at_ms,
        actor: actor.clone(),
        action: "federated_aggregate_allowance".into(),
        reason: format!("federated aggregate allowance {outcome}"),
        evidence: HashMap::from([
            ("namespace".into(), allowance.namespace.clone()),
            ("object_type".into(), allowance.object_type.clone()),
            ("allowance_seq".into(), seq.to_string()),
            ("allowance_digest".into(), record.allowance_digest.clone()),
            (
                "allowance_record".into(),
                serde_json::to_string(record).map_err(|error| error.to_string())?,
            ),
        ]),
        target_id: format!("{}:{}", allowance.namespace, allowance.object_type),
        outcome: outcome.into(),
    }])
}

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_federated_allowances (
    namespace TEXT NOT NULL,
    object_type TEXT NOT NULL,
    seq INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, object_type, seq)
);
";

fn decode(json: &str) -> Result<AllowanceRecord, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt federated allowance: {error}"))
}

fn encode(record: &AllowanceRecord) -> Result<String, String> {
    serde_json::to_string(record).map_err(|error| error.to_string())
}

impl SekaiDb {
    pub(crate) fn migrate_federated_allowances(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    fn federated_allowance_rows(
        &self,
        namespace: &str,
        object_type: &str,
        latest_only: bool,
    ) -> Result<Vec<(i64, AllowanceRecord)>, String> {
        let conn = self.conn();
        let sql = if latest_only {
            "SELECT seq, record_json FROM sekai_federated_allowances
             WHERE namespace = ?1 AND object_type = ?2 ORDER BY seq DESC LIMIT 1"
        } else {
            "SELECT seq, record_json FROM sekai_federated_allowances
             WHERE namespace = ?1 AND object_type = ?2 ORDER BY seq"
        };
        let mut statement = conn.prepare(sql).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![namespace, object_type], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (seq, json) = row.map_err(|error| error.to_string())?;
            decode(&json).map(|record| (seq, record))
        })
        .collect()
    }

    fn insert_federated_allowance_row(
        &self,
        seq: i64,
        record: &AllowanceRecord,
    ) -> Result<bool, String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_federated_allowances (namespace, object_type, seq, record_json)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                rusqlite::params![
                    record.allowance.namespace,
                    record.allowance.object_type,
                    seq,
                    encode(record)?
                ],
            )
            .map(|inserted| inserted == 1)
            .map_err(|error| error.to_string())
    }
}

impl PostgresDb {
    fn federated_allowance_rows(
        &self,
        namespace: &str,
        object_type: &str,
        latest_only: bool,
    ) -> Result<Vec<(i64, AllowanceRecord)>, String> {
        let sql = if latest_only {
            "SELECT seq, record_json FROM sekai_federated_allowances
             WHERE namespace = $1 AND object_type = $2 ORDER BY seq DESC LIMIT 1"
        } else {
            "SELECT seq, record_json FROM sekai_federated_allowances
             WHERE namespace = $1 AND object_type = $2 ORDER BY seq"
        };
        self.connection()?
            .query(sql, &[&namespace, &object_type])
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| decode(row.get(1)).map(|record| (row.get::<_, i64>(0), record)))
            .collect()
    }

    fn insert_federated_allowance_row(
        &self,
        seq: i64,
        record: &AllowanceRecord,
    ) -> Result<bool, String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_federated_allowances (namespace, object_type, seq, record_json)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[
                    &record.allowance.namespace,
                    &record.allowance.object_type,
                    &seq,
                    &encode(record)?,
                ],
            )
            .map(|inserted| inserted == 1)
            .map_err(|error| error.to_string())
    }
}

impl RuntimeDb {
    pub fn latest_federated_allowance(
        &self,
        namespace: &str,
        object_type: &str,
    ) -> Result<Option<(i64, AllowanceRecord)>, String> {
        let rows = match self {
            Self::Sqlite(db) => db.federated_allowance_rows(namespace, object_type, true),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.federated_allowance_rows(namespace, object_type, true)
            }),
        }?;
        Ok(rows.into_iter().next())
    }

    /// Every entry of an allowance's history, oldest first.
    pub fn federated_allowance_history(
        &self,
        namespace: &str,
        object_type: &str,
    ) -> Result<Vec<(i64, AllowanceRecord)>, String> {
        match self {
            Self::Sqlite(db) => db.federated_allowance_rows(namespace, object_type, false),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.federated_allowance_rows(namespace, object_type, false)
            }),
        }
    }

    /// Inserts history entry `seq`; false when another change took it first.
    pub fn insert_federated_allowance(
        &self,
        seq: i64,
        record: &AllowanceRecord,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.insert_federated_allowance_row(seq, record),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.insert_federated_allowance_row(seq, record))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::audit::DecisionFilter;
    use crate::sekai::federated_aggregate::{ALLOWANCE_SCHEMA, AggregateFunction};
    use std::collections::BTreeSet;

    fn allowance(namespace: &str, k: u64) -> Allowance {
        Allowance {
            schema: ALLOWANCE_SCHEMA.into(),
            namespace: namespace.into(),
            object_type: "shipment".into(),
            dimensions: BTreeSet::from(["region".into()]),
            measures: BTreeSet::from(["weight".into()]),
            functions: BTreeSet::from([AggregateFunction::Count, AggregateFunction::Sum]),
            min_group_size: k,
            noise_scale: None,
            requesters: BTreeSet::from(["buyer".into()]),
        }
    }

    /// Publish, supersede, withdraw and read the current allowance; every
    /// change records an audit decision; a retry records nothing twice; a
    /// concurrent change on the same entry is refused.
    fn allowance_contract(db: &RuntimeDb, ns: &str) {
        assert_eq!(current(db, ns, "shipment").unwrap(), None, "off by default");
        let first = publish(db, allowance(ns, 3), "opt in", "admin", 1).unwrap();
        assert_eq!(
            publish(db, allowance(ns, 3), "again", "admin", 2).unwrap(),
            first
        );
        assert_eq!(current(db, ns, "shipment").unwrap(), Some(first.clone()));
        assert!(publish(db, allowance(ns, 3), " ", "admin", 2).is_err());

        let superseding = publish(db, allowance(ns, 5), "raise k", "admin", 3).unwrap();
        assert_ne!(superseding.allowance_digest, first.allowance_digest);
        assert_eq!(current(db, ns, "shipment").unwrap(), Some(superseding));

        let withdrawn = withdraw(db, ns, "shipment", "opt out", "admin", 4)
            .unwrap()
            .unwrap();
        assert!(!withdrawn.active());
        assert_eq!(current(db, ns, "shipment").unwrap(), None);
        assert_eq!(
            withdraw(db, ns, "shipment", "again", "admin", 5).unwrap(),
            Some(withdrawn.clone())
        );
        assert_eq!(
            withdraw(db, ns, "invoice", "none", "admin", 5).unwrap(),
            None
        );

        let history = db.federated_allowance_history(ns, "shipment").unwrap();
        assert_eq!(history.len(), 3);
        assert!(!db.insert_federated_allowance(3, &withdrawn).unwrap());

        let decisions = db
            .list_decisions(&DecisionFilter {
                action: Some("federated_aggregate_allowance".into()),
                target_id: Some(format!("{ns}:shipment")),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        let mut outcomes: Vec<_> = decisions.iter().map(|d| d.outcome.as_str()).collect();
        outcomes.sort();
        assert_eq!(outcomes, ["published", "published", "withdrawn"]);
    }

    #[test]
    fn sqlite_allowances_follow_the_contract() {
        allowance_contract(&RuntimeDb::memory(), "acme");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_allowances_follow_the_contract() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        // A namespace of its own, so concurrent or repeated runs never share
        // a record.
        let ns = format!("allowance-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        allowance_contract(&db, &ns);
    }
}
