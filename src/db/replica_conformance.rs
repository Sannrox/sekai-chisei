//! Bounded callable conformance for real replica-safe persistence.

use crate::db::replica_safety::TwoReplicaSqlite;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::coordination::{
    ADMISSION_POLICY_FIFO, ContentionScope, ReconcileFilter, WORK_UNIT_STATUS_PENDING,
    WORK_UNIT_STATUS_STALE, WorkUnit,
};
use crate::sekai::lease::LeaseError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub const VERSION: &str = "sekai.replica-conformance/v1";
pub const SCHEMA_JSON: &str = include_str!("../../tests/fixtures/replica_conformance/v1.json");
pub const MAX_CHECKS: usize = 5;
const AUTHORITY_ID: &str = "sekai-conformance-authority-v1";
const IMPLEMENTATION_SOURCES: &[&str] = &[
    include_str!("replica_conformance.rs"),
    include_str!("replica_safety.rs"),
    include_str!("runtime_db.rs"),
    include_str!("sekai.rs"),
    include_str!("../sekai/coordination.rs"),
    include_str!("../sekai/lease.rs"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Current,
    Delayed,
    Unavailable,
    Unknown,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub passed: bool,
    pub observations: Vec<Outcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub evidence_ref: String,
    pub passed: bool,
    pub runtime_instances: u8,
    pub checks: Vec<Check>,
}

/// Fail closed unless a caller pins the exact adapter contract.
pub fn require_version(candidate: &str) -> Result<(), &'static str> {
    if candidate == VERSION {
        Ok(())
    } else {
        Err("unsupported replica conformance version")
    }
}

/// Run fixed synthetic fixtures against two independent real runtime stores.
///
/// No caller input, path, payload, credential, or raw storage error is accepted
/// or returned.
pub fn run() -> Report {
    let mut evidence_hasher = Sha256::new();
    evidence_hasher.update(SCHEMA_JSON.as_bytes());
    for source in IMPLEMENTATION_SOURCES {
        evidence_hasher.update(source.as_bytes());
    }
    let evidence_ref = format!("sha256:{:x}", evidence_hasher.finalize());
    let Ok(pair) = TwoReplicaSqlite::open() else {
        return Report {
            version: VERSION.into(),
            evidence_ref,
            passed: false,
            runtime_instances: 0,
            checks: vec![check("adapter_startup", false, vec![Outcome::Unavailable])],
        };
    };

    let mut checks = vec![
        duplicate_admission(&pair),
        stale_lease_fencing(&pair),
        stale_work_recovery(&pair),
    ];
    let authority_path = pair.path().to_path_buf();
    let ready = write_authority_identifier(&pair);
    checks.push(check(
        "authority_readiness",
        ready,
        vec![if ready {
            Outcome::Current
        } else {
            Outcome::Unknown
        }],
    ));
    let backup_path = authority_path.with_extension("conformance-backup");
    let backup_created = ready && fs::copy(&authority_path, &backup_path).is_ok();
    checks.push(store_loss_and_restore(
        &pair,
        &authority_path,
        &backup_path,
        backup_created,
    ));

    Report {
        version: VERSION.into(),
        evidence_ref,
        passed: checks.len() == MAX_CHECKS
            && checks.iter().all(|item| item.passed)
            && checks.iter().all(|item| item.observations.len() <= 4),
        runtime_instances: 2,
        checks,
    }
}

fn duplicate_admission(pair: &TwoReplicaSqlite) -> Check {
    let scope = scope("conformance-duplicate");
    let first = work("conformance-work-a", &scope.id, "conformance-key", 10);
    let duplicate = work("conformance-work-b", &scope.id, "conformance-key", 11);
    let setup =
        pair.a.create_contention_scope(&scope).is_ok() && pair.a.create_work_unit(&first).is_ok();
    let duplicate_rejected = setup
        && pair.b.create_work_unit(&duplicate).is_err_and(|error| {
            error.contains("UNIQUE constraint failed: sekai_work_units.idempotency_key")
        });
    let passed = setup
        && duplicate_rejected
        && pair
            .b
            .get_work_unit_by_idempotency_key("conformance-key")
            .ok()
            .flatten()
            .is_some_and(|stored| stored.id == first.id);
    check(
        "duplicate_admission",
        passed,
        vec![
            Outcome::Current,
            if passed {
                Outcome::Rejected
            } else {
                Outcome::Unknown
            },
        ],
    )
}

fn stale_lease_fencing(pair: &TwoReplicaSqlite) -> Check {
    let passed = pair
        .a
        .acquire_lease(
            "conformance",
            "authority",
            "replica-a",
            100,
            "lease-a",
            "synthetic",
            "local",
            10,
        )
        .ok()
        .is_some_and(|lease| {
            let takeover = pair.b.takeover_expired_lease(
                "conformance",
                "authority",
                "replica-b",
                &lease.fencing_token,
                lease.expires_at_ms,
                100,
                "lease-b",
                "synthetic",
                "local",
                lease.expires_at_ms,
            );
            takeover.is_ok_and(|next| {
                next.owner == "replica-b"
                    && next.generation == lease.generation + 1
                    && next.fencing_token != lease.fencing_token
            }) && matches!(
                pair.a.refresh_lease(
                    "conformance",
                    "authority",
                    &lease.fencing_token,
                    100,
                    "lease-stale",
                    "synthetic",
                    "local",
                    lease.expires_at_ms + 1,
                ),
                Err(LeaseError::Stale(_))
            )
        });
    check(
        "stale_conflict",
        passed,
        vec![
            Outcome::Delayed,
            if passed {
                Outcome::Rejected
            } else {
                Outcome::Unknown
            },
        ],
    )
}

fn stale_work_recovery(pair: &TwoReplicaSqlite) -> Check {
    let scope = scope("conformance-recovery");
    let unit = work(
        "conformance-stale-work",
        &scope.id,
        "conformance-stale-key",
        20,
    );
    let passed = pair.a.create_contention_scope(&scope).is_ok()
        && pair.a.create_work_unit(&unit).is_ok()
        && pair
            .a
            .try_admit_work_unit(&unit.id, "replica-a", 100)
            .is_ok_and(|result| result.admitted)
        && pair
            .b
            .reconcile_work_units(
                4_100,
                &ReconcileFilter {
                    work_unit_id: Some(unit.id.clone()),
                    limit: 1,
                    ..Default::default()
                },
            )
            .is_ok_and(|summary| summary.work_units_reconciled == 1)
        && pair
            .a
            .get_work_unit(&unit.id)
            .ok()
            .flatten()
            .is_some_and(|stored| stored.status == WORK_UNIT_STATUS_STALE);
    check(
        "stale_projection_recovery",
        passed,
        vec![
            Outcome::Delayed,
            if passed {
                Outcome::Current
            } else {
                Outcome::Unknown
            },
        ],
    )
}

fn write_authority_identifier(pair: &TwoReplicaSqlite) -> bool {
    let conn = pair.a.conn();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sekai_replica_conformance_authority (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             authority_id TEXT NOT NULL
         );",
    )
    .is_ok()
        && conn
            .execute(
                "INSERT INTO sekai_replica_conformance_authority(singleton, authority_id)
                 VALUES(1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET authority_id=excluded.authority_id",
                [AUTHORITY_ID],
            )
            .is_ok()
        && conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .is_ok()
        && readiness(pair.path()) == Readiness::Current
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Readiness {
    Current,
    Unavailable,
    Unknown,
}

fn readiness(path: &Path) -> Readiness {
    if !path.exists() {
        return Readiness::Unavailable;
    }
    let Ok(conn) =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    else {
        return Readiness::Unavailable;
    };
    match conn.query_row(
        "SELECT authority_id FROM sekai_replica_conformance_authority WHERE singleton=1",
        [],
        |row| row.get::<_, String>(0),
    ) {
        Ok(id) if id == AUTHORITY_ID => Readiness::Current,
        Ok(_) | Err(_) => Readiness::Unknown,
    }
}

fn store_loss_and_restore(
    pair: &TwoReplicaSqlite,
    path: &Path,
    backup: &Path,
    backup_created: bool,
) -> Check {
    // Keep both original runtime instances alive while the path-level readiness
    // gate refuses loss and mismatched replacement. Recovery then opens two new
    // runtime instances against the reconciled authority.
    let _live_replicas = (&pair.a, &pair.b);
    let replacement = path.with_extension("conformance-replacement");
    let observations = (|| -> Result<Vec<Outcome>, ()> {
        if !backup_created {
            return Err(());
        }
        fs::remove_file(path).map_err(|_| ())?;
        let _ = fs::remove_file(path.with_extension("db-shm"));
        let _ = fs::remove_file(path.with_extension("db-wal"));
        let unavailable = runtime_readiness(path);

        let conn = rusqlite::Connection::open(&replacement).map_err(|_| ())?;
        conn.execute_batch(
            "CREATE TABLE sekai_replica_conformance_authority (
                 singleton INTEGER PRIMARY KEY, authority_id TEXT NOT NULL
             );
             INSERT INTO sekai_replica_conformance_authority
                 (singleton, authority_id) VALUES (1, 'different-authority');",
        )
        .map_err(|_| ())?;
        drop(conn);
        fs::rename(&replacement, path).map_err(|_| ())?;
        let unknown = runtime_readiness(path);

        fs::remove_file(path).map_err(|_| ())?;
        let _ = fs::remove_file(path.with_extension("db-shm"));
        let _ = fs::remove_file(path.with_extension("db-wal"));
        fs::rename(backup, path).map_err(|_| ())?;
        let current = runtime_readiness(path);
        (unavailable == Readiness::Unavailable
            && unknown == Readiness::Unknown
            && current == Readiness::Current)
            .then_some(vec![
                Outcome::Unavailable,
                Outcome::Unknown,
                Outcome::Current,
            ])
            .ok_or(())
    })();
    let _ = fs::remove_file(backup);
    let _ = fs::remove_file(&replacement);
    let passed = observations.is_ok();
    check(
        "store_loss_restore_reconciliation",
        passed,
        observations.unwrap_or_else(|_| vec![Outcome::Unknown]),
    )
}

fn runtime_readiness(path: &Path) -> Readiness {
    let initial = readiness(path);
    if initial != Readiness::Current {
        return initial;
    }
    let Some(path) = path.to_str() else {
        return Readiness::Unknown;
    };
    let Ok(a) = SekaiDb::new(path) else {
        return Readiness::Unavailable;
    };
    let Ok(b) = SekaiDb::new(path) else {
        return Readiness::Unavailable;
    };
    let a = RuntimeDb::Sqlite(Arc::new(a));
    let b = RuntimeDb::Sqlite(Arc::new(b));
    let sees_expected_identifier = |db: &RuntimeDb| {
        db.conn()
            .query_row(
                "SELECT authority_id FROM sekai_replica_conformance_authority WHERE singleton=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .is_ok_and(|id| id == AUTHORITY_ID)
    };
    if sees_expected_identifier(&a) && sees_expected_identifier(&b) {
        Readiness::Current
    } else {
        Readiness::Unknown
    }
}

fn check(id: &str, passed: bool, observations: Vec<Outcome>) -> Check {
    Check {
        id: id.into(),
        passed,
        observations,
    }
}

fn scope(id: &str) -> ContentionScope {
    ContentionScope {
        id: id.into(),
        name: id.into(),
        parent_scope_id: String::new(),
        max_concurrency: 1,
        admission_policy: ADMISSION_POLICY_FIFO.into(),
        heartbeat_ttl_seconds: 2,
        timeout_seconds: 30,
        owner_principal: "synthetic".into(),
        created: 1,
        updated: 1,
    }
}

fn work(id: &str, scope_id: &str, key: &str, created: i64) -> WorkUnit {
    WorkUnit {
        id: id.into(),
        kind: "conformance".into(),
        actor: "synthetic".into(),
        target_object_id: String::new(),
        status: WORK_UNIT_STATUS_PENDING.into(),
        requested_spec: "{}".into(),
        scope_id: scope_id.into(),
        priority: 0,
        timeout_seconds: 30,
        heartbeat_ttl_seconds: 2,
        created_at: created,
        admitted_at: 0,
        started_at: 0,
        finished_at: 0,
        last_heartbeat_at: 0,
        failure_reason: String::new(),
        cancel_reason: String::new(),
        owner_principal: "synthetic".into(),
        creator_principal: "synthetic".into(),
        idempotency_key: key.into(),
        updated_at: created,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_complete_bounded_and_sanitized() {
        let report = run();
        assert!(report.passed, "{report:?}");
        assert_eq!(report.version, VERSION);
        assert_eq!(report.runtime_instances, 2);
        assert_eq!(report.checks.len(), MAX_CHECKS);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.len() < 2_048);
        assert!(!json.contains(std::env::temp_dir().to_string_lossy().as_ref()));
        assert!(!json.contains("error"));
        for outcome in ["current", "delayed", "unavailable", "unknown", "rejected"] {
            assert!(json.contains(outcome), "missing {outcome}: {json}");
        }
    }

    #[test]
    fn incompatible_version_fails_closed() {
        assert!(require_version(VERSION).is_ok());
        assert!(require_version("sekai.replica-conformance/v2").is_err());
    }
}
