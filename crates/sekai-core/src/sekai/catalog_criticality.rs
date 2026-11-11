//! Declared and derived catalog criticality, exported through the outbox (#1688).
//!
//! Declared is curated by owners. Derived is the highest criticality implied
//! by markings on data reachable through catalog lineage. Effective is the
//! higher of the two and only falls when those markings are declassified.
//! Each change appends one outbox event whose digest is the export evidence.
//!
//! Outbox contract (#2196): `(entry_id, seq)` is strictly increasing per
//! entry and never reused, and `event_id` is `{entry_id}:{seq}`. A consumer
//! may read an event again (overlapping pages, a retried poll), so it
//! dedupes on `event_id`. A missed append is repaired by
//! [`reconcile_outbox`], which any instance runs. Events older than
//! [`EVENT_RETENTION_MS`] are swept, except each entry's latest event, which
//! is kept forever: [`sync_outbox`] compares against it and numbers the next
//! event after it.

use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use crate::sekai::catalog::{CatalogError, EntryKind};

pub const CONTRACT: &str = "sekai.catalog-criticality/v1";
pub const DECLARED_PROPERTY: &str = "declared_criticality";
pub const DERIVED_PROPERTY: &str = "derived_criticality";
pub const EFFECTIVE_PROPERTY: &str = "effective_criticality";
pub const DEFAULT_PAGE_SIZE: i32 = 50;
pub const MAX_PAGE_SIZE: i32 = 100;
/// How long a superseded event is kept after it was written. An entry's
/// latest event is kept regardless.
pub const EVENT_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Rows a sweep deletes, or a reconcile pass checks, per batch.
pub(crate) const SWEEP_BATCH: i64 = 500;

const SQLITE_SCHEMA: &str = "
            CREATE TABLE IF NOT EXISTS sekai_catalog_criticality_outbox (
                event_id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                entry_id TEXT NOT NULL,
                entry_kind TEXT NOT NULL,
                source_system TEXT NOT NULL,
                source_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                declared TEXT NOT NULL DEFAULT '',
                derived TEXT NOT NULL DEFAULT '',
                effective TEXT NOT NULL DEFAULT '',
                evidence_digest TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                UNIQUE(entry_id, seq)
            );
            CREATE INDEX IF NOT EXISTS idx_sekai_catalog_criticality_outbox_ns
                ON sekai_catalog_criticality_outbox(namespace, created_at_ms, event_id);
            CREATE INDEX IF NOT EXISTS idx_sekai_catalog_criticality_outbox_created
                ON sekai_catalog_criticality_outbox(created_at_ms);
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

impl Criticality {
    pub fn parse(value: &str) -> Result<Self, CatalogError> {
        match value.trim() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(CatalogError::Invalid(format!(
                "criticality must be low, medium, high or critical, got {other:?}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_marking(marking: &str) -> Option<Self> {
        use crate::sekai::evidence_vocabulary::EvidenceClassification;
        use crate::sekai::markings::parse_classification;
        match parse_classification(marking).ok()? {
            EvidenceClassification::Public => Some(Self::Low),
            EvidenceClassification::Internal => Some(Self::Medium),
            EvidenceClassification::Confidential => Some(Self::High),
            EvidenceClassification::Restricted => Some(Self::Critical),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalityEvent {
    pub event_id: String,
    pub namespace: String,
    pub entry_id: String,
    pub entry_kind: String,
    pub source_system: String,
    pub source_id: String,
    pub seq: i64,
    pub declared: String,
    pub derived: String,
    pub effective: String,
    pub evidence_digest: String,
    pub created_at_ms: i64,
}

pub fn property_criticality(entry: &Object, key: &str) -> Option<Criticality> {
    entry
        .properties
        .get(key)
        .filter(|value| !value.is_empty())
        .and_then(|value| Criticality::parse(value).ok())
}

pub fn refresh_effective(entry: &mut Object) {
    let declared = property_criticality(entry, DECLARED_PROPERTY);
    let derived = property_criticality(entry, DERIVED_PROPERTY);
    write_levels(entry, declared, derived);
}

fn write_levels(entry: &mut Object, declared: Option<Criticality>, derived: Option<Criticality>) {
    let effective = match (declared, derived) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(level), None) | (None, Some(level)) => Some(level),
        (None, None) => None,
    };
    let put = |entry: &mut Object, key: &str, level: Option<Criticality>| match level {
        Some(level) => {
            entry.properties.insert(key.into(), level.as_str().into());
        }
        None => {
            entry.properties.remove(key);
        }
    };
    put(entry, DECLARED_PROPERTY, declared);
    put(entry, DERIVED_PROPERTY, derived);
    put(entry, EFFECTIVE_PROPERTY, effective);
}

/// Recompute derived criticality from reachable data markings and the
/// effective value. Declared stays as stored.
pub fn apply_derived(db: &RuntimeDb, entry: &mut Object) -> Result<(), CatalogError> {
    let kind = entry
        .properties
        .get("entry_kind")
        .map(String::as_str)
        .unwrap_or_default();
    let Ok(kind) = EntryKind::parse(kind) else {
        return Ok(());
    };
    if !kind.carries_derived_criticality() {
        return Ok(());
    }
    let mut derived = None;
    for marking in crate::sekai::catalog_lineage::reachable_data_markings(db, entry)? {
        match Criticality::from_marking(&marking) {
            Some(level) => {
                derived = Some(derived.map_or(level, |current: Criticality| current.max(level)));
            }
            None if marking.is_empty() => {}
            None => {
                return Err(CatalogError::Invalid(format!(
                    "reachable marking {marking:?} has no criticality mapping"
                )));
            }
        }
    }
    let declared = property_criticality(entry, DECLARED_PROPERTY);
    write_levels(entry, declared, derived);
    Ok(())
}

fn triple(entry: &Object) -> (String, String, String) {
    let get = |key: &str| {
        entry
            .properties
            .get(key)
            .cloned()
            .filter(|value| !value.is_empty())
            .unwrap_or_default()
    };
    (
        get(DECLARED_PROPERTY),
        get(DERIVED_PROPERTY),
        get(EFFECTIVE_PROPERTY),
    )
}

fn evidence_digest(event: &CriticalityEvent) -> String {
    let mut hasher = Sha256::new();
    for part in [
        CONTRACT,
        event.namespace.as_str(),
        event.entry_id.as_str(),
        event.entry_kind.as_str(),
        event.source_system.as_str(),
        event.source_id.as_str(),
        &event.seq.to_string(),
        event.declared.as_str(),
        event.derived.as_str(),
        event.effective.as_str(),
        &event.created_at_ms.to_string(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Append one outbox event when declared, derived or effective changed.
/// Reads the stored entry so a delayed emit cannot append a superseded
/// snapshot. A retry of the same triple is a no-op, so a lost emit is repaired.
pub fn sync_outbox(db: &RuntimeDb, entry: &Object, now_ms: i64) -> Result<bool, CatalogError> {
    let kind = entry
        .properties
        .get("entry_kind")
        .map(String::as_str)
        .unwrap_or_default();
    let Ok(kind) = EntryKind::parse(kind) else {
        return Ok(false);
    };
    if !kind.carries_derived_criticality() {
        return Ok(false);
    }
    loop {
        let Some(stored) = db.get_object(&entry.id).map_err(CatalogError::Storage)? else {
            return Ok(false);
        };
        if stored.kind != entry.kind || stored.namespace != entry.namespace {
            return Ok(false);
        }
        let stored_kind = stored
            .properties
            .get("entry_kind")
            .map(String::as_str)
            .unwrap_or_default();
        let Ok(stored_kind) = EntryKind::parse(stored_kind) else {
            return Ok(false);
        };
        if !stored_kind.carries_derived_criticality() {
            return Ok(false);
        }
        let (declared, derived, effective) = triple(&stored);
        let latest = db
            .latest_catalog_criticality_event(&stored.id)
            .map_err(CatalogError::Storage)?;
        if declared.is_empty() && derived.is_empty() && effective.is_empty() && latest.is_none() {
            return Ok(false);
        }
        if let Some(latest) = &latest
            && latest.declared == declared
            && latest.derived == derived
            && latest.effective == effective
        {
            return Ok(false);
        }
        let seq = latest.map(|event| event.seq + 1).unwrap_or(1);
        let get = |key: &str| stored.properties.get(key).cloned().unwrap_or_default();
        let mut event = CriticalityEvent {
            event_id: format!("{}:{seq}", stored.id),
            namespace: stored.namespace.clone(),
            entry_id: stored.id.clone(),
            entry_kind: stored_kind.as_str().into(),
            source_system: get("source_system"),
            source_id: get("source_id"),
            seq,
            declared,
            derived,
            effective,
            evidence_digest: String::new(),
            created_at_ms: now_ms,
        };
        event.evidence_digest = evidence_digest(&event);
        if db
            .insert_catalog_criticality_event(&event, stored.updated)
            .map_err(CatalogError::Storage)?
        {
            return Ok(true);
        }
    }
}

/// Append the missing event of every entry whose stored criticality differs
/// from its latest event, for example after a crash or a failed append that
/// followed the catalog write. Safe on every instance at once: each append is
/// fenced on the entry revision and the `(entry_id, seq)` key. Returns how
/// many events it appended; the first failure is returned after every other
/// entry was tried.
pub fn reconcile_outbox(db: &RuntimeDb, now_ms: i64) -> Result<usize, CatalogError> {
    let mut appended = 0;
    let mut first_error = None;
    let mut after = String::new();
    loop {
        let drifted = db
            .drifted_catalog_criticality_entries(&after, SWEEP_BATCH)
            .map_err(CatalogError::Storage)?;
        for entry_id in &drifted {
            let synced = db
                .get_object(entry_id)
                .map_err(CatalogError::Storage)
                .and_then(|entry| match entry {
                    Some(entry) => sync_outbox(db, &entry, now_ms),
                    None => Ok(false),
                });
            match synced {
                Ok(true) => appended += 1,
                Ok(false) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match drifted.last() {
            Some(last) if (drifted.len() as i64) == SWEEP_BATCH => after.clone_from(last),
            _ => break,
        }
    }
    first_error.map_or(Ok(appended), Err)
}

pub fn clamp_page_size(page_size: i32) -> Result<i32, CatalogError> {
    if page_size < 0 {
        return Err(CatalogError::Invalid("page_size must be >= 0".into()));
    }
    Ok(if page_size == 0 {
        DEFAULT_PAGE_SIZE
    } else {
        page_size.min(MAX_PAGE_SIZE)
    })
}

pub fn encode_page_token(created_at_ms: i64, event_id: &str) -> String {
    format!("{created_at_ms}\n{event_id}")
}

pub fn decode_page_token(token: &str) -> Result<Option<(i64, String)>, CatalogError> {
    if token.is_empty() {
        return Ok(None);
    }
    let (ms, event_id) = token
        .split_once('\n')
        .ok_or_else(|| CatalogError::Invalid("page_token is invalid".into()))?;
    let created_at_ms = ms
        .parse::<i64>()
        .map_err(|_| CatalogError::Invalid("page_token is invalid".into()))?;
    if event_id.is_empty() {
        return Err(CatalogError::Invalid("page_token is invalid".into()));
    }
    Ok(Some((created_at_ms, event_id.into())))
}

pub(crate) fn migrate_catalog_criticality_outbox(
    conn: &rusqlite::Connection,
) -> Result<(), String> {
    conn.execute_batch(SQLITE_SCHEMA)
        .map_err(|error| error.to_string())
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<CriticalityEvent> {
    Ok(CriticalityEvent {
        event_id: row.get(0)?,
        namespace: row.get(1)?,
        entry_id: row.get(2)?,
        entry_kind: row.get(3)?,
        source_system: row.get(4)?,
        source_id: row.get(5)?,
        seq: row.get(6)?,
        declared: row.get(7)?,
        derived: row.get(8)?,
        effective: row.get(9)?,
        evidence_digest: row.get(10)?,
        created_at_ms: row.get(11)?,
    })
}

impl SekaiDb {
    pub(crate) fn migrate_catalog_criticality_outbox(&self) -> Result<(), String> {
        migrate_catalog_criticality_outbox(&self.conn())
    }

    pub fn insert_catalog_criticality_event(
        &self,
        event: &CriticalityEvent,
        expected_updated: i64,
    ) -> Result<bool, String> {
        use rusqlite::{OptionalExtension, TransactionBehavior};
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let updated = tx
            .query_row(
                "SELECT updated FROM sekai_objects WHERE id = ?1",
                rusqlite::params![event.entry_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if updated != Some(expected_updated) {
            return Ok(false);
        }
        let n = tx
            .execute(
                "INSERT INTO sekai_catalog_criticality_outbox
                 (event_id, namespace, entry_id, entry_kind, source_system, source_id, seq,
                  declared, derived, effective, evidence_digest, created_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
                 ON CONFLICT(entry_id, seq) DO NOTHING",
                rusqlite::params![
                    event.event_id,
                    event.namespace,
                    event.entry_id,
                    event.entry_kind,
                    event.source_system,
                    event.source_id,
                    event.seq,
                    event.declared,
                    event.derived,
                    event.effective,
                    event.evidence_digest,
                    event.created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(n > 0)
    }

    /// Ids after `after`, in id order and at most `limit`, of catalog
    /// entries whose stored declared, derived or effective criticality
    /// differs from their latest outbox event. The kinds are the ones
    /// `EntryKind::carries_derived_criticality` accepts.
    pub fn drifted_catalog_criticality_entries(
        &self,
        after: &str,
        limit: i64,
    ) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT o.id FROM sekai_objects o
                 LEFT JOIN sekai_catalog_criticality_outbox e
                   ON e.entry_id = o.id
                  AND e.seq = (SELECT MAX(seq) FROM sekai_catalog_criticality_outbox
                               WHERE entry_id = o.id)
                 WHERE o.kind = ?1 AND o.id > ?2
                   AND json_extract(o.properties, '$.entry_kind')
                       IN ('service', 'release', 'environment')
                   AND (COALESCE(json_extract(o.properties, '$.declared_criticality'), '')
                            <> COALESCE(e.declared, '')
                     OR COALESCE(json_extract(o.properties, '$.derived_criticality'), '')
                            <> COALESCE(e.derived, '')
                     OR COALESCE(json_extract(o.properties, '$.effective_criticality'), '')
                            <> COALESCE(e.effective, ''))
                 ORDER BY o.id LIMIT ?3",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(
                rusqlite::params![crate::sekai::catalog::CATALOG_ENTRY_KIND, after, limit],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    /// Deletes at most [`SWEEP_BATCH`] events written before `cutoff_ms`
    /// that a later event of the same entry supersedes, and returns how many
    /// it deleted. An entry's latest event is never deleted.
    pub fn delete_superseded_catalog_criticality_events(
        &self,
        cutoff_ms: i64,
    ) -> Result<usize, String> {
        self.conn()
            .execute(
                "DELETE FROM sekai_catalog_criticality_outbox
                 WHERE rowid IN (
                     SELECT o.rowid FROM sekai_catalog_criticality_outbox o
                     WHERE o.created_at_ms < ?1
                       AND EXISTS (SELECT 1 FROM sekai_catalog_criticality_outbox n
                                   WHERE n.entry_id = o.entry_id AND n.seq > o.seq)
                     LIMIT ?2
                 )",
                rusqlite::params![cutoff_ms, SWEEP_BATCH],
            )
            .map_err(|error| error.to_string())
    }

    pub fn latest_catalog_criticality_event(
        &self,
        entry_id: &str,
    ) -> Result<Option<CriticalityEvent>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                "SELECT event_id, namespace, entry_id, entry_kind, source_system, source_id, seq,
                        declared, derived, effective, evidence_digest, created_at_ms
                 FROM sekai_catalog_criticality_outbox
                 WHERE entry_id = ?1
                 ORDER BY seq DESC LIMIT 1",
                rusqlite::params![entry_id],
                row_to_event,
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn list_catalog_criticality_outbox(
        &self,
        namespace: &str,
        page_size: i32,
        page_token: &str,
    ) -> Result<(Vec<CriticalityEvent>, String), String> {
        let page_size = clamp_page_size(page_size).map_err(|error| match error {
            CatalogError::Invalid(message) => message,
            other => format!("{other:?}"),
        })?;
        let cursor = decode_page_token(page_token).map_err(|error| match error {
            CatalogError::Invalid(message) => message,
            other => format!("{other:?}"),
        })?;
        let conn = self.conn();
        let limit = i64::from(page_size) + 1;
        let mut events = match cursor {
            Some((created_at_ms, event_id)) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT event_id, namespace, entry_id, entry_kind, source_system, source_id, seq,
                                declared, derived, effective, evidence_digest, created_at_ms
                         FROM sekai_catalog_criticality_outbox
                         WHERE namespace = ?1
                           AND (created_at_ms < ?2 OR (created_at_ms = ?2 AND event_id < ?3))
                         ORDER BY created_at_ms DESC, event_id DESC
                         LIMIT ?4",
                    )
                    .map_err(|error| error.to_string())?;
                let rows = stmt
                    .query_map(
                        rusqlite::params![namespace, created_at_ms, event_id, limit],
                        row_to_event,
                    )
                    .map_err(|error| error.to_string())?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?
            }
            None => {
                let mut stmt = conn
                    .prepare(
                        "SELECT event_id, namespace, entry_id, entry_kind, source_system, source_id, seq,
                                declared, derived, effective, evidence_digest, created_at_ms
                         FROM sekai_catalog_criticality_outbox
                         WHERE namespace = ?1
                         ORDER BY created_at_ms DESC, event_id DESC
                         LIMIT ?2",
                    )
                    .map_err(|error| error.to_string())?;
                let rows = stmt
                    .query_map(rusqlite::params![namespace, limit], row_to_event)
                    .map_err(|error| error.to_string())?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?
            }
        };
        let next = if events.len() > page_size as usize {
            events.pop();
            events
                .last()
                .map(|event| encode_page_token(event.created_at_ms, &event.event_id))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok((events, next))
    }
}

/// Outbox behaviour every store must show; the PostgreSQL conformance
/// tests run the same checks.
#[cfg(test)]
pub(crate) mod store_tests {
    use super::*;
    use crate::sekai::catalog::CATALOG_ENTRY_KIND;

    fn service(id: &str, declared: &str, updated: i64) -> Object {
        let mut properties =
            std::collections::HashMap::from([("entry_kind".to_string(), "service".to_string())]);
        if !declared.is_empty() {
            properties.insert(DECLARED_PROPERTY.into(), declared.into());
        }
        let mut entry = Object {
            id: id.into(),
            kind: CATALOG_ENTRY_KIND.into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: id.into(),
            properties,
            created: 1,
            updated,
        };
        refresh_effective(&mut entry);
        entry
    }

    fn seqs(db: &RuntimeDb, entry_id: &str) -> Vec<i64> {
        let mut seqs = Vec::new();
        let mut token = String::new();
        loop {
            let (events, next) = db
                .list_catalog_criticality_outbox("acme", MAX_PAGE_SIZE, &token)
                .unwrap();
            seqs.extend(
                events
                    .iter()
                    .filter(|event| event.entry_id == entry_id)
                    .map(|event| event.seq),
            );
            if next.is_empty() {
                seqs.sort();
                return seqs;
            }
            token = next;
        }
    }

    /// The sweep deletes only superseded events past retention, keeps every
    /// entry's latest however old, and the next event follows the latest.
    pub(crate) fn sweep_keeps_latest_event_and_seq_monotonic(db: &RuntimeDb) {
        db.create_object(&service("svc:a", "low", 1)).unwrap();
        sync_outbox(db, &service("svc:a", "low", 1), 1).unwrap();
        for (updated, declared) in [(2, "medium"), (3, "high")] {
            db.update_object(&service("svc:a", declared, updated))
                .unwrap();
            sync_outbox(db, &service("svc:a", declared, updated), updated).unwrap();
        }
        db.create_object(&service("svc:b", "low", 1)).unwrap();
        sync_outbox(db, &service("svc:b", "low", 1), 1).unwrap();
        assert_eq!(seqs(db, "svc:a"), [1, 2, 3]);

        // seq 2 and 3 of svc:a are inside retention at this cutoff.
        assert_eq!(
            db.sweep_catalog_criticality_outbox(2 + EVENT_RETENTION_MS)
                .unwrap(),
            1
        );
        assert_eq!(seqs(db, "svc:a"), [2, 3]);
        let swept = db
            .sweep_catalog_criticality_outbox(10 + EVENT_RETENTION_MS)
            .unwrap();
        assert_eq!(swept, 1);
        assert_eq!(seqs(db, "svc:a"), [3]);
        assert_eq!(seqs(db, "svc:b"), [1]);

        db.update_object(&service("svc:a", "critical", 4)).unwrap();
        assert!(sync_outbox(db, &service("svc:a", "critical", 4), 4).unwrap());
        let latest = db
            .latest_catalog_criticality_event("svc:a")
            .unwrap()
            .unwrap();
        assert_eq!((latest.seq, latest.event_id.as_str()), (4, "svc:a:4"));
        assert_eq!(latest.declared, "critical");
    }

    /// An entry whose append was lost is found and repaired once; entries in
    /// step with their latest event, or with no criticality, are left alone.
    pub(crate) fn reconcile_appends_a_missed_event_once(db: &RuntimeDb) {
        db.create_object(&service("svc:synced", "low", 1)).unwrap();
        sync_outbox(db, &service("svc:synced", "low", 1), 1).unwrap();
        db.create_object(&service("svc:none", "", 1)).unwrap();
        // The catalog write landed; the append after it did not.
        db.create_object(&service("svc:missed", "high", 1)).unwrap();
        db.update_object(&service("svc:synced", "medium", 2))
            .unwrap();
        assert_eq!(
            db.drifted_catalog_criticality_entries("", SWEEP_BATCH)
                .unwrap(),
            ["svc:missed", "svc:synced"]
        );

        assert_eq!(reconcile_outbox(db, 5).unwrap(), 2);

        assert_eq!(reconcile_outbox(db, 6).unwrap(), 0);
        assert!(
            db.drifted_catalog_criticality_entries("", SWEEP_BATCH)
                .unwrap()
                .is_empty()
        );
        let missed = db
            .latest_catalog_criticality_event("svc:missed")
            .unwrap()
            .unwrap();
        assert_eq!((missed.seq, missed.effective.as_str()), (1, "high"));
        assert_eq!(seqs(db, "svc:synced"), [1, 2]);
        assert!(seqs(db, "svc:none").is_empty());
    }

    /// `instances` share one store seeded with `seeded` entries `seed-{n}`,
    /// each holding events seq 1..=3 written at time 0. Every instance
    /// reconciles and sweeps at once: each superseded event is deleted once,
    /// each latest is kept, and each missed event is appended once.
    pub(crate) fn concurrent_instances_sweep_and_reconcile_once(
        instances: Vec<RuntimeDb>,
        seeded: i64,
    ) {
        let missed = 5;
        for n in 0..missed {
            instances[0]
                .create_object(&service(&format!("svc:{n}"), "high", 1))
                .unwrap();
        }
        let now = EVENT_RETENTION_MS + 1;
        let runs: Vec<_> = instances
            .into_iter()
            .map(|db| {
                std::thread::spawn(move || {
                    let appended = reconcile_outbox(&db, now).unwrap();
                    let swept = db.sweep_catalog_criticality_outbox(now).unwrap();
                    (db, appended, swept)
                })
            })
            .collect();
        let mut appended = 0;
        let mut swept = 0;
        let mut db = None;
        for run in runs {
            let (instance, a, s) = run.join().unwrap();
            appended += a;
            swept += s;
            db = Some(instance);
        }
        let db = db.unwrap();

        assert_eq!(appended, missed);
        assert_eq!(swept as i64, 2 * seeded);
        for n in 0..seeded {
            let latest = db
                .latest_catalog_criticality_event(&format!("seed-{n}"))
                .unwrap()
                .unwrap();
            assert_eq!(latest.seq, 3);
        }
        for n in 0..missed {
            let latest = db
                .latest_catalog_criticality_event(&format!("svc:{n}"))
                .unwrap()
                .unwrap();
            assert_eq!(latest.seq, 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use std::sync::Arc;

    fn sqlite() -> RuntimeDb {
        RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    #[test]
    fn sqlite_sweep_keeps_latest_event_and_seq_monotonic() {
        store_tests::sweep_keeps_latest_event_and_seq_monotonic(&sqlite());
    }

    #[test]
    fn sqlite_reconcile_appends_a_missed_event_once() {
        store_tests::reconcile_appends_a_missed_event_once(&sqlite());
    }

    #[test]
    fn sqlite_concurrent_instances_sweep_and_reconcile_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sekai.db");
        let path = path.to_str().unwrap();
        // More superseded events than one batch, so sweeps take turns.
        let seeded = SWEEP_BATCH / 2 + 7;
        {
            let seed = SekaiDb::new(path).unwrap();
            let mut conn = seed.conn();
            let tx = conn.transaction().unwrap();
            for n in 0..seeded {
                for seq in 1..=3_i64 {
                    tx.execute(
                        "INSERT INTO sekai_catalog_criticality_outbox
                         (event_id, namespace, entry_id, entry_kind, source_system, source_id,
                          seq, evidence_digest, created_at_ms)
                         VALUES (?1 || ':' || ?2, 'acme', ?1, 'service', 's', 's', ?2, 'd', 0)",
                        rusqlite::params![format!("seed-{n}"), seq],
                    )
                    .unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let instances = (0..2)
            .map(|_| RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path).unwrap())))
            .collect();
        store_tests::concurrent_instances_sweep_and_reconcile_once(instances, seeded);
    }

    #[test]
    fn marking_maps_to_criticality_and_effective_is_the_higher() {
        assert_eq!(
            Criticality::from_marking("confidential"),
            Some(Criticality::High)
        );
        assert_eq!(
            Criticality::from_marking("restricted"),
            Some(Criticality::Critical)
        );
        assert!(Criticality::Low < Criticality::High);
        let mut entry = Object {
            id: "catalog:1".into(),
            kind: crate::sekai::catalog::CATALOG_ENTRY_KIND.into(),
            name: "billing".into(),
            namespace: "acme".into(),
            external_id: "catalog:1".into(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        };
        write_levels(&mut entry, Some(Criticality::Low), Some(Criticality::High));
        assert_eq!(entry.properties[DECLARED_PROPERTY], "low");
        assert_eq!(entry.properties[DERIVED_PROPERTY], "high");
        assert_eq!(entry.properties[EFFECTIVE_PROPERTY], "high");
    }
}
