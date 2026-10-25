//! Declared and derived catalog criticality, exported through the outbox (#1688).
//!
//! Declared is curated by owners. Derived is the highest criticality implied
//! by markings on data reachable through catalog lineage. Effective is the
//! higher of the two and only falls when those markings are declassified.
//! Each change appends one outbox event whose digest is the export evidence.

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

#[cfg(test)]
mod tests {
    use super::*;

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
