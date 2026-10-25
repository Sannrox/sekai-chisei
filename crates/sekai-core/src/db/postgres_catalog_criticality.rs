use crate::db::postgres::PostgresDb;
use crate::sekai::catalog::CatalogError;
use crate::sekai::catalog_criticality::{
    CriticalityEvent, clamp_page_size, decode_page_token, encode_page_token,
};

impl PostgresDb {
    pub fn insert_catalog_criticality_event(
        &self,
        event: &CriticalityEvent,
        expected_updated: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let updated = tx
            .query_opt(
                "SELECT updated FROM sekai_objects WHERE id = $1 FOR UPDATE",
                &[&event.entry_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, i64>(0));
        if updated != Some(expected_updated) {
            return Ok(false);
        }
        let n = tx
            .execute(
                "INSERT INTO sekai_catalog_criticality_outbox
                 (event_id, namespace, entry_id, entry_kind, source_system, source_id, seq,
                  declared, derived, effective, evidence_digest, created_at_ms)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                 ON CONFLICT (entry_id, seq) DO NOTHING",
                &[
                    &event.event_id,
                    &event.namespace,
                    &event.entry_id,
                    &event.entry_kind,
                    &event.source_system,
                    &event.source_id,
                    &event.seq,
                    &event.declared,
                    &event.derived,
                    &event.effective,
                    &event.evidence_digest,
                    &event.created_at_ms,
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
        let row = self
            .connection()?
            .query_opt(
                "SELECT event_id, namespace, entry_id, entry_kind, source_system, source_id, seq,
                        declared, derived, effective, evidence_digest, created_at_ms
                 FROM sekai_catalog_criticality_outbox
                 WHERE entry_id = $1
                 ORDER BY seq DESC LIMIT 1",
                &[&entry_id],
            )
            .map_err(|error| error.to_string())?;
        row.map(row_to_event).transpose()
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
        let mut connection = self.connection()?;
        let limit = i64::from(page_size) + 1;
        let rows = match &cursor {
            Some((created_at_ms, event_id)) => connection
                .query(
                    "SELECT event_id, namespace, entry_id, entry_kind, source_system, source_id, seq,
                            declared, derived, effective, evidence_digest, created_at_ms
                     FROM sekai_catalog_criticality_outbox
                     WHERE namespace = $1
                       AND (created_at_ms < $2 OR (created_at_ms = $2 AND event_id < $3))
                     ORDER BY created_at_ms DESC, event_id DESC
                     LIMIT $4",
                    &[&namespace, created_at_ms, event_id, &limit],
                )
                .map_err(|error| error.to_string())?,
            None => connection
                .query(
                    "SELECT event_id, namespace, entry_id, entry_kind, source_system, source_id, seq,
                            declared, derived, effective, evidence_digest, created_at_ms
                     FROM sekai_catalog_criticality_outbox
                     WHERE namespace = $1
                     ORDER BY created_at_ms DESC, event_id DESC
                     LIMIT $2",
                    &[&namespace, &limit],
                )
                .map_err(|error| error.to_string())?,
        };
        let mut events = rows
            .into_iter()
            .map(row_to_event)
            .collect::<Result<Vec<_>, _>>()?;
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

fn row_to_event(row: postgres::Row) -> Result<CriticalityEvent, String> {
    Ok(CriticalityEvent {
        event_id: row.get(0),
        namespace: row.get(1),
        entry_id: row.get(2),
        entry_kind: row.get(3),
        source_system: row.get(4),
        source_id: row.get(5),
        seq: row.get(6),
        declared: row.get(7),
        derived: row.get(8),
        effective: row.get(9),
        evidence_digest: row.get(10),
        created_at_ms: row.get(11),
    })
}
