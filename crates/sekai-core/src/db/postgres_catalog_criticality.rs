use crate::db::postgres::PostgresDb;
use crate::sekai::catalog::CatalogError;
use crate::sekai::catalog_criticality::{
    CriticalityEvent, SWEEP_BATCH, clamp_page_size, decode_page_token, encode_page_token,
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

    /// Ids after `after`, in id order and at most `limit`, of catalog
    /// entries whose stored declared, derived or effective criticality
    /// differs from their latest outbox event. The kinds are the ones
    /// `EntryKind::carries_derived_criticality` accepts.
    pub fn drifted_catalog_criticality_entries(
        &self,
        after: &str,
        limit: i64,
    ) -> Result<Vec<String>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT o.id FROM sekai_objects o
                 LEFT JOIN sekai_catalog_criticality_outbox e
                   ON e.entry_id = o.id
                  AND e.seq = (SELECT MAX(seq) FROM sekai_catalog_criticality_outbox
                               WHERE entry_id = o.id)
                 WHERE o.kind = $1 AND o.id > $2
                   AND o.properties::jsonb ->> 'entry_kind'
                       IN ('service', 'release', 'environment')
                   AND (COALESCE(o.properties::jsonb ->> 'declared_criticality', '')
                            <> COALESCE(e.declared, '')
                     OR COALESCE(o.properties::jsonb ->> 'derived_criticality', '')
                            <> COALESCE(e.derived, '')
                     OR COALESCE(o.properties::jsonb ->> 'effective_criticality', '')
                            <> COALESCE(e.effective, ''))
                 ORDER BY o.id LIMIT $3",
                &[&crate::sekai::catalog::CATALOG_ENTRY_KIND, &after, &limit],
            )
            .map_err(|error| error.to_string())?;
        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    /// Deletes at most [`SWEEP_BATCH`] events written before `cutoff_ms`
    /// that a later event of the same entry supersedes, and returns how many
    /// it deleted. An entry's latest event is never deleted. The batch is
    /// locked first and rows another instance holds are skipped, so
    /// concurrent sweeps never wait on or overlap each other.
    pub fn delete_superseded_catalog_criticality_events(
        &self,
        cutoff_ms: i64,
    ) -> Result<usize, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let event_ids: Vec<String> = tx
            .query(
                "SELECT o.event_id FROM sekai_catalog_criticality_outbox o
                 WHERE o.created_at_ms < $1
                   AND EXISTS (SELECT 1 FROM sekai_catalog_criticality_outbox n
                               WHERE n.entry_id = o.entry_id AND n.seq > o.seq)
                 LIMIT $2 FOR UPDATE OF o SKIP LOCKED",
                &[&cutoff_ms, &SWEEP_BATCH],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| row.get(0))
            .collect();
        let deleted = tx
            .execute(
                "DELETE FROM sekai_catalog_criticality_outbox WHERE event_id = ANY($1)",
                &[&event_ids],
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        usize::try_from(deleted).map_err(|error| error.to_string())
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

#[cfg(test)]
mod tests {
    use crate::db::postgres::ScratchDatabase;
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::catalog_criticality::{SWEEP_BATCH, store_tests};
    use std::sync::Arc;

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_sweep_keeps_latest_event_and_seq_monotonic() {
        let scratch = ScratchDatabase::create();
        let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
        store_tests::sweep_keeps_latest_event_and_seq_monotonic(&db);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_reconcile_appends_a_missed_event_once() {
        let scratch = ScratchDatabase::create();
        let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
        store_tests::reconcile_appends_a_missed_event_once(&db);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_concurrent_instances_sweep_and_reconcile_once() {
        let scratch = ScratchDatabase::create();
        // More superseded events than one batch, so sweeps take turns.
        let seeded = SWEEP_BATCH / 2 + 7;
        scratch
            .connect()
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO sekai_catalog_criticality_outbox
                 (event_id, namespace, entry_id, entry_kind, source_system, source_id,
                  seq, evidence_digest, created_at_ms)
                 SELECT 'seed-' || n || ':' || seq, 'acme', 'seed-' || n, 'service', 's', 's',
                        seq, 'd', 0
                 FROM generate_series(0, $1::BIGINT - 1) AS n,
                      generate_series(1::BIGINT, 3::BIGINT) AS seq",
                &[&seeded],
            )
            .unwrap();
        // Each instance has its own pool, like two processes.
        let instances = (0..2)
            .map(|_| RuntimeDb::Postgres(Arc::new(scratch.connect())))
            .collect();
        store_tests::concurrent_instances_sweep_and_reconcile_once(instances, seeded);
    }
}
