//! One series' samples in a time range (#3472, ADR 0171) on SQLite and
//! PostgreSQL: a range scan over the partial series index of
//! `sekai_dataset_rows`, stopped one row past the scan cap.
//!
//! The queries repeat each index expression and its `IS NOT NULL`
//! predicate exactly, so the partial index applies. A quarantined dataset
//! is refused rather than served from its last healthy version.

use postgres::IsolationLevel;
use rusqlite::params;

use super::postgres::PostgresDb;
use super::sekai::SekaiDb;
use crate::sekai::series::{Sample, SeriesScan, parse_sample};

const SQLITE_SERIES_SQL: &str = "SELECT json_extract(data, '$.timestamp'),
            json_extract(data, '$.value')
     FROM sekai_dataset_rows
     WHERE dataset_id = ?1
       AND json_valid(data)
       AND json_extract(data, '$.series_id') IS NOT NULL
       AND json_extract(data, '$.series_id') = ?2
       AND CAST(json_extract(data, '$.timestamp') AS INTEGER) >= ?3
       AND CAST(json_extract(data, '$.timestamp') AS INTEGER) < ?4
     ORDER BY CAST(json_extract(data, '$.timestamp') AS INTEGER), id
     LIMIT ?5";

/// The integer timestamp of a row, or NULL when it is not one, so indexing
/// a row of any other dataset never fails an insert. `sekai_jsonb_object`
/// (migration 0032) is NULL for malformed JSON. Must match migration 0187
/// exactly.
const PG_TIMESTAMP: &str = "(CASE WHEN sekai_jsonb_object(data)->>'timestamp' ~ '^-?[0-9]{1,18}$'
           THEN (sekai_jsonb_object(data)->>'timestamp')::bigint END)";

fn pg_series_sql() -> String {
    format!(
        "SELECT sekai_jsonb_object(data)->>'timestamp', sekai_jsonb_object(data)->>'value'
         FROM sekai_dataset_rows
         WHERE dataset_id = $1
           AND (sekai_jsonb_object(data)->>'series_id') IS NOT NULL
           AND sekai_jsonb_object(data)->>'series_id' = $2
           AND {PG_TIMESTAMP} >= $3 AND {PG_TIMESTAMP} < $4
         ORDER BY {PG_TIMESTAMP}, id
         LIMIT $5"
    )
}

/// Parses scanned `(timestamp, value)` cells, or reports the cap when the
/// scan returned the row past it.
fn finish(
    cells: Vec<(Option<String>, Option<String>)>,
    scan_cap: usize,
) -> Result<SeriesScan, String> {
    if cells.len() > scan_cap {
        return Ok(SeriesScan::OverScanCap);
    }
    cells
        .into_iter()
        .map(|(timestamp, value)| {
            parse_sample(
                timestamp.as_deref().unwrap_or_default(),
                value.as_deref().unwrap_or_default(),
            )
        })
        .collect::<Result<Vec<Sample>, String>>()
        .map(SeriesScan::Samples)
}

/// The row limit that tells a scan of `scan_cap` samples it went past.
fn scan_limit(scan_cap: usize) -> i64 {
    i64::try_from(scan_cap).unwrap_or(i64::MAX - 1) + 1
}

impl SekaiDb {
    /// Samples of `series_id` in `dataset_id` with `start_ms <= timestamp <
    /// end_ms`, oldest first, or [`SeriesScan::OverScanCap`] past `scan_cap`
    /// samples (the read passes `series::MAX_SCANNED_SAMPLES`).
    pub fn series_samples(
        &self,
        dataset_id: &str,
        series_id: &str,
        start_ms: i64,
        end_ms: i64,
        scan_cap: usize,
    ) -> Result<SeriesScan, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let state = crate::sekai::dataset_health::load_state_conn(&tx, dataset_id)?;
        if state.quarantined {
            return Ok(SeriesScan::Quarantined);
        }
        let mut statement = tx
            .prepare(SQLITE_SERIES_SQL)
            .map_err(|error| error.to_string())?;
        // json_extract returns numbers for numeric JSON; samples are
        // stored as strings, but read either form as text.
        let cells = statement
            .query_map(
                params![
                    dataset_id,
                    series_id,
                    start_ms,
                    end_ms,
                    scan_limit(scan_cap)
                ],
                |row| {
                    let text = |index| -> rusqlite::Result<Option<String>> {
                        Ok(match row.get_ref(index)? {
                            rusqlite::types::ValueRef::Null => None,
                            rusqlite::types::ValueRef::Integer(value) => Some(value.to_string()),
                            rusqlite::types::ValueRef::Real(value) => Some(value.to_string()),
                            rusqlite::types::ValueRef::Text(value) => {
                                Some(String::from_utf8_lossy(value).into_owned())
                            }
                            rusqlite::types::ValueRef::Blob(_) => None,
                        })
                    };
                    Ok((text(0)?, text(1)?))
                },
            )
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        finish(cells, scan_cap)
    }
}

impl PostgresDb {
    /// PostgreSQL twin of [`SekaiDb::series_samples`], over the index of
    /// migration 0187.
    pub fn series_samples(
        &self,
        dataset_id: &str,
        series_id: &str,
        start_ms: i64,
        end_ms: i64,
        scan_cap: usize,
    ) -> Result<SeriesScan, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(|error| error.to_string())?;
        let state = crate::db::postgres_dataset_health::load_state_pg(&mut tx, dataset_id)?;
        if state.quarantined {
            return Ok(SeriesScan::Quarantined);
        }
        let cells = tx
            .query(
                &pg_series_sql(),
                &[
                    &dataset_id,
                    &series_id,
                    &start_ms,
                    &end_ms,
                    &scan_limit(scan_cap),
                ],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect();
        finish(cells, scan_cap)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::dataset_health::{DatasetHealthCheck, KIND_ROW_COUNT};
    use crate::sekai::series::{ERROR_INVALID_SAMPLE, SAMPLE_COLUMNS};

    fn create(db: &RuntimeDb, id: &str) {
        db.create_dataset(&Dataset {
            id: id.into(),
            name: id.into(),
            columns: SAMPLE_COLUMNS
                .into_iter()
                .map(|name| ColumnDef {
                    name: name.into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                })
                .collect(),
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
    }

    fn sample(series: &str, timestamp: &str, value: &str) -> HashMap<String, String> {
        HashMap::from([
            ("series_id".into(), series.into()),
            ("timestamp".into(), timestamp.into()),
            ("value".into(), value.into()),
        ])
    }

    fn timestamps(scan: SeriesScan) -> Vec<i64> {
        let SeriesScan::Samples(samples) = scan else {
            panic!("expected samples, got {scan:?}");
        };
        samples.iter().map(|sample| sample.timestamp_ms).collect()
    }

    /// One series in a half-open range, oldest first; the cap refuses
    /// rather than truncating; a bad cell in range fails by name; and a
    /// quarantined dataset is refused.
    fn reads_one_series_in_range(db: &RuntimeDb) {
        create(db, "samples");
        db.append_rows(
            "samples",
            &[
                sample("a", "30", "3"),
                sample("a", "10", "1"),
                sample("b", "20", "9"),
                sample("a", "40", "4"),
                sample("a", "9", "0"),
                sample("a", "20", "2"),
            ],
        )
        .unwrap();
        let read = |series, start, end, cap| {
            db.series_samples("samples", series, start, end, cap)
                .unwrap()
        };
        assert_eq!(timestamps(read("a", 10, 40, 10)), [10, 20, 30]);
        assert_eq!(timestamps(read("b", 0, 100, 10)), [20]);
        assert_eq!(timestamps(read("c", 0, 100, 10)), Vec::<i64>::new());
        assert_eq!(
            read("a", 10, 40, 3),
            SeriesScan::Samples(vec![
                Sample {
                    timestamp_ms: 10,
                    value: 1.0
                },
                Sample {
                    timestamp_ms: 20,
                    value: 2.0
                },
                Sample {
                    timestamp_ms: 30,
                    value: 3.0
                },
            ])
        );
        assert_eq!(read("a", 10, 40, 2), SeriesScan::OverScanCap);

        db.append_rows("samples", &[sample("a", "25", "warm")])
            .unwrap();
        let error = db.series_samples("samples", "a", 10, 40, 10).unwrap_err();
        assert!(error.starts_with(ERROR_INVALID_SAMPLE), "{error}");
        assert_eq!(timestamps(read("a", 30, 41, 10)), [30, 40]);

        create(db, "quarantined");
        db.put_dataset_health_check(&DatasetHealthCheck {
            dataset_id: "quarantined".into(),
            check_id: "rows".into(),
            kind: KIND_ROW_COUNT.into(),
            max_age_ms: 0,
            min_rows: 2,
            max_rows: 0,
            columns: Vec::new(),
            predicate: Vec::new(),
            blocking: true,
            every_ms: 0,
            tenant: "acme".into(),
            space: "ops".into(),
            last_run_ms: 0,
        })
        .unwrap();
        db.append_rows("quarantined", &[sample("a", "10", "1")])
            .unwrap();
        assert_eq!(
            db.series_samples("quarantined", "a", 0, 100, 10).unwrap(),
            SeriesScan::Quarantined
        );
    }

    #[test]
    fn sqlite_reads_one_series_in_range() {
        reads_one_series_in_range(&RuntimeDb::memory());
    }

    #[test]
    fn sqlite_series_read_seeks_the_series_index_in_order() {
        let db = SekaiDb::new(":memory:").unwrap();
        let conn = db.conn();
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {SQLITE_SERIES_SQL}"))
            .unwrap();
        let plan: Vec<String> = stmt
            .query_map(params!["samples", "a", 0, 10, 2], |row| row.get(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|step| step.contains("idx_dataset_rows_series"))
                && !plan.iter().any(|step| step.contains("TEMP B-TREE")),
            "plan {plan:?} does not seek idx_dataset_rows_series in order"
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_reads_one_series_in_range() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        reads_one_series_in_range(&RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect())));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_series_read_can_seek_the_series_index() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = scratch.connect();
        let mut conn = db.connection().unwrap();
        let mut tx = conn.transaction().unwrap();
        // Empty tables favor a sequential scan; forbidding it shows the
        // planner can prove the partial index predicate from the query.
        tx.batch_execute("SET LOCAL enable_seqscan = off").unwrap();
        let explain = format!(
            "EXPLAIN {}",
            pg_series_sql()
                .replace("$1", "'samples'")
                .replace("$2", "'a'")
                .replace("$3", "0")
                .replace("$4", "10")
                .replace("$5", "2")
        );
        let plan: Vec<String> = tx
            .query(&explain, &[])
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        assert!(
            plan.iter()
                .any(|step| step.contains("idx_dataset_rows_series")),
            "plan {plan:?} does not use idx_dataset_rows_series"
        );
    }
}
