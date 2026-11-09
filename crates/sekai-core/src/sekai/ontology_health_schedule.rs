//! Ontology health schedules (#2192): a namespace's health snapshot as a
//! member of the transform schedule graph (ADR 0103).
//!
//! A namespace administrator puts one schedule per namespace, carrying the
//! window, retention and threshold, and becomes the principal its snapshots
//! record as. `TickGovernedTransforms` records each due window as that
//! principal. The snapshot store keeps one snapshot per (namespace, window),
//! so two planes ticking at once, or a tick racing an on-demand
//! `RecordOntologyHealthSnapshot`, store a window once. The cursor
//! `last_window_start_ms` only keeps a finished window from being scored
//! again; a crash before it advances leaves the window due, and the retry
//! replays the stored snapshot.
//!
//! A window the recorder is refused for (a revoked administrator, say) halts
//! the schedule with `last_error`: the tick reports it once and does not try
//! again until a put replaces the schedule. Every put bumps `generation`, and
//! a tick advances or halts only the generation it read, so a halt from a
//! stale read never stops a schedule an administrator just put.

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::ontology_health::Part;
use crate::sekai::ontology_health_trend::{self, RecordRequest, Recorded, TrendError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSchedule {
    pub namespace: String,
    pub window_ms: i64,
    pub retention_ms: i64,
    pub threshold: u8,
    /// The administrator that put the schedule; snapshots record as them.
    pub recorded_by: String,
    pub updated_at_ms: i64,
    /// Bumped by every put; fences a tick that read an older schedule.
    pub generation: i64,
    /// Start of the last finished window; zero before the first.
    pub last_window_start_ms: i64,
    /// Why the schedule halted; empty while it runs.
    pub last_error: String,
}

impl HealthSchedule {
    /// The window holding `now_ms` when the schedule runs and has not
    /// finished it.
    pub fn due_window(&self, now_ms: i64) -> Option<i64> {
        let window = ontology_health_trend::window_start(now_ms, self.window_ms);
        (self.last_error.is_empty() && self.last_window_start_ms < window).then_some(window)
    }
}

/// What a put asks for; the plane sets the rest.
pub struct PutSchedule<'a> {
    pub namespace: &'a str,
    pub window_ms: i64,
    pub retention_ms: i64,
    pub threshold: u32,
    pub recorded_by: &'a str,
    pub now_ms: i64,
}

/// Creates or replaces the namespace's schedule. A replace keeps the cursor,
/// so a window already recorded is not scored again, and clears a halt.
pub fn put(db: &RuntimeDb, request: &PutSchedule<'_>) -> Result<HealthSchedule, TrendError> {
    let threshold = ontology_health_trend::validate(
        request.namespace,
        request.window_ms,
        request.retention_ms,
        request.threshold,
    )?;
    Ok(db.put_ontology_health_schedule(&HealthSchedule {
        namespace: request.namespace.into(),
        window_ms: request.window_ms,
        retention_ms: request.retention_ms,
        threshold,
        recorded_by: request.recorded_by.into(),
        updated_at_ms: request.now_ms,
        generation: 1,
        last_window_start_ms: 0,
        last_error: String::new(),
    })?)
}

/// The schedules with a window due at `now_ms`.
pub fn due(db: &RuntimeDb, now_ms: i64) -> Result<Vec<HealthSchedule>, String> {
    Ok(db
        .list_running_ontology_health_schedules()?
        .into_iter()
        .filter(|schedule| schedule.due_window(now_ms).is_some())
        .collect())
}

/// Records `schedule`'s window holding `now_ms` from `parts`, scored as its
/// recorder, then finishes the window. A stored window replays; a later
/// window recorded on demand makes this one stale, and it is finished too.
pub fn record_due(
    db: &RuntimeDb,
    schedule: &HealthSchedule,
    now_ms: i64,
    parts: &[Part],
    datasets: &[String],
    definition_revision: &str,
) -> Result<Recorded, TrendError> {
    let recorded = ontology_health_trend::record(
        db,
        &RecordRequest {
            namespace: &schedule.namespace,
            window_ms: schedule.window_ms,
            retention_ms: schedule.retention_ms,
            threshold: u32::from(schedule.threshold),
            recorded_by: &schedule.recorded_by,
            now_ms,
        },
        parts,
        datasets,
        definition_revision,
    )?;
    finish(db, schedule, now_ms, "")?;
    Ok(recorded)
}

/// Halts `schedule` at the window holding `now_ms` with `reason`. False when
/// a put or another tick changed it since it was read.
pub fn halt(
    db: &RuntimeDb,
    schedule: &HealthSchedule,
    now_ms: i64,
    reason: &str,
) -> Result<bool, String> {
    finish(db, schedule, now_ms, reason)
}

fn finish(
    db: &RuntimeDb,
    schedule: &HealthSchedule,
    now_ms: i64,
    error: &str,
) -> Result<bool, String> {
    db.finish_ontology_health_window(
        &schedule.namespace,
        schedule.generation,
        ontology_health_trend::window_start(now_ms, schedule.window_ms),
        error,
    )
}

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_ontology_health_schedules (
    namespace TEXT PRIMARY KEY,
    window_ms INTEGER NOT NULL,
    retention_ms INTEGER NOT NULL,
    threshold INTEGER NOT NULL,
    recorded_by TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    last_window_start_ms INTEGER NOT NULL,
    last_error TEXT NOT NULL
);
";

const COLUMNS: &str = "namespace, window_ms, retention_ms, threshold, recorded_by, \
    updated_at_ms, generation, last_window_start_ms, last_error";

/// Upsert: a new schedule starts at generation 1 with no window finished; a
/// replace bumps the generation, keeps the cursor and clears the halt.
const PUT_SQL: &str = "
INSERT INTO sekai_ontology_health_schedules
    (namespace, window_ms, retention_ms, threshold, recorded_by, updated_at_ms,
     generation, last_window_start_ms, last_error)
VALUES ($1, $2, $3, $4, $5, $6, 1, 0, '')
ON CONFLICT (namespace) DO UPDATE SET
    window_ms = excluded.window_ms,
    retention_ms = excluded.retention_ms,
    threshold = excluded.threshold,
    recorded_by = excluded.recorded_by,
    updated_at_ms = excluded.updated_at_ms,
    generation = sekai_ontology_health_schedules.generation + 1,
    last_error = ''
RETURNING namespace, window_ms, retention_ms, threshold, recorded_by,
    updated_at_ms, generation, last_window_start_ms, last_error";

/// Fenced by generation, and moves the cursor forward only.
const FINISH_SQL: &str = "
UPDATE sekai_ontology_health_schedules
SET last_window_start_ms = $1, last_error = $2
WHERE namespace = $3 AND generation = $4 AND last_window_start_ms < $1";

fn threshold_from(value: i64) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

fn sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HealthSchedule> {
    Ok(HealthSchedule {
        namespace: row.get(0)?,
        window_ms: row.get(1)?,
        retention_ms: row.get(2)?,
        threshold: threshold_from(row.get(3)?),
        recorded_by: row.get(4)?,
        updated_at_ms: row.get(5)?,
        generation: row.get(6)?,
        last_window_start_ms: row.get(7)?,
        last_error: row.get(8)?,
    })
}

fn postgres_row(row: &postgres::Row) -> HealthSchedule {
    HealthSchedule {
        namespace: row.get(0),
        window_ms: row.get(1),
        retention_ms: row.get(2),
        threshold: threshold_from(row.get(3)),
        recorded_by: row.get(4),
        updated_at_ms: row.get(5),
        generation: row.get(6),
        last_window_start_ms: row.get(7),
        last_error: row.get(8),
    }
}

impl SekaiDb {
    pub fn migrate_ontology_health_schedules(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    pub fn put_ontology_health_schedule(
        &self,
        schedule: &HealthSchedule,
    ) -> Result<HealthSchedule, String> {
        self.conn()
            .query_row(
                PUT_SQL,
                rusqlite::params![
                    schedule.namespace,
                    schedule.window_ms,
                    schedule.retention_ms,
                    i64::from(schedule.threshold),
                    schedule.recorded_by,
                    schedule.updated_at_ms,
                ],
                sqlite_row,
            )
            .map_err(|error| error.to_string())
    }

    pub fn get_ontology_health_schedule(
        &self,
        namespace: &str,
    ) -> Result<Option<HealthSchedule>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_ontology_health_schedules WHERE namespace = ?1"
                ),
                [namespace],
                sqlite_row,
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn delete_ontology_health_schedule(&self, namespace: &str) -> Result<bool, String> {
        self.conn()
            .execute(
                "DELETE FROM sekai_ontology_health_schedules WHERE namespace = ?1",
                [namespace],
            )
            .map(|deleted| deleted == 1)
            .map_err(|error| error.to_string())
    }

    pub fn list_running_ontology_health_schedules(&self) -> Result<Vec<HealthSchedule>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM sekai_ontology_health_schedules
                 WHERE last_error = '' ORDER BY namespace"
            ))
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], sqlite_row)
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<_, _>>()
            .map_err(|error| error.to_string())
    }

    pub fn finish_ontology_health_window(
        &self,
        namespace: &str,
        generation: i64,
        window_start_ms: i64,
        error: &str,
    ) -> Result<bool, String> {
        self.conn()
            .execute(
                FINISH_SQL,
                rusqlite::params![window_start_ms, error, namespace, generation],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }
}

impl PostgresDb {
    pub fn put_ontology_health_schedule(
        &self,
        schedule: &HealthSchedule,
    ) -> Result<HealthSchedule, String> {
        self.connection()?
            .query_one(
                PUT_SQL,
                &[
                    &schedule.namespace,
                    &schedule.window_ms,
                    &schedule.retention_ms,
                    &i64::from(schedule.threshold),
                    &schedule.recorded_by,
                    &schedule.updated_at_ms,
                ],
            )
            .map(|row| postgres_row(&row))
            .map_err(|error| error.to_string())
    }

    pub fn get_ontology_health_schedule(
        &self,
        namespace: &str,
    ) -> Result<Option<HealthSchedule>, String> {
        self.connection()?
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_ontology_health_schedules WHERE namespace = $1"
                ),
                &[&namespace],
            )
            .map(|row| row.as_ref().map(postgres_row))
            .map_err(|error| error.to_string())
    }

    pub fn delete_ontology_health_schedule(&self, namespace: &str) -> Result<bool, String> {
        self.connection()?
            .execute(
                "DELETE FROM sekai_ontology_health_schedules WHERE namespace = $1",
                &[&namespace],
            )
            .map(|deleted| deleted == 1)
            .map_err(|error| error.to_string())
    }

    pub fn list_running_ontology_health_schedules(&self) -> Result<Vec<HealthSchedule>, String> {
        Ok(self
            .connection()?
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_ontology_health_schedules
                     WHERE last_error = '' ORDER BY namespace"
                ),
                &[],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(postgres_row)
            .collect())
    }

    pub fn finish_ontology_health_window(
        &self,
        namespace: &str,
        generation: i64,
        window_start_ms: i64,
        error: &str,
    ) -> Result<bool, String> {
        self.connection()?
            .execute(
                FINISH_SQL,
                &[&window_start_ms, &error, &namespace, &generation],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }
}

impl RuntimeDb {
    pub fn put_ontology_health_schedule(
        &self,
        schedule: &HealthSchedule,
    ) -> Result<HealthSchedule, String> {
        match self {
            Self::Sqlite(db) => db.put_ontology_health_schedule(schedule),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_ontology_health_schedule(schedule))
            }
        }
    }

    pub fn get_ontology_health_schedule(
        &self,
        namespace: &str,
    ) -> Result<Option<HealthSchedule>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_health_schedule(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_ontology_health_schedule(namespace))
            }
        }
    }

    pub fn delete_ontology_health_schedule(&self, namespace: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_ontology_health_schedule(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.delete_ontology_health_schedule(namespace))
            }
        }
    }

    pub fn list_running_ontology_health_schedules(&self) -> Result<Vec<HealthSchedule>, String> {
        match self {
            Self::Sqlite(db) => db.list_running_ontology_health_schedules(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_running_ontology_health_schedules())
            }
        }
    }

    pub fn finish_ontology_health_window(
        &self,
        namespace: &str,
        generation: i64,
        window_start_ms: i64,
        error: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.finish_ontology_health_window(namespace, generation, window_start_ms, error)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.finish_ontology_health_window(namespace, generation, window_start_ms, error)
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::ontology_health::PART_LINT;
    use std::sync::Arc;

    const HOUR: i64 = 3_600_000;

    fn put_hourly(db: &RuntimeDb, ns: &str, recorded_by: &str) -> HealthSchedule {
        put(
            db,
            &PutSchedule {
                namespace: ns,
                window_ms: HOUR,
                retention_ms: 24 * HOUR,
                threshold: 50,
                recorded_by,
                now_ms: HOUR,
            },
        )
        .unwrap()
    }

    fn lint(score: u8) -> Vec<Part> {
        vec![Part {
            score: Some(score),
            ..Part::unavailable(PART_LINT, "")
        }]
    }

    /// One plane's tick of `ns`: record every due window, as the gRPC tick does
    /// after scoring. Returns how many windows this plane wrote.
    fn tick(db: &RuntimeDb, ns: &str, now_ms: i64) -> usize {
        due(db, now_ms)
            .unwrap()
            .iter()
            .filter(|schedule| schedule.namespace == ns)
            .map(|schedule| record_due(db, schedule, now_ms, &lint(80), &[], "").unwrap())
            .filter(|recorded| matches!(recorded, Recorded::Fresh { .. }))
            .count()
    }

    fn windows(db: &RuntimeDb, ns: &str) -> Vec<i64> {
        let (snapshots, _) = db.list_ontology_health_trend(ns).unwrap();
        snapshots.iter().map(|s| s.window_start_ms).collect()
    }

    /// The schedule contract on either backend.
    fn contract(db: Arc<RuntimeDb>, ns: &str) {
        let base = 100 * HOUR;
        put_hourly(&db, ns, "ops");
        // Two planes tick the same window at once: one snapshot.
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (db, ns) = (db.clone(), ns.to_owned());
                std::thread::spawn(move || tick(&db, &ns, base + 5))
            })
            .collect();
        let fresh: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(fresh, 1);
        assert_eq!(windows(&db, ns), [base]);
        let schedule = db.get_ontology_health_schedule(ns).unwrap().unwrap();
        assert_eq!(schedule.last_window_start_ms, base);
        assert_eq!(schedule.recorded_by, "ops");
        // A finished window is not due again; the next one is.
        assert_eq!(tick(&db, ns, base + HOUR - 1), 0);
        assert_eq!(tick(&db, ns, base + HOUR + 5), 1);

        // A crash after the record but before the cursor moved: the window
        // stays due, and the retry replays the stored snapshot.
        let window = base + 2 * HOUR;
        let stale_read = due(&db, window).unwrap();
        let schedule = stale_read.iter().find(|s| s.namespace == ns).unwrap();
        ontology_health_trend::record(
            &db,
            &RecordRequest {
                namespace: ns,
                window_ms: HOUR,
                retention_ms: 24 * HOUR,
                threshold: 50,
                recorded_by: "ops",
                now_ms: window,
            },
            &lint(80),
            &[],
            "",
        )
        .unwrap();
        assert!(matches!(
            record_due(&db, schedule, window + 1, &lint(10), &[], "").unwrap(),
            Recorded::Replay(_)
        ));
        assert_eq!(tick(&db, ns, window + 2), 0);

        // A refused recorder halts the schedule: no longer due, error kept.
        let read = db.get_ontology_health_schedule(ns).unwrap().unwrap();
        let window = base + 3 * HOUR;
        assert!(halt(&db, &read, window, "namespace access denied").unwrap());
        assert!(
            due(&db, window + 4 * HOUR)
                .unwrap()
                .iter()
                .all(|s| s.namespace != ns)
        );
        let halted = db.get_ontology_health_schedule(ns).unwrap().unwrap();
        assert_eq!(halted.last_error, "namespace access denied");

        // A put replaces the recorder and clears the halt; a halt from the
        // read before the put is fenced off by the generation.
        let replaced = put_hourly(&db, ns, "ops-2");
        assert_eq!(replaced.generation, read.generation + 1);
        assert_eq!(replaced.last_window_start_ms, window);
        assert!(replaced.last_error.is_empty());
        assert!(!halt(&db, &read, window + HOUR, "stale").unwrap());
        assert_eq!(tick(&db, ns, window + HOUR), 1);
        let (snapshots, _) = db.list_ontology_health_trend(ns).unwrap();
        assert_eq!(snapshots.last().unwrap().recorded_by, "ops-2");

        // Delete stops the schedule and keeps the trend.
        assert!(db.delete_ontology_health_schedule(ns).unwrap());
        assert!(!db.delete_ontology_health_schedule(ns).unwrap());
        assert_eq!(tick(&db, ns, window + 2 * HOUR), 0);
        assert_eq!(windows(&db, ns).len(), 4);
    }

    #[test]
    fn sqlite_schedule_records_one_snapshot_per_window_across_planes() {
        contract(Arc::new(RuntimeDb::memory()), "acme");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_schedule_records_one_snapshot_per_window_across_planes() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => {
                PostgresDb::connect_with_ca_certificate(&url, 4, &std::fs::read(path).unwrap())
            }
            Err(_) => PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(Arc::new(db.unwrap()));
        let ns = format!("schedule-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        contract(Arc::new(db), &ns);
    }

    #[test]
    fn a_put_refuses_a_short_window_or_an_out_of_range_threshold() {
        let db = RuntimeDb::memory();
        let request = |window_ms, threshold| PutSchedule {
            namespace: "acme",
            window_ms,
            retention_ms: HOUR,
            threshold,
            recorded_by: "ops",
            now_ms: HOUR,
        };
        for bad in [request(1_000, 50), request(HOUR, 101)] {
            assert!(matches!(put(&db, &bad), Err(TrendError::Invalid(_))));
        }
        assert_eq!(db.get_ontology_health_schedule("acme").unwrap(), None);
    }
}
