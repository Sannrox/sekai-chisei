//! Stored ontology health trends and threshold events (#1694).
//!
//! A record stores one snapshot of a namespace's part scores per time
//! window. A stored schedule (`ontology_health_schedule`, #2192) records
//! from the transform schedule tick; `RecordOntologyHealthSnapshot` records
//! on demand. Recording is
//! idempotent per (namespace, window): the window's first record is kept and
//! every later or concurrent one replays it. When the total (the lowest part)
//! falls below the threshold, one event is written in the same transaction
//! as the snapshot, only on the drop: a recovery and a new drop write
//! another. Snapshots and events past the retention are pruned on record.
//! Problems are not stored, only scores, so a trend never names a subject.

use serde::{Deserialize, Serialize};

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::ontology_health::{PART_FRESHNESS, PART_QUALITY, PART_SOURCE, Part};
use crate::sekai::source_health::HEALTH_CONTRACT;

pub const EVENT_BELOW_THRESHOLD: &str = "below_threshold";
/// The shortest window a record may use.
pub const MIN_WINDOW_MS: i64 = 60_000;

/// One part's score when recorded; `None` when it was unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartScore {
    pub part: String,
    pub score: Option<u8>,
    /// False when the inputs were capped: the score may be too high.
    pub complete: bool,
    /// The datasets a dataset part (freshness, quality) was scored from;
    /// for the source part, the source contract and then its sources (see
    /// [`PartScore::source_inputs`]). Never returned: a reader sees the part
    /// only while they may read every one of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<String>,
}

impl PartScore {
    /// The sources (`ontology_health::source_subject`) a source part was
    /// scored from. The inputs start with the source contract, which names
    /// no dataset: a binary that reads every input as a dataset, as those
    /// before the source part do, hides the part and the events it fed.
    /// `None` when they do not start with it, so a reader fails closed.
    pub fn source_inputs(&self) -> Option<&[String]> {
        match self.inputs.split_first() {
            Some((contract, sources)) if contract == HEALTH_CONTRACT => Some(sources),
            _ => None,
        }
    }
}

/// What one scoring's parts were scored from, stored with its snapshot so
/// each reader can be re-authorized. Never returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScoreInputs {
    /// The datasets of the freshness and quality parts.
    pub datasets: Vec<String>,
    /// The sources (`ontology_health::source_subject`) of the source part.
    pub sources: Vec<String>,
    /// The published definition revision of the contract and lint parts;
    /// empty when none was published.
    pub definition_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub namespace: String,
    pub window_start_ms: i64,
    pub window_ms: i64,
    pub recorded_at_ms: i64,
    pub recorded_by: String,
    pub threshold: u8,
    pub parts: Vec<PartScore>,
    /// The published definition revision the contract and lint parts were
    /// scored from; empty when none was published.
    #[serde(default)]
    pub definition_revision: String,
}

impl HealthSnapshot {
    /// The lowest recorded score; `None` when no part had one.
    pub fn total(&self) -> Option<u8> {
        self.parts.iter().filter_map(|part| part.score).min()
    }

    fn below_threshold(&self) -> bool {
        self.total().is_some_and(|total| total < self.threshold)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthEvent {
    pub namespace: String,
    pub window_start_ms: i64,
    pub kind: String,
    pub score: u8,
    pub threshold: u8,
    pub emitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    /// This call wrote the snapshot, and the event when health dropped.
    Fresh {
        snapshot: HealthSnapshot,
        event: Option<HealthEvent>,
    },
    /// The window was already recorded; nothing was written.
    Replay(HealthSnapshot),
    /// A later window is already recorded: an older one would reorder the
    /// trend and misjudge the drop.
    Stale,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TrendError {
    Invalid(String),
    Store(String),
}

impl From<String> for TrendError {
    fn from(error: String) -> Self {
        Self::Store(error)
    }
}

/// What one record asks for. `window_ms`, `retention_ms` and `threshold`
/// come from the caller's schedule.
pub struct RecordRequest<'a> {
    pub namespace: &'a str,
    pub window_ms: i64,
    pub retention_ms: i64,
    pub threshold: u32,
    pub recorded_by: &'a str,
    pub now_ms: i64,
}

/// Checks a record's or a schedule's window, retention and threshold, and
/// returns the threshold.
pub fn validate(
    namespace: &str,
    window_ms: i64,
    retention_ms: i64,
    threshold: u32,
) -> Result<u8, TrendError> {
    if namespace.trim().is_empty() {
        return Err(TrendError::Invalid("namespace is required".into()));
    }
    if window_ms < MIN_WINDOW_MS {
        return Err(TrendError::Invalid(format!(
            "window_ms must be at least {MIN_WINDOW_MS}"
        )));
    }
    if retention_ms < window_ms {
        return Err(TrendError::Invalid(
            "retention_ms must cover at least one window".into(),
        ));
    }
    u8::try_from(threshold)
        .ok()
        .filter(|threshold| *threshold <= 100)
        .ok_or_else(|| TrendError::Invalid("threshold must be 0-100".into()))
}

/// The start of the `window_ms` window holding `now_ms`.
pub fn window_start(now_ms: i64, window_ms: i64) -> i64 {
    now_ms - now_ms.rem_euclid(window_ms)
}

/// Records `parts`, scored from `inputs`, for the window holding `now_ms`.
pub fn record(
    db: &crate::db::runtime_db::RuntimeDb,
    request: &RecordRequest<'_>,
    parts: &[Part],
    inputs: &ScoreInputs,
) -> Result<Recorded, TrendError> {
    let threshold = validate(
        request.namespace,
        request.window_ms,
        request.retention_ms,
        request.threshold,
    )?;
    let window_start_ms = window_start(request.now_ms, request.window_ms);
    let snapshot = HealthSnapshot {
        namespace: request.namespace.into(),
        window_start_ms,
        window_ms: request.window_ms,
        recorded_at_ms: request.now_ms,
        recorded_by: request.recorded_by.into(),
        threshold,
        definition_revision: inputs.definition_revision.clone(),
        parts: parts
            .iter()
            .map(|part| PartScore {
                part: part.part.into(),
                score: part.score,
                complete: part.complete,
                inputs: match part.part {
                    PART_FRESHNESS | PART_QUALITY => sorted(&inputs.datasets),
                    PART_SOURCE => std::iter::once(HEALTH_CONTRACT.to_owned())
                        .chain(sorted(&inputs.sources))
                        .collect(),
                    _ => Vec::new(),
                },
            })
            .collect(),
    };
    Ok(db.record_ontology_health_snapshot(&snapshot, window_start_ms - request.retention_ms)?)
}

fn sorted(ids: &[String]) -> Vec<String> {
    let mut ids = ids.to_vec();
    ids.sort();
    ids
}

/// The event `snapshot` writes after `previous` (the latest earlier
/// snapshot): only a drop below the threshold, so a stay below writes none.
fn drop_event(snapshot: &HealthSnapshot, previous: Option<&HealthSnapshot>) -> Option<HealthEvent> {
    let dropped =
        snapshot.below_threshold() && !previous.is_some_and(HealthSnapshot::below_threshold);
    dropped.then(|| HealthEvent {
        namespace: snapshot.namespace.clone(),
        window_start_ms: snapshot.window_start_ms,
        kind: EVENT_BELOW_THRESHOLD.into(),
        score: snapshot.total().unwrap_or_default(),
        threshold: snapshot.threshold,
        emitted_at_ms: snapshot.recorded_at_ms,
    })
}

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_ontology_health_snapshots (
    namespace TEXT NOT NULL,
    window_start_ms INTEGER NOT NULL,
    body_json TEXT NOT NULL,
    PRIMARY KEY (namespace, window_start_ms)
);
CREATE TABLE IF NOT EXISTS sekai_ontology_health_events (
    namespace TEXT NOT NULL,
    window_start_ms INTEGER NOT NULL,
    body_json TEXT NOT NULL,
    PRIMARY KEY (namespace, window_start_ms)
);
";

fn decode<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt health record: {error}"))
}

fn encode<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

impl SekaiDb {
    pub fn migrate_ontology_health_trends(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    /// Records `snapshot` in one immediate transaction, which serializes
    /// records of every namespace.
    pub fn record_ontology_health_snapshot(
        &self,
        snapshot: &HealthSnapshot,
        prune_before_ms: i64,
    ) -> Result<Recorded, String> {
        use rusqlite::{OptionalExtension, params};
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT body_json FROM sekai_ontology_health_snapshots
                 WHERE namespace = ?1 AND window_start_ms = ?2",
                params![snapshot.namespace, snapshot.window_start_ms],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(body) = stored {
            return Ok(Recorded::Replay(decode(&body)?));
        }
        let latest: Option<(i64, String)> = tx
            .query_row(
                "SELECT window_start_ms, body_json FROM sekai_ontology_health_snapshots
                 WHERE namespace = ?1 ORDER BY window_start_ms DESC LIMIT 1",
                params![snapshot.namespace],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let previous = match latest {
            Some((window, _)) if window > snapshot.window_start_ms => {
                return Ok(Recorded::Stale);
            }
            Some((_, body)) => Some(decode::<HealthSnapshot>(&body)?),
            None => None,
        };
        let event = drop_event(snapshot, previous.as_ref());
        tx.execute(
            "INSERT INTO sekai_ontology_health_snapshots (namespace, window_start_ms, body_json)
             VALUES (?1, ?2, ?3)",
            params![
                snapshot.namespace,
                snapshot.window_start_ms,
                encode(snapshot)?
            ],
        )
        .map_err(|error| error.to_string())?;
        if let Some(event) = &event {
            tx.execute(
                "INSERT INTO sekai_ontology_health_events (namespace, window_start_ms, body_json)
                 VALUES (?1, ?2, ?3)",
                params![event.namespace, event.window_start_ms, encode(event)?],
            )
            .map_err(|error| error.to_string())?;
        }
        for table in [
            "sekai_ontology_health_snapshots",
            "sekai_ontology_health_events",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE namespace = ?1 AND window_start_ms < ?2"),
                params![snapshot.namespace, prune_before_ms],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(Recorded::Fresh {
            snapshot: snapshot.clone(),
            event,
        })
    }

    pub fn list_ontology_health_trend(
        &self,
        namespace: &str,
    ) -> Result<(Vec<HealthSnapshot>, Vec<HealthEvent>), String> {
        let conn = self.conn();
        let read = |table: &str| -> Result<Vec<String>, String> {
            let mut statement = conn
                .prepare(&format!(
                    "SELECT body_json FROM {table} WHERE namespace = ?1 ORDER BY window_start_ms"
                ))
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map(rusqlite::params![namespace], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<_, _>>()
                .map_err(|error| error.to_string())
        };
        let snapshots = read("sekai_ontology_health_snapshots")?;
        let events = read("sekai_ontology_health_events")?;
        Ok((
            snapshots
                .iter()
                .map(|body| decode(body))
                .collect::<Result<_, _>>()?,
            events
                .iter()
                .map(|body| decode(body))
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl PostgresDb {
    /// As on SQLite; a transaction-scoped advisory lock on the namespace
    /// serializes its records, so the latest snapshot read is the one the
    /// insert follows.
    pub fn record_ontology_health_snapshot(
        &self,
        snapshot: &HealthSnapshot,
        prune_before_ms: i64,
    ) -> Result<Recorded, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 1694))",
            &[&snapshot.namespace],
        )
        .map_err(|error| error.to_string())?;
        let stored = tx
            .query_opt(
                "SELECT body_json FROM sekai_ontology_health_snapshots
                 WHERE namespace = $1 AND window_start_ms = $2",
                &[&snapshot.namespace, &snapshot.window_start_ms],
            )
            .map_err(|error| error.to_string())?;
        if let Some(row) = stored {
            return Ok(Recorded::Replay(decode(&row.get::<_, String>(0))?));
        }
        let latest = tx
            .query_opt(
                "SELECT window_start_ms, body_json FROM sekai_ontology_health_snapshots
                 WHERE namespace = $1 ORDER BY window_start_ms DESC LIMIT 1",
                &[&snapshot.namespace],
            )
            .map_err(|error| error.to_string())?
            .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)));
        let previous = match latest {
            Some((window, _)) if window > snapshot.window_start_ms => {
                return Ok(Recorded::Stale);
            }
            Some((_, body)) => Some(decode::<HealthSnapshot>(&body)?),
            None => None,
        };
        let event = drop_event(snapshot, previous.as_ref());
        tx.execute(
            "INSERT INTO sekai_ontology_health_snapshots (namespace, window_start_ms, body_json)
             VALUES ($1, $2, $3)",
            &[
                &snapshot.namespace,
                &snapshot.window_start_ms,
                &encode(snapshot)?,
            ],
        )
        .map_err(|error| error.to_string())?;
        if let Some(event) = &event {
            tx.execute(
                "INSERT INTO sekai_ontology_health_events (namespace, window_start_ms, body_json)
                 VALUES ($1, $2, $3)",
                &[&event.namespace, &event.window_start_ms, &encode(event)?],
            )
            .map_err(|error| error.to_string())?;
        }
        for table in [
            "sekai_ontology_health_snapshots",
            "sekai_ontology_health_events",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE namespace = $1 AND window_start_ms < $2"),
                &[&snapshot.namespace, &prune_before_ms],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(Recorded::Fresh {
            snapshot: snapshot.clone(),
            event,
        })
    }

    pub fn list_ontology_health_trend(
        &self,
        namespace: &str,
    ) -> Result<(Vec<HealthSnapshot>, Vec<HealthEvent>), String> {
        let mut connection = self.connection()?;
        let mut read = |table: &str| -> Result<Vec<String>, String> {
            Ok(connection
                .query(
                    &format!(
                        "SELECT body_json FROM {table} WHERE namespace = $1 ORDER BY window_start_ms"
                    ),
                    &[&namespace],
                )
                .map_err(|error| error.to_string())?
                .iter()
                .map(|row| row.get(0))
                .collect())
        };
        let snapshots = read("sekai_ontology_health_snapshots")?;
        let events = read("sekai_ontology_health_events")?;
        Ok((
            snapshots
                .iter()
                .map(|body| decode(body))
                .collect::<Result<_, _>>()?,
            events
                .iter()
                .map(|body| decode(body))
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl crate::db::runtime_db::RuntimeDb {
    pub fn record_ontology_health_snapshot(
        &self,
        snapshot: &HealthSnapshot,
        prune_before_ms: i64,
    ) -> Result<Recorded, String> {
        match self {
            Self::Sqlite(db) => db.record_ontology_health_snapshot(snapshot, prune_before_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.record_ontology_health_snapshot(snapshot, prune_before_ms)
            }),
        }
    }

    pub fn list_ontology_health_trend(
        &self,
        namespace: &str,
    ) -> Result<(Vec<HealthSnapshot>, Vec<HealthEvent>), String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_health_trend(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_ontology_health_trend(namespace))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::ontology_health::PART_LINT;

    const HOUR: i64 = 3_600_000;

    fn part(name: &'static str, score: u8) -> Part {
        Part {
            score: Some(score),
            ..Part::unavailable(name, "")
        }
    }

    fn at(db: &RuntimeDb, ns: &str, now_ms: i64, lint: u8) -> Recorded {
        record(
            db,
            &RecordRequest {
                namespace: ns,
                window_ms: HOUR,
                retention_ms: 3 * HOUR,
                threshold: 50,
                recorded_by: "ops",
                now_ms,
            },
            &[part(PART_FRESHNESS, 90), part(PART_LINT, lint)],
            &ScoreInputs {
                datasets: vec!["orders".to_owned()],
                sources: Vec::new(),
                definition_revision: "sha256:revision".into(),
            },
        )
        .unwrap()
    }

    fn event_windows(db: &RuntimeDb, ns: &str) -> Vec<i64> {
        let (_, events) = db.list_ontology_health_trend(ns).unwrap();
        events.iter().map(|event| event.window_start_ms).collect()
    }

    /// The trend contract on either backend.
    fn contract(db: &RuntimeDb, ns: &str) {
        let base = 100 * HOUR;
        // Healthy, then a drop: one event, on the drop.
        assert!(matches!(
            at(db, ns, base + 5, 80),
            Recorded::Fresh { event: None, .. }
        ));
        let Recorded::Fresh {
            event: Some(event), ..
        } = at(db, ns, base + HOUR + 5, 30)
        else {
            panic!("the drop writes an event");
        };
        assert_eq!((event.score, event.threshold), (30, 50));
        // The same window again, as a retry after a crash past commit would
        // be: the stored snapshot, no second event.
        let Recorded::Replay(replayed) = at(db, ns, base + HOUR + 900, 10) else {
            panic!("the window replays");
        };
        assert_eq!(replayed.total(), Some(30));
        // Staying below writes nothing; recovering and dropping again does.
        assert!(matches!(
            at(db, ns, base + 2 * HOUR, 20),
            Recorded::Fresh { event: None, .. }
        ));
        assert!(matches!(
            at(db, ns, base + 3 * HOUR, 70),
            Recorded::Fresh { event: None, .. }
        ));
        assert!(matches!(
            at(db, ns, base + 4 * HOUR, 40),
            Recorded::Fresh { event: Some(_), .. }
        ));
        // An older window after a newer one is refused, unless it is stored.
        assert!(matches!(
            at(db, ns, base + 2 * HOUR, 90),
            Recorded::Replay(_)
        ));
        assert_eq!(at(db, ns, base - HOUR, 90), Recorded::Stale);
        // Pruned past three hours of retention: the first drop is gone.
        let (snapshots, _) = db.list_ontology_health_trend(ns).unwrap();
        let windows: Vec<i64> = snapshots.iter().map(|s| s.window_start_ms).collect();
        assert_eq!(
            windows,
            [
                base + HOUR,
                base + 2 * HOUR,
                base + 3 * HOUR,
                base + 4 * HOUR
            ]
        );
        assert_eq!(event_windows(db, ns), [base + HOUR, base + 4 * HOUR]);
        let pruned = at(db, ns, base + 5 * HOUR, 40);
        assert!(matches!(pruned, Recorded::Fresh { event: None, .. }));
        assert_eq!(event_windows(db, ns), [base + 4 * HOUR]);
        // Another namespace is its own trend.
        assert!(matches!(
            at(db, &format!("{ns}-other"), base + 5, 10),
            Recorded::Fresh { event: Some(_), .. }
        ));
    }

    #[test]
    fn sqlite_records_one_snapshot_per_window_and_one_event_per_drop() {
        contract(&RuntimeDb::memory(), "acme");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_records_one_snapshot_per_window_and_one_event_per_drop() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => {
                PostgresDb::connect_with_ca_certificate(&url, 4, &std::fs::read(path).unwrap())
            }
            Err(_) => PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        let ns = format!("health-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        contract(&db, &ns);
        concurrent(std::sync::Arc::new(db), &format!("{ns}-concurrent"));
    }

    /// Eight concurrent records of one window: one writes, the rest replay.
    fn concurrent(db: std::sync::Arc<RuntimeDb>, ns: &str) {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (db, ns) = (db.clone(), ns.to_owned());
                std::thread::spawn(move || at(&db, &ns, 7 * HOUR + 1, 10))
            })
            .collect();
        let fresh = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|recorded| matches!(recorded, Recorded::Fresh { .. }))
            .count();
        assert_eq!(fresh, 1);
        assert_eq!(event_windows(&db, ns), [7 * HOUR]);
    }

    #[test]
    fn a_concurrent_record_of_one_window_stores_it_once() {
        concurrent(std::sync::Arc::new(RuntimeDb::memory()), "acme");
    }

    #[test]
    fn a_record_refuses_a_short_window_or_an_out_of_range_threshold() {
        let db = RuntimeDb::memory();
        let request = |window_ms, retention_ms, threshold| RecordRequest {
            namespace: "acme",
            window_ms,
            retention_ms,
            threshold,
            recorded_by: "ops",
            now_ms: HOUR,
        };
        for bad in [
            request(1_000, HOUR, 50),
            request(HOUR, 1_000, 50),
            request(HOUR, HOUR, 101),
        ] {
            assert!(matches!(
                record(&db, &bad, &[], &ScoreInputs::default()),
                Err(TrendError::Invalid(_))
            ));
        }
    }

    /// The source contract leads a source part's inputs even when it scored
    /// no source, so a binary that reads every input as a dataset always
    /// hides it.
    #[test]
    fn a_source_part_stores_the_source_contract_before_its_sources() {
        let db = RuntimeDb::memory();
        let stored = |ns: &str, sources: &[&str]| {
            let recorded = record(
                &db,
                &RecordRequest {
                    namespace: ns,
                    window_ms: HOUR,
                    retention_ms: HOUR,
                    threshold: 0,
                    recorded_by: "ops",
                    now_ms: HOUR,
                },
                &[part(PART_SOURCE, 50)],
                &ScoreInputs {
                    sources: sources.iter().map(|source| (*source).to_owned()).collect(),
                    ..Default::default()
                },
            );
            let Ok(Recorded::Fresh { snapshot, .. }) = recorded else {
                panic!("{recorded:?}");
            };
            snapshot.parts[0].clone()
        };
        let part = stored("acme", &["web@sha256:t", "ops@sha256:t"]);
        assert_eq!(part.inputs[0], HEALTH_CONTRACT);
        assert_eq!(
            part.source_inputs(),
            Some(&["ops@sha256:t".to_owned(), "web@sha256:t".to_owned()][..])
        );
        assert_eq!(stored("empty", &[]).inputs, [HEALTH_CONTRACT]);
        let unknown = PartScore {
            inputs: vec!["sekai.source-health/v2".into()],
            ..part
        };
        assert_eq!(unknown.source_inputs(), None);
    }
}
