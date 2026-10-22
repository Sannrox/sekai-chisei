//! Policy shadow state (#1630) on both community backends.
//!
//! One row per namespace holds the shadowed candidate and atomic counters, so
//! every instance resolving policy for the namespace adds to the same report.
//! Observations and samples are keyed by `shadow_id`, so a restarted or
//! stopped run never receives counts meant for an earlier one. Samples of
//! differing decisions are capped per delta class.

use crate::chisei::policy::Policy;
use crate::chisei::policy_shadow::{
    ACTIVATION_CLAIM_MS, ACTIVATION_IN_PROGRESS, MAX_SHADOW_SAMPLES, PolicyShadow,
    PolicyShadowReport, ShadowCounts, ShadowDelta, ShadowSample,
};
use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS chisei_policy_shadow (
    namespace TEXT PRIMARY KEY,
    shadow_id TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    candidate_version TEXT NOT NULL,
    active_version TEXT NOT NULL,
    min_evaluations INTEGER NOT NULL,
    min_match_rate_bps INTEGER NOT NULL,
    started_by TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    evaluated INTEGER NOT NULL DEFAULT 0,
    unchanged INTEGER NOT NULL DEFAULT 0,
    re_routed INTEGER NOT NULL DEFAULT 0,
    would_deny INTEGER NOT NULL DEFAULT 0,
    would_allow INTEGER NOT NULL DEFAULT 0,
    activation_claimed_at_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chisei_policy_shadow_sample (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shadow_id TEXT NOT NULL,
    delta TEXT NOT NULL,
    preferred_runtime TEXT NOT NULL,
    preferred_model TEXT NOT NULL,
    active TEXT NOT NULL,
    candidate TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS chisei_policy_shadow_by_run
    ON chisei_policy_shadow (shadow_id);
CREATE INDEX IF NOT EXISTS chisei_policy_shadow_sample_by_class
    ON chisei_policy_shadow_sample (shadow_id, delta);
";

const SHADOW_COLUMNS: &str = "shadow_id, namespace, candidate_json, candidate_version, \
     active_version, min_evaluations, min_match_rate_bps, started_by, started_at_ms, \
     evaluated, unchanged, re_routed, would_deny, would_allow";

/// The report verdict as a row predicate, so a claim is taken only while the
/// stored counters pass (`PolicyShadowReport::verdict`; 10,000 bps is 100%).
const PASSING: &str = "evaluated >= min_evaluations \
     AND unchanged * 10000 >= min_match_rate_bps * evaluated";

/// True unless an activation claim is live at the time bound to `now`.
/// Counting pauses during a claim, so the admitted report is the one checked.
fn unclaimed_at(now: &str) -> String {
    format!(
        "(activation_claimed_at_ms = 0 OR {now} >= activation_claimed_at_ms + {ACTIVATION_CLAIM_MS})"
    )
}

const SAMPLE_COLUMNS: &str =
    "delta, preferred_runtime, preferred_model, active, candidate, observed_at_ms";

/// Columns of one `chisei_policy_shadow` row, in `SHADOW_COLUMNS` order.
struct ShadowRow {
    shadow_id: String,
    namespace: String,
    candidate_json: String,
    candidate_version: String,
    active_version: String,
    min_evaluations: i64,
    min_match_rate_bps: i64,
    started_by: String,
    started_at_ms: i64,
    counts: [i64; 5],
}

impl ShadowRow {
    fn into_parts(self) -> Result<(PolicyShadow, ShadowCounts), String> {
        let candidate: Policy = serde_json::from_str(&self.candidate_json)
            .map_err(|error| format!("stored policy shadow candidate is invalid: {error}"))?;
        let shadow = PolicyShadow {
            shadow_id: self.shadow_id,
            namespace: self.namespace,
            candidate,
            candidate_version: self.candidate_version,
            active_version: self.active_version,
            min_evaluations: u32::try_from(self.min_evaluations)
                .map_err(|error| error.to_string())?,
            min_match_rate_bps: u32::try_from(self.min_match_rate_bps)
                .map_err(|error| error.to_string())?,
            started_by: self.started_by,
            started_at_ms: self.started_at_ms,
        };
        shadow.validate()?;
        let [evaluated, unchanged, re_routed, would_deny, would_allow] = self.counts;
        Ok((
            shadow,
            ShadowCounts {
                evaluated,
                unchanged,
                re_routed,
                would_deny,
                would_allow,
            },
        ))
    }
}

fn sample_from_columns(
    delta: String,
    preferred_runtime: String,
    preferred_model: String,
    active: String,
    candidate: String,
    observed_at_ms: i64,
) -> Result<ShadowSample, String> {
    Ok(ShadowSample {
        delta: ShadowDelta::parse(&delta)?,
        preferred_runtime,
        preferred_model,
        active,
        candidate,
        observed_at_ms,
    })
}

/// Counter column a delta increments. Fixed strings, never caller input.
fn delta_column(delta: ShadowDelta) -> &'static str {
    match delta {
        ShadowDelta::Unchanged => "unchanged",
        ShadowDelta::ReRouted => "re_routed",
        ShadowDelta::WouldDeny => "would_deny",
        ShadowDelta::WouldAllow => "would_allow",
    }
}

fn candidate_json(shadow: &PolicyShadow) -> Result<String, String> {
    shadow.validate()?;
    serde_json::to_string(&shadow.candidate).map_err(|error| error.to_string())
}

/// Refuses to replace a run whose activation was admitted within the claim.
fn refuse_claimed(claimed_at_ms: Option<i64>, now_ms: i64) -> Result<(), String> {
    match claimed_at_ms {
        Some(at) if at > 0 && now_ms < at.saturating_add(ACTIVATION_CLAIM_MS) => {
            Err(ACTIVATION_IN_PROGRESS.into())
        }
        _ => Ok(()),
    }
}

/// The shadow of the first scope in `scopes` that has one.
fn first_in_scope_order(scopes: &[String], shadows: Vec<PolicyShadow>) -> Option<PolicyShadow> {
    scopes.iter().find_map(|scope| {
        shadows
            .iter()
            .find(|shadow| &shadow.namespace == scope)
            .cloned()
    })
}

fn sqlite_shadow_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShadowRow> {
    Ok(ShadowRow {
        shadow_id: row.get(0)?,
        namespace: row.get(1)?,
        candidate_json: row.get(2)?,
        candidate_version: row.get(3)?,
        active_version: row.get(4)?,
        min_evaluations: row.get(5)?,
        min_match_rate_bps: row.get(6)?,
        started_by: row.get(7)?,
        started_at_ms: row.get(8)?,
        counts: [
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
            row.get(12)?,
            row.get(13)?,
        ],
    })
}

fn postgres_shadow_row(row: &postgres::Row) -> ShadowRow {
    ShadowRow {
        shadow_id: row.get(0),
        namespace: row.get(1),
        candidate_json: row.get(2),
        candidate_version: row.get(3),
        active_version: row.get(4),
        min_evaluations: row.get(5),
        min_match_rate_bps: row.get(6),
        started_by: row.get(7),
        started_at_ms: row.get(8),
        counts: [
            row.get(9),
            row.get(10),
            row.get(11),
            row.get(12),
            row.get(13),
        ],
    }
}

impl SekaiDb {
    pub(crate) fn migrate_policy_shadow(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    /// Replaces any shadow for the namespace and resets its report.
    pub fn start_policy_shadow(&self, shadow: &PolicyShadow) -> Result<(), String> {
        use rusqlite::OptionalExtension;
        let candidate_json = candidate_json(shadow)?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let claimed_at: Option<i64> = tx
            .query_row(
                "SELECT activation_claimed_at_ms FROM chisei_policy_shadow WHERE namespace = ?1",
                [&shadow.namespace],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        refuse_claimed(claimed_at, shadow.started_at_ms)?;
        tx.execute(
            "DELETE FROM chisei_policy_shadow_sample WHERE shadow_id IN
                (SELECT shadow_id FROM chisei_policy_shadow WHERE namespace = ?1)",
            [&shadow.namespace],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO chisei_policy_shadow (
                namespace, shadow_id, candidate_json, candidate_version, active_version,
                min_evaluations, min_match_rate_bps, started_by, started_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                shadow.namespace,
                shadow.shadow_id,
                candidate_json,
                shadow.candidate_version,
                shadow.active_version,
                i64::from(shadow.min_evaluations),
                i64::from(shadow.min_match_rate_bps),
                shadow.started_by,
                shadow.started_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    /// Marks run `shadow_id` as admitted for activation. Returns false when the
    /// namespace no longer holds that run.
    pub fn claim_policy_shadow_activation(
        &self,
        namespace: &str,
        shadow_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.conn()
            .execute(
                &format!(
                    "UPDATE chisei_policy_shadow SET activation_claimed_at_ms = ?3
                     WHERE namespace = ?1 AND shadow_id = ?2 AND {PASSING}"
                ),
                rusqlite::params![namespace, shadow_id, now_ms],
            )
            .map(|updated| updated > 0)
            .map_err(|error| error.to_string())
    }

    /// Whether run `shadow_id` still holds the unexpired claim made at
    /// `claimed_at_ms`.
    pub fn confirm_policy_shadow_activation(
        &self,
        namespace: &str,
        shadow_id: &str,
        claimed_at_ms: i64,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM chisei_policy_shadow
                 WHERE namespace = ?1 AND shadow_id = ?2 AND activation_claimed_at_ms = ?3
                   AND ?4 < activation_claimed_at_ms + ?5",
                rusqlite::params![
                    namespace,
                    shadow_id,
                    claimed_at_ms,
                    now_ms,
                    ACTIVATION_CLAIM_MS
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count > 0)
            .map_err(|error| error.to_string())
    }

    /// Removes the namespace's shadow, or only run `shadow_id` when given.
    /// With `unclaimed_at_ms`, a run whose activation claim is still live at
    /// that time is refused instead. Returns whether a shadow was removed.
    pub fn stop_policy_shadow(
        &self,
        namespace: &str,
        shadow_id: Option<&str>,
        unclaimed_at_ms: Option<i64>,
    ) -> Result<bool, String> {
        use rusqlite::OptionalExtension;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let current: Option<i64> = tx
            .query_row(
                "SELECT activation_claimed_at_ms FROM chisei_policy_shadow
                 WHERE namespace = ?1 AND (?2 IS NULL OR shadow_id = ?2)",
                rusqlite::params![namespace, shadow_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(now_ms) = unclaimed_at_ms {
            refuse_claimed(current, now_ms)?;
        }
        let removed: Option<String> = tx
            .query_row(
                "DELETE FROM chisei_policy_shadow
                 WHERE namespace = ?1 AND (?2 IS NULL OR shadow_id = ?2)
                 RETURNING shadow_id",
                rusqlite::params![namespace, shadow_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(removed) = removed.as_deref() {
            tx.execute(
                "DELETE FROM chisei_policy_shadow_sample WHERE shadow_id = ?1",
                [removed],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(removed.is_some())
    }

    pub fn find_policy_shadow(&self, scopes: &[String]) -> Result<Option<PolicyShadow>, String> {
        if scopes.is_empty() {
            return Ok(None);
        }
        let placeholders = (1..=scopes.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let conn = self.conn();
        let mut statement = conn
            .prepare(&format!(
                "SELECT {SHADOW_COLUMNS} FROM chisei_policy_shadow WHERE namespace IN ({placeholders})"
            ))
            .map_err(|error| error.to_string())?;
        let shadows = statement
            .query_map(rusqlite::params_from_iter(scopes.iter()), sqlite_shadow_row)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.into_parts().map(|(shadow, _)| shadow))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(first_in_scope_order(scopes, shadows))
    }

    /// Counts one live decision against run `shadow_id`, and keeps the sample
    /// while its class is under the cap. A run restarted or stopped since is
    /// left untouched.
    pub fn record_policy_shadow_observation(
        &self,
        shadow_id: &str,
        sample: &ShadowSample,
    ) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let column = delta_column(sample.delta);
        let counted = tx
            .execute(
                &format!(
                    "UPDATE chisei_policy_shadow
                     SET evaluated = evaluated + 1, {column} = {column} + 1
                     WHERE shadow_id = ?1 AND {}",
                    unclaimed_at("?2")
                ),
                rusqlite::params![shadow_id, sample.observed_at_ms],
            )
            .map_err(|error| error.to_string())?;
        if counted > 0 && sample.delta != ShadowDelta::Unchanged {
            tx.execute(
                &format!(
                    "INSERT INTO chisei_policy_shadow_sample (shadow_id, {SAMPLE_COLUMNS})
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
                     WHERE (SELECT COUNT(*) FROM chisei_policy_shadow_sample
                            WHERE shadow_id = ?1 AND delta = ?2) < ?8"
                ),
                rusqlite::params![
                    shadow_id,
                    sample.delta.as_str(),
                    sample.preferred_runtime,
                    sample.preferred_model,
                    sample.active,
                    sample.candidate,
                    sample.observed_at_ms,
                    MAX_SHADOW_SAMPLES,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn policy_shadow_report(
        &self,
        namespace: &str,
    ) -> Result<Option<PolicyShadowReport>, String> {
        use rusqlite::OptionalExtension;
        let conn = self.conn();
        let Some(row) = conn
            .query_row(
                &format!("SELECT {SHADOW_COLUMNS} FROM chisei_policy_shadow WHERE namespace = ?1"),
                [namespace],
                sqlite_shadow_row,
            )
            .optional()
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let (shadow, counts) = row.into_parts()?;
        let mut statement = conn
            .prepare(&format!(
                "SELECT {SAMPLE_COLUMNS} FROM chisei_policy_shadow_sample
                 WHERE shadow_id = ?1 ORDER BY delta, id"
            ))
            .map_err(|error| error.to_string())?;
        let samples = statement
            .query_map([&shadow.shadow_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|(delta, runtime, model, active, candidate, at)| {
                sample_from_columns(delta, runtime, model, active, candidate, at)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(PolicyShadowReport {
            shadow,
            counts,
            samples,
        }))
    }
}

impl PostgresDb {
    pub fn start_policy_shadow(&self, shadow: &PolicyShadow) -> Result<(), String> {
        let candidate_json = candidate_json(shadow)?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // Starts for one namespace run one at a time, so the claim check below
        // sees the run this upsert replaces even when no row exists yet.
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 1630))",
            &[&shadow.namespace],
        )
        .map_err(|error| error.to_string())?;
        // Lock the current run first: an observation of it either committed
        // before this point, so its sample is deleted below, or it waits and
        // then finds the run replaced.
        let previous: Option<(String, i64)> = tx
            .query_opt(
                "SELECT shadow_id, activation_claimed_at_ms FROM chisei_policy_shadow
                 WHERE namespace = $1 FOR UPDATE",
                &[&shadow.namespace],
            )
            .map_err(|error| error.to_string())?
            .map(|row| (row.get(0), row.get(1)));
        refuse_claimed(previous.as_ref().map(|(_, at)| *at), shadow.started_at_ms)?;
        if let Some((previous, _)) = previous.as_ref() {
            tx.execute(
                "DELETE FROM chisei_policy_shadow_sample WHERE shadow_id = $1",
                &[&previous],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute(
            "INSERT INTO chisei_policy_shadow (
                namespace, shadow_id, candidate_json, candidate_version, active_version,
                min_evaluations, min_match_rate_bps, started_by, started_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (namespace) DO UPDATE SET
                shadow_id = EXCLUDED.shadow_id,
                candidate_json = EXCLUDED.candidate_json,
                candidate_version = EXCLUDED.candidate_version,
                active_version = EXCLUDED.active_version,
                min_evaluations = EXCLUDED.min_evaluations,
                min_match_rate_bps = EXCLUDED.min_match_rate_bps,
                started_by = EXCLUDED.started_by,
                started_at_ms = EXCLUDED.started_at_ms,
                evaluated = 0, unchanged = 0, re_routed = 0, would_deny = 0, would_allow = 0,
                activation_claimed_at_ms = 0",
            &[
                &shadow.namespace,
                &shadow.shadow_id,
                &candidate_json,
                &shadow.candidate_version,
                &shadow.active_version,
                &i64::from(shadow.min_evaluations),
                &i64::from(shadow.min_match_rate_bps),
                &shadow.started_by,
                &shadow.started_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn claim_policy_shadow_activation(
        &self,
        namespace: &str,
        shadow_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.connection()?
            .execute(
                &format!(
                    "UPDATE chisei_policy_shadow SET activation_claimed_at_ms = $3
                     WHERE namespace = $1 AND shadow_id = $2 AND {PASSING}"
                ),
                &[&namespace, &shadow_id, &now_ms],
            )
            .map(|updated| updated > 0)
            .map_err(|error| error.to_string())
    }

    pub fn confirm_policy_shadow_activation(
        &self,
        namespace: &str,
        shadow_id: &str,
        claimed_at_ms: i64,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.connection()?
            .query_one(
                "SELECT COUNT(*) FROM chisei_policy_shadow
                 WHERE namespace = $1 AND shadow_id = $2 AND activation_claimed_at_ms = $3
                   AND $4 < activation_claimed_at_ms + $5",
                &[
                    &namespace,
                    &shadow_id,
                    &claimed_at_ms,
                    &now_ms,
                    &ACTIVATION_CLAIM_MS,
                ],
            )
            .map(|row| row.get::<_, i64>(0) > 0)
            .map_err(|error| error.to_string())
    }

    pub fn stop_policy_shadow(
        &self,
        namespace: &str,
        shadow_id: Option<&str>,
        unclaimed_at_ms: Option<i64>,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let current: Option<i64> = tx
            .query_opt(
                "SELECT activation_claimed_at_ms FROM chisei_policy_shadow
                 WHERE namespace = $1 AND ($2::TEXT IS NULL OR shadow_id = $2)
                 FOR UPDATE",
                &[&namespace, &shadow_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if let Some(now_ms) = unclaimed_at_ms {
            refuse_claimed(current, now_ms)?;
        }
        let removed: Option<String> = tx
            .query_opt(
                "DELETE FROM chisei_policy_shadow
                 WHERE namespace = $1 AND ($2::TEXT IS NULL OR shadow_id = $2)
                 RETURNING shadow_id",
                &[&namespace, &shadow_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if let Some(removed) = removed.as_deref() {
            tx.execute(
                "DELETE FROM chisei_policy_shadow_sample WHERE shadow_id = $1",
                &[&removed],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(removed.is_some())
    }

    pub fn find_policy_shadow(&self, scopes: &[String]) -> Result<Option<PolicyShadow>, String> {
        if scopes.is_empty() {
            return Ok(None);
        }
        let shadows = self
            .connection()?
            .query(
                &format!(
                    "SELECT {SHADOW_COLUMNS} FROM chisei_policy_shadow WHERE namespace = ANY($1)"
                ),
                &[&scopes],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| {
                postgres_shadow_row(row)
                    .into_parts()
                    .map(|(shadow, _)| shadow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(first_in_scope_order(scopes, shadows))
    }

    /// The counter `UPDATE` holds the shadow row lock until commit, so the
    /// sample cap check below is serialized per run.
    pub fn record_policy_shadow_observation(
        &self,
        shadow_id: &str,
        sample: &ShadowSample,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let column = delta_column(sample.delta);
        let counted = tx
            .execute(
                &format!(
                    "UPDATE chisei_policy_shadow
                     SET evaluated = evaluated + 1, {column} = {column} + 1
                     WHERE shadow_id = $1 AND {}",
                    unclaimed_at("$2")
                ),
                &[&shadow_id, &sample.observed_at_ms],
            )
            .map_err(|error| error.to_string())?;
        if counted > 0 && sample.delta != ShadowDelta::Unchanged {
            tx.execute(
                &format!(
                    "INSERT INTO chisei_policy_shadow_sample (shadow_id, {SAMPLE_COLUMNS})
                     SELECT $1, $2, $3, $4, $5, $6, $7
                     WHERE (SELECT COUNT(*) FROM chisei_policy_shadow_sample
                            WHERE shadow_id = $1 AND delta = $2) < $8"
                ),
                &[
                    &shadow_id,
                    &sample.delta.as_str(),
                    &sample.preferred_runtime,
                    &sample.preferred_model,
                    &sample.active,
                    &sample.candidate,
                    &sample.observed_at_ms,
                    &MAX_SHADOW_SAMPLES,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn policy_shadow_report(
        &self,
        namespace: &str,
    ) -> Result<Option<PolicyShadowReport>, String> {
        let mut connection = self.connection()?;
        let Some(row) = connection
            .query_opt(
                &format!("SELECT {SHADOW_COLUMNS} FROM chisei_policy_shadow WHERE namespace = $1"),
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let (shadow, counts) = postgres_shadow_row(&row).into_parts()?;
        let samples = connection
            .query(
                &format!(
                    "SELECT {SAMPLE_COLUMNS} FROM chisei_policy_shadow_sample
                     WHERE shadow_id = $1 ORDER BY delta, id"
                ),
                &[&shadow.shadow_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                sample_from_columns(
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    row.get(3),
                    row.get(4),
                    row.get(5),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(PolicyShadowReport {
            shadow,
            counts,
            samples,
        }))
    }
}
