use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, params};

pub const AUDIT_DATASET: &str = "audit";
pub const LLM_CALLS_DATASET: &str = "llm_calls";
pub const TASK_OBSERVATIONS_DATASET: &str = "task_observations";

const DAY_MS: i64 = 86_400_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub dataset: String,
    pub namespace: String,
    pub data_class: String,
    pub retention_days: i32,
    pub updated: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionRun {
    pub audit_deleted: i32,
    pub llm_calls_deleted: i32,
    pub task_observations_deleted: i32,
}

fn validate_policy(policy: &RetentionPolicy) -> Result<(), String> {
    if !matches!(
        policy.dataset.as_str(),
        AUDIT_DATASET | LLM_CALLS_DATASET | TASK_OBSERVATIONS_DATASET
    ) {
        return Err("dataset must be audit, llm_calls, or task_observations".into());
    }
    if policy.retention_days <= 0 {
        return Err("retention_days must be positive".into());
    }
    if policy.dataset == AUDIT_DATASET
        && (!policy.namespace.is_empty() || !policy.data_class.is_empty())
    {
        return Err("scoped audit retention requires classified audit records".into());
    }
    if policy.dataset == TASK_OBSERVATIONS_DATASET && !policy.data_class.is_empty() {
        return Err("data-class task retention requires classified task observations".into());
    }
    Ok(())
}

fn effective_policy<'a>(
    policies: &'a [RetentionPolicy],
    dataset: &str,
    namespace: &str,
    data_class: &str,
) -> Option<&'a RetentionPolicy> {
    policies
        .iter()
        .filter(|policy| {
            policy.dataset == dataset
                && (policy.namespace.is_empty() || policy.namespace == namespace)
                && (policy.data_class.is_empty() || policy.data_class == data_class)
        })
        .max_by_key(|policy| {
            (
                u8::from(!policy.namespace.is_empty()) + u8::from(!policy.data_class.is_empty()),
                std::cmp::Reverse(policy.retention_days),
            )
        })
}

impl SekaiDb {
    pub(crate) fn migrate_retention(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_retention_policies (
                dataset TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT '',
                data_class TEXT NOT NULL DEFAULT '',
                retention_days INTEGER NOT NULL,
                updated INTEGER NOT NULL,
                PRIMARY KEY (dataset, namespace, data_class)
            );",
        )
        .map_err(|e| e.to_string())?;
        let now = chrono::Utc::now().timestamp_millis();
        for (dataset, days) in [
            (AUDIT_DATASET, 365),
            (LLM_CALLS_DATASET, 90),
            (TASK_OBSERVATIONS_DATASET, 90),
        ] {
            conn.execute(
                "INSERT OR IGNORE INTO sekai_retention_policies
                 (dataset, namespace, data_class, retention_days, updated)
                 VALUES (?1, '', '', ?2, ?3)",
                params![dataset, days, now],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String> {
        validate_policy(policy)?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_retention_policies
             (dataset, namespace, data_class, retention_days, updated)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(dataset, namespace, data_class) DO UPDATE SET
               retention_days=excluded.retention_days, updated=excluded.updated",
            params![
                policy.dataset,
                policy.namespace,
                policy.data_class,
                policy.retention_days,
                policy.updated
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT dataset, namespace, data_class, retention_days, updated
                 FROM sekai_retention_policies
                 ORDER BY dataset, namespace, data_class",
            )
            .map_err(|e| e.to_string())?;
        stmt.query_map([], |row| {
            Ok(RetentionPolicy {
                dataset: row.get(0)?,
                namespace: row.get(1)?,
                data_class: row.get(2)?,
                retention_days: row.get(3)?,
                updated: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
    }

    pub fn run_retention(&self, now: i64) -> Result<RetentionRun, String> {
        let policies = self.list_retention_policies()?;
        let mut run = RetentionRun::default();

        // Audit entries are chained, so only a contiguous expired prefix can
        // be removed. Scoped audit classification is added to the stored
        // record before scoped policies can safely participate here.
        if let Some(policy) = policies.iter().find(|p| {
            p.dataset == AUDIT_DATASET && p.namespace.is_empty() && p.data_class.is_empty()
        }) {
            run.audit_deleted =
                self.purge_old_records(now - i64::from(policy.retention_days) * DAY_MS)?;
        }

        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let llm_rows = {
            let mut stmt = tx
                .prepare("SELECT id, data FROM sekai_dataset_rows WHERE dataset_id = 'llm_calls'")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (id, data) in llm_rows {
            let row: std::collections::HashMap<String, String> =
                serde_json::from_str(&data).unwrap_or_default();
            let namespace = row.get("project").map(String::as_str).unwrap_or_default();
            let data_class = row
                .get("data_class")
                .map(String::as_str)
                .unwrap_or_default();
            let timestamp = row
                .get("timestamp_ms")
                .and_then(|value| value.parse::<i64>().ok());
            if let (Some(timestamp), Some(policy)) = (
                timestamp,
                effective_policy(&policies, LLM_CALLS_DATASET, namespace, data_class),
            ) && timestamp < now - i64::from(policy.retention_days) * DAY_MS
            {
                run.llm_calls_deleted += tx
                    .execute("DELETE FROM sekai_dataset_rows WHERE id = ?1", params![id])
                    .map_err(|e| e.to_string())? as i32;
            }
        }

        let observation_rows = {
            let mut stmt = tx
                .prepare(
                    "SELECT rowid, namespace, component_id, status, timestamp
                     FROM sekai_task_observations
                     ORDER BY component_id, timestamp, rowid",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        let mut expired = std::collections::BTreeMap::<String, (String, Vec<(i64, String)>)>::new();
        for (rowid, namespace, component_id, status, timestamp_seconds) in observation_rows {
            if let Some(policy) =
                effective_policy(&policies, TASK_OBSERVATIONS_DATASET, &namespace, "")
                && timestamp_seconds < (now - i64::from(policy.retention_days) * DAY_MS) / 1000
            {
                let entry = expired
                    .entry(component_id)
                    .or_insert_with(|| (namespace, Vec::new()));
                entry.1.push((rowid, status));
            }
        }
        for (component_id, (namespace, rows)) in expired {
            let baseline = tx
                .query_row(
                    "SELECT task_total, task_succeeded, consecutive_failures
                     FROM sekai_task_observation_baselines WHERE component_id = ?1",
                    params![component_id],
                    |row| {
                        Ok((
                            row.get::<_, i32>(0)?,
                            row.get::<_, i32>(1)?,
                            row.get::<_, i32>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or((0, 0, 0));
            let succeeded = rows.iter().filter(|(_, status)| status == "done").count() as i32;
            let trailing_failures = rows
                .iter()
                .rev()
                .take_while(|(_, status)| status != "done")
                .count() as i32;
            let consecutive_failures = if trailing_failures == rows.len() as i32 {
                baseline.2 + trailing_failures
            } else {
                trailing_failures
            };
            tx.execute(
                "INSERT INTO sekai_task_observation_baselines
                 (component_id, namespace, task_total, task_succeeded, consecutive_failures, created)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(component_id) DO UPDATE SET
                   namespace=excluded.namespace,
                   task_total=excluded.task_total,
                   task_succeeded=excluded.task_succeeded,
                   consecutive_failures=excluded.consecutive_failures,
                   created=excluded.created",
                params![
                    component_id,
                    namespace,
                    baseline.0 + rows.len() as i32,
                    baseline.1 + succeeded,
                    consecutive_failures,
                    now / 1000
                ],
            )
            .map_err(|e| e.to_string())?;
            for (rowid, _) in rows {
                run.task_observations_deleted +=
                    tx.execute(
                        "DELETE FROM sekai_task_observations WHERE rowid = ?1",
                        params![rowid],
                    )
                    .map_err(|e| e.to_string())? as i32;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::audit::Decision;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use std::collections::HashMap;

    #[test]
    fn installs_bounded_defaults_and_validates_overrides() {
        let db = SekaiDb::new(":memory:").unwrap();
        let policies = db.list_retention_policies().unwrap();
        assert_eq!(policies.len(), 3);
        assert!(
            policies
                .iter()
                .any(|p| p.dataset == AUDIT_DATASET && p.retention_days == 365)
        );
        let mut invalid = policies[0].clone();
        invalid.retention_days = 0;
        assert!(db.set_retention_policy(&invalid).is_err());
    }

    #[test]
    fn prunes_scoped_usage_and_preserves_other_namespaces() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: vec![ColumnDef {
                name: "timestamp_ms".into(),
                col_type: "string".into(),
            }],
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        let rows = [
            HashMap::from([
                ("timestamp_ms".into(), "1".into()),
                ("project".into(), "erase".into()),
            ]),
            HashMap::from([
                ("timestamp_ms".into(), "1".into()),
                ("project".into(), "keep".into()),
            ]),
        ];
        db.append_rows(LLM_CALLS_DATASET, &rows).unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: LLM_CALLS_DATASET.into(),
            namespace: "erase".into(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        // Keep the global default from matching either row in this synthetic clock.
        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.llm_calls_deleted, 1);
        let rows = db
            .query_rows(LLM_CALLS_DATASET, &Default::default())
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["project"], "keep");
    }

    #[test]
    fn specific_policy_can_retain_rows_longer_than_default() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[HashMap::from([
                ("timestamp_ms".into(), "1".into()),
                ("project".into(), "legal".into()),
            ])],
        )
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: LLM_CALLS_DATASET.into(),
            namespace: "legal".into(),
            data_class: String::new(),
            retention_days: 365,
            updated: 1,
        })
        .unwrap();

        let run = db.run_retention(120 * DAY_MS).unwrap();
        assert_eq!(run.llm_calls_deleted, 0);
        assert_eq!(
            db.query_rows(LLM_CALLS_DATASET, &Default::default())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn class_policy_uses_shorter_window_than_equal_scope_namespace_policy() {
        let policies = vec![
            RetentionPolicy {
                dataset: LLM_CALLS_DATASET.into(),
                namespace: "legal".into(),
                data_class: String::new(),
                retention_days: 365,
                updated: 1,
            },
            RetentionPolicy {
                dataset: LLM_CALLS_DATASET.into(),
                namespace: String::new(),
                data_class: "sensitive".into(),
                retention_days: 7,
                updated: 1,
            },
        ];

        let selected =
            effective_policy(&policies, LLM_CALLS_DATASET, "legal", "sensitive").unwrap();
        assert_eq!(selected.retention_days, 7);
    }

    #[test]
    fn rejects_scoped_audit_policy_until_audit_records_are_classified() {
        let db = SekaiDb::new(":memory:").unwrap();
        let error = db
            .set_retention_policy(&RetentionPolicy {
                dataset: AUDIT_DATASET.into(),
                namespace: "legal".into(),
                data_class: String::new(),
                retention_days: 365,
                updated: 1,
            })
            .unwrap_err();
        assert!(error.contains("classified audit records"));
    }

    #[test]
    fn rejects_class_scoped_task_policy_until_observations_are_classified() {
        let db = SekaiDb::new(":memory:").unwrap();
        let error = db
            .set_retention_policy(&RetentionPolicy {
                dataset: TASK_OBSERVATIONS_DATASET.into(),
                namespace: String::new(),
                data_class: "sensitive".into(),
                retention_days: 7,
                updated: 1,
            })
            .unwrap_err();
        assert!(error.contains("classified task observations"));
    }

    #[test]
    fn audit_retention_records_a_verifiable_anchor() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.record_decision(&Decision {
            id: "old".into(),
            timestamp: 1,
            actor: "a".into(),
            action: "x".into(),
            reason: String::new(),
            evidence: HashMap::new(),
            target_id: "target".into(),
            outcome: String::new(),
        })
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: AUDIT_DATASET.into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.audit_deleted, 1);
        let verification = db.verify_ledger().unwrap();
        assert!(verification.ok);
        assert_eq!(verification.anchor_seq, 1);
    }

    #[test]
    fn task_observation_retention_converts_millisecond_clock_to_seconds() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            for (request_id, timestamp) in [("old", 1), ("fresh", 100_000)] {
                conn.execute(
                    "INSERT INTO sekai_task_observations
                     (request_id, namespace, component_id, model, status, timestamp)
                     VALUES (?1, 'ns', 'component', '', 'succeeded', ?2)",
                    params![request_id, timestamp],
                )
                .unwrap();
            }
        }
        db.set_retention_policy(&RetentionPolicy {
            dataset: TASK_OBSERVATIONS_DATASET.into(),
            namespace: "ns".into(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();

        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.task_observations_deleted, 1);
        let remaining: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_task_observations WHERE request_id = 'fresh'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn task_observation_retention_preserves_lifetime_statistics() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            for (request_id, status, timestamp) in [
                ("old-success", "done", 1),
                ("old-failure", "failed", 2),
                ("fresh-success", "done", 200_000),
            ] {
                conn.execute(
                    "INSERT INTO sekai_task_observations
                     (request_id, namespace, component_id, model, status, timestamp)
                     VALUES (?1, 'ns', 'component', '', ?2, ?3)",
                    params![request_id, status, timestamp],
                )
                .unwrap();
            }
        }
        db.set_retention_policy(&RetentionPolicy {
            dataset: TASK_OBSERVATIONS_DATASET.into(),
            namespace: "ns".into(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        let before = crate::sekai::observation::task_observation_stats(&db, "component").unwrap();

        let run = db.run_retention(3 * DAY_MS).unwrap();

        assert_eq!(run.task_observations_deleted, 2);
        let after = crate::sekai::observation::task_observation_stats(&db, "component").unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn audit_retention_removes_related_object_changes() {
        use crate::sekai::audit::ObjectChange;

        let db = SekaiDb::new(":memory:").unwrap();
        db.record_object_change(&ObjectChange {
            id: "old-change".into(),
            object_id: "target".into(),
            field: "name".into(),
            old_value: "old".into(),
            new_value: "new".into(),
            changed_by: "actor".into(),
            timestamp: 1,
        })
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: AUDIT_DATASET.into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();

        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.audit_deleted, 1);
        assert!(db.list_object_changes("target", 10, 0).unwrap().is_empty());
    }
}
