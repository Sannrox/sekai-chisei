use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, KIND_MODEL, Object, REL_CONTAINS};
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskObservation {
    pub request_id: String,
    pub namespace: String,
    pub data_class: String,
    pub component_id: String,
    pub model: String,
    pub status: String,
    pub timestamp: i64,
    pub packages: Vec<String>,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskObservationStats {
    pub task_total: i32,
    pub task_succeeded: i32,
    pub success_rate: i32,
    pub consecutive_failures: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskObservationBaseline {
    task_total: i32,
    task_succeeded: i32,
    consecutive_failures: i32,
}

pub struct TaskCompletion {
    pub request_id: String,
    pub namespace: String,
    pub model: String,
    pub status: String,
    pub packages: Vec<String>,
    pub context: HashMap<String, String>,
}

impl SekaiDb {
    pub(crate) fn migrate_task_observations(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_task_observations (
                request_id TEXT NOT NULL,
                namespace TEXT NOT NULL,
                data_class TEXT NOT NULL DEFAULT 'unclassified',
                component_id TEXT NOT NULL,
                model TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                packages_json TEXT NOT NULL DEFAULT '[]',
                context_json TEXT NOT NULL DEFAULT '{}',
                retention_tombstone INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (request_id, component_id)
            );
            CREATE INDEX IF NOT EXISTS idx_task_observations_component_time
                ON sekai_task_observations(component_id, timestamp, request_id);
            CREATE INDEX IF NOT EXISTS idx_task_observations_namespace_time
                ON sekai_task_observations(namespace, timestamp, request_id);
            CREATE TABLE IF NOT EXISTS sekai_task_observation_baselines (
                component_id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                task_total INTEGER NOT NULL,
                task_succeeded INTEGER NOT NULL,
                consecutive_failures INTEGER NOT NULL,
                created INTEGER NOT NULL
            );",
        )
        .map_err(|e| e.to_string())?;
        for column in [
            "data_class TEXT NOT NULL DEFAULT 'unclassified'",
            "retention_tombstone INTEGER NOT NULL DEFAULT 0",
        ] {
            if let Err(error) = conn.execute(
                &format!("ALTER TABLE sekai_task_observations ADD COLUMN {column}"),
                [],
            ) && !error.to_string().contains("duplicate column name")
            {
                return Err(error.to_string());
            }
        }
        let legacy = {
            let mut stmt = conn
                .prepare(
                    "SELECT rowid,context_json FROM sekai_task_observations
                     WHERE data_class='unclassified'",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (rowid, context) in legacy {
            let context: HashMap<String, String> =
                serde_json::from_str(&context).unwrap_or_default();
            if let Some(data_class) = context.get("data_class") {
                conn.execute(
                    "UPDATE sekai_task_observations SET data_class=?1 WHERE rowid=?2",
                    params![data_class, rowid],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    pub fn insert_task_observation(&self, observation: &TaskObservation) -> Result<(), String> {
        let packages_json =
            serde_json::to_string(&observation.packages).map_err(|e| e.to_string())?;
        let context_json =
            serde_json::to_string(&observation.context).map_err(|e| e.to_string())?;
        let conn = self.conn();
        conn.execute(
            "INSERT OR IGNORE INTO sekai_task_observations
             (request_id, namespace, data_class, component_id, model, status, timestamp, packages_json, context_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                observation.request_id,
                observation.namespace,
                observation.data_class,
                observation.component_id,
                observation.model,
                observation.status,
                observation.timestamp,
                packages_json,
                context_json
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_task_observations_for_component(
        &self,
        component_id: &str,
    ) -> Result<Vec<TaskObservation>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT request_id, namespace, data_class, component_id, model, status, timestamp, packages_json, context_json
                 FROM sekai_task_observations
                 WHERE component_id = ?1
                 ORDER BY timestamp, rowid",
            )
            .map_err(|e| e.to_string())?;
        stmt.query_map([component_id], row_to_task_observation)
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    fn insert_task_observation_baseline(
        &self,
        component_id: &str,
        namespace: &str,
        baseline: &TaskObservationBaseline,
        created: i64,
    ) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR IGNORE INTO sekai_task_observation_baselines
             (component_id, namespace, task_total, task_succeeded, consecutive_failures, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                component_id,
                namespace,
                baseline.task_total,
                baseline.task_succeeded,
                baseline.consecutive_failures,
                created
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn get_task_observation_baseline(
        &self,
        component_id: &str,
    ) -> Result<Option<TaskObservationBaseline>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT task_total, task_succeeded, consecutive_failures
             FROM sekai_task_observation_baselines WHERE component_id = ?1",
            [component_id],
            |row| {
                Ok(TaskObservationBaseline {
                    task_total: row.get(0)?,
                    task_succeeded: row.get(1)?,
                    consecutive_failures: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }
}

fn row_to_task_observation(row: &rusqlite::Row) -> Result<TaskObservation, rusqlite::Error> {
    let packages_json: String = row.get(7)?;
    let context_json: String = row.get(8)?;
    let packages = serde_json::from_str(&packages_json).unwrap_or_default();
    let context = serde_json::from_str(&context_json).unwrap_or_default();
    Ok(TaskObservation {
        request_id: row.get(0)?,
        namespace: row.get(1)?,
        data_class: row.get(2)?,
        component_id: row.get(3)?,
        model: row.get(4)?,
        status: row.get(5)?,
        timestamp: row.get(6)?,
        packages,
        context,
    })
}

pub fn task_observation_stats(
    db: &SekaiDb,
    component_id: &str,
) -> Result<TaskObservationStats, String> {
    let observations = db.list_task_observations_for_component(component_id)?;
    let baseline =
        db.get_task_observation_baseline(component_id)?
            .unwrap_or(TaskObservationBaseline {
                task_total: 0,
                task_succeeded: 0,
                consecutive_failures: 0,
            });
    let observation_total = observations.len() as i32;
    let observation_succeeded = observations
        .iter()
        .filter(|observation| observation.status == "done")
        .count() as i32;
    let task_total = baseline.task_total + observation_total;
    let task_succeeded = baseline.task_succeeded + observation_succeeded;
    let success_rate = if task_total > 0 {
        task_succeeded * 100 / task_total
    } else {
        0
    };
    let observation_trailing_failures = observations
        .iter()
        .rev()
        .take_while(|observation| observation.status != "done")
        .count() as i32;
    let consecutive_failures = if observation_trailing_failures == observation_total {
        baseline.consecutive_failures + observation_trailing_failures
    } else {
        observation_trailing_failures
    };
    Ok(TaskObservationStats {
        task_total,
        task_succeeded,
        success_rate,
        consecutive_failures,
    })
}

pub fn task_total(db: &SekaiDb, component_id: &str) -> Result<i32, String> {
    Ok(task_observation_stats(db, component_id)?.task_total)
}

pub fn task_succeeded(db: &SekaiDb, component_id: &str) -> Result<i32, String> {
    Ok(task_observation_stats(db, component_id)?.task_succeeded)
}

pub fn success_rate(db: &SekaiDb, component_id: &str) -> Result<i32, String> {
    Ok(task_observation_stats(db, component_id)?.success_rate)
}

pub fn consecutive_failures(db: &SekaiDb, component_id: &str) -> Result<i32, String> {
    Ok(task_observation_stats(db, component_id)?.consecutive_failures)
}

pub fn on_task_completed(db: &SekaiDb, event: &TaskCompletion) {
    let now = chrono::Utc::now().timestamp();
    let request_id = if event.request_id.trim().is_empty() {
        format!("generated:{}", uuid::Uuid::new_v4())
    } else {
        event.request_id.clone()
    };
    // Find or skip namespace
    let namespace_obj = match db
        .find_by_external_id(&format!("namespace:{}", event.namespace))
        .ok()
        .flatten()
    {
        Some(o) => o,
        None => return,
    };

    // Update component stats
    let components = db
        .get_linked_objects(&namespace_obj.id, REL_CONTAINS, &Direction::Outgoing)
        .unwrap_or_default();
    for mut comp in components {
        if comp.kind != KIND_COMPONENT {
            continue;
        }
        preserve_legacy_task_observation_baseline_if_needed(db, &comp, &event.namespace, now);
        let observation = TaskObservation {
            request_id: request_id.clone(),
            namespace: event.namespace.clone(),
            data_class: event
                .context
                .get("data_class")
                .cloned()
                .unwrap_or_else(|| "unclassified".into()),
            component_id: comp.id.clone(),
            model: event.model.clone(),
            status: event.status.clone(),
            timestamp: now,
            packages: event.packages.clone(),
            context: event.context.clone(),
        };
        if db.insert_task_observation(&observation).is_err() {
            continue;
        }
        let Ok(stats) = task_observation_stats(db, &comp.id) else {
            continue;
        };
        comp.properties
            .insert("task_total".into(), stats.task_total.to_string());
        comp.properties
            .insert("task_succeeded".into(), stats.task_succeeded.to_string());
        comp.properties
            .insert("success_rate".into(), stats.success_rate.to_string());
        comp.properties.insert(
            "consecutive_failures".into(),
            stats.consecutive_failures.to_string(),
        );
        comp.updated = now;
        db.update_object(&comp).ok();
    }

    // Ensure model object
    if !event.model.is_empty() {
        let model_ext = format!("model:{}", event.model);
        if db.find_by_external_id(&model_ext).ok().flatten().is_none() {
            let obj = Object {
                id: uuid::Uuid::new_v4().to_string(),
                kind: KIND_MODEL.into(),
                name: event.model.clone(),
                namespace: "".into(),
                external_id: model_ext,
                properties: HashMap::new(),
                created: now,
                updated: now,
            };
            db.create_object(&obj).ok();
        }
    }
}

fn preserve_legacy_task_observation_baseline_if_needed(
    db: &SekaiDb,
    comp: &Object,
    namespace: &str,
    timestamp: i64,
) {
    let Ok(existing_observations) = db.list_task_observations_for_component(&comp.id) else {
        return;
    };
    if !existing_observations.is_empty() {
        return;
    }
    if db
        .get_task_observation_baseline(&comp.id)
        .ok()
        .flatten()
        .is_some()
    {
        return;
    }
    let total = comp
        .properties
        .get("task_total")
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(0)
        .max(0);
    if total == 0 {
        return;
    }
    let succeeded = comp
        .properties
        .get("task_succeeded")
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(0)
        .clamp(0, total);
    let failed = total - succeeded;
    let trailing_failures = comp
        .properties
        .get("consecutive_failures")
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(0)
        .clamp(0, failed);
    let baseline = TaskObservationBaseline {
        task_total: total,
        task_succeeded: succeeded,
        consecutive_failures: trailing_failures,
    };
    let _ = db.insert_task_observation_baseline(&comp.id, namespace, &baseline, timestamp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Link;

    fn setup() -> SekaiDb {
        let db = SekaiDb::new(":memory:").unwrap();
        let now = 0i64;
        db.create_object(&Object {
            id: "r1".into(),
            kind: "namespace".into(),
            name: "my-namespace".into(),
            namespace: "".into(),
            external_id: "namespace:my-namespace".into(),
            properties: HashMap::new(),
            created: now,
            updated: now,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: KIND_COMPONENT.into(),
            name: "comp".into(),
            namespace: "".into(),
            external_id: "".into(),
            properties: HashMap::new(),
            created: now,
            updated: now,
        })
        .unwrap();
        db.create_link(&Link {
            id: "l1".into(),
            from_id: "r1".into(),
            to_id: "c1".into(),
            relation: REL_CONTAINS.into(),
            created: now,
        })
        .unwrap();
        db
    }

    #[test]
    fn test_observation_updates_stats() {
        let db = setup();
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t1".into(),
                namespace: "my-namespace".into(),
                model: "claude".into(),
                status: "done".into(),
                packages: vec![],
                context: HashMap::new(),
            },
        );
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t2".into(),
                namespace: "my-namespace".into(),
                model: "claude".into(),
                status: "failed".into(),
                packages: vec![],
                context: HashMap::new(),
            },
        );

        let comp = db.get_object("c1").unwrap().unwrap();
        assert_eq!(comp.properties["task_total"], "2");
        assert_eq!(comp.properties["task_succeeded"], "1");
        assert_eq!(comp.properties["success_rate"], "50");
        assert_eq!(comp.properties["consecutive_failures"], "1");

        let observations = db.list_task_observations_for_component("c1").unwrap();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].request_id, "t1");
        assert_eq!(observations[1].request_id, "t2");
        assert_eq!(task_total(&db, "c1").unwrap(), 2);
        assert_eq!(task_succeeded(&db, "c1").unwrap(), 1);
        assert_eq!(success_rate(&db, "c1").unwrap(), 50);
        assert_eq!(consecutive_failures(&db, "c1").unwrap(), 1);
    }

    #[test]
    fn persists_task_observation_data_class_from_context() {
        let db = setup();
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "classified".into(),
                namespace: "my-namespace".into(),
                model: "model".into(),
                status: "done".into(),
                packages: Vec::new(),
                context: HashMap::from([("data_class".into(), "sensitive".into())]),
            },
        );

        let observations = db.list_task_observations_for_component("c1").unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].data_class, "sensitive");
    }

    #[test]
    fn test_observation_creates_model() {
        let db = setup();
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t1".into(),
                namespace: "my-namespace".into(),
                model: "claude-sonnet".into(),
                status: "done".into(),
                packages: vec![],
                context: HashMap::new(),
            },
        );
        assert!(
            db.find_by_external_id("model:claude-sonnet")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn test_observation_rows_keep_history_and_metadata() {
        let db = setup();
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t1".into(),
                namespace: "my-namespace".into(),
                model: "claude".into(),
                status: "done".into(),
                packages: vec!["core".into(), "tools".into()],
                context: HashMap::from([("package".into(), "core".into())]),
            },
        );
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t2".into(),
                namespace: "my-namespace".into(),
                model: "gpt".into(),
                status: "failed".into(),
                packages: vec!["core".into()],
                context: HashMap::from([("attempt".into(), "2".into())]),
            },
        );
        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t3".into(),
                namespace: "my-namespace".into(),
                model: "gpt".into(),
                status: "failed".into(),
                packages: vec![],
                context: HashMap::new(),
            },
        );

        let observations = db.list_task_observations_for_component("c1").unwrap();
        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].namespace, "my-namespace");
        assert_eq!(observations[0].component_id, "c1");
        assert_eq!(observations[0].model, "claude");
        assert_eq!(observations[0].status, "done");
        assert_eq!(observations[0].packages, vec!["core", "tools"]);
        assert_eq!(observations[0].context["package"], "core");

        let stats = task_observation_stats(&db, "c1").unwrap();
        assert_eq!(
            stats,
            TaskObservationStats {
                task_total: 3,
                task_succeeded: 1,
                success_rate: 33,
                consecutive_failures: 2,
            }
        );

        let comp = db.get_object("c1").unwrap().unwrap();
        assert_eq!(comp.properties["task_total"], "3");
        assert_eq!(comp.properties["task_succeeded"], "1");
        assert_eq!(comp.properties["success_rate"], "33");
        assert_eq!(comp.properties["consecutive_failures"], "2");
    }

    #[test]
    fn test_observation_preserves_legacy_component_stats() {
        let db = setup();
        let mut comp = db.get_object("c1").unwrap().unwrap();
        comp.properties = HashMap::from([
            ("task_total".into(), "100".into()),
            ("task_succeeded".into(), "80".into()),
            ("success_rate".into(), "80".into()),
            ("consecutive_failures".into(), "2".into()),
        ]);
        comp.updated = 10;
        db.update_object(&comp).unwrap();

        on_task_completed(
            &db,
            &TaskCompletion {
                request_id: "t101".into(),
                namespace: "my-namespace".into(),
                model: "claude".into(),
                status: "failed".into(),
                packages: vec![],
                context: HashMap::new(),
            },
        );

        let observations = db.list_task_observations_for_component("c1").unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].request_id, "t101");

        let comp = db.get_object("c1").unwrap().unwrap();
        assert_eq!(comp.properties["task_total"], "101");
        assert_eq!(comp.properties["task_succeeded"], "80");
        assert_eq!(comp.properties["success_rate"], "79");
        assert_eq!(comp.properties["consecutive_failures"], "3");
    }

    #[test]
    fn test_empty_request_ids_still_record_distinct_completions() {
        let db = setup();
        for status in ["done", "failed"] {
            on_task_completed(
                &db,
                &TaskCompletion {
                    request_id: "".into(),
                    namespace: "my-namespace".into(),
                    model: "claude".into(),
                    status: status.into(),
                    packages: vec![],
                    context: HashMap::new(),
                },
            );
        }

        let observations = db.list_task_observations_for_component("c1").unwrap();
        assert_eq!(observations.len(), 2);
        assert_ne!(observations[0].request_id, observations[1].request_id);

        let comp = db.get_object("c1").unwrap().unwrap();
        assert_eq!(comp.properties["task_total"], "2");
        assert_eq!(comp.properties["task_succeeded"], "1");
        assert_eq!(comp.properties["success_rate"], "50");
        assert_eq!(comp.properties["consecutive_failures"], "1");
    }
}
