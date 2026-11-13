//! Require an object log at Combined/Sekai process start (#2287).

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

use crate::combined_stores::{data_dir, data_dir_file};
use crate::db::runtime_db::RuntimeDb;
use crate::domain::{ListFilter, Object};
use crate::plane::ProcessPlane;
use crate::sekai::action_instance::STATUS_ADMITTED;
use crate::sekai::object_log::{
    DEFAULT_LOG_FILE, LOG_PATH_ENV, backfill_already_complete, backfill_recorded_objects,
    hold_local_log, install_process_log_path,
};
use crate::sekai::object_log_host::{HOST_ENV, ObjectLogHost};

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObjectLogBinding {
    Local(PathBuf),
    Host,
}

/// Combined and Sekai processes open an object log before serving. Combined
/// defaults to `<SEKAI_DATA_DIR>/objects.mikura`. A named host is exclusive
/// with a local path. Chisei does not open the log.
pub fn require_object_log(plane: ProcessPlane, db: &RuntimeDb) -> Result<(), String> {
    if !plane.serves_sekai() {
        return Ok(());
    }
    match resolve_binding(
        plane,
        std::env::var(HOST_ENV).ok(),
        std::env::var(LOG_PATH_ENV).ok(),
        PathBuf::from(data_dir_file(&data_dir(), DEFAULT_LOG_FILE)),
    )? {
        ObjectLogBinding::Host => {
            let host = ObjectLogHost::from_env()?
                .ok_or_else(|| format!("{HOST_ENV} is required for this object-log profile"))?;
            host.load("sekai", "boot", "probe").map_err(|error| {
                format!("{HOST_ENV} is set but the object-log host is not available: {error}")
            })?;
            // A shared host has no exclusive writer. Boot must not snapshot
            // SQL and append over concurrent admits; the host already owns
            // identity. One-time recovery is the local exclusive-lock path.
        }
        ObjectLogBinding::Local(path) => {
            if std::env::var(LOG_PATH_ENV)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .is_none()
            {
                install_process_log_path(path.clone());
            }
            hold_local_log(&path).map_err(|error| {
                if error.contains(mikura::LOG_IN_USE) {
                    format!(
                        "{LOG_PATH_ENV} {}: {error}; a second process cannot share a local log. Name {HOST_ENV} for a multi-process deployment",
                        path.display()
                    )
                } else {
                    format!("{LOG_PATH_ENV} {}: {error}", path.display())
                }
            })?;
            if !backfill_already_complete(&path)? {
                let objects = backfill_sources(db)?;
                backfill_recorded_objects(&path, objects.iter())?;
            }
        }
    }
    Ok(())
}

fn resolve_binding(
    plane: ProcessPlane,
    host: Option<String>,
    path: Option<String>,
    default_path: PathBuf,
) -> Result<ObjectLogBinding, String> {
    let host = host
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let path = path
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    match (host, path, plane) {
        (Some(_), Some(_), _) => Err(format!(
            "{LOG_PATH_ENV} and {HOST_ENV} are mutually exclusive"
        )),
        (Some(_), None, _) => Ok(ObjectLogBinding::Host),
        (None, Some(path), _) => Ok(ObjectLogBinding::Local(PathBuf::from(path))),
        (None, None, ProcessPlane::Combined | ProcessPlane::Sekai) => {
            Ok(ObjectLogBinding::Local(default_path))
        }
        (None, None, ProcessPlane::Chisei) => Err(format!(
            "object log is not opened on a Chisei process; set {LOG_PATH_ENV} or {HOST_ENV} on the Sekai process"
        )),
    }
}

fn backfill_sources(db: &RuntimeDb) -> Result<Vec<Object>, String> {
    let mut objects = db.list_all_objects(&ListFilter::default())?;
    objects.retain(|object| !object.namespace.trim().is_empty());
    let mut seen: HashSet<(String, String, String)> = objects
        .iter()
        .map(|object| {
            (
                object.namespace.clone(),
                object.kind.clone(),
                object.id.clone(),
            )
        })
        .collect();
    let namespaces: BTreeSet<String> = objects
        .iter()
        .map(|object| object.namespace.clone())
        .collect();
    for namespace in namespaces {
        let mut offset = 0;
        loop {
            let page = db.list_action_instances_page(
                &namespace,
                None,
                Some(STATUS_ADMITTED),
                100,
                offset,
            )?;
            if page.is_empty() {
                break;
            }
            offset += page.len();
            for instance in page {
                let Some(object) = object_from_admitted_instance(db, &instance)? else {
                    continue;
                };
                let key = (
                    object.namespace.clone(),
                    object.kind.clone(),
                    object.id.clone(),
                );
                if seen.insert(key) {
                    objects.push(object);
                }
            }
        }
    }
    objects.sort_by(|left, right| {
        (&left.namespace, &left.kind, &left.id).cmp(&(&right.namespace, &right.kind, &right.id))
    });
    Ok(objects)
}

fn object_from_admitted_instance(
    db: &RuntimeDb,
    instance: &crate::sekai::action_instance::ActionInstance,
) -> Result<Option<Object>, String> {
    let object_id = serde_json::from_str::<serde_json::Value>(&instance.parameters_json)
        .ok()
        .and_then(|value| {
            value
                .get("object_id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .filter(|value| !value.trim().is_empty());
    let Some(object_id) = object_id else {
        return Ok(None);
    };
    db.get_object(&object_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use std::sync::Arc;

    #[test]
    fn combined_without_env_defaults_a_local_log() {
        let default = PathBuf::from(DEFAULT_LOG_FILE);
        let binding = resolve_binding(ProcessPlane::Combined, None, None, default.clone()).unwrap();
        assert_eq!(binding, ObjectLogBinding::Local(default));
    }

    #[test]
    fn host_and_path_are_exclusive() {
        let error = resolve_binding(
            ProcessPlane::Combined,
            Some("127.0.0.1:9".into()),
            Some("objects.mikura".into()),
            PathBuf::from(DEFAULT_LOG_FILE),
        )
        .unwrap_err();
        assert!(error.contains("mutually exclusive"), "{error}");
    }

    #[test]
    fn backfill_sources_include_recorded_objects() {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        let object = Object {
            id: "c1".into(),
            kind: "Customer".into(),
            name: "Acme".into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: [("region".into(), "eu".into())].into_iter().collect(),
            created: 1,
            updated: 1,
        };
        db.create_object(&object).unwrap();
        let sources = backfill_sources(&db).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].id, "c1");
    }

    #[test]
    fn backfill_sources_omit_empty_namespace_objects() {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&Object {
            id: "rule-1".into(),
            kind: "TrustScoreRule".into(),
            name: "rule".into(),
            namespace: String::new(),
            external_id: String::new(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_object(&Object {
            id: "c1".into(),
            kind: "Customer".into(),
            name: "Acme".into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: [("region".into(), "eu".into())].into_iter().collect(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        let sources = backfill_sources(&db).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].id, "c1");
    }
}
