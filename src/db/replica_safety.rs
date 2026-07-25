//! Replica-safety inventory and two-replica race harness (#117 / #304).
//!
//! The inventory is fail-closed for unlisted surfaces that appear in
//! `required_authoritative_surfaces`. The harness opens two independent
//! community stores against one shared SQLite file so concurrent-replica
//! tests do not rely on wall-clock budgets as the sole pass criterion.

use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

pub const REPLICA_SAFETY_INVENTORY_VERSION: &str = "sekai.replica-safety/v1";
pub const REPLICA_SAFETY_INVENTORY_JSON: &str =
    include_str!("../../tests/fixtures/replica_safety/v1.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaAuthorityClass {
    SharedStoreRequired,
    CacheAllowed,
    ProcessLocalOk,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReplicaSafetySurface {
    pub id: String,
    pub class: ReplicaAuthorityClass,
    #[serde(default)]
    pub max_stale_ms: Option<u64>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReplicaSafetyInventory {
    pub version: String,
    pub parent_issue: u64,
    #[serde(default)]
    pub description: String,
    pub surfaces: Vec<ReplicaSafetySurface>,
    pub required_authoritative_surfaces: Vec<String>,
    #[serde(default)]
    pub non_goals: Vec<String>,
}

impl ReplicaSafetyInventory {
    pub fn load() -> Result<Self, String> {
        let inventory: Self = serde_json::from_str(REPLICA_SAFETY_INVENTORY_JSON)
            .map_err(|error| format!("parse replica-safety inventory: {error}"))?;
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != REPLICA_SAFETY_INVENTORY_VERSION {
            return Err(format!(
                "unsupported replica-safety inventory version {:?}; expected {:?}",
                self.version, REPLICA_SAFETY_INVENTORY_VERSION
            ));
        }
        if self.surfaces.is_empty() {
            return Err("replica-safety inventory has no surfaces".into());
        }

        let mut seen = BTreeSet::new();
        for surface in &self.surfaces {
            if !seen.insert(surface.id.as_str()) {
                return Err(format!("duplicate replica-safety surface {}", surface.id));
            }
            match surface.class {
                ReplicaAuthorityClass::CacheAllowed => {
                    let Some(stale) = surface.max_stale_ms else {
                        return Err(format!(
                            "surface {} is cache_allowed but missing max_stale_ms",
                            surface.id
                        ));
                    };
                    if stale == 0 {
                        return Err(format!(
                            "surface {} cache_allowed max_stale_ms must be > 0",
                            surface.id
                        ));
                    }
                }
                ReplicaAuthorityClass::SharedStoreRequired
                | ReplicaAuthorityClass::ProcessLocalOk => {
                    if surface.max_stale_ms.is_some() {
                        return Err(format!(
                            "surface {} must not set max_stale_ms for class {:?}",
                            surface.id, surface.class
                        ));
                    }
                }
            }
            if surface.evidence.is_empty() {
                return Err(format!("surface {} missing evidence paths", surface.id));
            }
        }

        for required in &self.required_authoritative_surfaces {
            let Some(surface) = self.surfaces.iter().find(|s| s.id == *required) else {
                return Err(format!(
                    "required authoritative surface {required} is missing from inventory"
                ));
            };
            if matches!(surface.class, ReplicaAuthorityClass::ProcessLocalOk) {
                return Err(format!(
                    "required authoritative surface {required} cannot be process_local_ok"
                ));
            }
        }

        Ok(())
    }

    pub fn surface(&self, id: &str) -> Option<&ReplicaSafetySurface> {
        self.surfaces.iter().find(|surface| surface.id == id)
    }

    /// Fail closed when a caller asserts an authoritative surface that is not inventoried.
    pub fn require_authoritative(&self, id: &str) -> Result<&ReplicaSafetySurface, String> {
        let surface = self
            .surface(id)
            .ok_or_else(|| format!("unlisted authoritative surface {id}"))?;
        if matches!(surface.class, ReplicaAuthorityClass::ProcessLocalOk) {
            return Err(format!(
                "surface {id} is process_local_ok and cannot be treated as multi-replica authority"
            ));
        }
        Ok(surface)
    }
}

/// Two independent community stores against one shared SQLite file.
///
/// Dropping this type removes the temporary database files.
pub struct TwoReplicaSqlite {
    path: PathBuf,
    pub a: Arc<RuntimeDb>,
    pub b: Arc<RuntimeDb>,
}

impl TwoReplicaSqlite {
    pub fn open() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "sekai-replica-safety-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        let path_str = path
            .to_str()
            .ok_or_else(|| "replica-safety temp path is not UTF-8".to_string())?;
        let a = Arc::new(RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path_str)?)));
        let b = Arc::new(RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path_str)?)));
        Ok(Self { path, a, b })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Race `workers` threads, each receiving a clone of either replica in round-robin order.
    ///
    /// Returns each worker's `Result` in spawn order. Contending work must use database
    /// authority; wall-clock elapsed time is not part of the contract.
    pub fn race_results<T, F>(&self, workers: usize, work: F) -> Vec<T>
    where
        T: Send + 'static,
        F: Fn(usize, Arc<RuntimeDb>) -> T + Send + Sync + 'static,
    {
        assert!(workers >= 2, "replica race requires at least two workers");
        let barrier = Arc::new(Barrier::new(workers));
        let work = Arc::new(work);
        let handles = (0..workers)
            .map(|index| {
                let db = if index % 2 == 0 {
                    Arc::clone(&self.a)
                } else {
                    Arc::clone(&self.b)
                };
                let barrier = Arc::clone(&barrier);
                let work = Arc::clone(&work);
                thread::spawn(move || {
                    barrier.wait();
                    work(index, db)
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("replica worker panicked"))
            .collect()
    }
}

impl Drop for TwoReplicaSqlite {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
        let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
        // Give the OS a moment on slow filesystems; ignore errors.
        let _ = Duration::from_millis(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::chisei_budget::METRIC_TOKENS;
    use std::path::Path;

    #[test]
    fn inventory_loads_and_lists_required_authoritative_surfaces() {
        let inventory = ReplicaSafetyInventory::load().expect("inventory");
        assert_eq!(inventory.parent_issue, 117);
        for id in &inventory.required_authoritative_surfaces {
            inventory.require_authoritative(id).expect(id);
        }
        let budget = inventory.surface("chisei.budget").unwrap();
        assert_eq!(budget.class, ReplicaAuthorityClass::SharedStoreRequired);
        let creds = inventory.surface("sekai.credentials").unwrap();
        assert_eq!(creds.class, ReplicaAuthorityClass::CacheAllowed);
        assert_eq!(creds.max_stale_ms, Some(5_000));
    }

    #[test]
    fn inventory_evidence_paths_exist() {
        let inventory = ReplicaSafetyInventory::load().unwrap();
        for surface in &inventory.surfaces {
            for path in &surface.evidence {
                assert!(
                    Path::new(path).exists(),
                    "missing evidence path {path} for {}",
                    surface.id
                );
            }
        }
    }

    #[test]
    fn unlisted_surface_fails_closed() {
        let inventory = ReplicaSafetyInventory::load().unwrap();
        let err = inventory
            .require_authoritative("not.a.surface")
            .unwrap_err();
        assert!(err.contains("unlisted"));
    }

    #[test]
    fn two_replica_budget_race_has_single_winner() {
        let inventory = ReplicaSafetyInventory::load().unwrap();
        inventory.require_authoritative("chisei.budget").unwrap();

        let pair = TwoReplicaSqlite::open().expect("open shared sqlite");
        pair.a
            .budget_set_limit("global", METRIC_TOKENS, 10, "daily")
            .unwrap();

        let results = pair.race_results(2, |_index, db| {
            db.budget_check_and_reserve_chain("global", METRIC_TOKENS, 6, 0)
        });
        let successes = results.iter().filter(|result| result.is_ok()).count();
        assert_eq!(successes, 1, "results={results:?}");
        assert_eq!(
            pair.b.budget_usage("global", METRIC_TOKENS, 0).unwrap().0,
            6
        );
    }
}
