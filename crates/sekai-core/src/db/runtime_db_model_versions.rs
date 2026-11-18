//! Dual-backend dispatch for model version references (#3020).
use super::*;
use crate::sekai::model_version::{ModelVersion, ModelVersionRegistration};

/// Dispatch statuses of an isolated run that has not produced an output.
const UNFINISHED_DISPATCH: [&str; 4] = ["pending", "claimed", "failed", "refused"];

impl RuntimeDb {
    /// Registers a model version trained by `registration.run_id`. The
    /// version's marking and training dataset versions come from that run's
    /// receipt. Registering the same digest again returns the stored record.
    pub fn register_model_version(
        &self,
        registration: ModelVersionRegistration,
        created_at_ms: i64,
    ) -> Result<ModelVersion, String> {
        registration.validate()?;
        let run = self
            .get_governed_transform_run(&registration.run_id)?
            .ok_or("model version run not found")?;
        if run.quarantined || UNFINISHED_DISPATCH.contains(&run.dispatch_status.as_str()) {
            return Err("model version run did not complete".into());
        }
        let version = ModelVersion::from_run(
            registration,
            &run.namespace,
            &run.markings_out,
            &run.input_versions,
            created_at_ms,
        )?;
        self.insert_model_version(&version)
    }

    pub fn insert_model_version(&self, version: &ModelVersion) -> Result<ModelVersion, String> {
        match self {
            Self::Sqlite(db) => db.insert_model_version(version),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.insert_model_version(version))
            }
        }
    }

    pub fn get_model_version(
        &self,
        namespace: &str,
        version_id: &str,
    ) -> Result<Option<ModelVersion>, String> {
        match self {
            Self::Sqlite(db) => db.get_model_version(namespace, version_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_model_version(namespace, version_id))
            }
        }
    }

    pub fn list_model_versions(
        &self,
        namespace: &str,
        model_name: &str,
    ) -> Result<Vec<ModelVersion>, String> {
        match self {
            Self::Sqlite(db) => db.list_model_versions(namespace, model_name),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_model_versions(namespace, model_name))
            }
        }
    }
}
