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

/// Dual-backend dispatch for model stages (#3023).
impl RuntimeDb {
    pub fn put_model_stage(
        &self,
        stage: &crate::sekai::model_stage::ModelStage,
    ) -> Result<crate::sekai::model_stage::ModelStage, String> {
        match self {
            Self::Sqlite(db) => db.put_model_stage(stage),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_model_stage(stage)),
        }
    }

    pub fn get_model_stage(
        &self,
        namespace: &str,
        model_name: &str,
        stage: &str,
    ) -> Result<Option<crate::sekai::model_stage::ModelStage>, String> {
        match self {
            Self::Sqlite(db) => db.get_model_stage(namespace, model_name, stage),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_model_stage(namespace, model_name, stage)
            }),
        }
    }

    pub fn list_model_stages(
        &self,
        namespace: &str,
        model_name: &str,
    ) -> Result<Vec<crate::sekai::model_stage::ModelStage>, String> {
        match self {
            Self::Sqlite(db) => db.list_model_stages(namespace, model_name),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_model_stages(namespace, model_name))
            }
        }
    }

    /// Moves `stage` to its `version_id` only while it still holds
    /// `expected_version_id`, recording `receipt` in the same transaction.
    pub fn promote_model_stage(
        &self,
        stage: &crate::sekai::model_stage::ModelStage,
        expected_version_id: &str,
        receipt: &sekai_domain::receipt::OperationReceipt,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.promote_model_stage(stage, expected_version_id, receipt),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.promote_model_stage(stage, expected_version_id, receipt)
            }),
        }
    }
}

/// Dual-backend dispatch for model stage reviews (#3159).
impl RuntimeDb {
    pub fn get_model_stage_review(
        &self,
        key: &crate::db::model_stage_review_store::ReviewKey<'_>,
    ) -> Result<Option<crate::sekai::model_stage::ModelStageReview>, String> {
        match self {
            Self::Sqlite(db) => db.get_model_stage_review(key),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_model_stage_review(key))
            }
        }
    }

    /// Inserts a pending review with its receipt; `false` when one exists.
    pub fn submit_model_stage_review(
        &self,
        review: &crate::sekai::model_stage::ModelStageReview,
        receipt: &sekai_domain::receipt::OperationReceipt,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.submit_model_stage_review(review, receipt),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.submit_model_stage_review(review, receipt))
            }
        }
    }

    /// Decides a pending review with its receipt; `false` when it is no
    /// longer pending or the decider submitted it.
    pub fn decide_model_stage_review(
        &self,
        decided: &crate::sekai::model_stage::ModelStageReview,
        receipt: &sekai_domain::receipt::OperationReceipt,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.decide_model_stage_review(decided, receipt),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.decide_model_stage_review(decided, receipt))
            }
        }
    }
}
