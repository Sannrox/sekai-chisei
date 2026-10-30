//! Dual-backend community-store dispatch for model platform.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_model_platform_certification(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<crate::sekai::model_platform::ModelPlatformCertification>, String> {
        match self {
            Self::Sqlite(db) => db.get_model_platform_certification(namespace, certification_id),
            Self::Postgres(_) => Err(crate::sekai::model_platform::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn put_model_platform_certification(
        &self,
        certification: &crate::sekai::model_platform::ModelPlatformCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_model_platform_certification(certification),
            Self::Postgres(_) => Err(crate::sekai::model_platform::POSTGRES_UNAVAILABLE.into()),
        }
    }

    pub fn cas_model_platform_certification(
        &self,
        expected: &crate::sekai::model_platform::ModelPlatformCertification,
        next: &crate::sekai::model_platform::ModelPlatformCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_model_platform_certification(expected, next),
            Self::Postgres(_) => Err(crate::sekai::model_platform::POSTGRES_UNAVAILABLE.into()),
        }
    }
}
