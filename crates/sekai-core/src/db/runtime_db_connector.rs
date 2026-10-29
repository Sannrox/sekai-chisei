//! Dual-backend community-store dispatch for connector.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_connector_certification(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<crate::sekai::connector_certification::ConnectorCertification>, String> {
        match self {
            Self::Sqlite(db) => db.get_connector_certification(namespace, certification_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_connector_certification(namespace, certification_id)
            }),
        }
    }

    pub fn list_connector_certifications(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::connector_certification::ConnectorCertification>, String> {
        match self {
            Self::Sqlite(db) => db.list_connector_certifications(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_connector_certifications(namespace))
            }
        }
    }

    pub fn commit_connector_certifications(
        &self,
        certifications: &[&crate::sekai::connector_certification::ConnectorCertification],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_connector_certifications(certifications),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.commit_connector_certifications(certifications)
            }),
        }
    }

    pub fn cas_connector_certification(
        &self,
        expected: &crate::sekai::connector_certification::ConnectorCertification,
        next: &crate::sekai::connector_certification::ConnectorCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_connector_certification(expected, next),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.cas_connector_certification(expected, next))
            }
        }
    }
}
