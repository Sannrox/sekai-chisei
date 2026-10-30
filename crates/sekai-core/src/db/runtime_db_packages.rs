//! Dual-backend community-store dispatch for packages.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_client_package(
        &self,
        namespace: &str,
        package_id: &str,
    ) -> Result<Option<crate::sekai::client_package::ClientPackage>, String> {
        match self {
            Self::Sqlite(db) => db.get_client_package(namespace, package_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_client_package(namespace, package_id))
            }
        }
    }

    pub fn list_client_packages(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::client_package::ClientPackage>, String> {
        match self {
            Self::Sqlite(db) => db.list_client_packages(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_client_packages(namespace))
            }
        }
    }

    pub fn commit_client_packages(
        &self,
        packages: &[&crate::sekai::client_package::ClientPackage],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_client_packages(packages),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.commit_client_packages(packages))
            }
        }
    }

    pub fn get_capability_package(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<crate::sekai::capability_package::CapabilityPackageCertification>, String>
    {
        match self {
            Self::Sqlite(db) => db.get_capability_package(namespace, certification_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_capability_package(namespace, certification_id)
            }),
        }
    }

    pub fn list_live_package_namespaces(&self, package_id: &str) -> Result<Vec<String>, String> {
        match self {
            Self::Sqlite(db) => db.list_live_package_namespaces(package_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_live_package_namespaces(package_id))
            }
        }
    }

    pub fn get_package_feed_cursor(
        &self,
        namespace: &str,
        consumer: &str,
    ) -> Result<Option<u64>, String> {
        match self {
            Self::Sqlite(db) => db.get_package_feed_cursor(namespace, consumer),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_package_feed_cursor(namespace, consumer))
            }
        }
    }

    pub fn advance_package_feed_cursor(
        &self,
        namespace: &str,
        consumer: &str,
        expected: Option<u64>,
        next: u64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.advance_package_feed_cursor(namespace, consumer, expected, next),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.advance_package_feed_cursor(namespace, consumer, expected, next)
            }),
        }
    }

    pub fn list_capability_packages(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::capability_package::CapabilityPackageCertification>, String> {
        match self {
            Self::Sqlite(db) => db.list_capability_packages(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_capability_packages(namespace))
            }
        }
    }

    pub fn commit_capability_packages(
        &self,
        packages: &[&crate::sekai::capability_package::CapabilityPackageCertification],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_capability_packages(packages),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.commit_capability_packages(packages))
            }
        }
    }

    pub fn cas_capability_package(
        &self,
        expected: &crate::sekai::capability_package::CapabilityPackageCertification,
        next: &crate::sekai::capability_package::CapabilityPackageCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_capability_package(expected, next),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.cas_capability_package(expected, next))
            }
        }
    }
}
