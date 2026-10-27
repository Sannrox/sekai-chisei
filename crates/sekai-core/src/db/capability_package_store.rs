//! SQLite persistence for capability-package certifications (#707).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::capability_package::{CapabilityPackageCertification, PACKAGE_UNAVAILABLE};

impl SekaiDb {
    pub fn get_capability_package(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<CapabilityPackageCertification>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_capability_packages
                 WHERE namespace = ?1 AND certification_id = ?2",
                params![namespace, certification_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode capability package: {error}"))
        })
        .transpose()
    }

    pub fn list_capability_packages(
        &self,
        namespace: &str,
    ) -> Result<Vec<CapabilityPackageCertification>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_capability_packages
                 WHERE namespace = ?1
                 ORDER BY certification_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut packages = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            packages.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode capability package: {error}"))?,
            );
        }
        Ok(packages)
    }

    pub fn commit_capability_packages(
        &self,
        packages: &[&CapabilityPackageCertification],
    ) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        for package in packages {
            let json = serde_json::to_string(package)
                .map_err(|error| format!("encode capability package: {error}"))?;
            let changed = if package.superseded_by.is_empty() {
                tx.execute(
                    "INSERT INTO sekai_capability_packages
                        (namespace, certification_id, owner, record_json)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(namespace, certification_id) DO NOTHING",
                    params![
                        package.namespace,
                        package.certification_id,
                        package.owner,
                        json
                    ],
                )
                .map_err(constraint_unavailable)?
            } else {
                tx.execute(
                    "UPDATE sekai_capability_packages
                     SET record_json = ?4
                     WHERE namespace = ?1
                       AND certification_id = ?2
                       AND owner = ?3
                       AND json_extract(record_json, '$.superseded_by') = ''",
                    params![
                        package.namespace,
                        package.certification_id,
                        package.owner,
                        json
                    ],
                )
                .map_err(constraint_unavailable)?
            };
            if changed == 0 {
                return Err(PACKAGE_UNAVAILABLE.into());
            }
        }
        tx.commit().map_err(constraint_unavailable)?;
        Ok(())
    }

    pub fn cas_capability_package(
        &self,
        expected: &CapabilityPackageCertification,
        next: &CapabilityPackageCertification,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.certification_id != next.certification_id
            || expected.owner != next.owner
        {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode capability package: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT record_json FROM sekai_capability_packages
                 WHERE namespace = ?1 AND certification_id = ?2",
                params![expected.namespace, expected.certification_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let current: CapabilityPackageCertification =
            serde_json::from_str(&current.ok_or(PACKAGE_UNAVAILABLE)?)
                .map_err(|error| format!("decode capability package: {error}"))?;
        if current != *expected {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_capability_packages
                 SET record_json = ?1
                 WHERE namespace = ?2 AND certification_id = ?3 AND owner = ?4",
                params![next_json, next.namespace, next.certification_id, next.owner],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn constraint_unavailable(error: rusqlite::Error) -> String {
    let text = error.to_string();
    if text.to_ascii_lowercase().contains("unique") {
        PACKAGE_UNAVAILABLE.into()
    } else {
        text
    }
}
