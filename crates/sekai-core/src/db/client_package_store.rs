//! SQLite persistence for versioned client packages (#702).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::client_package::{ClientPackage, PACKAGE_UNAVAILABLE};

impl SekaiDb {
    pub fn put_client_package(&self, package: &ClientPackage) -> Result<(), String> {
        self.commit_client_packages(&[package])
    }

    pub fn get_client_package(
        &self,
        namespace: &str,
        package_id: &str,
    ) -> Result<Option<ClientPackage>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_client_packages
                 WHERE namespace = ?1 AND package_id = ?2",
                params![namespace, package_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode client package: {error}"))
        })
        .transpose()
    }

    pub fn list_client_packages(&self, namespace: &str) -> Result<Vec<ClientPackage>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_client_packages
                 WHERE namespace = ?1
                 ORDER BY package_id",
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
                    .map_err(|error| format!("decode client package: {error}"))?,
            );
        }
        Ok(packages)
    }

    pub fn commit_client_packages(&self, packages: &[&ClientPackage]) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        for package in packages {
            // A supersede rewrites the predecessor as stored now, changing
            // only `superseded_by`, so a concurrent change is not overwritten.
            let json = if package.superseded_by.is_empty() {
                serde_json::to_string(package)
                    .map_err(|error| format!("encode client package: {error}"))?
            } else {
                let current_json: Option<String> = tx
                    .query_row(
                        "SELECT record_json FROM sekai_client_packages
                         WHERE namespace = ?1 AND package_id = ?2",
                        params![package.namespace, package.package_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|error| error.to_string())?;
                let next = superseded(
                    serde_json::from_str(&current_json.ok_or(PACKAGE_UNAVAILABLE)?)
                        .map_err(|error| format!("decode client package: {error}"))?,
                    package,
                )?;
                serde_json::to_string(&next)
                    .map_err(|error| format!("encode client package: {error}"))?
            };
            let changed = if package.superseded_by.is_empty() {
                tx.execute(
                    "INSERT INTO sekai_client_packages
                        (namespace, package_id, owner, record_json)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(namespace, package_id) DO UPDATE SET
                        record_json = excluded.record_json
                     WHERE sekai_client_packages.owner = excluded.owner
                       AND sekai_client_packages.record_json = excluded.record_json",
                    params![package.namespace, package.package_id, package.owner, json],
                )
                .map_err(constraint_unavailable)?
            } else {
                tx.execute(
                    "UPDATE sekai_client_packages
                     SET record_json = ?4
                     WHERE namespace = ?1
                       AND package_id = ?2
                       AND owner = ?3
                       AND json_extract(record_json, '$.superseded_by') = ''",
                    params![package.namespace, package.package_id, package.owner, json],
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
}

/// The stored predecessor with only `superseded_by` taken from the caller's
/// copy. Refuses a predecessor owned by someone else or already superseded.
pub(crate) fn superseded(
    mut current: ClientPackage,
    package: &ClientPackage,
) -> Result<ClientPackage, String> {
    if current.owner != package.owner || !current.superseded_by.is_empty() {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    current.superseded_by = package.superseded_by.clone();
    Ok(current)
}

fn constraint_unavailable(error: rusqlite::Error) -> String {
    let text = error.to_string();
    if text.to_ascii_lowercase().contains("unique") {
        PACKAGE_UNAVAILABLE.into()
    } else {
        text
    }
}
