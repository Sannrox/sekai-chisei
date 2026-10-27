//! PostgreSQL persistence for versioned client packages (#1477).

use postgres::error::SqlState;

use crate::db::postgres::PostgresDb;
use crate::sekai::client_package::{ClientPackage, PACKAGE_UNAVAILABLE};

impl PostgresDb {
    pub fn get_client_package(
        &self,
        namespace: &str,
        package_id: &str,
    ) -> Result<Option<ClientPackage>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_client_packages
                 WHERE namespace = $1 AND package_id = $2",
                &[&namespace, &package_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_client_packages(&self, namespace: &str) -> Result<Vec<ClientPackage>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_client_packages
                 WHERE namespace = $1
                 ORDER BY package_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn commit_client_packages(&self, packages: &[&ClientPackage]) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for package in packages {
            let json = serde_json::to_string(package)
                .map_err(|error| format!("encode client package: {error}"))?;
            let changed = if package.superseded_by.is_empty() {
                tx.execute(
                    "INSERT INTO sekai_client_packages
                        (namespace, package_id, owner, record_json)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (namespace, package_id) DO UPDATE SET
                        record_json = EXCLUDED.record_json
                     WHERE sekai_client_packages.owner = EXCLUDED.owner
                       AND sekai_client_packages.record_json = EXCLUDED.record_json",
                    &[
                        &package.namespace,
                        &package.package_id,
                        &package.owner,
                        &json,
                    ],
                )
                .map_err(constraint_unavailable)?
            } else {
                tx.execute(
                    "UPDATE sekai_client_packages
                     SET record_json = $4
                     WHERE namespace = $1
                       AND package_id = $2
                       AND owner = $3
                       AND (record_json::jsonb) ->> 'superseded_by' = ''",
                    &[
                        &package.namespace,
                        &package.package_id,
                        &package.owner,
                        &json,
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
}

fn decode(json: &str) -> Result<ClientPackage, String> {
    serde_json::from_str(json).map_err(|error| format!("decode client package: {error}"))
}

fn constraint_unavailable(error: postgres::Error) -> String {
    if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        PACKAGE_UNAVAILABLE.into()
    } else {
        error.to_string()
    }
}
