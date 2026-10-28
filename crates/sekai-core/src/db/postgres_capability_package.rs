//! PostgreSQL persistence for capability-package certifications (#1478).

use postgres::GenericClient;
use postgres::error::SqlState;

use crate::db::postgres::PostgresDb;
use crate::sekai::capability_package::{CapabilityPackageCertification, PACKAGE_UNAVAILABLE};

impl PostgresDb {
    /// Namespaces holding a live certification of `package_id`.
    pub fn list_live_package_namespaces(&self, package_id: &str) -> Result<Vec<String>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT DISTINCT namespace FROM sekai_capability_packages
                 WHERE (record_json::jsonb) ->> 'package_id' = $1
                   AND (record_json::jsonb) ->> 'superseded_by' = ''
                   AND (record_json::jsonb) ->> 'revocation' = ''
                 ORDER BY namespace",
                &[&package_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }

    /// See the SQLite store.
    pub fn get_package_feed_cursor(
        &self,
        namespace: &str,
        consumer: &str,
    ) -> Result<Option<u64>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT next_seq FROM sekai_package_feed_cursors
                 WHERE namespace = $1 AND consumer = $2",
                &[&namespace, &consumer],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, i64>(0).max(0) as u64))
    }

    /// See the SQLite store.
    pub fn advance_package_feed_cursor(
        &self,
        namespace: &str,
        consumer: &str,
        expected: Option<u64>,
        next: u64,
    ) -> Result<bool, String> {
        let overflow = |_| "feed position overflows".to_string();
        let next = i64::try_from(next).map_err(overflow)?;
        let mut connection = self.connection()?;
        let changed = match expected {
            None => connection.execute(
                "INSERT INTO sekai_package_feed_cursors (namespace, consumer, next_seq)
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                &[&namespace, &consumer, &next],
            ),
            Some(expected) => {
                let expected = i64::try_from(expected).map_err(overflow)?;
                connection.execute(
                    "UPDATE sekai_package_feed_cursors SET next_seq = $3
                     WHERE namespace = $1 AND consumer = $2 AND next_seq = $4",
                    &[&namespace, &consumer, &next, &expected],
                )
            }
        }
        .map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }

    pub fn get_capability_package(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<CapabilityPackageCertification>, String> {
        get_package(&mut *self.connection()?, namespace, certification_id, false)
    }

    pub fn list_capability_packages(
        &self,
        namespace: &str,
    ) -> Result<Vec<CapabilityPackageCertification>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_capability_packages
                 WHERE namespace = $1
                 ORDER BY certification_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn commit_capability_packages(
        &self,
        packages: &[&CapabilityPackageCertification],
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for package in packages {
            let json = serde_json::to_string(package)
                .map_err(|error| format!("encode capability package: {error}"))?;
            let changed = if package.superseded_by.is_empty() {
                tx.execute(
                    "INSERT INTO sekai_capability_packages
                        (namespace, certification_id, owner, record_json)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (namespace, certification_id) DO NOTHING",
                    &[
                        &package.namespace,
                        &package.certification_id,
                        &package.owner,
                        &json,
                    ],
                )
                .map_err(constraint_unavailable)?
            } else {
                // Keep a concurrent revoke: the unique live index ignores
                // revoked rows, and sequential recertify-after-revoke must
                // still see the stored revocation. Match that revocation
                // (empty or revoked) so a stale supersede cannot clear it.
                tx.execute(
                    "UPDATE sekai_capability_packages
                     SET record_json = $4
                     WHERE namespace = $1
                       AND certification_id = $2
                       AND owner = $3
                       AND (record_json::jsonb) ->> 'superseded_by' = ''
                       AND (record_json::jsonb) ->> 'revocation' = $5",
                    &[
                        &package.namespace,
                        &package.certification_id,
                        &package.owner,
                        &json,
                        &package.revocation,
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let current = get_package(
            &mut tx,
            &expected.namespace,
            &expected.certification_id,
            true,
        )?
        .ok_or(PACKAGE_UNAVAILABLE)?;
        if current != *expected {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_capability_packages
                 SET record_json = $1
                 WHERE namespace = $2 AND certification_id = $3 AND owner = $4",
                &[
                    &next_json,
                    &next.namespace,
                    &next.certification_id,
                    &next.owner,
                ],
            )
            .map_err(constraint_unavailable)?;
        if changed == 0 {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())
    }
}

fn get_package(
    client: &mut impl GenericClient,
    namespace: &str,
    certification_id: &str,
    for_update: bool,
) -> Result<Option<CapabilityPackageCertification>, String> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    client
        .query_opt(
            &format!(
                "SELECT record_json FROM sekai_capability_packages
                 WHERE namespace = $1 AND certification_id = $2{lock}"
            ),
            &[&namespace, &certification_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| decode(&row.get::<_, String>(0)))
        .transpose()
}

fn decode(json: &str) -> Result<CapabilityPackageCertification, String> {
    serde_json::from_str(json).map_err(|error| format!("decode capability package: {error}"))
}

fn constraint_unavailable(error: postgres::Error) -> String {
    if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        PACKAGE_UNAVAILABLE.into()
    } else {
        error.to_string()
    }
}
