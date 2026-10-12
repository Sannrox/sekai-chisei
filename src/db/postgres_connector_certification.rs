//! PostgreSQL persistence for connector certifications (ADR 0055), with the
//! same semantics as the SQLite store (#1481).

use postgres::GenericClient;
use postgres::error::SqlState;

use crate::db::postgres::PostgresDb;
use crate::sekai::connector_certification::{CONNECTOR_UNAVAILABLE, ConnectorCertification};

impl PostgresDb {
    pub fn get_connector_certification(
        &self,
        namespace: &str,
        certification_id: &str,
    ) -> Result<Option<ConnectorCertification>, String> {
        get_certification(&mut *self.connection()?, namespace, certification_id, false)
    }

    pub fn list_connector_certifications(
        &self,
        namespace: &str,
    ) -> Result<Vec<ConnectorCertification>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_connector_certifications
                 WHERE namespace = $1
                 ORDER BY certification_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| decode(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn commit_connector_certifications(
        &self,
        certifications: &[&ConnectorCertification],
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for certification in certifications {
            let json = if certification.superseded_by.is_empty() {
                serde_json::to_string(certification)
                    .map_err(|error| format!("encode connector certification: {error}"))?
            } else {
                let current = get_certification(
                    &mut transaction,
                    &certification.namespace,
                    &certification.certification_id,
                    true,
                )?
                .ok_or(CONNECTOR_UNAVAILABLE)?;
                if current.owner != certification.owner || !current.superseded_by.is_empty() {
                    return Err(CONNECTOR_UNAVAILABLE.into());
                }
                let mut next = current;
                next.superseded_by = certification.superseded_by.clone();
                serde_json::to_string(&next)
                    .map_err(|error| format!("encode connector certification: {error}"))?
            };
            let changed = if certification.superseded_by.is_empty() {
                transaction.execute(
                    "INSERT INTO sekai_connector_certifications
                        (namespace, certification_id, owner, record_json)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (namespace, certification_id) DO NOTHING",
                    &[
                        &certification.namespace,
                        &certification.certification_id,
                        &certification.owner,
                        &json,
                    ],
                )
            } else {
                transaction.execute(
                    "UPDATE sekai_connector_certifications
                     SET record_json = $4
                     WHERE namespace = $1
                       AND certification_id = $2
                       AND owner = $3
                       AND (record_json::jsonb) ->> 'superseded_by' = ''",
                    &[
                        &certification.namespace,
                        &certification.certification_id,
                        &certification.owner,
                        &json,
                    ],
                )
            }
            .map_err(constraint_unavailable)?;
            if changed == 0 {
                return Err(CONNECTOR_UNAVAILABLE.into());
            }
        }
        transaction.commit().map_err(constraint_unavailable)
    }

    pub fn cas_connector_certification(
        &self,
        expected: &ConnectorCertification,
        next: &ConnectorCertification,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.certification_id != next.certification_id
            || expected.owner != next.owner
        {
            return Err(CONNECTOR_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode connector certification: {error}"))?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let current = get_certification(
            &mut transaction,
            &expected.namespace,
            &expected.certification_id,
            true,
        )?
        .ok_or(CONNECTOR_UNAVAILABLE)?;
        if current != *expected {
            return Err(CONNECTOR_UNAVAILABLE.into());
        }
        let changed = transaction
            .execute(
                "UPDATE sekai_connector_certifications
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
            return Err(CONNECTOR_UNAVAILABLE.into());
        }
        transaction.commit().map_err(|error| error.to_string())
    }
}

fn get_certification(
    client: &mut impl GenericClient,
    namespace: &str,
    certification_id: &str,
    for_update: bool,
) -> Result<Option<ConnectorCertification>, String> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    client
        .query_opt(
            &format!(
                "SELECT record_json FROM sekai_connector_certifications
                 WHERE namespace = $1 AND certification_id = $2{lock}"
            ),
            &[&namespace, &certification_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| decode(&row.get::<_, String>(0)))
        .transpose()
}

fn decode(json: &str) -> Result<ConnectorCertification, String> {
    serde_json::from_str(json).map_err(|error| format!("decode connector certification: {error}"))
}

/// A unique violation is a lost race or a second live certification.
fn constraint_unavailable(error: postgres::Error) -> String {
    if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        CONNECTOR_UNAVAILABLE.into()
    } else {
        error.to_string()
    }
}
