//! PostgreSQL storage for purpose authorizations (ADR 0031) and
//! classification lattices (ADR 0032). Same tables and semantics as SQLite
//! (`src/db/object_security.rs`): an authorization id is written once and
//! revoked once, and a namespace keeps one current lattice.

use crate::db::object_security::verify_stored_lattice;
use crate::db::postgres::PostgresDb;
use crate::sekai::classification_lattice::ClassificationLattice;
use crate::sekai::purpose_authorization::{PURPOSE_AUTHORIZATION_VERSION, PurposeAuthorization};

const AUTHORIZATION_COLUMNS: &str = "authorization_id, contract_version, actor, purpose, namespace,
    kind, not_before_ms, not_after_ms, policy_activation_digest, created_by, created_at_ms,
    revoked_at_ms";

fn row_to_authorization(row: &postgres::Row) -> Result<PurposeAuthorization, String> {
    PurposeAuthorization {
        authorization_id: row.get(0),
        contract_version: row.get(1),
        actor: row.get(2),
        purpose: row.get(3),
        namespace: row.get(4),
        kind: row.get(5),
        not_before_ms: row.get(6),
        not_after_ms: row.get(7),
        policy_activation_digest: row.get(8),
        created_by: row.get(9),
        created_at_ms: row.get(10),
        revoked_at_ms: row.get(11),
    }
    .prepare()
}

impl PostgresDb {
    pub fn put_purpose_authorization(
        &self,
        authorization: &PurposeAuthorization,
    ) -> Result<PurposeAuthorization, String> {
        let authorization = authorization.prepare()?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_purpose_authorizations
                 (authorization_id, contract_version, actor, purpose, namespace, kind,
                  not_before_ms, not_after_ms, policy_activation_digest, created_by,
                  created_at_ms, revoked_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                &[
                    &authorization.authorization_id,
                    &authorization.contract_version,
                    &authorization.actor,
                    &authorization.purpose,
                    &authorization.namespace,
                    &authorization.kind,
                    &authorization.not_before_ms,
                    &authorization.not_after_ms,
                    &authorization.policy_activation_digest,
                    &authorization.created_by,
                    &authorization.created_at_ms,
                    &authorization.revoked_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(authorization)
    }

    /// Revokes in one statement, returning the revoked row, so the update and
    /// the read cannot interleave with another revocation.
    pub fn revoke_purpose_authorization(
        &self,
        authorization_id: &str,
        revoked_at_ms: i64,
    ) -> Result<PurposeAuthorization, String> {
        if authorization_id.is_empty() || revoked_at_ms <= 0 {
            return Err("purpose authorization revocation identity or time is invalid".into());
        }
        let row = self
            .connection()?
            .query_opt(
                &format!(
                    "UPDATE sekai_purpose_authorizations SET revoked_at_ms = $1
                     WHERE authorization_id = $2 AND revoked_at_ms = 0
                     RETURNING {AUTHORIZATION_COLUMNS}"
                ),
                &[&revoked_at_ms, &authorization_id],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "purpose authorization is missing or already revoked".to_string())?;
        row_to_authorization(&row)
    }

    pub fn find_purpose_authorization(
        &self,
        actor: &str,
        purpose: &str,
        namespace: &str,
        kind: &str,
        activation_digest: &str,
        now_ms: i64,
    ) -> Result<Option<PurposeAuthorization>, String> {
        self.connection()?
            .query_opt(
                &format!(
                    "SELECT {AUTHORIZATION_COLUMNS}
                     FROM sekai_purpose_authorizations
                     WHERE actor = $1 AND purpose = $2 AND namespace = $3
                       AND (kind = '' OR kind = $4)
                       AND policy_activation_digest = $5
                       AND contract_version = $7
                       AND revoked_at_ms = 0
                       AND not_before_ms <= $6 AND not_after_ms >= $6
                     ORDER BY kind DESC, authorization_id
                     LIMIT 1"
                ),
                &[
                    &actor,
                    &purpose,
                    &namespace,
                    &kind,
                    &activation_digest,
                    &now_ms,
                    &PURPOSE_AUTHORIZATION_VERSION,
                ],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row_to_authorization(&row))
            .transpose()
    }

    pub fn put_classification_lattice(
        &self,
        lattice: &ClassificationLattice,
        actor: &str,
        now_ms: i64,
    ) -> Result<ClassificationLattice, String> {
        if actor.trim().is_empty() || now_ms <= 0 {
            return Err("classification lattice actor or time is invalid".into());
        }
        let lattice = lattice.prepare()?;
        let digest = lattice.digest()?;
        let lattice_json = serde_json::to_string(&lattice).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_classification_lattices
                 (namespace, contract_version, digest, lattice_json, created_by, created_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (namespace) DO UPDATE SET
                    contract_version = EXCLUDED.contract_version,
                    digest = EXCLUDED.digest,
                    lattice_json = EXCLUDED.lattice_json,
                    created_by = EXCLUDED.created_by,
                    created_at_ms = EXCLUDED.created_at_ms",
                &[
                    &lattice.namespace,
                    &lattice.contract_version,
                    &digest,
                    &lattice_json,
                    &actor,
                    &now_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(lattice)
    }

    /// When the namespace's current classification lattice was stored.
    pub fn classification_lattice_recorded_at_ms(
        &self,
        namespace: &str,
    ) -> Result<Option<i64>, String> {
        self.connection()?
            .query_opt(
                "SELECT created_at_ms FROM sekai_classification_lattices WHERE namespace = $1",
                &[&namespace],
            )
            .map(|row| row.map(|row| row.get(0)))
            .map_err(|error| error.to_string())
    }

    pub fn get_classification_lattice(
        &self,
        namespace: &str,
    ) -> Result<Option<ClassificationLattice>, String> {
        load_classification_lattice(&mut *self.connection()?, namespace)
    }
}

/// The namespace's lattice read through `client`, so a transform reads it in
/// the transaction that derives its markings, as SQLite does.
pub fn load_classification_lattice(
    client: &mut impl postgres::GenericClient,
    namespace: &str,
) -> Result<Option<ClassificationLattice>, String> {
    client
        .query_opt(
            "SELECT namespace, contract_version, digest, lattice_json
             FROM sekai_classification_lattices WHERE namespace = $1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            let stored_namespace: String = row.get(0);
            let contract_version: String = row.get(1);
            let digest: String = row.get(2);
            let lattice_json: String = row.get(3);
            verify_stored_lattice(
                namespace,
                &stored_namespace,
                &contract_version,
                &digest,
                &lattice_json,
            )
        })
        .transpose()
}
