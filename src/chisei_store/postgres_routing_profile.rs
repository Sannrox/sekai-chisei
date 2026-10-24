//! PostgreSQL parity for customer-hosted routing profiles (#1171).

use crate::chisei::routing_profiles::HostedRoutingProfile;
use crate::chisei_store::chisei_routing_profile::hosted_profile_from_parts;
use crate::db::postgres::PostgresDb;

pub trait PostgresRoutingProfilePostgresDbExt {
    fn put_hosted_routing_profile(&self, profile: &HostedRoutingProfile) -> Result<(), String>;

    fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<HostedRoutingProfile>, String>;

    fn revoke_hosted_routing_profile(
        &self,
        namespace: &str,
        profile_id: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn list_all_hosted_routing_profiles(&self) -> Result<Vec<HostedRoutingProfile>, String>;
}

impl PostgresRoutingProfilePostgresDbExt for PostgresDb {
    fn put_hosted_routing_profile(&self, profile: &HostedRoutingProfile) -> Result<(), String> {
        let patterns =
            serde_json::to_string(&profile.model_patterns).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_routing_profiles (
                    namespace, profile_id, endpoint_origin, model_patterns_json,
                    credential_ref, registered_by, registered_at_ms, revoked_at_ms,
                    artifact_digest, require_runtime_evidence, evidence_provider,
                    evidence_model, evidence_profile_version, evidence_artifact_digest,
                    evidence_endpoint
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8, $9, $10, $11, $12, $13, $14)
                 ON CONFLICT (namespace, profile_id) DO UPDATE SET
                    endpoint_origin = EXCLUDED.endpoint_origin,
                    model_patterns_json = EXCLUDED.model_patterns_json,
                    credential_ref = EXCLUDED.credential_ref,
                    artifact_digest = EXCLUDED.artifact_digest,
                    registered_by = EXCLUDED.registered_by,
                    registered_at_ms = EXCLUDED.registered_at_ms,
                    revoked_at_ms = NULL,
                    require_runtime_evidence = EXCLUDED.require_runtime_evidence,
                    evidence_provider = EXCLUDED.evidence_provider,
                    evidence_model = EXCLUDED.evidence_model,
                    evidence_profile_version = EXCLUDED.evidence_profile_version,
                    evidence_artifact_digest = EXCLUDED.evidence_artifact_digest,
                    evidence_endpoint = EXCLUDED.evidence_endpoint",
                &[
                    &profile.namespace,
                    &profile.profile_id,
                    &profile.endpoint_origin,
                    &patterns,
                    &profile.credential_ref,
                    &profile.registered_by,
                    &profile.registered_at_ms,
                    &profile.artifact_digest,
                    &profile.require_runtime_evidence,
                    &profile.evidence_provider,
                    &profile.evidence_model,
                    &profile.evidence_profile_version,
                    &profile.evidence_artifact_digest,
                    &profile.evidence_endpoint,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<HostedRoutingProfile>, String> {
        self.connection()?
            .query(
                "SELECT profile_id, endpoint_origin, model_patterns_json, credential_ref,
                        registered_by, registered_at_ms, artifact_digest,
                        require_runtime_evidence, evidence_provider, evidence_model,
                        evidence_profile_version, evidence_artifact_digest, evidence_endpoint
                 FROM chisei_routing_profiles
                 WHERE namespace = $1 AND revoked_at_ms IS NULL
                 ORDER BY profile_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                hosted_profile_from_parts(
                    namespace.into(),
                    row.get(0),
                    row.get(1),
                    &row.get::<_, String>(2),
                    row.get(3),
                    row.get(6),
                    row.get(4),
                    row.get(5),
                    row.get(7),
                    row.get(8),
                    row.get(9),
                    row.get(10),
                    row.get(11),
                    row.get(12),
                )
            })
            .collect()
    }

    fn revoke_hosted_routing_profile(
        &self,
        namespace: &str,
        profile_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.connection()?
            .execute(
                "UPDATE chisei_routing_profiles SET revoked_at_ms = $3
                 WHERE namespace = $1 AND profile_id = $2 AND revoked_at_ms IS NULL",
                &[&namespace, &profile_id, &now_ms],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    fn list_all_hosted_routing_profiles(&self) -> Result<Vec<HostedRoutingProfile>, String> {
        self.connection()?
            .query(
                "SELECT namespace, profile_id, endpoint_origin, model_patterns_json, credential_ref,
                        registered_by, registered_at_ms, artifact_digest,
                        require_runtime_evidence, evidence_provider, evidence_model,
                        evidence_profile_version, evidence_artifact_digest, evidence_endpoint
                 FROM chisei_routing_profiles
                 WHERE revoked_at_ms IS NULL
                 ORDER BY namespace, profile_id",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                hosted_profile_from_parts(
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    &row.get::<_, String>(3),
                    row.get(4),
                    row.get(7),
                    row.get(5),
                    row.get(6),
                    row.get(8),
                    row.get(9),
                    row.get(10),
                    row.get(11),
                    row.get(12),
                    row.get(13),
                )
            })
            .collect()
    }
}
