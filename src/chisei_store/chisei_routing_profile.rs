//! Customer-hosted routing profiles (#1171) on both community backends.

use crate::chisei::routing_profiles::HostedRoutingProfile;
use crate::chisei_store::postgres_routing_profile::PostgresRoutingProfilePostgresDbExt;
use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;

pub trait ChiseiRoutingProfileBackend: Send + Sync {
    /// Registers or replaces a namespace's hosted profile, clearing any
    /// earlier revocation.
    fn put_hosted_routing_profile(&self, profile: &HostedRoutingProfile) -> Result<(), String>;

    /// The namespace's registered, unrevoked hosted profiles, sorted by id.
    fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<HostedRoutingProfile>, String>;

    /// Revokes one profile. Returns whether an active profile was revoked.
    fn revoke_hosted_routing_profile(
        &self,
        namespace: &str,
        profile_id: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    /// Every unrevoked hosted profile, all namespaces.
    fn list_all_hosted_routing_profiles(&self) -> Result<Vec<HostedRoutingProfile>, String>;
}

pub(crate) fn decode_model_patterns(json: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt routing profile: {error}"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn hosted_profile_from_parts(
    namespace: String,
    profile_id: String,
    endpoint_origin: String,
    patterns: &str,
    credential_ref: String,
    artifact_digest: Option<String>,
    registered_by: String,
    registered_at_ms: i64,
    require_runtime_evidence: bool,
    evidence_provider: String,
    evidence_model: String,
    evidence_profile_version: String,
    evidence_artifact_digest: String,
    evidence_endpoint: String,
) -> Result<HostedRoutingProfile, String> {
    Ok(HostedRoutingProfile {
        namespace,
        profile_id,
        endpoint_origin,
        model_patterns: decode_model_patterns(patterns)?,
        credential_ref,
        artifact_digest,
        registered_by,
        registered_at_ms,
        require_runtime_evidence,
        evidence_provider,
        evidence_model,
        evidence_profile_version,
        evidence_artifact_digest,
        evidence_endpoint,
    })
}

impl ChiseiRoutingProfileBackend for SekaiDb {
    fn put_hosted_routing_profile(&self, profile: &HostedRoutingProfile) -> Result<(), String> {
        let patterns =
            serde_json::to_string(&profile.model_patterns).map_err(|error| error.to_string())?;
        self.conn()
            .execute(
                "INSERT INTO chisei_routing_profiles (
                    namespace, profile_id, endpoint_origin, model_patterns_json,
                    credential_ref, registered_by, registered_at_ms, revoked_at_ms,
                    artifact_digest, require_runtime_evidence, evidence_provider,
                    evidence_model, evidence_profile_version, evidence_artifact_digest,
                    evidence_endpoint
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT (namespace, profile_id) DO UPDATE SET
                    endpoint_origin = excluded.endpoint_origin,
                    model_patterns_json = excluded.model_patterns_json,
                    credential_ref = excluded.credential_ref,
                    artifact_digest = excluded.artifact_digest,
                    registered_by = excluded.registered_by,
                    registered_at_ms = excluded.registered_at_ms,
                    revoked_at_ms = NULL,
                    require_runtime_evidence = excluded.require_runtime_evidence,
                    evidence_provider = excluded.evidence_provider,
                    evidence_model = excluded.evidence_model,
                    evidence_profile_version = excluded.evidence_profile_version,
                    evidence_artifact_digest = excluded.evidence_artifact_digest,
                    evidence_endpoint = excluded.evidence_endpoint",
                rusqlite::params![
                    profile.namespace,
                    profile.profile_id,
                    profile.endpoint_origin,
                    patterns,
                    profile.credential_ref,
                    profile.registered_by,
                    profile.registered_at_ms,
                    profile.artifact_digest,
                    profile.require_runtime_evidence as i64,
                    profile.evidence_provider,
                    profile.evidence_model,
                    profile.evidence_profile_version,
                    profile.evidence_artifact_digest,
                    profile.evidence_endpoint,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<HostedRoutingProfile>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT profile_id, endpoint_origin, model_patterns_json, credential_ref,
                        registered_by, registered_at_ms, artifact_digest,
                        require_runtime_evidence, evidence_provider, evidence_model,
                        evidence_profile_version, evidence_artifact_digest, evidence_endpoint
                 FROM chisei_routing_profiles
                 WHERE namespace = ?1 AND revoked_at_ms IS NULL
                 ORDER BY profile_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([namespace], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(
                |(
                    profile_id,
                    endpoint_origin,
                    patterns,
                    credential_ref,
                    registered_by,
                    at,
                    artifact_digest,
                    require,
                    ev_provider,
                    ev_model,
                    ev_version,
                    ev_digest,
                    ev_endpoint,
                )| {
                    hosted_profile_from_parts(
                        namespace.into(),
                        profile_id,
                        endpoint_origin,
                        &patterns,
                        credential_ref,
                        artifact_digest,
                        registered_by,
                        at,
                        require != 0,
                        ev_provider,
                        ev_model,
                        ev_version,
                        ev_digest,
                        ev_endpoint,
                    )
                },
            )
            .collect()
    }

    fn revoke_hosted_routing_profile(
        &self,
        namespace: &str,
        profile_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.conn()
            .execute(
                "UPDATE chisei_routing_profiles SET revoked_at_ms = ?3
                 WHERE namespace = ?1 AND profile_id = ?2 AND revoked_at_ms IS NULL",
                rusqlite::params![namespace, profile_id, now_ms],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    fn list_all_hosted_routing_profiles(&self) -> Result<Vec<HostedRoutingProfile>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT namespace, profile_id, endpoint_origin, model_patterns_json, credential_ref,
                        registered_by, registered_at_ms, artifact_digest,
                        require_runtime_evidence, evidence_provider, evidence_model,
                        evidence_profile_version, evidence_artifact_digest, evidence_endpoint
                 FROM chisei_routing_profiles
                 WHERE revoked_at_ms IS NULL
                 ORDER BY namespace, profile_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(
                |(
                    namespace,
                    profile_id,
                    endpoint_origin,
                    patterns,
                    credential_ref,
                    registered_by,
                    at,
                    artifact_digest,
                    require,
                    ev_provider,
                    ev_model,
                    ev_version,
                    ev_digest,
                    ev_endpoint,
                )| {
                    hosted_profile_from_parts(
                        namespace,
                        profile_id,
                        endpoint_origin,
                        &patterns,
                        credential_ref,
                        artifact_digest,
                        registered_by,
                        at,
                        require != 0,
                        ev_provider,
                        ev_model,
                        ev_version,
                        ev_digest,
                        ev_endpoint,
                    )
                },
            )
            .collect()
    }
}

impl ChiseiRoutingProfileBackend for PostgresDb {
    fn put_hosted_routing_profile(&self, profile: &HostedRoutingProfile) -> Result<(), String> {
        PostgresRoutingProfilePostgresDbExt::put_hosted_routing_profile(self, profile)
    }

    fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<HostedRoutingProfile>, String> {
        PostgresRoutingProfilePostgresDbExt::list_hosted_routing_profiles(self, namespace)
    }

    fn revoke_hosted_routing_profile(
        &self,
        namespace: &str,
        profile_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        PostgresRoutingProfilePostgresDbExt::revoke_hosted_routing_profile(
            self, namespace, profile_id, now_ms,
        )
    }

    fn list_all_hosted_routing_profiles(&self) -> Result<Vec<HostedRoutingProfile>, String> {
        PostgresRoutingProfilePostgresDbExt::list_all_hosted_routing_profiles(self)
    }
}
