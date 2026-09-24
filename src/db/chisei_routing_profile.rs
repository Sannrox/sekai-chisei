//! Customer-hosted routing profiles (#1171) on both community backends.

use crate::chisei::routing_profiles::HostedRoutingProfile;
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
}

pub(crate) fn decode_model_patterns(json: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt routing profile: {error}"))
}

impl SekaiDb {
    pub(crate) fn migrate_routing_profiles(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_routing_profiles (
                    namespace TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    endpoint_origin TEXT NOT NULL,
                    model_patterns_json TEXT NOT NULL,
                    credential_ref TEXT NOT NULL,
                    registered_by TEXT NOT NULL,
                    registered_at_ms INTEGER NOT NULL,
                    revoked_at_ms INTEGER,
                    PRIMARY KEY (namespace, profile_id)
                 );",
            )
            .map_err(|error| error.to_string())
    }
}

impl ChiseiRoutingProfileBackend for SekaiDb {
    fn put_hosted_routing_profile(&self, profile: &HostedRoutingProfile) -> Result<(), String> {
        let patterns =
            serde_json::to_string(&profile.model_patterns).map_err(|error| error.to_string())?;
        self.conn()
            .execute(
                "INSERT INTO chisei_routing_profiles (
                    namespace, profile_id, endpoint_origin, model_patterns_json,
                    credential_ref, registered_by, registered_at_ms, revoked_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                 ON CONFLICT (namespace, profile_id) DO UPDATE SET
                    endpoint_origin = excluded.endpoint_origin,
                    model_patterns_json = excluded.model_patterns_json,
                    credential_ref = excluded.credential_ref,
                    registered_by = excluded.registered_by,
                    registered_at_ms = excluded.registered_at_ms,
                    revoked_at_ms = NULL",
                rusqlite::params![
                    profile.namespace,
                    profile.profile_id,
                    profile.endpoint_origin,
                    patterns,
                    profile.credential_ref,
                    profile.registered_by,
                    profile.registered_at_ms,
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
                        registered_by, registered_at_ms
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
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(
                |(profile_id, endpoint_origin, patterns, credential_ref, registered_by, at)| {
                    Ok(HostedRoutingProfile {
                        namespace: namespace.into(),
                        profile_id,
                        endpoint_origin,
                        model_patterns: decode_model_patterns(&patterns)?,
                        credential_ref,
                        registered_by,
                        registered_at_ms: at,
                    })
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
}

impl ChiseiRoutingProfileBackend for PostgresDb {
    fn put_hosted_routing_profile(&self, profile: &HostedRoutingProfile) -> Result<(), String> {
        PostgresDb::put_hosted_routing_profile(self, profile)
    }

    fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<HostedRoutingProfile>, String> {
        PostgresDb::list_hosted_routing_profiles(self, namespace)
    }

    fn revoke_hosted_routing_profile(
        &self,
        namespace: &str,
        profile_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        PostgresDb::revoke_hosted_routing_profile(self, namespace, profile_id, now_ms)
    }
}
