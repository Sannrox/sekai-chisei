//! PostgreSQL parity for customer-hosted routing profiles (#1171).

use crate::chisei::routing_profiles::HostedRoutingProfile;
use crate::db::chisei_routing_profile::decode_model_patterns;
use crate::db::postgres::PostgresDb;

impl PostgresDb {
    pub fn put_hosted_routing_profile(&self, profile: &HostedRoutingProfile) -> Result<(), String> {
        let patterns =
            serde_json::to_string(&profile.model_patterns).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_routing_profiles (
                    namespace, profile_id, endpoint_origin, model_patterns_json,
                    credential_ref, registered_by, registered_at_ms, revoked_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)
                 ON CONFLICT (namespace, profile_id) DO UPDATE SET
                    endpoint_origin = EXCLUDED.endpoint_origin,
                    model_patterns_json = EXCLUDED.model_patterns_json,
                    credential_ref = EXCLUDED.credential_ref,
                    registered_by = EXCLUDED.registered_by,
                    registered_at_ms = EXCLUDED.registered_at_ms,
                    revoked_at_ms = NULL",
                &[
                    &profile.namespace,
                    &profile.profile_id,
                    &profile.endpoint_origin,
                    &patterns,
                    &profile.credential_ref,
                    &profile.registered_by,
                    &profile.registered_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_hosted_routing_profiles(
        &self,
        namespace: &str,
    ) -> Result<Vec<HostedRoutingProfile>, String> {
        self.connection()?
            .query(
                "SELECT profile_id, endpoint_origin, model_patterns_json, credential_ref,
                        registered_by, registered_at_ms
                 FROM chisei_routing_profiles
                 WHERE namespace = $1 AND revoked_at_ms IS NULL
                 ORDER BY profile_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                Ok(HostedRoutingProfile {
                    namespace: namespace.into(),
                    profile_id: row.get(0),
                    endpoint_origin: row.get(1),
                    model_patterns: decode_model_patterns(&row.get::<_, String>(2))?,
                    credential_ref: row.get(3),
                    registered_by: row.get(4),
                    registered_at_ms: row.get(5),
                })
            })
            .collect()
    }

    pub fn revoke_hosted_routing_profile(
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
}
