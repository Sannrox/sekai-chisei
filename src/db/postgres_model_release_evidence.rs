//! PostgreSQL parity for model-release evidence (#1396).

use crate::chisei::model_release_evidence::{
    EvaluationTrustRoots, ModelEvaluationEvidence, ModelReleaseFeedback, ModelReleaseIdentity,
    ModelRuntimeEvidence,
};
use crate::db::postgres::PostgresDb;

fn identity_params(identity: &ModelReleaseIdentity) -> [&str; 5] {
    [
        identity.provider.as_str(),
        identity.model.as_str(),
        identity.profile_version.as_str(),
        identity.artifact_digest.as_str(),
        identity.endpoint.as_str(),
    ]
}

#[allow(clippy::too_many_arguments)]
fn decode_feedback(
    id: String,
    namespace: String,
    provider: String,
    model: String,
    profile_version: String,
    artifact_digest: String,
    endpoint: String,
    actor: String,
    note: String,
    recorded_at_ms: i64,
) -> ModelReleaseFeedback {
    ModelReleaseFeedback {
        id,
        namespace,
        identity: ModelReleaseIdentity {
            provider,
            model,
            profile_version,
            artifact_digest,
            endpoint,
        },
        actor,
        note,
        recorded_at_ms,
    }
}

impl PostgresDb {
    pub fn put_model_release_trust(
        &self,
        roots: &EvaluationTrustRoots,
        updated_at_ms: i64,
    ) -> Result<(), String> {
        roots.validate()?;
        let json = serde_json::to_string(roots).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_model_release_trust (id, roots_json, updated_at_ms)
                 VALUES (1, $1, $2)
                 ON CONFLICT (id) DO UPDATE SET
                    roots_json = EXCLUDED.roots_json,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[&json, &updated_at_ms],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_model_release_trust(&self) -> Result<Option<EvaluationTrustRoots>, String> {
        self.connection()?
            .query_opt(
                "SELECT roots_json FROM chisei_model_release_trust WHERE id = 1",
                &[],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let json: String = row.get(0);
                let roots: EvaluationTrustRoots =
                    serde_json::from_str(&json).map_err(|error| error.to_string())?;
                roots.validate()?;
                Ok(roots)
            })
            .transpose()
    }

    pub fn put_model_runtime_evidence(
        &self,
        evidence: &ModelRuntimeEvidence,
        ingested_at_ms: i64,
    ) -> Result<(), String> {
        evidence.validate()?;
        let json = serde_json::to_string(evidence).map_err(|error| error.to_string())?;
        let parts = identity_params(&evidence.identity);
        self.connection()?
            .execute(
                "INSERT INTO chisei_model_runtime_evidence (
                    provider, model, profile_version, artifact_digest, endpoint,
                    payload_json, ingested_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (provider, model, profile_version, artifact_digest, endpoint)
                 DO UPDATE SET
                    payload_json = EXCLUDED.payload_json,
                    ingested_at_ms = EXCLUDED.ingested_at_ms
                 WHERE (EXCLUDED.payload_json::jsonb ->> 'observed_at')::bigint
                    >= (chisei_model_runtime_evidence.payload_json::jsonb ->> 'observed_at')::bigint",
                &[
                    &parts[0],
                    &parts[1],
                    &parts[2],
                    &parts[3],
                    &parts[4],
                    &json,
                    &ingested_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_model_runtime_evidence(
        &self,
        identity: &ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        identity.validate()?;
        let parts = identity_params(identity);
        Ok(self
            .connection()?
            .query_opt(
                "SELECT payload_json FROM chisei_model_runtime_evidence
                 WHERE provider = $1 AND model = $2 AND profile_version = $3
                   AND artifact_digest = $4 AND endpoint = $5",
                &[&parts[0], &parts[1], &parts[2], &parts[3], &parts[4]],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0)))
    }

    pub fn put_model_evaluation_export(
        &self,
        evidence: &ModelEvaluationEvidence,
        exported_at_ms: i64,
    ) -> Result<(), String> {
        evidence.validate()?;
        let json = serde_json::to_string(evidence).map_err(|error| error.to_string())?;
        let parts = identity_params(&evidence.identity);
        self.connection()?
            .execute(
                "INSERT INTO chisei_model_evaluation_export (
                    provider, model, profile_version, artifact_digest, endpoint,
                    payload_json, exported_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (provider, model, profile_version, artifact_digest, endpoint)
                 DO UPDATE SET
                    payload_json = EXCLUDED.payload_json,
                    exported_at_ms = EXCLUDED.exported_at_ms",
                &[
                    &parts[0],
                    &parts[1],
                    &parts[2],
                    &parts[3],
                    &parts[4],
                    &json,
                    &exported_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_model_evaluation_export(
        &self,
        identity: &ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        identity.validate()?;
        let parts = identity_params(identity);
        Ok(self
            .connection()?
            .query_opt(
                "SELECT payload_json FROM chisei_model_evaluation_export
                 WHERE provider = $1 AND model = $2 AND profile_version = $3
                   AND artifact_digest = $4 AND endpoint = $5",
                &[&parts[0], &parts[1], &parts[2], &parts[3], &parts[4]],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0)))
    }

    pub fn put_model_release_feedback(&self, record: &ModelReleaseFeedback) -> Result<(), String> {
        record.validate()?;
        let parts = identity_params(&record.identity);
        self.connection()?
            .execute(
                "INSERT INTO chisei_model_release_feedback (
                    id, namespace, provider, model, profile_version, artifact_digest, endpoint,
                    actor, note, recorded_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT (id) DO UPDATE SET
                    namespace = EXCLUDED.namespace,
                    provider = EXCLUDED.provider,
                    model = EXCLUDED.model,
                    profile_version = EXCLUDED.profile_version,
                    artifact_digest = EXCLUDED.artifact_digest,
                    endpoint = EXCLUDED.endpoint,
                    actor = EXCLUDED.actor,
                    note = EXCLUDED.note,
                    recorded_at_ms = EXCLUDED.recorded_at_ms",
                &[
                    &record.id,
                    &record.namespace,
                    &parts[0],
                    &parts[1],
                    &parts[2],
                    &parts[3],
                    &parts[4],
                    &record.actor,
                    &record.note,
                    &record.recorded_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_model_release_feedback(
        &self,
        namespace: &str,
    ) -> Result<Vec<ModelReleaseFeedback>, String> {
        self.connection()?
            .query(
                "SELECT id, namespace, provider, model, profile_version, artifact_digest, endpoint,
                        actor, note, recorded_at_ms
                 FROM chisei_model_release_feedback
                 WHERE namespace = $1
                 ORDER BY recorded_at_ms, id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                Ok(decode_feedback(
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    row.get(3),
                    row.get(4),
                    row.get(5),
                    row.get(6),
                    row.get(7),
                    row.get(8),
                    row.get(9),
                ))
            })
            .collect()
    }
}
