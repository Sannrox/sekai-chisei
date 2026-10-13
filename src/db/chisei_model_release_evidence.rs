//! Model-release evidence and trust roots (#1396) on both community backends.

use crate::chisei::model_release_evidence::{
    EvaluationTrustRoots, ModelEvaluationEvidence, ModelReleaseFeedback, ModelReleaseIdentity,
    ModelRuntimeEvidence,
};
use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS chisei_model_release_trust (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    roots_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chisei_model_runtime_evidence (
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    ingested_at_ms INTEGER NOT NULL,
    PRIMARY KEY (provider, model, profile_version, artifact_digest, endpoint)
);
CREATE TABLE IF NOT EXISTS chisei_model_evaluation_export (
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    exported_at_ms INTEGER NOT NULL,
    PRIMARY KEY (provider, model, profile_version, artifact_digest, endpoint)
);
CREATE TABLE IF NOT EXISTS chisei_model_release_feedback (
    id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    actor TEXT NOT NULL,
    note TEXT NOT NULL,
    recorded_at_ms INTEGER NOT NULL
);
";

const ALTER_ROUTING: &[&str] = &[
    "ALTER TABLE chisei_routing_profiles ADD COLUMN require_runtime_evidence INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_provider TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_model TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_profile_version TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_artifact_digest TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE chisei_routing_profiles ADD COLUMN evidence_endpoint TEXT NOT NULL DEFAULT ''",
];

pub trait ChiseiModelReleaseEvidenceBackend: Send + Sync {
    fn put_model_release_trust(
        &self,
        roots: &EvaluationTrustRoots,
        updated_at_ms: i64,
    ) -> Result<(), String>;
    fn get_model_release_trust(&self) -> Result<Option<EvaluationTrustRoots>, String>;
    fn put_model_runtime_evidence(
        &self,
        evidence: &ModelRuntimeEvidence,
        ingested_at_ms: i64,
    ) -> Result<(), String>;
    fn get_model_runtime_evidence(
        &self,
        identity: &ModelReleaseIdentity,
    ) -> Result<Option<String>, String>;
    fn put_model_evaluation_export(
        &self,
        evidence: &ModelEvaluationEvidence,
        exported_at_ms: i64,
    ) -> Result<(), String>;
    fn get_model_evaluation_export(
        &self,
        identity: &ModelReleaseIdentity,
    ) -> Result<Option<String>, String>;
    fn put_model_release_feedback(&self, record: &ModelReleaseFeedback) -> Result<(), String>;
    fn list_model_release_feedback(
        &self,
        namespace: &str,
    ) -> Result<Vec<ModelReleaseFeedback>, String>;
}

impl SekaiDb {
    pub(crate) fn migrate_model_release_evidence(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())?;
        for statement in ALTER_ROUTING {
            conn.execute(statement, []).map(|_| ()).or_else(|error| {
                let text = error.to_string();
                if text.contains("duplicate column") {
                    Ok(())
                } else {
                    Err(text)
                }
            })?;
        }
        Ok(())
    }
}

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

impl ChiseiModelReleaseEvidenceBackend for SekaiDb {
    fn put_model_release_trust(
        &self,
        roots: &EvaluationTrustRoots,
        updated_at_ms: i64,
    ) -> Result<(), String> {
        roots.validate()?;
        let json = serde_json::to_string(roots).map_err(|error| error.to_string())?;
        self.conn()
            .execute(
                "INSERT INTO chisei_model_release_trust (id, roots_json, updated_at_ms)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT (id) DO UPDATE SET
                    roots_json = excluded.roots_json,
                    updated_at_ms = excluded.updated_at_ms",
                rusqlite::params![json, updated_at_ms],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn get_model_release_trust(&self) -> Result<Option<EvaluationTrustRoots>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare("SELECT roots_json FROM chisei_model_release_trust WHERE id = 1")
            .map_err(|error| error.to_string())?;
        match statement.query_row([], |row| row.get::<_, String>(0)) {
            Ok(json) => {
                let roots: EvaluationTrustRoots =
                    serde_json::from_str(&json).map_err(|error| error.to_string())?;
                roots.validate()?;
                Ok(Some(roots))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn put_model_runtime_evidence(
        &self,
        evidence: &ModelRuntimeEvidence,
        ingested_at_ms: i64,
    ) -> Result<(), String> {
        evidence.validate()?;
        let json = serde_json::to_string(evidence).map_err(|error| error.to_string())?;
        let parts = identity_params(&evidence.identity);
        self.conn()
            .execute(
                "INSERT INTO chisei_model_runtime_evidence (
                    provider, model, profile_version, artifact_digest, endpoint,
                    payload_json, ingested_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (provider, model, profile_version, artifact_digest, endpoint)
                 DO UPDATE SET
                    payload_json = excluded.payload_json,
                    ingested_at_ms = excluded.ingested_at_ms
                 WHERE CAST(json_extract(excluded.payload_json, '$.observed_at') AS INTEGER)
                    >= CAST(json_extract(chisei_model_runtime_evidence.payload_json, '$.observed_at') AS INTEGER)",
                rusqlite::params![
                    parts[0],
                    parts[1],
                    parts[2],
                    parts[3],
                    parts[4],
                    json,
                    ingested_at_ms
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn get_model_runtime_evidence(
        &self,
        identity: &ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        identity.validate()?;
        let parts = identity_params(identity);
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT payload_json FROM chisei_model_runtime_evidence
                 WHERE provider = ?1 AND model = ?2 AND profile_version = ?3
                   AND artifact_digest = ?4 AND endpoint = ?5",
            )
            .map_err(|error| error.to_string())?;
        match statement.query_row(parts, |row| row.get::<_, String>(0)) {
            Ok(json) => Ok(Some(json)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn put_model_evaluation_export(
        &self,
        evidence: &ModelEvaluationEvidence,
        exported_at_ms: i64,
    ) -> Result<(), String> {
        evidence.validate()?;
        let json = serde_json::to_string(evidence).map_err(|error| error.to_string())?;
        let parts = identity_params(&evidence.identity);
        self.conn()
            .execute(
                "INSERT INTO chisei_model_evaluation_export (
                    provider, model, profile_version, artifact_digest, endpoint,
                    payload_json, exported_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (provider, model, profile_version, artifact_digest, endpoint)
                 DO UPDATE SET
                    payload_json = excluded.payload_json,
                    exported_at_ms = excluded.exported_at_ms",
                rusqlite::params![
                    parts[0],
                    parts[1],
                    parts[2],
                    parts[3],
                    parts[4],
                    json,
                    exported_at_ms
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn get_model_evaluation_export(
        &self,
        identity: &ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        identity.validate()?;
        let parts = identity_params(identity);
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT payload_json FROM chisei_model_evaluation_export
                 WHERE provider = ?1 AND model = ?2 AND profile_version = ?3
                   AND artifact_digest = ?4 AND endpoint = ?5",
            )
            .map_err(|error| error.to_string())?;
        match statement.query_row(parts, |row| row.get::<_, String>(0)) {
            Ok(json) => Ok(Some(json)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn put_model_release_feedback(&self, record: &ModelReleaseFeedback) -> Result<(), String> {
        record.validate()?;
        let parts = identity_params(&record.identity);
        self.conn()
            .execute(
                "INSERT INTO chisei_model_release_feedback (
                    id, namespace, provider, model, profile_version, artifact_digest, endpoint,
                    actor, note, recorded_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT (id) DO UPDATE SET
                    namespace = excluded.namespace,
                    provider = excluded.provider,
                    model = excluded.model,
                    profile_version = excluded.profile_version,
                    artifact_digest = excluded.artifact_digest,
                    endpoint = excluded.endpoint,
                    actor = excluded.actor,
                    note = excluded.note,
                    recorded_at_ms = excluded.recorded_at_ms",
                rusqlite::params![
                    record.id,
                    record.namespace,
                    parts[0],
                    parts[1],
                    parts[2],
                    parts[3],
                    parts[4],
                    record.actor,
                    record.note,
                    record.recorded_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn list_model_release_feedback(
        &self,
        namespace: &str,
    ) -> Result<Vec<ModelReleaseFeedback>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT id, namespace, provider, model, profile_version, artifact_digest, endpoint,
                        actor, note, recorded_at_ms
                 FROM chisei_model_release_feedback
                 WHERE namespace = ?1
                 ORDER BY recorded_at_ms, id",
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
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(rows
            .into_iter()
            .map(|(id, ns, p, m, v, d, e, actor, note, at)| {
                decode_feedback(id, ns, p, m, v, d, e, actor, note, at)
            })
            .collect())
    }
}

impl ChiseiModelReleaseEvidenceBackend for PostgresDb {
    fn put_model_release_trust(
        &self,
        roots: &EvaluationTrustRoots,
        updated_at_ms: i64,
    ) -> Result<(), String> {
        PostgresDb::put_model_release_trust(self, roots, updated_at_ms)
    }
    fn get_model_release_trust(&self) -> Result<Option<EvaluationTrustRoots>, String> {
        PostgresDb::get_model_release_trust(self)
    }
    fn put_model_runtime_evidence(
        &self,
        evidence: &ModelRuntimeEvidence,
        ingested_at_ms: i64,
    ) -> Result<(), String> {
        PostgresDb::put_model_runtime_evidence(self, evidence, ingested_at_ms)
    }
    fn get_model_runtime_evidence(
        &self,
        identity: &ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        PostgresDb::get_model_runtime_evidence(self, identity)
    }
    fn put_model_evaluation_export(
        &self,
        evidence: &ModelEvaluationEvidence,
        exported_at_ms: i64,
    ) -> Result<(), String> {
        PostgresDb::put_model_evaluation_export(self, evidence, exported_at_ms)
    }
    fn get_model_evaluation_export(
        &self,
        identity: &ModelReleaseIdentity,
    ) -> Result<Option<String>, String> {
        PostgresDb::get_model_evaluation_export(self, identity)
    }
    fn put_model_release_feedback(&self, record: &ModelReleaseFeedback) -> Result<(), String> {
        PostgresDb::put_model_release_feedback(self, record)
    }
    fn list_model_release_feedback(
        &self,
        namespace: &str,
    ) -> Result<Vec<ModelReleaseFeedback>, String> {
        PostgresDb::list_model_release_feedback(self, namespace)
    }
}
