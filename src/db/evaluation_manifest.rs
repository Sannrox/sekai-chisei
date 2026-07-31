//! SQLite persistence for content-bound resolved evaluation manifests.

use crate::chisei::evaluation_manifest::{EvaluationManifestReplay, ResolvedEvaluationManifest};
use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

impl SekaiDb {
    pub(crate) fn migrate_evaluation_manifests(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_evaluation_manifests (
                    manifest_digest TEXT PRIMARY KEY,
                    manifest_id TEXT NOT NULL UNIQUE,
                    namespace TEXT NOT NULL,
                    plan_version_id TEXT NOT NULL,
                    subject_identity TEXT NOT NULL,
                    evaluation_time_ms INTEGER NOT NULL,
                    body_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_manifests_namespace
                    ON chisei_evaluation_manifests(
                        namespace, plan_version_id, subject_identity, evaluation_time_ms
                    );
                CREATE TABLE IF NOT EXISTS chisei_evaluation_manifest_requests (
                    namespace TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, actor, request_id),
                    FOREIGN KEY(manifest_digest)
                        REFERENCES chisei_evaluation_manifests(manifest_digest)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_manifest_requests_manifest
                    ON chisei_evaluation_manifest_requests(manifest_digest);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn get_evaluation_manifest(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<ResolvedEvaluationManifest>, String> {
        self.conn()
            .query_row(
                "SELECT body_json FROM chisei_evaluation_manifests
                 WHERE manifest_digest=?1",
                params![manifest_digest],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|body| decode_manifest(&body))
            .transpose()
    }

    pub fn get_evaluation_manifest_for_request(
        &self,
        namespace: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<Option<EvaluationManifestReplay>, String> {
        self.conn()
            .query_row(
                "SELECT requests.request_digest, manifests.manifest_digest,
                        manifests.body_json
                 FROM chisei_evaluation_manifest_requests AS requests
                 JOIN chisei_evaluation_manifests AS manifests
                   ON manifests.manifest_digest=requests.manifest_digest
                 WHERE requests.namespace=?1
                   AND requests.actor=?2
                   AND requests.request_id=?3",
                params![namespace, actor, request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|(request_digest, manifest_digest, body)| {
                let manifest = decode_manifest(&body)?;
                if manifest.manifest_digest != manifest_digest {
                    return Err(
                        "persisted evaluation manifest digest does not match its storage key"
                            .into(),
                    );
                }
                Ok(EvaluationManifestReplay {
                    request_digest,
                    manifest,
                })
            })
            .transpose()
    }

    pub fn put_evaluation_manifest(
        &self,
        manifest: &ResolvedEvaluationManifest,
        request_id: &str,
        request_digest: &str,
    ) -> Result<ResolvedEvaluationManifest, String> {
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let stored = put_evaluation_manifest_in_transaction(
            &transaction,
            manifest,
            request_id,
            request_digest,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }
}

pub(crate) fn put_evaluation_manifest_in_transaction(
    transaction: &Transaction<'_>,
    manifest: &ResolvedEvaluationManifest,
    request_id: &str,
    request_digest: &str,
) -> Result<ResolvedEvaluationManifest, String> {
    if let Some(replay) = get_request_tx(
        transaction,
        &manifest.namespace,
        &manifest.resolved_by,
        request_id,
    )? {
        if replay.request_digest == request_digest
            && replay.manifest.manifest_digest == manifest.manifest_digest
        {
            return Ok(replay.manifest);
        }
        return Err("evaluation resolution request already exists with different content".into());
    }
    let stored_manifest =
        if let Some(existing) = get_manifest_tx(transaction, &manifest.manifest_digest)? {
            existing
        } else {
            let body_json = serde_json::to_string(manifest).map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO chisei_evaluation_manifests
                         (manifest_digest, manifest_id, namespace, plan_version_id,
                          subject_identity, evaluation_time_ms, body_json, created_at_ms)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        manifest.manifest_digest,
                        manifest.manifest_id,
                        manifest.namespace,
                        manifest.plan_version_id,
                        manifest.subject_identity,
                        manifest.evaluation_time_ms,
                        body_json,
                        manifest.created_at_ms,
                    ],
                )
                .map_err(|error| error.to_string())?;
            manifest.clone()
        };
    if stored_manifest.manifest_digest != manifest.manifest_digest {
        return Err("evaluation manifest digest conflicts with stored content".into());
    }
    transaction
        .execute(
            "INSERT INTO chisei_evaluation_manifest_requests
                 (namespace, actor, request_id, request_digest, manifest_digest, created_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                manifest.namespace,
                manifest.resolved_by,
                request_id,
                request_digest,
                stored_manifest.manifest_digest,
                manifest.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(stored_manifest)
}

fn get_manifest_tx(
    transaction: &Transaction<'_>,
    manifest_digest: &str,
) -> Result<Option<ResolvedEvaluationManifest>, String> {
    transaction
        .query_row(
            "SELECT body_json FROM chisei_evaluation_manifests
             WHERE manifest_digest=?1",
            params![manifest_digest],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|body| decode_manifest(&body))
        .transpose()
}

fn get_request_tx(
    transaction: &Transaction<'_>,
    namespace: &str,
    actor: &str,
    request_id: &str,
) -> Result<Option<EvaluationManifestReplay>, String> {
    transaction
        .query_row(
            "SELECT requests.request_digest, manifests.manifest_digest,
                    manifests.body_json
             FROM chisei_evaluation_manifest_requests AS requests
             JOIN chisei_evaluation_manifests AS manifests
               ON manifests.manifest_digest=requests.manifest_digest
             WHERE requests.namespace=?1
               AND requests.actor=?2
               AND requests.request_id=?3",
            params![namespace, actor, request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|(request_digest, manifest_digest, body)| {
            let manifest = decode_manifest(&body)?;
            if manifest.manifest_digest != manifest_digest {
                return Err(
                    "persisted evaluation manifest digest does not match its storage key".into(),
                );
            }
            Ok(EvaluationManifestReplay {
                request_digest,
                manifest,
            })
        })
        .transpose()
}

fn decode_manifest(body: &str) -> Result<ResolvedEvaluationManifest, String> {
    serde_json::from_str(body)
        .map_err(|error| format!("invalid persisted evaluation manifest: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_manifest::{
        MANIFEST_CONTRACT, RESOLVER_VERSION, ResolvedEvaluationNode, ResolvedEvaluatorBinding,
        ResolvedInputBinding, ResolvedInvariantBinding, prepare_manifest,
    };

    fn manifest() -> ResolvedEvaluationManifest {
        prepare_manifest(ResolvedEvaluationManifest {
            contract_version: MANIFEST_CONTRACT.into(),
            resolver_version: RESOLVER_VERSION.into(),
            manifest_id: String::new(),
            manifest_digest: String::new(),
            namespace: "acme".into(),
            plan_version_id: "plan:1".into(),
            plan_digest: format!("sha256:{}", "a".repeat(64)),
            subject_profile: "document/v1".into(),
            subject_identity: "document:42".into(),
            subject_content_digest: format!("sha256:{}", "b".repeat(64)),
            invariant_set_id: "set:1".into(),
            invariant_set_digest: format!("sha256:{}", "c".repeat(64)),
            invariant_profile_digest: format!("sha256:{}", "d".repeat(64)),
            evaluation_time_ms: 42,
            resolved_by: "local".into(),
            requirements: vec![],
            nodes: vec![ResolvedEvaluationNode {
                node_id: "schema".into(),
                evaluator: ResolvedEvaluatorBinding {
                    definition_id: "definition:1".into(),
                    definition_digest: format!("sha256:{}", "e".repeat(64)),
                    implementation_digest: format!("sha256:{}", "f".repeat(64)),
                    stochastic_policy: None,
                },
                depends_on_node_ids: vec![],
                input_bindings: vec![ResolvedInputBinding {
                    name: "subject".into(),
                    source_kind: "subject".into(),
                    schema_id: "schema://document/v1".into(),
                }],
                parameters_json: "{}".into(),
                invariants: vec![ResolvedInvariantBinding {
                    invariant_version_id: "invariant:1".into(),
                    content_digest: format!("sha256:{}", "1".repeat(64)),
                    predicate_kind: "schema_conforms".into(),
                    input_schema: "schema://document/v1".into(),
                    result_schema: "schema://pass-fail/v1".into(),
                    evidence_types: vec![],
                    provenance_evidence_object_ids: vec![],
                    waiver_version_ids: vec![],
                }],
                evidence_object_ids: vec![],
                classification: "required".into(),
            }],
            evidence: vec![],
            waivers: vec![],
            created_at_ms: 100,
        })
        .unwrap()
    }

    #[test]
    fn manifest_and_request_replay_are_immutable() {
        let db = SekaiDb::new(":memory:").unwrap();
        let manifest = manifest();
        let stored = db
            .put_evaluation_manifest(&manifest, "resolve-1", "request-digest")
            .unwrap();
        assert_eq!(stored, manifest);
        let replay = db
            .put_evaluation_manifest(&manifest, "resolve-1", "request-digest")
            .unwrap();
        assert_eq!(replay, manifest);
        assert_eq!(
            db.get_evaluation_manifest_for_request("acme", "local", "resolve-1")
                .unwrap()
                .unwrap()
                .manifest,
            manifest
        );
        assert!(
            db.put_evaluation_manifest(&manifest, "resolve-1", "changed")
                .unwrap_err()
                .contains("different content")
        );
    }
}
