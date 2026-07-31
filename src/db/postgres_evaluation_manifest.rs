//! PostgreSQL persistence for content-bound resolved evaluation manifests.

use crate::chisei::evaluation_manifest::{EvaluationManifestReplay, ResolvedEvaluationManifest};
use crate::db::postgres::PostgresDb;
use postgres::GenericClient;

impl PostgresDb {
    pub fn get_evaluation_manifest(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<ResolvedEvaluationManifest>, String> {
        let mut connection = self.connection()?;
        get_manifest(&mut *connection, manifest_digest)
    }

    pub fn get_evaluation_manifest_for_request(
        &self,
        namespace: &str,
        actor: &str,
        request_id: &str,
    ) -> Result<Option<EvaluationManifestReplay>, String> {
        let mut connection = self.connection()?;
        get_request(&mut *connection, namespace, actor, request_id)
    }

    pub fn put_evaluation_manifest(
        &self,
        manifest: &ResolvedEvaluationManifest,
        request_id: &str,
        request_digest: &str,
    ) -> Result<ResolvedEvaluationManifest, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let stored = put_evaluation_manifest_in_transaction(
            &mut transaction,
            manifest,
            request_id,
            request_digest,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }
}

pub(crate) fn put_evaluation_manifest_in_transaction(
    transaction: &mut postgres::Transaction<'_>,
    manifest: &ResolvedEvaluationManifest,
    request_id: &str,
    request_digest: &str,
) -> Result<ResolvedEvaluationManifest, String> {
    let lock_key = format!(
        "{}\0{}\0{}",
        manifest.namespace, manifest.resolved_by, request_id
    );
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
    // Different request IDs may resolve to the same content digest. Lock
    // that immutable identity as well so concurrent deduplication cannot
    // race on the manifest primary key.
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&manifest.manifest_digest],
        )
        .map_err(|error| error.to_string())?;
    if let Some(replay) = get_request(
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
        if let Some(existing) = get_manifest(transaction, &manifest.manifest_digest)? {
            existing
        } else {
            let body_json = serde_json::to_string(manifest).map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO chisei_evaluation_manifests
                         (manifest_digest, manifest_id, namespace, plan_version_id,
                          subject_identity, evaluation_time_ms, body_json, created_at_ms)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                    &[
                        &manifest.manifest_digest,
                        &manifest.manifest_id,
                        &manifest.namespace,
                        &manifest.plan_version_id,
                        &manifest.subject_identity,
                        &manifest.evaluation_time_ms,
                        &body_json,
                        &manifest.created_at_ms,
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
                 VALUES ($1,$2,$3,$4,$5,$6)",
            &[
                &manifest.namespace,
                &manifest.resolved_by,
                &request_id,
                &request_digest,
                &stored_manifest.manifest_digest,
                &manifest.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(stored_manifest)
}

fn get_manifest(
    client: &mut impl GenericClient,
    manifest_digest: &str,
) -> Result<Option<ResolvedEvaluationManifest>, String> {
    client
        .query_opt(
            "SELECT body_json FROM chisei_evaluation_manifests
             WHERE manifest_digest=$1",
            &[&manifest_digest],
        )
        .map_err(|error| error.to_string())?
        .map(|row| decode_manifest(row.get(0)))
        .transpose()
}

fn get_request(
    client: &mut impl GenericClient,
    namespace: &str,
    actor: &str,
    request_id: &str,
) -> Result<Option<EvaluationManifestReplay>, String> {
    client
        .query_opt(
            "SELECT requests.request_digest, manifests.manifest_digest,
                    manifests.body_json
             FROM chisei_evaluation_manifest_requests AS requests
             JOIN chisei_evaluation_manifests AS manifests
               ON manifests.manifest_digest=requests.manifest_digest
             WHERE requests.namespace=$1
               AND requests.actor=$2
               AND requests.request_id=$3",
            &[&namespace, &actor, &request_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            let manifest_digest: String = row.get(1);
            let manifest = decode_manifest(row.get(2))?;
            if manifest.manifest_digest != manifest_digest {
                return Err(
                    "persisted evaluation manifest digest does not match its storage key".into(),
                );
            }
            Ok(EvaluationManifestReplay {
                request_digest: row.get(0),
                manifest,
            })
        })
        .transpose()
}

fn decode_manifest(body: &str) -> Result<ResolvedEvaluationManifest, String> {
    serde_json::from_str(body)
        .map_err(|error| format!("invalid persisted evaluation manifest: {error}"))
}
