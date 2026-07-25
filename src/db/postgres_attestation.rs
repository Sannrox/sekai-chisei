use crate::db::postgres::PostgresDb;
use crate::sekai::attestation::{
    AttestationVerification, EVIDENCE_ATTESTATION_HASH, EVIDENCE_ATTESTATION_ID, PolicyAttestation,
    attestation_content_hash, policy_version, replay_decision,
};
use crate::sekai::audit::Decision;

impl PostgresDb {
    pub fn record_decision_with_attestation(
        &self,
        decision: &Decision,
        attestation: Option<&PolicyAttestation>,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if let Some(value) = attestation {
            insert_attestation(&mut tx, value)?;
        }
        // Decision + optional attestation commit in one transaction.
        crate::db::postgres_decision::insert_chained_decision(&mut tx, decision)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn get_attestation(&self, id: &str) -> Result<Option<PolicyAttestation>, String> {
        self.connection()?
            .query_opt(
                "SELECT id,decision_id,policy_kind,policy_scope,policy_version,policy_snapshot,
                        inputs,decision,content_hash,created
                 FROM sekai_attestations WHERE id=$1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_attestation)
            .transpose()
    }

    pub fn list_attestations(
        &self,
        decision_id: Option<&str>,
        policy_scope: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<PolicyAttestation>, String> {
        self.connection()?
            .query(
                "SELECT id,decision_id,policy_kind,policy_scope,policy_version,policy_snapshot,
                        inputs,decision,content_hash,created
                 FROM sekai_attestations
                 WHERE ($1::text IS NULL OR decision_id=$1)
                   AND ($2::text IS NULL OR policy_scope=$2)
                 ORDER BY created DESC,id DESC LIMIT $3 OFFSET $4",
                &[
                    &decision_id,
                    &policy_scope,
                    &if limit > 0 { limit.min(500) } else { 100 },
                    &offset.max(0),
                ],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_attestation)
            .collect()
    }

    pub fn verify_attestation(&self, id: &str) -> Result<AttestationVerification, String> {
        let Some(attestation) = self.get_attestation(id)? else {
            return Ok(AttestationVerification {
                ok: false,
                found: false,
                hash_ok: false,
                replay_ok: false,
                replayed_decision: String::new(),
                decision_linked: false,
                error: format!("attestation {id} not found"),
            });
        };
        let hash_ok = attestation_content_hash(&attestation) == attestation.content_hash
            && policy_version(&attestation.policy_snapshot) == attestation.policy_version;
        let (replay_ok, replayed_decision) = replay_decision(&attestation);
        let decision_linked = self
            .connection()?
            .query_opt(
                "SELECT evidence FROM sekai_decisions WHERE id=$1",
                &[&attestation.decision_id],
            )
            .map_err(|error| error.to_string())?
            .and_then(|row| {
                serde_json::from_str::<std::collections::HashMap<String, String>>(
                    row.get::<_, String>(0).as_str(),
                )
                .ok()
            })
            .is_some_and(|evidence| {
                evidence.get(EVIDENCE_ATTESTATION_ID) == Some(&attestation.id)
                    && evidence.get(EVIDENCE_ATTESTATION_HASH) == Some(&attestation.content_hash)
            });
        let mut errors = Vec::new();
        if !hash_ok {
            errors.push("content or policy-version hash mismatch: record was altered");
        }
        if !replay_ok {
            errors.push("recorded decision does not match policy replay");
        }
        if !decision_linked {
            errors.push("audit decision missing or does not bind this attestation");
        }
        Ok(AttestationVerification {
            ok: hash_ok && replay_ok && decision_linked,
            found: true,
            hash_ok,
            replay_ok,
            replayed_decision,
            decision_linked,
            error: errors.join("; "),
        })
    }
}

fn insert_attestation(
    tx: &mut postgres::Transaction<'_>,
    value: &PolicyAttestation,
) -> Result<(), String> {
    let inputs = serde_json::to_string(&value.inputs).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_attestations
         (id,decision_id,policy_kind,policy_scope,policy_version,policy_snapshot,
          inputs,decision,content_hash,created)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        &[
            &value.id,
            &value.decision_id,
            &value.policy_kind,
            &value.policy_scope,
            &value.policy_version,
            &value.policy_snapshot,
            &inputs,
            &value.decision,
            &value.content_hash,
            &value.created,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn row_to_attestation(row: postgres::Row) -> Result<PolicyAttestation, String> {
    Ok(PolicyAttestation {
        id: row.get(0),
        decision_id: row.get(1),
        policy_kind: row.get(2),
        policy_scope: row.get(3),
        policy_version: row.get(4),
        policy_snapshot: row.get(5),
        inputs: serde_json::from_str(row.get::<_, String>(6).as_str())
            .map_err(|error| error.to_string())?,
        decision: row.get(7),
        content_hash: row.get(8),
        created: row.get(9),
    })
}
