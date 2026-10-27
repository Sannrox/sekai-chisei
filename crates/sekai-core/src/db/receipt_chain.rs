//! Chisei persistence for the signed per-namespace receipt chain (#1449).

use rusqlite::{Connection, OptionalExtension, params};

use crate::db::sekai::SekaiDb;
use sekai_domain::receipt::{OperationReceipt, ReceiptEventKind};
use sekai_types::governed_transform::{TransformRun, redact_run_partition_receipts};
use sekai_types::receipt_chain::{
    BUNDLE_VERSION, CHECKPOINT_INTERVAL, ChainEntry, Checkpoint, CheckpointKind, DIGEST_ALGORITHM,
    GENESIS_HEAD_HASH, PublishedKey, ReceiptChainBundle, ReceiptKind, SIGNATURE_ALGORITHM,
    SigningKeySet, authenticate_checkpoint, entry_hash, verify_bundle,
};

thread_local! {
    static TEST_SIGNER: std::cell::RefCell<Option<SigningKeySet>> =
        const { std::cell::RefCell::new(None) };
}

/// Installs a process-thread signer for tests. Drop the guard to clear it.
#[cfg(test)]
pub struct ReceiptChainSignerGuard {
    _private: (),
}

#[cfg(test)]
impl Drop for ReceiptChainSignerGuard {
    fn drop(&mut self) {
        TEST_SIGNER.with(|cell| {
            cell.replace(None);
        });
    }
}

#[cfg(test)]
pub fn install_test_signer(keys: SigningKeySet) -> ReceiptChainSignerGuard {
    TEST_SIGNER.with(|cell| {
        cell.replace(Some(keys));
    });
    ReceiptChainSignerGuard { _private: () }
}

pub fn current_signer() -> Result<Option<SigningKeySet>, String> {
    if let Some(keys) = TEST_SIGNER.with(|cell| cell.borrow().clone()) {
        return Ok(Some(keys));
    }
    signer_from_env()
}

pub fn signer_from_env() -> Result<Option<SigningKeySet>, String> {
    let mut keys = match std::env::var("CHISEI_RECEIPT_CHAIN_SIGNING_KEY") {
        Ok(value) if value.trim().is_empty() => return Ok(None),
        Ok(value) => SigningKeySet::from_seed_hex(value.trim(), 0)?,
        Err(_) => return Ok(None),
    };
    if let Ok(previous) = std::env::var("CHISEI_RECEIPT_CHAIN_PREVIOUS_PUBLIC_KEYS") {
        for value in previous.split(',') {
            let value = value.trim();
            if !value.is_empty() {
                keys.trust_public_key(value, 0)?;
            }
        }
    }
    Ok(Some(keys))
}

pub fn kind_for_operation_receipt(receipt: &OperationReceipt) -> ReceiptKind {
    if receipt
        .events
        .iter()
        .any(|event| event.kind == ReceiptEventKind::ModelCalled)
    {
        ReceiptKind::AgentTurn
    } else {
        ReceiptKind::Action
    }
}

pub const SQLITE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS chisei_receipt_chain (
    namespace TEXT NOT NULL,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, seq)
);
CREATE INDEX IF NOT EXISTS idx_chisei_receipt_chain_receipt
    ON chisei_receipt_chain(namespace, receipt_id);
CREATE TABLE IF NOT EXISTS chisei_receipt_chain_checkpoints (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    head_seq INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, kind, head_seq)
);
CREATE TABLE IF NOT EXISTS chisei_receipt_chain_keys (
    key_id TEXT PRIMARY KEY,
    public_key_hex TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    retired_at_ms INTEGER
);
";

impl SekaiDb {
    pub fn migrate_receipt_chain(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(SQLITE_SCHEMA)
            .map_err(|error| error.to_string())
    }

    pub fn export_receipt_chain(&self, namespace: &str) -> Result<ReceiptChainBundle, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let bundle = load_bundle(&tx, namespace)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(bundle)
    }

    pub fn append_operation_receipt_chain(
        &self,
        conn: &Connection,
        receipt: &OperationReceipt,
    ) -> Result<(), String> {
        let Some(keys) = current_signer()? else {
            return Ok(());
        };
        let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
        append_receipt(
            conn,
            &keys,
            &receipt.namespace,
            kind_for_operation_receipt(receipt),
            &receipt.operation_id,
            &receipt_json,
            receipt.started_at_ms,
        )
    }
}

pub fn append_transform_run_chain(conn: &Connection, run: &TransformRun) -> Result<(), String> {
    let Some(keys) = current_signer()? else {
        return Ok(());
    };
    let receipt_json = serde_json::to_string(run).map_err(|error| error.to_string())?;
    append_receipt(
        conn,
        &keys,
        &run.namespace,
        ReceiptKind::TransformRun,
        &run.run_id,
        &receipt_json,
        run.created_at_ms,
    )
}

/// Rewrites chained transform-run bodies after dataset field redaction and
/// re-signs the namespace so historical revisions do not keep partition
/// selectors or member digests.
pub fn redact_transform_run_chain(conn: &Connection, dataset_id: &str) -> Result<(), String> {
    if !chain_table_present(conn) {
        return Ok(());
    }
    let pending = pending_transform_redactions(conn, dataset_id)?;
    if pending.is_empty() {
        return Ok(());
    }
    let Some(keys) = current_signer()? else {
        return Err(
            "receipt chain signing key is required to redact chained transform receipts".into(),
        );
    };
    persist_published_keys(conn, &keys)?;
    let mut namespaces = Vec::new();
    for (namespace, _, _) in &pending {
        if !namespaces.iter().any(|seen| seen == namespace) {
            namespaces.push(namespace.clone());
        }
    }
    for namespace in &namespaces {
        authenticate_namespace(conn, &keys, namespace)?;
    }
    for (namespace, seq, updated) in pending {
        conn.execute(
            "UPDATE chisei_receipt_chain SET receipt_json = ?1
             WHERE namespace = ?2 AND seq = ?3",
            params![updated, namespace, seq],
        )
        .map_err(|error| error.to_string())?;
    }
    for namespace in namespaces {
        resign_namespace(conn, &keys, &namespace)?;
    }
    Ok(())
}

fn pending_transform_redactions(
    conn: &Connection,
    dataset_id: &str,
) -> Result<Vec<(String, i64, String)>, String> {
    let rows = {
        let mut stmt = conn
            .prepare(
                "SELECT namespace, seq, receipt_json FROM chisei_receipt_chain
                 WHERE kind = 'transform_run'",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
    };
    let mut pending = Vec::new();
    for (namespace, seq, receipt_json) in rows {
        let Ok(mut run) = serde_json::from_str::<TransformRun>(&receipt_json) else {
            continue;
        };
        if !redact_run_partition_receipts(
            dataset_id,
            &mut run.input_partitions,
            &mut run.output_partitions,
        ) {
            continue;
        }
        pending.push((
            namespace,
            seq,
            serde_json::to_string(&run).map_err(|error| error.to_string())?,
        ));
    }
    Ok(pending)
}

fn authenticate_namespace(
    conn: &Connection,
    keys: &SigningKeySet,
    namespace: &str,
) -> Result<(), String> {
    let bundle = load_bundle(conn, namespace)?;
    let trusted: Vec<String> = keys
        .published_keys()
        .into_iter()
        .map(|key| key.public_key_hex)
        .collect();
    let trusted_refs: Vec<&str> = trusted.iter().map(String::as_str).collect();
    verify_bundle(&bundle, &trusted_refs).map_err(|error| error.to_string())
}

fn resign_namespace(
    conn: &Connection,
    keys: &SigningKeySet,
    namespace: &str,
) -> Result<(), String> {
    let rows = {
        let mut stmt = conn
            .prepare(
                "SELECT seq, kind, receipt_id, receipt_json, created_at_ms
                 FROM chisei_receipt_chain WHERE namespace = ?1 ORDER BY seq",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![namespace], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
    };
    conn.execute(
        "DELETE FROM chisei_receipt_chain_checkpoints
         WHERE namespace = ?1 AND kind IN ('latest', 'periodic', 'genesis')",
        params![namespace],
    )
    .map_err(|error| error.to_string())?;
    insert_checkpoint(
        conn,
        &keys.issued_checkpoint(
            namespace,
            CheckpointKind::Genesis,
            0,
            GENESIS_HEAD_HASH,
            0,
            0,
        )?,
    )?;
    let mut prev_hash = GENESIS_HEAD_HASH.to_string();
    let mut head_seq = 0_i64;
    let mut head_hash = GENESIS_HEAD_HASH.to_string();
    let mut now_ms = 0_i64;
    for (seq, kind, receipt_id, receipt_json, created_at_ms) in rows {
        let kind = ReceiptKind::parse(&kind)?;
        let entry_hash = entry_hash(
            seq,
            &prev_hash,
            namespace,
            kind,
            &receipt_id,
            &receipt_json,
            created_at_ms,
        );
        let key_id = keys.current_key_id();
        let signature = keys.sign_entry(&entry_hash);
        conn.execute(
            "UPDATE chisei_receipt_chain
             SET prev_hash = ?1, entry_hash = ?2, key_id = ?3, signature = ?4
             WHERE namespace = ?5 AND seq = ?6",
            params![prev_hash, entry_hash, key_id, signature, namespace, seq],
        )
        .map_err(|error| error.to_string())?;
        if seq % CHECKPOINT_INTERVAL == 0 {
            insert_checkpoint(
                conn,
                &keys.issued_checkpoint(
                    namespace,
                    CheckpointKind::Periodic,
                    seq,
                    &entry_hash,
                    seq,
                    created_at_ms,
                )?,
            )?;
        }
        prev_hash = entry_hash.clone();
        head_seq = seq;
        head_hash = entry_hash;
        now_ms = created_at_ms;
    }
    upsert_latest(conn, keys, namespace, head_seq, &head_hash, now_ms)
}

pub fn append_receipt(
    conn: &Connection,
    keys: &SigningKeySet,
    namespace: &str,
    kind: ReceiptKind,
    receipt_id: &str,
    receipt_json: &str,
    now_ms: i64,
) -> Result<(), String> {
    if !chain_table_present(conn) {
        return Ok(());
    }
    persist_published_keys(conn, keys)?;
    let latest_body: Option<String> = conn
        .query_row(
            "SELECT receipt_json FROM chisei_receipt_chain
             WHERE namespace = ?1 AND receipt_id = ?2
             ORDER BY seq DESC LIMIT 1",
            params![namespace, receipt_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if latest_body.as_deref() == Some(receipt_json) {
        return Ok(());
    }
    ensure_genesis(conn, keys, namespace, now_ms)?;
    let max_seq: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chisei_receipt_chain WHERE namespace = ?1",
            params![namespace],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    assert_signed_head(conn, keys, namespace, max_seq)?;
    let seq = max_seq + 1;
    let prev_hash = if max_seq == 0 {
        GENESIS_HEAD_HASH.to_string()
    } else {
        conn.query_row(
            "SELECT entry_hash FROM chisei_receipt_chain WHERE namespace = ?1 AND seq = ?2",
            params![namespace, max_seq],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?
    };
    let entry_hash = entry_hash(
        seq,
        &prev_hash,
        namespace,
        kind,
        receipt_id,
        receipt_json,
        now_ms,
    );
    let key_id = keys.current_key_id();
    let signature = keys.sign_entry(&entry_hash);
    conn.execute(
        "INSERT INTO chisei_receipt_chain(
            namespace, seq, kind, receipt_id, receipt_json, prev_hash, entry_hash,
            key_id, signature, created_at_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            namespace,
            seq,
            kind.as_str(),
            receipt_id,
            receipt_json,
            prev_hash,
            entry_hash,
            key_id,
            signature,
            now_ms
        ],
    )
    .map_err(|error| error.to_string())?;
    upsert_latest(conn, keys, namespace, seq, &entry_hash, now_ms)?;
    if seq % CHECKPOINT_INTERVAL == 0 {
        insert_checkpoint(
            conn,
            &keys.issued_checkpoint(
                namespace,
                CheckpointKind::Periodic,
                seq,
                &entry_hash,
                seq,
                now_ms,
            )?,
        )?;
    }
    Ok(())
}

pub fn load_bundle(conn: &Connection, namespace: &str) -> Result<ReceiptChainBundle, String> {
    if namespace.is_empty() {
        return Err("receipt chain namespace must be non-empty".into());
    }
    if !chain_table_present(conn) {
        return Err("receipt chain is not migrated on this store".into());
    }
    let keys = load_keys(conn)?;
    let checkpoints = load_checkpoints(conn, namespace)?;
    if checkpoints.is_empty() {
        return Err(format!("no receipt chain for namespace {namespace}"));
    }
    let mut entries = Vec::new();
    let mut stmt = conn
        .prepare(
            "SELECT seq, kind, receipt_id, receipt_json, prev_hash, entry_hash,
                    key_id, signature, created_at_ms
             FROM chisei_receipt_chain WHERE namespace = ?1 ORDER BY seq",
        )
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map(params![namespace], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    for row in rows {
        let (
            seq,
            kind,
            receipt_id,
            receipt_json,
            prev_hash,
            entry_hash,
            key_id,
            signature,
            created_at_ms,
        ) = row.map_err(|error| error.to_string())?;
        entries.push(ChainEntry {
            seq,
            namespace: namespace.to_string(),
            kind: ReceiptKind::parse(&kind)?,
            receipt_id,
            receipt_json,
            prev_hash,
            entry_hash,
            key_id,
            signature,
            created_at_ms,
        });
    }
    Ok(ReceiptChainBundle {
        bundle_version: BUNDLE_VERSION.into(),
        namespace: namespace.into(),
        digest_algorithm: DIGEST_ALGORITHM.into(),
        signature_algorithm: SIGNATURE_ALGORITHM.into(),
        keys,
        checkpoints,
        entries,
    })
}

fn chain_table_present(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chisei_receipt_chain'",
        [],
        |_| Ok(()),
    )
    .is_ok()
}

fn persist_published_keys(conn: &Connection, keys: &SigningKeySet) -> Result<(), String> {
    for key in keys.published_keys() {
        conn.execute(
            "INSERT INTO chisei_receipt_chain_keys(key_id, public_key_hex, created_at_ms, retired_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key_id) DO NOTHING",
            params![
                key.key_id,
                key.public_key_hex,
                key.created_at_ms,
                key.retired_at_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        if let Some(retired_at_ms) = key.retired_at_ms {
            conn.execute(
                "UPDATE chisei_receipt_chain_keys SET retired_at_ms = ?1
                 WHERE key_id = ?2 AND retired_at_ms IS NULL",
                params![retired_at_ms, key.key_id],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn ensure_genesis(
    conn: &Connection,
    keys: &SigningKeySet,
    namespace: &str,
    now_ms: i64,
) -> Result<(), String> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM chisei_receipt_chain_checkpoints
             WHERE namespace = ?1 AND kind = 'genesis'",
            params![namespace],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if exists.is_some() {
        return Ok(());
    }
    insert_checkpoint(
        conn,
        &keys.issued_checkpoint(
            namespace,
            CheckpointKind::Genesis,
            0,
            GENESIS_HEAD_HASH,
            0,
            now_ms,
        )?,
    )?;
    insert_checkpoint(
        conn,
        &keys.issued_checkpoint(
            namespace,
            CheckpointKind::Latest,
            0,
            GENESIS_HEAD_HASH,
            0,
            now_ms,
        )?,
    )
}

fn upsert_latest(
    conn: &Connection,
    keys: &SigningKeySet,
    namespace: &str,
    head_seq: i64,
    head_hash: &str,
    now_ms: i64,
) -> Result<(), String> {
    conn.execute(
        "DELETE FROM chisei_receipt_chain_checkpoints WHERE namespace = ?1 AND kind = 'latest'",
        params![namespace],
    )
    .map_err(|error| error.to_string())?;
    insert_checkpoint(
        conn,
        &keys.issued_checkpoint(
            namespace,
            CheckpointKind::Latest,
            head_seq,
            head_hash,
            head_seq,
            now_ms,
        )?,
    )
}

fn insert_checkpoint(conn: &Connection, checkpoint: &Checkpoint) -> Result<(), String> {
    conn.execute(
        "INSERT INTO chisei_receipt_chain_checkpoints(
            namespace, kind, head_seq, head_hash, entry_count, key_id, signature, created_at_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            checkpoint.namespace,
            checkpoint.kind.as_str(),
            checkpoint.head_seq,
            checkpoint.head_hash,
            checkpoint.entry_count,
            checkpoint.key_id,
            checkpoint.signature,
            checkpoint.created_at_ms
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn assert_signed_head(
    conn: &Connection,
    keys: &SigningKeySet,
    namespace: &str,
    max_seq: i64,
) -> Result<(), String> {
    let latest = conn
        .query_row(
            "SELECT kind, head_seq, head_hash, entry_count, key_id, signature, created_at_ms
             FROM chisei_receipt_chain_checkpoints
             WHERE namespace = ?1 AND kind = 'latest'",
            params![namespace],
            |row| {
                Ok(Checkpoint {
                    namespace: namespace.to_string(),
                    kind: CheckpointKind::Latest,
                    head_seq: row.get(1)?,
                    head_hash: row.get(2)?,
                    entry_count: row.get(3)?,
                    key_id: row.get(4)?,
                    signature: row.get(5)?,
                    created_at_ms: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(latest) = latest else {
        return Err("receipt chain latest checkpoint is missing".into());
    };
    authenticate_checkpoint(&latest, &keys.published_keys())?;
    if latest.head_seq != max_seq || latest.entry_count != max_seq {
        return Err(format!(
            "signed head seq {} does not match stored seq {max_seq}",
            latest.head_seq
        ));
    }
    let expected_hash = if max_seq == 0 {
        GENESIS_HEAD_HASH.to_string()
    } else {
        conn.query_row(
            "SELECT entry_hash FROM chisei_receipt_chain WHERE namespace = ?1 AND seq = ?2",
            params![namespace, max_seq],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?
    };
    if latest.head_hash != expected_hash {
        return Err("signed head hash does not match the stored chain head".into());
    }
    Ok(())
}

fn load_keys(conn: &Connection) -> Result<Vec<PublishedKey>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT key_id, public_key_hex, created_at_ms, retired_at_ms
             FROM chisei_receipt_chain_keys ORDER BY created_at_ms, key_id",
        )
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok(PublishedKey {
                key_id: row.get(0)?,
                public_key_hex: row.get(1)?,
                created_at_ms: row.get(2)?,
                retired_at_ms: row.get(3)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.map(|row| row.map_err(|error| error.to_string()))
        .collect()
}

fn load_checkpoints(conn: &Connection, namespace: &str) -> Result<Vec<Checkpoint>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT kind, head_seq, head_hash, entry_count, key_id, signature, created_at_ms
             FROM chisei_receipt_chain_checkpoints WHERE namespace = ?1
             ORDER BY created_at_ms, head_seq",
        )
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map(params![namespace], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut checkpoints = Vec::new();
    for row in rows {
        let (kind, head_seq, head_hash, entry_count, key_id, signature, created_at_ms) =
            row.map_err(|error| error.to_string())?;
        checkpoints.push(Checkpoint {
            namespace: namespace.to_string(),
            kind: parse_checkpoint_kind(&kind)?,
            head_seq,
            head_hash,
            entry_count,
            key_id,
            signature,
            created_at_ms,
        });
    }
    Ok(checkpoints)
}

fn parse_checkpoint_kind(value: &str) -> Result<CheckpointKind, String> {
    match value {
        "genesis" => Ok(CheckpointKind::Genesis),
        "periodic" => Ok(CheckpointKind::Periodic),
        "latest" => Ok(CheckpointKind::Latest),
        other => Err(format!("unknown checkpoint kind {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::governed_transform::{
        insert_transform_run, redact_transform_partition_receipts, stamp_run_dispatch,
    };
    use rusqlite::TransactionBehavior;
    use sekai_domain::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    };
    use sekai_types::governed_transform::{
        ISOLATED_CLASS, TRANSFORM_WORK_FAILED, TRANSFORM_WORK_PENDING, TransformPartition,
        TransformRun,
    };
    use sekai_types::receipt_chain::verify_bundle;
    use std::collections::BTreeMap;

    const SEED: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const SEED_B: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn sample_receipt(id: &str, kind: ReceiptEventKind) -> OperationReceipt {
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: id.into(),
            parent_operation_id: None,
            namespace: "ns".into(),
            operation_class: "governed_action_instance".into(),
            initiating_actor: "alice".into(),
            schema_version: "action-instance/v1".into(),
            policy_version: "implicit-allow".into(),
            started_at_ms: 10,
            completed_at_ms: Some(11),
            events: vec![OperationReceiptEvent {
                event_id: format!("{id}-e1"),
                operation_id: id.into(),
                parent_event_id: None,
                timestamp_ms: 10,
                kind,
                surface: kind.surface(),
                actor: "alice".into(),
                references: Vec::new(),
                attributes: BTreeMap::new(),
            }],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: None,
        }
    }

    fn isolated_run(id: &str) -> TransformRun {
        TransformRun {
            input_versions: Default::default(),
            run_id: id.into(),
            namespace: "ns".into(),
            transform_id: "tf-1".into(),
            definition_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            input_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            output_digest:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            last_input_row_id: 1,
            incremental: false,
            quarantined: false,
            quality_rule: String::new(),
            rows_in: 1,
            rows_out: 1,
            lineage_parent: String::new(),
            created_at_ms: 20,
            markings_in: String::new(),
            markings_out: String::new(),
            profile: ISOLATED_CLASS.into(),
            engine: "python".into(),
            runtime_image: "python:3.12".into(),
            dispatch_status: TRANSFORM_WORK_PENDING.into(),
            trigger_cause: "manual".into(),
            trigger_ref: String::new(),
            input_partitions: Vec::new(),
            output_partitions: Vec::new(),
        }
    }

    #[test]
    fn sqlite_export_verifies_action_agent_and_isolated_transform() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys.clone());
        db.put_operation_receipt(&sample_receipt(
            "op-action",
            ReceiptEventKind::ActionPerformed,
        ))
        .unwrap();
        db.put_operation_receipt(&sample_receipt("op-agent", ReceiptEventKind::ModelCalled))
            .unwrap();
        {
            let conn = db.conn();
            append_transform_run_chain(&conn, &isolated_run("run-iso")).unwrap();
        }
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex = keys.current_public_key_hex();
        verify_bundle(&bundle, &[hex.as_str()]).expect("persisted bundle verifies");
        assert_eq!(bundle.entries.len(), 3);
        assert_eq!(bundle.entries[0].kind, ReceiptKind::Action);
        assert_eq!(bundle.entries[1].kind, ReceiptKind::AgentTurn);
        assert_eq!(bundle.entries[2].kind, ReceiptKind::TransformRun);
    }

    #[test]
    fn sqlite_transform_run_updates_append_a_revision() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys.clone());
        let mut run = isolated_run("run-iso");
        {
            let conn = db.conn();
            append_transform_run_chain(&conn, &run).unwrap();
            run.rows_out = 9;
            append_transform_run_chain(&conn, &run).unwrap();
        }
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex = keys.current_public_key_hex();
        verify_bundle(&bundle, &[hex.as_str()]).unwrap();
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(bundle.entries[0].receipt_id, "run-iso");
        assert_eq!(bundle.entries[1].receipt_id, "run-iso");
    }

    #[test]
    fn sqlite_transform_dispatch_status_appends_a_revision() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys.clone());
        let run = isolated_run("run-iso");
        {
            let mut conn = db.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_transform_run(&tx, &run).unwrap();
            stamp_run_dispatch(&tx, &run.run_id, TRANSFORM_WORK_FAILED).unwrap();
            tx.commit().unwrap();
        }
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex = keys.current_public_key_hex();
        verify_bundle(&bundle, &[hex.as_str()]).unwrap();
        assert_eq!(bundle.entries.len(), 2);
        assert!(
            bundle.entries[0]
                .receipt_json
                .contains(TRANSFORM_WORK_PENDING)
        );
        assert!(
            bundle.entries[1]
                .receipt_json
                .contains(TRANSFORM_WORK_FAILED)
        );
    }

    #[test]
    fn sqlite_redaction_rewrites_chained_transform_partitions() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys.clone());
        let mut run = isolated_run("run-iso");
        run.input_partitions = vec![TransformPartition {
            dataset_id: "in".into(),
            partition_key: "east".into(),
            digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .into(),
            rows: 1,
        }];
        {
            let mut conn = db.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_transform_run(&tx, &run).unwrap();
            redact_transform_partition_receipts(&tx, "in", true).unwrap();
            tx.commit().unwrap();
        }
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex = keys.current_public_key_hex();
        verify_bundle(&bundle, &[hex.as_str()]).unwrap();
        assert_eq!(bundle.entries.len(), 1);
        assert!(!bundle.entries[0].receipt_json.contains("east"));
        assert!(bundle.entries[0].receipt_json.contains("[redacted]"));
    }

    #[test]
    fn sqlite_redaction_requires_a_signer_for_chained_bodies() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let mut run = isolated_run("run-iso");
        run.input_partitions = vec![TransformPartition {
            dataset_id: "in".into(),
            partition_key: "east".into(),
            digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .into(),
            rows: 1,
        }];
        {
            let _guard = install_test_signer(keys.clone());
            let mut conn = db.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_transform_run(&tx, &run).unwrap();
            tx.commit().unwrap();
        }
        let error = {
            let mut conn = db.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            redact_transform_partition_receipts(&tx, "in", true).unwrap_err()
        };
        assert!(error.contains("signing key"));
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex = keys.current_public_key_hex();
        verify_bundle(&bundle, &[hex.as_str()]).unwrap();
        assert!(bundle.entries[0].receipt_json.contains("east"));
    }

    #[test]
    fn sqlite_redaction_after_rotation_needs_the_previous_public_key() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys_a = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let mut run = isolated_run("run-iso");
        run.input_partitions = vec![TransformPartition {
            dataset_id: "in".into(),
            partition_key: "east".into(),
            digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .into(),
            rows: 1,
        }];
        {
            let _guard = install_test_signer(keys_a.clone());
            let mut conn = db.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_transform_run(&tx, &run).unwrap();
            tx.commit().unwrap();
        }
        let keys_b = SigningKeySet::from_seed_hex(SEED_B, 2).unwrap();
        let error = {
            let _guard = install_test_signer(keys_b.clone());
            let mut conn = db.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            redact_transform_partition_receipts(&tx, "in", true).unwrap_err()
        };
        assert!(error.contains("trusted") || error.contains("signature") || error.contains("key"));
        let mut keys_b = SigningKeySet::from_seed_hex(SEED_B, 2).unwrap();
        keys_b
            .trust_public_key(&keys_a.current_public_key_hex(), 0)
            .unwrap();
        {
            let _guard = install_test_signer(keys_b.clone());
            let mut conn = db.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            redact_transform_partition_receipts(&tx, "in", true).unwrap();
            tx.commit().unwrap();
        }
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex_b = keys_b.current_public_key_hex();
        verify_bundle(&bundle, &[hex_b.as_str()]).unwrap();
        assert!(!bundle.entries[0].receipt_json.contains("east"));
    }

    #[test]
    fn sqlite_redaction_refuses_to_resign_a_tampered_chain() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys.clone());
        db.put_operation_receipt(&sample_receipt("op-1", ReceiptEventKind::ActionPerformed))
            .unwrap();
        let mut run = isolated_run("run-iso");
        run.input_partitions = vec![TransformPartition {
            dataset_id: "in".into(),
            partition_key: "east".into(),
            digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .into(),
            rows: 1,
        }];
        {
            let mut conn = db.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_transform_run(&tx, &run).unwrap();
            tx.commit().unwrap();
        }
        {
            let conn = db.conn();
            conn.execute(
                "UPDATE chisei_receipt_chain SET receipt_json = '{\"tampered\":true}'
                 WHERE receipt_id = 'op-1'",
                [],
            )
            .unwrap();
        }
        let error = {
            let mut conn = db.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            redact_transform_partition_receipts(&tx, "in", true).unwrap_err()
        };
        assert!(error.contains("entry_hash") || error.contains("position"));
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex = keys.current_public_key_hex();
        assert!(verify_bundle(&bundle, &[hex.as_str()]).is_err());
        assert!(
            bundle
                .entries
                .iter()
                .any(|entry| entry.receipt_json.contains("east"))
        );
        assert!(
            bundle
                .entries
                .iter()
                .any(|entry| entry.receipt_json.contains("tampered"))
        );
    }

    #[test]
    fn sqlite_updated_receipt_appends_a_new_chain_entry() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys.clone());
        db.put_operation_receipt(&sample_receipt("op-1", ReceiptEventKind::ActionPerformed))
            .unwrap();
        let mut updated = sample_receipt("op-1", ReceiptEventKind::ActionPerformed);
        updated.completed_at_ms = Some(20);
        db.put_operation_receipt(&updated).unwrap();
        db.put_operation_receipt(&updated).unwrap();
        db.put_operation_receipt(&sample_receipt("op-1", ReceiptEventKind::ActionPerformed))
            .unwrap();
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex = keys.current_public_key_hex();
        verify_bundle(&bundle, &[hex.as_str()]).expect("revision bundle verifies");
        assert_eq!(bundle.entries.len(), 3);
        assert!(
            bundle
                .entries
                .iter()
                .all(|entry| entry.receipt_id == "op-1")
        );
        assert_ne!(
            bundle.entries[0].receipt_json,
            bundle.entries[1].receipt_json
        );
        assert_eq!(
            bundle.entries[0].receipt_json,
            bundle.entries[2].receipt_json
        );
    }

    #[test]
    fn sqlite_lifecycle_updates_append_chain_entries() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys.clone());
        db.put_operation_receipt(&sample_receipt("op-1", ReceiptEventKind::ActionPerformed))
            .unwrap();
        db.authorize_operation_reporter("op-1", "bob", vec![ReceiptEventKind::ActionPerformed])
            .unwrap();
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex = keys.current_public_key_hex();
        verify_bundle(&bundle, &[hex.as_str()]).unwrap();
        assert_eq!(bundle.entries.len(), 2);
    }

    #[test]
    fn sqlite_refuses_to_extend_a_truncated_chain() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys);
        db.put_operation_receipt(&sample_receipt("op-1", ReceiptEventKind::ActionPerformed))
            .unwrap();
        db.put_operation_receipt(&sample_receipt("op-2", ReceiptEventKind::ActionPerformed))
            .unwrap();
        db.conn()
            .execute("DELETE FROM chisei_receipt_chain WHERE seq = 2", [])
            .unwrap();
        let error = db
            .put_operation_receipt(&sample_receipt("op-3", ReceiptEventKind::ActionPerformed))
            .expect_err("truncated chain must not grow");
        assert!(error.contains("signed head"), "{error}");
    }

    #[test]
    fn sqlite_refuses_to_reset_a_chain_that_lost_its_latest() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys);
        db.put_operation_receipt(&sample_receipt("op-1", ReceiptEventKind::ActionPerformed))
            .unwrap();
        {
            let conn = db.conn();
            conn.execute("DELETE FROM chisei_receipt_chain", [])
                .unwrap();
            conn.execute(
                "DELETE FROM chisei_receipt_chain_checkpoints WHERE kind = 'latest'",
                [],
            )
            .unwrap();
        }
        let error = db
            .put_operation_receipt(&sample_receipt("op-2", ReceiptEventKind::ActionPerformed))
            .expect_err("genesis without latest must not reset");
        assert!(error.contains("latest checkpoint is missing"), "{error}");
    }

    #[test]
    fn sqlite_refuses_a_latest_checkpoint_not_signed_by_the_operator() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys);
        db.put_operation_receipt(&sample_receipt("op-1", ReceiptEventKind::ActionPerformed))
            .unwrap();
        let attacker = SigningKeySet::from_seed_hex(SEED_B, 1).unwrap();
        {
            let conn = db.conn();
            let head_hash: String = conn
                .query_row(
                    "SELECT entry_hash FROM chisei_receipt_chain WHERE seq = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            conn.execute(
                "DELETE FROM chisei_receipt_chain_checkpoints WHERE kind = 'latest'",
                [],
            )
            .unwrap();
            persist_published_keys(&conn, &attacker).unwrap();
            insert_checkpoint(
                &conn,
                &attacker
                    .issued_checkpoint("ns", CheckpointKind::Latest, 1, &head_hash, 1, 99)
                    .unwrap(),
            )
            .unwrap();
        }
        let error = db
            .put_operation_receipt(&sample_receipt("op-2", ReceiptEventKind::ActionPerformed))
            .expect_err("foreign latest must not authorize append");
        assert!(
            error.contains("unknown checkpoint signing key")
                || error.contains("checkpoint signature")
                || error.contains("not in the trusted set"),
            "{error}"
        );
    }

    #[test]
    fn sqlite_rotated_signer_needs_the_previous_public_key() {
        let db = SekaiDb::new(":memory:").unwrap();
        let original = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let original_hex = original.current_public_key_hex();
        {
            let _guard = install_test_signer(original);
            db.put_operation_receipt(&sample_receipt("op-1", ReceiptEventKind::ActionPerformed))
                .unwrap();
        }
        let rotated = SigningKeySet::from_seed_hex(SEED_B, 1).unwrap();
        {
            let _guard = install_test_signer(rotated);
            let error = db
                .put_operation_receipt(&sample_receipt("op-2", ReceiptEventKind::ActionPerformed))
                .expect_err("new seed alone cannot authenticate the old head");
            assert!(
                error.contains("unknown checkpoint signing key")
                    || error.contains("checkpoint signature"),
                "{error}"
            );
        }
        let mut trusted = SigningKeySet::from_seed_hex(SEED_B, 1).unwrap();
        trusted.trust_public_key(&original_hex, 0).unwrap();
        let _guard = install_test_signer(trusted.clone());
        db.put_operation_receipt(&sample_receipt("op-2", ReceiptEventKind::ActionPerformed))
            .unwrap();
        let bundle = db.export_receipt_chain("ns").unwrap();
        let new_hex = trusted.current_public_key_hex();
        verify_bundle(&bundle, &[original_hex.as_str(), new_hex.as_str()]).unwrap();
        assert_eq!(bundle.entries.len(), 2);
    }

    #[test]
    fn sqlite_tamper_fails_at_exact_position() {
        let db = SekaiDb::new(":memory:").unwrap();
        let keys = SigningKeySet::from_seed_hex(SEED, 1).unwrap();
        let _guard = install_test_signer(keys.clone());
        db.put_operation_receipt(&sample_receipt("op-1", ReceiptEventKind::ActionPerformed))
            .unwrap();
        db.put_operation_receipt(&sample_receipt("op-2", ReceiptEventKind::ActionPerformed))
            .unwrap();
        db.conn()
            .execute(
                "UPDATE chisei_receipt_chain SET receipt_json = receipt_json || ' ' WHERE seq = 2",
                [],
            )
            .unwrap();
        let bundle = db.export_receipt_chain("ns").unwrap();
        let hex = keys.current_public_key_hex();
        let error = verify_bundle(&bundle, &[hex.as_str()]).expect_err("tamper must fail");
        assert_eq!(error.position, 1);
        assert_eq!(error.seq, 2);
    }
}
