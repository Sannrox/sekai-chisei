//! PostgreSQL persistence for the signed per-namespace receipt chain (#1449).

use postgres::{GenericClient, IsolationLevel};

use crate::chisei::receipt::OperationReceipt;
use crate::db::postgres::PostgresDb;
use crate::db::receipt_chain::{current_signer, kind_for_operation_receipt};
use sekai_types::governed_transform::{TransformRun, redact_run_partition_receipts};
use sekai_types::receipt_chain::{
    BUNDLE_VERSION, CHECKPOINT_INTERVAL, ChainEntry, Checkpoint, CheckpointKind, DIGEST_ALGORITHM,
    GENESIS_HEAD_HASH, PublishedKey, ReceiptChainBundle, ReceiptKind, SIGNATURE_ALGORITHM,
    SigningKeySet, authenticate_checkpoint, entry_hash, verify_bundle,
};

impl PostgresDb {
    pub fn export_receipt_chain(&self, namespace: &str) -> Result<ReceiptChainBundle, String> {
        let mut conn = self.connection()?;
        let mut tx = conn
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(|error| error.to_string())?;
        let bundle = load_bundle(&mut tx, namespace)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(bundle)
    }

    pub(crate) fn append_operation_receipt_chain<C: GenericClient>(
        &self,
        client: &mut C,
        receipt: &OperationReceipt,
    ) -> Result<(), String> {
        let Some(keys) = current_signer()? else {
            return Ok(());
        };
        let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
        append_receipt(
            client,
            &keys,
            &receipt.namespace,
            kind_for_operation_receipt(receipt),
            &receipt.operation_id,
            &receipt_json,
            receipt.started_at_ms,
        )
    }
}

pub(crate) fn append_transform_run_chain<C: GenericClient>(
    client: &mut C,
    run: &TransformRun,
) -> Result<(), String> {
    let Some(keys) = current_signer()? else {
        return Ok(());
    };
    let receipt_json = serde_json::to_string(run).map_err(|error| error.to_string())?;
    append_receipt(
        client,
        &keys,
        &run.namespace,
        ReceiptKind::TransformRun,
        &run.run_id,
        &receipt_json,
        run.created_at_ms,
    )
}

pub(crate) fn redact_transform_run_chain<C: GenericClient>(
    client: &mut C,
    dataset_id: &str,
) -> Result<(), String> {
    if !chain_table_present(client)? {
        return Ok(());
    }
    let pending = pending_transform_redactions(client, dataset_id)?;
    if pending.is_empty() {
        return Ok(());
    }
    let Some(keys) = current_signer()? else {
        return Err(
            "receipt chain signing key is required to redact chained transform receipts".into(),
        );
    };
    persist_published_keys(client, &keys)?;
    let genesis_namespaces = client
        .query(
            "SELECT namespace FROM chisei_receipt_chain_checkpoints
             WHERE kind = 'genesis' ORDER BY namespace",
            &[],
        )
        .map_err(|error| error.to_string())?;
    for row in genesis_namespaces {
        let namespace: String = row.get(0);
        lock_namespace_advisory(client, namespace.as_str())?;
        lock_namespace_chain(client, namespace.as_str())?;
    }
    let pending = pending_transform_redactions(client, dataset_id)?;
    let mut namespaces = Vec::new();
    for (namespace, _, _) in &pending {
        if !namespaces.iter().any(|seen| seen == namespace) {
            namespaces.push(namespace.clone());
        }
    }
    if namespaces.is_empty() {
        return Ok(());
    }
    for namespace in &namespaces {
        authenticate_namespace(client, &keys, namespace)?;
    }
    for (namespace, seq, updated) in pending {
        client
            .execute(
                "UPDATE chisei_receipt_chain SET receipt_json = $1
                 WHERE namespace = $2 AND seq = $3",
                &[&updated, &namespace, &seq],
            )
            .map_err(|error| error.to_string())?;
    }
    for namespace in namespaces {
        resign_namespace(client, &keys, &namespace)?;
    }
    Ok(())
}

fn pending_transform_redactions<C: GenericClient>(
    client: &mut C,
    dataset_id: &str,
) -> Result<Vec<(String, i64, String)>, String> {
    let rows = client
        .query(
            "SELECT namespace, seq, receipt_json FROM chisei_receipt_chain
             WHERE kind = 'transform_run'",
            &[],
        )
        .map_err(|error| error.to_string())?;
    let mut pending = Vec::new();
    for row in rows {
        let namespace: String = row.get(0);
        let seq: i64 = row.get(1);
        let receipt_json: String = row.get(2);
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

fn lock_namespace_advisory<C: GenericClient>(
    client: &mut C,
    namespace: &str,
) -> Result<(), String> {
    let lock_key = crate::db::postgres::advisory_lock_key(&["receipt_chain", namespace]);
    client
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn lock_namespace_chain<C: GenericClient>(client: &mut C, namespace: &str) -> Result<(), String> {
    client
        .query_opt(
            "SELECT 1 FROM chisei_receipt_chain_checkpoints
             WHERE namespace = $1 AND kind = 'genesis' FOR UPDATE",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    client
        .query(
            "SELECT seq FROM chisei_receipt_chain WHERE namespace = $1 FOR UPDATE",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn authenticate_namespace<C: GenericClient>(
    client: &mut C,
    keys: &SigningKeySet,
    namespace: &str,
) -> Result<(), String> {
    let bundle = load_bundle(client, namespace)?;
    let trusted: Vec<String> = keys
        .published_keys()
        .into_iter()
        .map(|key| key.public_key_hex)
        .collect();
    let trusted_refs: Vec<&str> = trusted.iter().map(String::as_str).collect();
    verify_bundle(&bundle, &trusted_refs).map_err(|error| error.to_string())
}

fn resign_namespace<C: GenericClient>(
    client: &mut C,
    keys: &SigningKeySet,
    namespace: &str,
) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT seq, kind, receipt_id, receipt_json, created_at_ms
             FROM chisei_receipt_chain WHERE namespace = $1 ORDER BY seq",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "DELETE FROM chisei_receipt_chain_checkpoints
             WHERE namespace = $1 AND kind IN ('latest', 'periodic', 'genesis')",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    insert_checkpoint(
        client,
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
    for row in rows {
        let seq: i64 = row.get(0);
        let kind: String = row.get(1);
        let receipt_id: String = row.get(2);
        let receipt_json: String = row.get(3);
        let created_at_ms: i64 = row.get(4);
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
        client
            .execute(
                "UPDATE chisei_receipt_chain
                 SET prev_hash = $1, entry_hash = $2, key_id = $3, signature = $4
                 WHERE namespace = $5 AND seq = $6",
                &[
                    &prev_hash,
                    &entry_hash,
                    &key_id,
                    &signature,
                    &namespace,
                    &seq,
                ],
            )
            .map_err(|error| error.to_string())?;
        if seq % CHECKPOINT_INTERVAL == 0 {
            insert_checkpoint(
                client,
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
    upsert_latest(client, keys, namespace, head_seq, &head_hash, now_ms)
}

fn append_receipt<C: GenericClient>(
    client: &mut C,
    keys: &SigningKeySet,
    namespace: &str,
    kind: ReceiptKind,
    receipt_id: &str,
    receipt_json: &str,
    now_ms: i64,
) -> Result<(), String> {
    if !chain_table_present(client)? {
        return Ok(());
    }
    persist_published_keys(client, keys)?;
    lock_namespace_advisory(client, namespace)?;
    let kind_str = kind.as_str();
    let latest_body = client
        .query_opt(
            "SELECT receipt_json FROM chisei_receipt_chain
             WHERE namespace = $1 AND receipt_id = $2
             ORDER BY seq DESC LIMIT 1",
            &[&namespace, &receipt_id],
        )
        .map_err(|error| error.to_string())?;
    if latest_body
        .as_ref()
        .is_some_and(|row| row.get::<_, String>(0) == receipt_json)
    {
        return Ok(());
    }
    ensure_genesis(client, keys, namespace, now_ms)?;
    client
        .query_one(
            "SELECT 1 FROM chisei_receipt_chain_checkpoints
             WHERE namespace = $1 AND kind = 'genesis' FOR UPDATE",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    let max_seq: i64 = client
        .query_one(
            "SELECT COALESCE(MAX(seq), 0) FROM chisei_receipt_chain WHERE namespace = $1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    assert_signed_head(client, keys, namespace, max_seq)?;
    let seq = max_seq + 1;
    let prev_hash = if max_seq == 0 {
        GENESIS_HEAD_HASH.to_string()
    } else {
        client
            .query_one(
                "SELECT entry_hash FROM chisei_receipt_chain WHERE namespace = $1 AND seq = $2",
                &[&namespace, &max_seq],
            )
            .map_err(|error| error.to_string())?
            .get(0)
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
    client
        .execute(
            "INSERT INTO chisei_receipt_chain(
                namespace, seq, kind, receipt_id, receipt_json, prev_hash, entry_hash,
                key_id, signature, created_at_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[
                &namespace,
                &seq,
                &kind_str,
                &receipt_id,
                &receipt_json,
                &prev_hash,
                &entry_hash,
                &key_id,
                &signature,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    upsert_latest(client, keys, namespace, seq, &entry_hash, now_ms)?;
    if seq % CHECKPOINT_INTERVAL == 0 {
        insert_checkpoint(
            client,
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

fn load_bundle<C: GenericClient>(
    client: &mut C,
    namespace: &str,
) -> Result<ReceiptChainBundle, String> {
    if namespace.is_empty() {
        return Err("receipt chain namespace must be non-empty".into());
    }
    if !chain_table_present(client)? {
        return Err("receipt chain is not migrated on this store".into());
    }
    let keys = load_keys(client)?;
    let checkpoints = load_checkpoints(client, namespace)?;
    if checkpoints.is_empty() {
        return Err(format!("no receipt chain for namespace {namespace}"));
    }
    let rows = client
        .query(
            "SELECT seq, kind, receipt_id, receipt_json, prev_hash, entry_hash,
                    key_id, signature, created_at_ms
             FROM chisei_receipt_chain WHERE namespace = $1 ORDER BY seq",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    let mut entries = Vec::new();
    for row in rows {
        let kind: String = row.get(1);
        entries.push(ChainEntry {
            seq: row.get(0),
            namespace: namespace.to_string(),
            kind: ReceiptKind::parse(&kind)?,
            receipt_id: row.get(2),
            receipt_json: row.get(3),
            prev_hash: row.get(4),
            entry_hash: row.get(5),
            key_id: row.get(6),
            signature: row.get(7),
            created_at_ms: row.get(8),
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

fn chain_table_present<C: GenericClient>(client: &mut C) -> Result<bool, String> {
    let row = client
        .query_one("SELECT to_regclass('chisei_receipt_chain')::text", &[])
        .map_err(|error| error.to_string())?;
    let name: Option<String> = row.get(0);
    Ok(name.is_some())
}

fn persist_published_keys<C: GenericClient>(
    client: &mut C,
    keys: &SigningKeySet,
) -> Result<(), String> {
    for key in keys.published_keys() {
        client
            .execute(
                "INSERT INTO chisei_receipt_chain_keys(key_id, public_key_hex, created_at_ms, retired_at_ms)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (key_id) DO NOTHING",
                &[
                    &key.key_id,
                    &key.public_key_hex,
                    &key.created_at_ms,
                    &key.retired_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        if let Some(retired_at_ms) = key.retired_at_ms {
            client
                .execute(
                    "UPDATE chisei_receipt_chain_keys SET retired_at_ms = $1
                     WHERE key_id = $2 AND retired_at_ms IS NULL",
                    &[&retired_at_ms, &key.key_id],
                )
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn ensure_genesis<C: GenericClient>(
    client: &mut C,
    keys: &SigningKeySet,
    namespace: &str,
    now_ms: i64,
) -> Result<(), String> {
    let exists = client
        .query_opt(
            "SELECT 1 FROM chisei_receipt_chain_checkpoints
             WHERE namespace = $1 AND kind = 'genesis'",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    if exists.is_some() {
        return Ok(());
    }
    let genesis = keys.issued_checkpoint(
        namespace,
        CheckpointKind::Genesis,
        0,
        GENESIS_HEAD_HASH,
        0,
        now_ms,
    )?;
    let kind_str = genesis.kind.as_str();
    client
        .execute(
            "INSERT INTO chisei_receipt_chain_checkpoints(
                namespace, kind, head_seq, head_hash, entry_count, key_id, signature, created_at_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (namespace, kind, head_seq) DO NOTHING",
            &[
                &genesis.namespace,
                &kind_str,
                &genesis.head_seq,
                &genesis.head_hash,
                &genesis.entry_count,
                &genesis.key_id,
                &genesis.signature,
                &genesis.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    let latest_exists = client
        .query_opt(
            "SELECT 1 FROM chisei_receipt_chain_checkpoints
             WHERE namespace = $1 AND kind = 'latest'",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    if latest_exists.is_some() {
        return Ok(());
    }
    let latest = keys.issued_checkpoint(
        namespace,
        CheckpointKind::Latest,
        0,
        GENESIS_HEAD_HASH,
        0,
        now_ms,
    )?;
    let latest_kind = latest.kind.as_str();
    client
        .execute(
            "INSERT INTO chisei_receipt_chain_checkpoints(
                namespace, kind, head_seq, head_hash, entry_count, key_id, signature, created_at_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (namespace, kind, head_seq) DO NOTHING",
            &[
                &latest.namespace,
                &latest_kind,
                &latest.head_seq,
                &latest.head_hash,
                &latest.entry_count,
                &latest.key_id,
                &latest.signature,
                &latest.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn upsert_latest<C: GenericClient>(
    client: &mut C,
    keys: &SigningKeySet,
    namespace: &str,
    head_seq: i64,
    head_hash: &str,
    now_ms: i64,
) -> Result<(), String> {
    client
        .execute(
            "DELETE FROM chisei_receipt_chain_checkpoints WHERE namespace = $1 AND kind = 'latest'",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    insert_checkpoint(
        client,
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

fn insert_checkpoint<C: GenericClient>(
    client: &mut C,
    checkpoint: &Checkpoint,
) -> Result<(), String> {
    let kind_str = checkpoint.kind.as_str();
    client
        .execute(
            "INSERT INTO chisei_receipt_chain_checkpoints(
                namespace, kind, head_seq, head_hash, entry_count, key_id, signature, created_at_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &checkpoint.namespace,
                &kind_str,
                &checkpoint.head_seq,
                &checkpoint.head_hash,
                &checkpoint.entry_count,
                &checkpoint.key_id,
                &checkpoint.signature,
                &checkpoint.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn assert_signed_head<C: GenericClient>(
    client: &mut C,
    keys: &SigningKeySet,
    namespace: &str,
    max_seq: i64,
) -> Result<(), String> {
    let latest = client
        .query_opt(
            "SELECT kind, head_seq, head_hash, entry_count, key_id, signature, created_at_ms
             FROM chisei_receipt_chain_checkpoints
             WHERE namespace = $1 AND kind = 'latest'",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    let Some(row) = latest else {
        return Err("receipt chain latest checkpoint is missing".into());
    };
    let latest = Checkpoint {
        namespace: namespace.to_string(),
        kind: CheckpointKind::Latest,
        head_seq: row.get(1),
        head_hash: row.get(2),
        entry_count: row.get(3),
        key_id: row.get(4),
        signature: row.get(5),
        created_at_ms: row.get(6),
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
        client
            .query_one(
                "SELECT entry_hash FROM chisei_receipt_chain WHERE namespace = $1 AND seq = $2",
                &[&namespace, &max_seq],
            )
            .map_err(|error| error.to_string())?
            .get(0)
    };
    if latest.head_hash != expected_hash {
        return Err("signed head hash does not match the stored chain head".into());
    }
    Ok(())
}

fn load_keys<C: GenericClient>(client: &mut C) -> Result<Vec<PublishedKey>, String> {
    let rows = client
        .query(
            "SELECT key_id, public_key_hex, created_at_ms, retired_at_ms
             FROM chisei_receipt_chain_keys ORDER BY created_at_ms, key_id",
            &[],
        )
        .map_err(|error| error.to_string())?;
    Ok(rows
        .iter()
        .map(|row| PublishedKey {
            key_id: row.get(0),
            public_key_hex: row.get(1),
            created_at_ms: row.get(2),
            retired_at_ms: row.get(3),
        })
        .collect())
}

fn load_checkpoints<C: GenericClient>(
    client: &mut C,
    namespace: &str,
) -> Result<Vec<Checkpoint>, String> {
    let rows = client
        .query(
            "SELECT kind, head_seq, head_hash, entry_count, key_id, signature, created_at_ms
             FROM chisei_receipt_chain_checkpoints WHERE namespace = $1
             ORDER BY created_at_ms, head_seq",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    let mut checkpoints = Vec::new();
    for row in rows {
        let kind: String = row.get(0);
        checkpoints.push(Checkpoint {
            namespace: namespace.to_string(),
            kind: parse_checkpoint_kind(&kind)?,
            head_seq: row.get(1),
            head_hash: row.get(2),
            entry_count: row.get(3),
            key_id: row.get(4),
            signature: row.get(5),
            created_at_ms: row.get(6),
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
