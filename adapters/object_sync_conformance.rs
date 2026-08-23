//! Reusable offline conformance checks for source-sync transports and outboxes.

use crate::object_sync_sdk::{FlushDisposition, OutboxLimits, SourceOutbox, SourceSyncTransport};
use sekai_chisei::sekai::object_sync::SourceBatch;
use std::fs;
use std::path::Path;

pub fn assert_deterministic_batch(first: &SourceBatch, second: &SourceBatch) -> Result<(), String> {
    if first.idempotency_key != second.idempotency_key
        || first.batch_digest != second.batch_digest
        || first.records != second.records
    {
        return Err("source adapter batch construction is not deterministic".into());
    }
    Ok(())
}

pub fn assert_snapshot_chain(batches: &[SourceBatch]) -> Result<(), String> {
    if batches.is_empty() || !batches[0].current_cursor.is_empty() {
        return Err("snapshot chain did not start without a committed checkpoint".into());
    }
    for pair in batches.windows(2) {
        if pair[0].proposed_next_cursor != pair[1].current_cursor {
            return Err("snapshot page did not resume from the prior committed cursor".into());
        }
        if pair[0].idempotency_key == pair[1].idempotency_key
            || pair[0].batch_digest == pair[1].batch_digest
        {
            return Err("distinct snapshot pages reused batch identity".into());
        }
    }
    Ok(())
}

pub fn assert_cross_page_identity(
    first: &SourceBatch,
    second: &SourceBatch,
    source_id: &str,
) -> Result<(), String> {
    let first_record = first
        .records
        .iter()
        .find(|record| record.source_id() == source_id)
        .ok_or_else(|| "snapshot page one is missing the shared source identity".to_string())?;
    let second_record = second
        .records
        .iter()
        .find(|record| record.source_id() == source_id)
        .ok_or_else(|| "snapshot page two is missing the shared source identity".to_string())?;
    if first_record.type_name != second_record.type_name
        || first_record.source_version == second_record.source_version
    {
        return Err("cross-page source identity was not a compatible refresh".into());
    }
    Ok(())
}

pub fn run_restart_and_commit<T: SourceSyncTransport>(
    root: &Path,
    batch: &SourceBatch,
    ambiguous: &mut T,
    committed: &mut T,
) -> Result<(), String> {
    let outbox = SourceOutbox::open(root, OutboxLimits::default())?;
    outbox.enqueue(batch)?;
    let first = outbox.flush(ambiguous, true)?;
    if first.entries.len() != 1
        || first.entries[0].disposition != FlushDisposition::Pending
        || outbox.pending()?.len() != 1
    {
        return Err("ambiguous source delivery did not remain pending".into());
    }

    let restarted = SourceOutbox::open(root, OutboxLimits::default())?;
    if restarted.pending()? != [batch.clone()] {
        return Err("source outbox did not recover the exact pending batch".into());
    }
    let second = restarted.flush(committed, true)?;
    if second.entries.len() != 1
        || second.entries[0].disposition != FlushDisposition::Committed
        || !restarted.pending()?.is_empty()
    {
        return Err("exact committed source delivery was not removed".into());
    }
    Ok(())
}

pub fn assert_files_omit(root: &Path, forbidden: &[&str]) -> Result<(), String> {
    if !root.exists() {
        return Ok(());
    }
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory)
            .map_err(|_| "failed to inspect source conformance files".to_string())?
        {
            let entry =
                entry.map_err(|_| "failed to inspect source conformance files".to_string())?;
            let metadata = entry
                .metadata()
                .map_err(|_| "failed to inspect source conformance file".to_string())?;
            if metadata.is_dir() {
                directories.push(entry.path());
                continue;
            }
            let bytes = fs::read(entry.path())
                .map_err(|_| "failed to read source conformance file".to_string())?;
            let text = String::from_utf8_lossy(&bytes);
            if forbidden.iter().any(|value| text.contains(value)) {
                return Err("source adapter persisted forbidden sensitive data".into());
            }
        }
    }
    Ok(())
}
