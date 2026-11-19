//! The source record behind one synced object (#3058).
//!
//! An object landed by `ApplySourceBatch` carries the plane-owned `sync_*`
//! properties naming its source, and its binding's landed row may retain the
//! original payload (source batch v3). This module reads both back. It does
//! no authorization: callers pass properties the caller may already read.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::db::source_batch_dataset::{
    HIDDEN_COLUMN, KEY_COLUMN, PAYLOAD_COLUMN, binding_dataset_id,
};
use crate::sekai::dataset::{RowFilter, RowQuery};
use crate::sekai::object_sync::object_id_for;

/// Source identity and revision of one object, with its retained payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSourceRecord {
    pub source: String,
    pub source_instance: String,
    pub source_id: String,
    /// The source revision that last wrote the object.
    pub source_version: String,
    pub payload_digest: String,
    /// `None` when the landed row keeps no payload (v1 or v2 batch), or keeps
    /// one that does not hash to `payload_digest`.
    pub payload: Option<String>,
    /// The record is a tombstone or its landed row is hidden.
    pub hidden: bool,
}

/// The source record behind object `object_id` of `kind` in `namespace`, read
/// from its `sync_*` `properties` and its binding's newest landed row. `None`
/// when the properties name no source binding, or name one whose derived
/// object id is not `object_id`: ordinary object writes may set `sync_*` keys,
/// so only the id the binding derives ties an object to a landed row.
pub fn object_source_record(
    db: &RuntimeDb,
    object_id: &str,
    namespace: &str,
    kind: &str,
    properties: &HashMap<String, String>,
) -> Result<Option<ObjectSourceRecord>, String> {
    let field = |key: &str| properties.get(key).cloned().unwrap_or_default();
    let (source_instance, source_id, type_digest) = (
        field("sync_source_instance"),
        field("sync_source_id"),
        field("sync_type_digest"),
    );
    if source_instance.is_empty()
        || source_id.is_empty()
        || type_digest.is_empty()
        || object_id_for(&type_digest, &source_id) != object_id
    {
        return Ok(None);
    }
    let Some(state) = db.get_source_sync_state(namespace, &source_instance, &type_digest)? else {
        return Ok(None);
    };
    // Dataset row queries scan the binding's rows and filter in memory on
    // both backends; only matching rows are kept. A keyed newest-first
    // lookup needs an index migration (#3259).
    let row = db
        .query_rows(
            &binding_dataset_id(&state.binding.binding_id, kind),
            &RowQuery {
                filters: vec![RowFilter {
                    column: KEY_COLUMN.into(),
                    op: "eq".into(),
                    value: source_id.clone(),
                }],
                ..Default::default()
            },
        )?
        .pop();
    let row_hidden = row
        .as_ref()
        .is_some_and(|row| row.get(HIDDEN_COLUMN).is_some_and(|value| value == "1"));
    let payload_digest = field("sync_payload_digest");
    // A quarantined dataset serves its last healthy version, which can hold
    // an older revision's row. Only a payload that hashes to the digest the
    // object carries now belongs to this revision.
    let payload = row
        .and_then(|mut row| row.remove(PAYLOAD_COLUMN))
        .filter(|payload| {
            !payload.is_empty()
                && format!("sha256:{:x}", Sha256::digest(payload.as_bytes())) == payload_digest
        });
    Ok(Some(ObjectSourceRecord {
        source: field("sync_source"),
        source_instance,
        source_id,
        source_version: field("sync_source_version"),
        payload_digest,
        payload,
        hidden: row_hidden || field("sync_tombstoned") == "true",
    }))
}
