//! Rebuildable object-type membership projection (#877).

pub use sekai_types::object_type_index::*;

/// Digest of what a migration of the object type's rows depends on: the
/// backing dataset, key column, property mapping, hidden column and whether
/// it is edits-only (#1693).
pub fn datasource_fingerprint(source: &ObjectTypeDatasource) -> String {
    // A canonical JSON encoding: no delimiter in a column or property name can
    // make two configurations encode alike.
    let encoded = serde_json::to_string(&(
        &source.kind,
        &source.dataset_id,
        &source.key_column,
        &source.hidden_column,
        source.edits_only,
        &source.property_mapping,
    ))
    .unwrap_or_default();
    crate::sekai::embedding_index::sha_hex(&encoded)
}
