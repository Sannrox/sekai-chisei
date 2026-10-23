//! Object field-change records written by the audit host.

#[derive(Debug, Clone, Default)]
pub struct ObjectChange {
    pub id: String,
    pub object_id: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub changed_by: String,
    pub timestamp: i64,
    /// Stored operation that produced the change; empty when none did.
    pub operation_id: String,
}
