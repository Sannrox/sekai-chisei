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
    /// Which kind of writer made the change (#1690): one of the `WRITER_*`
    /// kinds, empty when the row records none (read as unattributed).
    pub writer_kind: String,
    /// The writer's own identity: source transaction, `run@checkpoint`, or
    /// Action instance. Empty for direct writes.
    pub writer_ref: String,
    /// The durable receipt for the write, empty when the writer keeps none.
    pub receipt_id: String,
}

pub const WRITER_SOURCE_TRANSACTION: &str = "source_transaction";
pub const WRITER_TRANSFORM_RUN: &str = "transform_run";
pub const WRITER_ACTION_INSTANCE: &str = "action_instance";
pub const WRITER_DIRECT: &str = "direct";
/// How a row without a recorded writer reads. Never inferred.
pub const WRITER_UNATTRIBUTED: &str = "unattributed";

/// Who wrote a set of changes, stamped on every row the write produces.
/// The default records nothing, so the rows read as unattributed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeAttribution {
    pub operation_id: String,
    pub writer_kind: String,
    pub writer_ref: String,
    pub receipt_id: String,
}

impl ChangeAttribution {
    /// A direct object write by its caller.
    pub fn direct() -> Self {
        Self {
            writer_kind: WRITER_DIRECT.into(),
            ..Self::default()
        }
    }

    /// An Action instance's write; its operation receipt is the receipt.
    pub fn action(instance_id: &str, operation_id: &str) -> Self {
        Self {
            operation_id: operation_id.into(),
            writer_kind: WRITER_ACTION_INSTANCE.into(),
            writer_ref: instance_id.into(),
            receipt_id: operation_id.into(),
        }
    }

    /// A committed source batch; its transaction record is the receipt.
    pub fn source(transaction_id: &str) -> Self {
        Self {
            writer_kind: WRITER_SOURCE_TRANSACTION.into(),
            writer_ref: transaction_id.into(),
            receipt_id: transaction_id.into(),
            ..Self::default()
        }
    }

    /// A transform run at a checkpoint; the run record is the receipt.
    pub fn transform(run_id: &str, checkpoint: &str) -> Self {
        Self {
            writer_kind: WRITER_TRANSFORM_RUN.into(),
            writer_ref: format!("{run_id}@{checkpoint}"),
            receipt_id: run_id.into(),
            ..Self::default()
        }
    }

    /// Stamps every change with this attribution.
    pub fn stamp(&self, mut changes: Vec<ObjectChange>) -> Vec<ObjectChange> {
        for change in &mut changes {
            change.operation_id = self.operation_id.clone();
            change.writer_kind = self.writer_kind.clone();
            change.writer_ref = self.writer_ref.clone();
            change.receipt_id = self.receipt_id.clone();
        }
        changes
    }
}
