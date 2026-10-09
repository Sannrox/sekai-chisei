//! Chisei-owned port for Sekai commit lookup (ADR 0092 rule 1).
//!
//! Chisei asks whether a Sekai commit exists for an operation through
//! [`SekaiCommitLookup`]. Combined mode implements it over the in-process
//! Sekai store and the Chisei plane over the authenticated gRPC hop; both live
//! in composition code. The receipt projections below are pure Chisei.

use std::collections::BTreeMap;

use crate::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SekaiCommitRef {
    pub namespace: String,
    pub instance_id: String,
    pub status: String,
}

pub trait SekaiCommitLookup: Send + Sync {
    fn lookup_commit(&self, operation_id: &str) -> Result<Option<SekaiCommitRef>, String>;
}

pub fn hop_projection_receipt(operation_id: &str, commit: &SekaiCommitRef) -> OperationReceipt {
    let mut receipt = OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.to_string(),
        parent_operation_id: None,
        namespace: commit.namespace.clone(),
        operation_class: "sekai_commit_projection".into(),
        initiating_actor: "typed-hop".into(),
        schema_version: "typed-hop/v1".into(),
        policy_version: "typed-hop".into(),
        started_at_ms: 0,
        completed_at_ms: None,
        events: vec![OperationReceiptEvent {
            event_id: format!("{operation_id}:sekai-commit"),
            operation_id: operation_id.to_string(),
            parent_event_id: None,
            timestamp_ms: 0,
            surface: ReceiptEventKind::BudgetDecided.surface(),
            kind: ReceiptEventKind::BudgetDecided,
            actor: String::new(),
            references: Vec::new(),
            attributes: BTreeMap::new(),
        }],
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    };
    project_commit_handles(&mut receipt, commit);
    receipt
}

pub fn project_commit_handles(receipt: &mut OperationReceipt, commit: &SekaiCommitRef) {
    if let Some(event) = receipt.events.first_mut() {
        event.attributes.insert(
            "sekai_commit_instance_id".into(),
            commit.instance_id.clone(),
        );
        event
            .attributes
            .insert("sekai_commit_status".into(), commit.status.clone());
    }
}
