#[path = "../adapters/workflow_action_sdk.rs"]
mod workflow_action_sdk;
#[path = "../adapters/workflow_approval_step.rs"]
mod workflow_approval_step;
#[path = "../adapters/workflow_job_step.rs"]
mod workflow_job_step;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::governed_action_type::{EFFECT_KIND_NOTIFY, GovernedActionType};
use sekai_chisei::sekai::workflow_action::{
    PROFILE_APPROVAL_STEP, PROFILE_JOB_STEP, STATUS_CANCELLED, STATUS_PARKED, STATUS_RESUMED,
    STATUS_SUBMITTED, WORKFLOW_UNAVAILABLE, WorkflowActionBinding, WorkflowReceiptReconciliation,
    WorkflowStepEnvelope, cancel_step, park_step, reconcile_receipt, resume_step, submit_step,
};
use sekai_chisei::workflow_action_catalog::built_in_workflow_adapters;
use std::path::{Path, PathBuf};
use workflow_action_sdk::{WorkflowCommand, WorkflowTransport, command, enqueue, flush};

struct PlaneTransport {
    db: RuntimeDb,
    actor: String,
    now_ms: i64,
}

impl WorkflowTransport for PlaneTransport {
    fn submit(&mut self, envelope: &WorkflowStepEnvelope) -> Result<WorkflowActionBinding, String> {
        submit_step(&self.db, &self.actor, envelope, self.now_ms)
    }

    fn park(&mut self, envelope: &WorkflowStepEnvelope) -> Result<WorkflowActionBinding, String> {
        park_step(&self.db, &self.actor, envelope, self.now_ms)
    }

    fn resume(&mut self, envelope: &WorkflowStepEnvelope) -> Result<WorkflowActionBinding, String> {
        resume_step(&self.db, &self.actor, envelope, self.now_ms)
    }

    fn cancel(&mut self, envelope: &WorkflowStepEnvelope) -> Result<WorkflowActionBinding, String> {
        cancel_step(&self.db, &self.actor, envelope, self.now_ms)
    }

    fn callback(
        &mut self,
        envelope: &WorkflowStepEnvelope,
        payload_digest: &str,
    ) -> Result<WorkflowActionBinding, String> {
        sekai_chisei::sekai::workflow_action::callback_step(
            &self.db,
            &self.actor,
            envelope,
            payload_digest,
            self.now_ms,
        )
    }

    fn reconcile(
        &mut self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<WorkflowReceiptReconciliation, String> {
        reconcile_receipt(&self.db, &self.actor, namespace, binding_id)
    }
}

fn digest(tag: u8) -> String {
    format!("sha256:{tag:02x}{}", "ab".repeat(31))
}

fn setup() -> RuntimeDb {
    let db = RuntimeDb::memory();
    db.put_governed_action_type(
        GovernedActionType {
            namespace: "ops".into(),
            type_id: "workflow.job_step".into(),
            version: "1".into(),
            description: "job step".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"runtime":{"type":"string"}},"required":["runtime"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: String::new(),
            object_mutation: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        },
        "operator",
        1,
    )
    .unwrap();
    db.put_governed_action_type(
        GovernedActionType {
            namespace: "ops".into(),
            type_id: "workflow.approval_step".into(),
            version: "1".into(),
            description: "approval step".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"decision":{"type":"string"}},"required":["decision"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            policy_scope: String::new(),
            budget_scope: String::new(),
            object_kind: String::new(),
            object_mutation: String::new(),
            enabled: true,
            created_by: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            disabled_at_ms: 0,
        },
        "operator",
        1,
    )
    .unwrap();
    db
}

fn outbox(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sekai-workflow-adapter-{name}-{}",
        uuid::Uuid::new_v4()
    ))
}

fn deliver(
    dir: &Path,
    transport: &mut PlaneTransport,
    item: WorkflowCommand,
) -> WorkflowActionBinding {
    let path = enqueue(dir, &item).unwrap();
    transport.now_ms += 1;
    flush(&path, transport).unwrap()
}

fn adapter_lifecycle(mut envelope: WorkflowStepEnvelope, profile: &str) {
    let db = setup();
    let mut transport = PlaneTransport {
        db,
        actor: "integrator".into(),
        now_ms: 1_000,
    };
    let dir = outbox(profile);

    let submitted = deliver(
        &dir,
        &mut transport,
        command("submit", envelope.clone(), ""),
    );
    assert_eq!(submitted.status, STATUS_SUBMITTED);
    assert_eq!(submitted.profile_id, profile);
    let duplicate = deliver(
        &dir,
        &mut transport,
        command("submit", envelope.clone(), ""),
    );
    assert_eq!(duplicate, submitted);

    envelope.cursor = 0;
    let parked = deliver(&dir, &mut transport, command("park", envelope.clone(), ""));
    assert_eq!(parked.status, STATUS_PARKED);
    let mut stale = envelope.clone();
    stale.cursor = 8;
    let stale_dir = dir.join("stale");
    let stale_path = enqueue(&stale_dir, &command("park", stale, "")).unwrap();
    transport.now_ms += 1;
    assert_eq!(
        flush(&stale_path, &mut transport).unwrap_err(),
        WORKFLOW_UNAVAILABLE
    );

    envelope.cursor = 1;
    let resumed = deliver(
        &dir,
        &mut transport,
        command("resume", envelope.clone(), ""),
    );
    assert_eq!(resumed.status, STATUS_RESUMED);
    envelope.cursor = 2;
    let callback = deliver(
        &dir,
        &mut transport,
        command("callback", envelope.clone(), &digest(9)),
    );
    assert_eq!(callback.status, STATUS_RESUMED);
    envelope.cursor = 3;
    let cancelled = deliver(
        &dir,
        &mut transport,
        command("cancel", envelope.clone(), ""),
    );
    assert_eq!(cancelled.status, STATUS_CANCELLED);

    let report = transport
        .reconcile(&submitted.namespace, &submitted.binding_id)
        .unwrap();
    assert!(report.receipt_present);
    assert!(report.matched);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn two_adapters_pass_submit_park_resume_cancel_duplicate_stale_callback_and_receipts() {
    let job = workflow_job_step::translate(
        workflow_job_step::parse(include_bytes!(
            "../adapters/fixtures/workflow_job_step.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(job.profile_id, PROFILE_JOB_STEP);
    assert_eq!(workflow_job_step::ADAPTER_ID, PROFILE_JOB_STEP);
    assert_eq!(workflow_job_step::ADAPTER_VERSION, "1.0.0");
    assert_eq!(job.step_id, "job:nightly/build");
    adapter_lifecycle(job, PROFILE_JOB_STEP);

    let approval = workflow_approval_step::translate(
        workflow_approval_step::parse(include_bytes!(
            "../adapters/fixtures/workflow_approval_step.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(approval.profile_id, PROFILE_APPROVAL_STEP);
    assert_eq!(workflow_approval_step::ADAPTER_ID, PROFILE_APPROVAL_STEP);
    assert_eq!(workflow_approval_step::ADAPTER_VERSION, "1.0.0");
    assert_eq!(approval.step_id, "req:change-1/security");
    adapter_lifecycle(approval, PROFILE_APPROVAL_STEP);
}

#[test]
fn hidden_fields_and_catalog_stay_closed() {
    let mut job: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../adapters/fixtures/workflow_job_step.json"
    ))
    .unwrap();
    job.as_object_mut()
        .unwrap()
        .insert("policy".into(), serde_json::json!("allow"));
    assert!(workflow_job_step::parse(&serde_json::to_vec(&job).unwrap()).is_err());
    let mut approval: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../adapters/fixtures/workflow_approval_step.json"
    ))
    .unwrap();
    approval
        .as_object_mut()
        .unwrap()
        .insert("budget".into(), serde_json::json!(12));
    assert!(workflow_approval_step::parse(&serde_json::to_vec(&approval).unwrap()).is_err());
    let catalog = built_in_workflow_adapters();
    assert_eq!(catalog.len(), 2);
    assert_eq!(catalog[0].adapter_id, PROFILE_JOB_STEP);
    assert_eq!(catalog[1].adapter_id, PROFILE_APPROVAL_STEP);
}

#[test]
fn outbox_names_are_digest_bound_and_generation_fenced() {
    let mut job = workflow_job_step::translate(
        workflow_job_step::parse(include_bytes!(
            "../adapters/fixtures/workflow_job_step.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let dir = outbox("digest");
    job.namespace = "../outside".into();
    let first = enqueue(&dir, &command("park", job.clone(), "")).unwrap();
    assert_eq!(first.parent().unwrap(), dir.as_path());
    assert!(!first.to_string_lossy().contains(".."));
    job.cursor = 1;
    let second = enqueue(&dir, &command("park", job, "")).unwrap();
    assert_ne!(first, second);
    std::fs::remove_dir_all(&dir).ok();
}
