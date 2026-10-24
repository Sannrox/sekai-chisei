//! Applying a definition change bundle through its approved proposal (#1693).
//!
//! Apply is a durable record of ordered steps: for every dataset that backs
//! an object type the bundle backfills, fill the bundle's dataset branch,
//! verify it, and merge it as one new dataset version; then publish the
//! proposal's revision, last. Each step is idempotent on its own (the branch
//! is written once, a dataset merge replays as merged, the publish carries an
//! idempotency key derived from the record), and the record marks a step done
//! only after its effect, so a restarted apply continues from the first step
//! not done without applying any twice. A failed step leaves the published
//! revision unchanged and the record failed with that step named. The record
//! is stored with a revision: every write is a compare-and-swap, so two
//! appliers never interleave their bookkeeping.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const APPLY_CONTRACT_VERSION: &str = "sekai.definition-bundle-apply/v1";

pub const STATUS_RUNNING: &str = "running";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_COMPLETED: &str = "completed";

pub const STEP_PENDING: &str = "pending";
pub const STEP_DONE: &str = "done";
pub const STEP_FAILED: &str = "failed";

pub const STEP_PUBLISH: &str = "publish";
const BACKFILL: &str = "backfill:";
const VERIFY: &str = "verify:";
const MERGE: &str = "merge:";

/// Store error text for a stale record revision.
pub const APPLY_REVISION_CONFLICT: &str =
    "definition bundle apply changed by another applier; retry";

/// What one step does, parsed from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind<'a> {
    Backfill(&'a str),
    Verify(&'a str),
    Merge(&'a str),
    Publish,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyStep {
    /// `backfill:<dataset>`, `verify:<dataset>`, `merge:<dataset>`, or `publish`.
    pub name: String,
    pub status: String,
    /// What the step left behind: the branch, the dataset merge proposal
    /// (which names the merged version), or the published digest; the error
    /// when it failed.
    #[serde(default)]
    pub detail: String,
    /// The durable identity of the step's effect (the branch incarnation it
    /// filled, the dataset proposal it opened). Unlike `detail` it survives a
    /// failure, so a retry after an ambiguous commit replays that effect.
    #[serde(default)]
    pub effect: String,
}

impl ApplyStep {
    pub fn kind(&self) -> Option<StepKind<'_>> {
        if self.name == STEP_PUBLISH {
            return Some(StepKind::Publish);
        }
        let dataset = |prefix: &str| self.name.strip_prefix(prefix).filter(|d| !d.is_empty());
        dataset(BACKFILL)
            .map(StepKind::Backfill)
            .or_else(|| dataset(VERIFY).map(StepKind::Verify))
            .or_else(|| dataset(MERGE).map(StepKind::Merge))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleApply {
    pub contract_version: String,
    pub namespace: String,
    /// One apply per proposal; the proposal pins the base and candidate.
    pub proposal_id: String,
    pub bundle_digest: String,
    pub status: String,
    pub steps: Vec<ApplyStep>,
    #[serde(default)]
    pub failed_step: String,
    #[serde(default)]
    pub error: String,
    pub applied_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// Per object type the bundle backfills, a digest of its datasource
    /// configuration as the steps used it (empty when it had no dataset to
    /// migrate); the publish requires it unchanged.
    #[serde(default)]
    pub datasource_fingerprints: std::collections::BTreeMap<String, String>,
    /// Per dataset, the columns this apply defined for its backfill targets.
    /// Recorded before they are added, so a retry knows them as its own.
    #[serde(default)]
    pub bundle_columns: std::collections::BTreeMap<String, Vec<String>>,
}

impl BundleApply {
    /// The record for a fresh apply: backfill, verify and merge for each
    /// backing dataset, in order, then publish.
    pub fn plan(
        namespace: &str,
        proposal_id: &str,
        bundle_digest: &str,
        datasets: &[String],
        applied_by: &str,
        now_ms: i64,
    ) -> Self {
        let pending = |name: String| ApplyStep {
            name,
            status: STEP_PENDING.into(),
            detail: String::new(),
            effect: String::new(),
        };
        let mut steps = Vec::new();
        for dataset in datasets {
            steps.push(pending(format!("{BACKFILL}{dataset}")));
            steps.push(pending(format!("{VERIFY}{dataset}")));
            steps.push(pending(format!("{MERGE}{dataset}")));
        }
        steps.push(pending(STEP_PUBLISH.into()));
        Self {
            contract_version: APPLY_CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            proposal_id: proposal_id.into(),
            bundle_digest: bundle_digest.into(),
            status: STATUS_RUNNING.into(),
            steps,
            failed_step: String::new(),
            error: String::new(),
            applied_by: applied_by.into(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            datasource_fingerprints: Default::default(),
            bundle_columns: Default::default(),
        }
    }

    /// The datasets the record plans for, in order.
    pub fn datasets(&self) -> Vec<String> {
        self.steps
            .iter()
            .filter_map(|step| match step.kind() {
                Some(StepKind::Backfill(dataset)) => Some(dataset.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Align the steps with the datasets backing the bundle now: a dataset
    /// still backing keeps its steps, a new one gets pending steps, and one
    /// no longer backing is dropped. Publish stays last.
    pub fn reconcile(&mut self, datasets: &[String], now_ms: i64) {
        if self.datasets() == datasets {
            return;
        }
        let mut planned = Self::plan(
            &self.namespace,
            &self.proposal_id,
            &self.bundle_digest,
            datasets,
            "",
            0,
        )
        .steps;
        for step in &mut planned {
            if let Some(existing) = self
                .steps
                .iter()
                .find(|existing| existing.name == step.name)
            {
                *step = existing.clone();
            }
        }
        self.steps = planned;
        if self.status == STATUS_COMPLETED && self.next_step().is_some() {
            self.status = STATUS_RUNNING.into();
        }
        self.updated_at_ms = now_ms;
    }

    /// The first step not done, if any.
    pub fn next_step(&self) -> Option<usize> {
        self.steps.iter().position(|step| step.status != STEP_DONE)
    }

    /// Resume a running or failed apply: the failed step goes back to
    /// pending and the record runs again. A completed apply stays completed.
    pub fn resume(&mut self, actor: &str, now_ms: i64) {
        if self.status == STATUS_COMPLETED {
            return;
        }
        for step in &mut self.steps {
            if step.status == STEP_FAILED {
                step.status = STEP_PENDING.into();
                step.detail.clear();
            }
        }
        self.status = STATUS_RUNNING.into();
        self.failed_step.clear();
        self.error.clear();
        self.applied_by = actor.into();
        self.updated_at_ms = now_ms;
    }

    /// Mark a step done; the record completes with its last step.
    pub fn complete_step(&mut self, index: usize, detail: &str, now_ms: i64) {
        let step = &mut self.steps[index];
        step.status = STEP_DONE.into();
        step.detail = detail.into();
        if self.next_step().is_none() {
            self.status = STATUS_COMPLETED.into();
        }
        self.updated_at_ms = now_ms;
    }

    /// Mark a step failed and the record failed with it named.
    pub fn fail_step(&mut self, index: usize, error: &str, now_ms: i64) {
        let step = &mut self.steps[index];
        step.status = STEP_FAILED.into();
        step.detail = error.into();
        self.failed_step = step.name.clone();
        self.error = error.into();
        self.status = STATUS_FAILED.into();
        self.updated_at_ms = now_ms;
    }

    /// Start one dataset's steps over (its branch must be refilled): its
    /// backfill and verify go back to pending, and its merge forgets the
    /// dataset proposal it opened.
    pub fn restart_dataset(&mut self, dataset: &str, now_ms: i64) {
        for step in &mut self.steps {
            if matches!(
                step.kind(),
                Some(StepKind::Backfill(d) | StepKind::Verify(d) | StepKind::Merge(d)) if d == dataset
            ) {
                step.status = STEP_PENDING.into();
                step.detail.clear();
                step.effect.clear();
            }
        }
        self.updated_at_ms = now_ms;
    }

    /// The idempotency key of the publish step: the same on every retry of
    /// this apply, so a publish that landed before a crash replays.
    pub fn publish_idempotency_key(&self) -> String {
        let digest = Sha256::digest(format!("{}\u{1f}{}", self.proposal_id, self.bundle_digest));
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("bundle-apply-{}", &hex[..32])
    }

    /// The columns this apply defined in `dataset`.
    pub fn owned_columns(&self, dataset: &str) -> std::collections::BTreeSet<String> {
        self.bundle_columns
            .get(dataset)
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    /// Record the effect a step has made so far without completing it, so a
    /// retry continues from it (the dataset merge proposal it opened).
    pub fn note_step(&mut self, index: usize, effect: &str, now_ms: i64) {
        self.steps[index].effect = effect.into();
        self.updated_at_ms = now_ms;
    }
}

/// Storage for apply records. Each write passes the revision it read (0 for
/// a new record) and fails with [`APPLY_REVISION_CONFLICT`] when another
/// writer moved it; it returns the new revision.
pub trait BundleApplyStore {
    fn get_definition_bundle_apply(
        &self,
        namespace: &str,
        proposal_id: &str,
    ) -> Result<Option<(BundleApply, i64)>, String>;
    fn put_definition_bundle_apply(
        &self,
        apply: &BundleApply,
        expected_revision: i64,
    ) -> Result<i64, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> BundleApply {
        BundleApply::plan(
            "acme",
            "p1",
            "sha256:abc",
            &["ds-a".into(), "ds-b".into()],
            "applier",
            1,
        )
    }

    #[test]
    fn plan_orders_each_dataset_then_publishes_last() {
        let apply = record();
        let names = apply
            .steps
            .iter()
            .map(|step| step.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "backfill:ds-a",
                "verify:ds-a",
                "merge:ds-a",
                "backfill:ds-b",
                "verify:ds-b",
                "merge:ds-b",
                "publish",
            ]
        );
        assert_eq!(apply.datasets(), vec!["ds-a", "ds-b"]);
        assert_eq!(apply.steps[1].kind(), Some(StepKind::Verify("ds-a")));
        assert_eq!(apply.steps[6].kind(), Some(StepKind::Publish));
    }

    #[test]
    fn a_failed_step_names_itself_and_a_resume_retries_from_it() {
        let mut apply = record();
        apply.complete_step(0, "bundle-abc", 2);
        apply.fail_step(1, "verify failed", 3);
        assert_eq!(apply.status, STATUS_FAILED);
        assert_eq!(apply.failed_step, "verify:ds-a");
        apply.resume("applier", 4);
        assert_eq!(apply.status, STATUS_RUNNING);
        // The done step stays done; the failed one runs again.
        assert_eq!(apply.next_step(), Some(1));
        assert!(apply.failed_step.is_empty() && apply.error.is_empty());
    }

    #[test]
    fn reconcile_keeps_surviving_datasets_and_adds_new_ones_before_publish() {
        let mut apply = record();
        apply.complete_step(0, "inc-a", 2);
        apply.reconcile(&["ds-a".into(), "ds-c".into()], 3);
        let names = apply
            .steps
            .iter()
            .map(|step| (step.name.as_str(), step.status.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                ("backfill:ds-a", STEP_DONE),
                ("verify:ds-a", STEP_PENDING),
                ("merge:ds-a", STEP_PENDING),
                ("backfill:ds-c", STEP_PENDING),
                ("verify:ds-c", STEP_PENDING),
                ("merge:ds-c", STEP_PENDING),
                ("publish", STEP_PENDING),
            ]
        );
    }

    #[test]
    fn completing_the_last_step_completes_the_record() {
        let mut apply = record();
        for index in 0..apply.steps.len() {
            assert_eq!(apply.status, STATUS_RUNNING);
            apply.complete_step(index, "", 5);
        }
        assert_eq!(apply.status, STATUS_COMPLETED);
        assert_eq!(apply.next_step(), None);
        apply.resume("other", 6);
        assert_eq!(apply.status, STATUS_COMPLETED);
        let key = apply.publish_idempotency_key();
        assert!(key.starts_with("bundle-apply-") && key.len() == 45, "{key}");
        assert_eq!(key, record().publish_idempotency_key());
    }

    /// Every write compares and swaps the revision, on every backend.
    fn exercise_store_compare_and_swap(db: &crate::db::runtime_db::RuntimeDb) {
        let mut apply = record();
        assert!(
            db.get_definition_bundle_apply("acme", "p1")
                .unwrap()
                .is_none()
        );
        assert_eq!(db.put_definition_bundle_apply(&apply, 0).unwrap(), 1);
        // A second creator loses.
        assert_eq!(
            db.put_definition_bundle_apply(&apply, 0).unwrap_err(),
            APPLY_REVISION_CONFLICT
        );
        apply.complete_step(0, "bundle-abc", 2);
        assert_eq!(db.put_definition_bundle_apply(&apply, 1).unwrap(), 2);
        // A writer holding the old revision loses.
        assert_eq!(
            db.put_definition_bundle_apply(&apply, 1).unwrap_err(),
            APPLY_REVISION_CONFLICT
        );
        let (stored, revision) = db
            .get_definition_bundle_apply("acme", "p1")
            .unwrap()
            .unwrap();
        assert_eq!((stored, revision), (apply, 2));
    }

    #[test]
    fn store_compares_and_swaps_the_record_revision() {
        exercise_store_compare_and_swap(&crate::db::runtime_db::RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_store_compares_and_swaps_the_record_revision() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = crate::db::runtime_db::RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        exercise_store_compare_and_swap(&db);
    }

    /// Registration takes the binding lock in its own transaction (#1693);
    /// a re-registration replaces the binding.
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_datasource_registration_runs_under_the_binding_lock() {
        use crate::sekai::object_type_index::{CONTRACT_VERSION, ObjectTypeDatasource};
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = crate::db::runtime_db::RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        let mut binding = ObjectTypeDatasource {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "acme".into(),
            kind: "Ticket".into(),
            definition_digest: "sha256:ticket".into(),
            dataset_id: "tickets".into(),
            key_column: "id".into(),
            property_mapping: Default::default(),
            hidden_column: String::new(),
            edits_only: false,
        };
        db.register_object_type_datasource(&binding, 1).unwrap();
        binding.key_column = "key".into();
        db.register_object_type_datasource(&binding, 2).unwrap();
        let stored = db
            .get_object_type_datasource("acme", "Ticket")
            .unwrap()
            .unwrap();
        assert_eq!(stored.key_column, "key");
    }

    /// Adding columns appends only those missing and keeps the existing
    /// definitions as stored, on every backend (#1693).
    fn exercise_add_dataset_columns(db: &crate::db::runtime_db::RuntimeDb) {
        use crate::sekai::dataset::{ColumnDef, Dataset};
        let column = |name: &str, classification: &str| ColumnDef {
            name: name.into(),
            col_type: "string".into(),
            classification: classification.into(),
        };
        let id = format!("ds-{}", uuid::Uuid::new_v4().as_simple());
        db.create_dataset(&Dataset {
            id: id.clone(),
            name: id.clone(),
            columns: vec![column("id", "public"), column("title", "sensitive")],
            object_id: String::new(),
            created: 0,
            partition_keys: Vec::new(),
        })
        .unwrap();
        db.add_dataset_columns(
            &id,
            &[column("title", "public"), column("subject", "public")],
        )
        .unwrap();
        let columns = db.get_dataset(&id).unwrap().unwrap().columns;
        let names = columns
            .iter()
            .map(|c| (c.name.as_str(), c.classification.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                ("id", "public"),
                ("title", "sensitive"),
                ("subject", "public")
            ]
        );
    }

    #[test]
    fn add_dataset_columns_appends_only_the_missing() {
        exercise_add_dataset_columns(&crate::db::runtime_db::RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_add_dataset_columns_appends_only_the_missing() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = crate::db::runtime_db::RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        exercise_add_dataset_columns(&db);
    }
}
