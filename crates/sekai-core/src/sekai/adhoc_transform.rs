//! Caller-scoped ad-hoc governed transform runs (ADR 0138, #1964).
//!
//! An inline definition runs once with the caller's read authority. Its
//! identity is a digest of the namespace, the caller, the session label and
//! the idempotency key, so a retry returns the same run across restarts and
//! one caller can neither reach nor collide with another's run. The output
//! lands in a scratch dataset named from the identity, bound to a scratch
//! object in the namespace, with an expiry a later sweep honours. A plane
//! output budget is checked before anything is written; the run is recorded
//! and receipted like any run, with trigger cause [`TRANSFORM_TRIGGER_ADHOC`]
//! and the session label as its trigger reference.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::governed_transform::{GovernedTransform, TransformRun};

/// Trigger cause of an ad-hoc run's receipt.
pub const TRANSFORM_TRIGGER_ADHOC: &str = "adhoc";
/// Error of a run whose output exceeds the plane budget.
pub const ADHOC_OUTPUT_BUDGET: &str = "transform_adhoc_output_budget";
/// Error of a run reading a column the caller may not read.
pub const ADHOC_COLUMN_DENIED: &str = "transform_adhoc_column_denied";
/// Error of a retried identity carrying a different definition.
pub const ADHOC_IDENTITY_CONFLICT: &str =
    "an ad-hoc run with this session and idempotency key ran a different definition";
/// Kind of the object a scratch output dataset is bound to.
pub const SCRATCH_OBJECT_KIND: &str = "sekai_adhoc_scratch";
/// How long a scratch output is kept before the sweep may delete it.
pub const DEFAULT_SCRATCH_RETENTION_MS: i64 = 86_400_000;
/// Longest accepted session label.
pub const MAX_SESSION_LABEL: usize = 128;
/// Longest accepted idempotency key.
pub const MAX_IDEMPOTENCY_KEY: usize = 128;

/// Plane caps on one run's output; the request cannot raise them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputBudget {
    pub max_rows: usize,
    pub max_bytes: usize,
}

impl Default for OutputBudget {
    fn default() -> Self {
        Self {
            max_rows: 10_000,
            max_bytes: 8 * 1024 * 1024,
        }
    }
}

impl OutputBudget {
    /// Refuses output over either cap; output is never truncated.
    pub fn admit(&self, rows: &[HashMap<String, String>]) -> Result<(), String> {
        let bytes: usize = rows
            .iter()
            .flat_map(|row| row.iter())
            .map(|(column, value)| column.len() + value.len())
            .sum();
        if rows.len() > self.max_rows || bytes > self.max_bytes {
            return Err(ADHOC_OUTPUT_BUDGET.into());
        }
        Ok(())
    }
}

/// Who asks, in which session, under which key.
#[derive(Debug, Clone)]
pub struct AdHocRequest {
    pub namespace: String,
    pub caller: String,
    pub session_label: String,
    pub idempotency_key: String,
}

impl AdHocRequest {
    pub fn validate(&self) -> Result<(), String> {
        for (name, value, max) in [
            ("session_label", &self.session_label, MAX_SESSION_LABEL),
            (
                "idempotency_key",
                &self.idempotency_key,
                MAX_IDEMPOTENCY_KEY,
            ),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{name} required"));
            }
            if value.len() > max {
                return Err(format!("{name} exceeds {max} bytes"));
            }
        }
        if self.caller.trim().is_empty() {
            return Err("caller required".into());
        }
        Ok(())
    }

    /// The run identity: one per namespace, caller, session and key.
    pub fn identity(&self) -> String {
        // Each part length-prefixed, so no two distinct requests share one.
        let mut hasher = Sha256::new();
        for part in [
            &self.namespace,
            &self.caller,
            &self.session_label,
            &self.idempotency_key,
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// The scratch output dataset of this identity.
    pub fn scratch_dataset_id(&self) -> String {
        format!("scratch-{}", &self.identity()[..32])
    }

    /// Binds `transform` to this request: its id and output name the scratch
    /// dataset, so the definition digest covers them.
    pub fn bind(&self, mut transform: GovernedTransform) -> GovernedTransform {
        let scratch = self.scratch_dataset_id();
        transform.namespace = self.namespace.clone();
        transform.transform_id = scratch.clone();
        transform.output_dataset_id = scratch;
        transform.schedule = None;
        transform.trigger = None;
        transform.definition_digest = String::new();
        transform
    }
}

/// A committed ad-hoc run and where its output is.
#[derive(Debug, Clone)]
pub struct AdHocRun {
    pub run: TransformRun,
    pub scratch_dataset_id: String,
    pub expires_at_ms: i64,
    /// True when an earlier submission with this identity made the run.
    pub replayed: bool,
}

/// Runs the bound, prepared `transform` for `request`. A repeated identity
/// returns its run; the same identity with another definition is refused.
pub fn run(
    db: &RuntimeDb,
    request: &AdHocRequest,
    transform: &GovernedTransform,
    budget: &OutputBudget,
    column_allowlists: &HashMap<String, Vec<String>>,
    expires_at_ms: i64,
    tenant_id: &str,
    now_ms: i64,
) -> Result<AdHocRun, String> {
    request.validate()?;
    match db {
        RuntimeDb::Sqlite(store) => store.run_adhoc_transform(
            request,
            transform,
            budget,
            column_allowlists,
            expires_at_ms,
            tenant_id,
            now_ms,
        ),
        RuntimeDb::Postgres(store) => crate::db::postgres::off_runtime(|| {
            store.run_adhoc_transform(
                request,
                transform,
                budget,
                column_allowlists,
                expires_at_ms,
                tenant_id,
                now_ms,
            )
        }),
    }
}

/// The scratch object a run's output dataset is bound to.
pub(crate) fn scratch_object(request: &AdHocRequest, now_ms: i64) -> crate::domain::Object {
    let dataset_id = request.scratch_dataset_id();
    crate::domain::Object {
        id: format!("{dataset_id}-object"),
        kind: SCRATCH_OBJECT_KIND.into(),
        name: dataset_id,
        namespace: request.namespace.clone(),
        external_id: String::new(),
        properties: HashMap::from([
            ("session_label".to_string(), request.session_label.clone()),
            ("owner".to_string(), request.caller.clone()),
        ]),
        created: now_ms,
        updated: now_ms,
    }
}

/// The grant that keeps a scratch output to its caller.
pub fn scratch_grant(request: &AdHocRequest, now_ms: i64) -> crate::sekai::security::Grant {
    let object_id = format!("{}-object", request.scratch_dataset_id());
    crate::sekai::security::Grant {
        id: format!("{object_id}-owner"),
        object_id,
        principal: request.caller.clone(),
        role: crate::sekai::security::Role::Admin,
        created: now_ms,
        ..Default::default()
    }
}

/// Refuses rows carrying a key outside `allowed`, when a caller's read of
/// the dataset is limited to it. A run reads whole rows, so a hidden key
/// would otherwise reach the output.
pub(crate) fn require_allowed_columns(
    allowed: Option<&Vec<String>>,
    records: &[crate::sekai::dataset::DatasetRowRecord],
) -> Result<(), String> {
    let Some(allowed) = allowed else {
        return Ok(());
    };
    if records
        .iter()
        .flat_map(|(_, row)| row.keys())
        .any(|key| !allowed.contains(key))
    {
        return Err(ADHOC_COLUMN_DENIED.into());
    }
    Ok(())
}

/// Column definitions of the scratch dataset, from its output rows.
pub(crate) fn scratch_columns(rows: &[HashMap<String, String>]) -> String {
    let mut names: Vec<&String> = rows.iter().flat_map(|row| row.keys()).collect();
    names.sort();
    names.dedup();
    serde_json::to_string(
        &names
            .into_iter()
            .map(|name| {
                (
                    name,
                    "string",
                    crate::sekai::schema::default_property_classification(),
                )
            })
            .collect::<Vec<_>>(),
    )
    .expect("column names serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(caller: &str, key: &str) -> AdHocRequest {
        AdHocRequest {
            namespace: "ops".into(),
            caller: caller.into(),
            session_label: "s1".into(),
            idempotency_key: key.into(),
        }
    }

    #[test]
    fn identity_is_per_caller_session_and_key() {
        assert_eq!(
            request("ana", "k").identity(),
            request("ana", "k").identity()
        );
        assert_ne!(
            request("ana", "k").identity(),
            request("bo", "k").identity()
        );
        assert_ne!(
            request("ana", "k").identity(),
            request("ana", "j").identity()
        );
        assert!(
            request("ana", "k")
                .scratch_dataset_id()
                .starts_with("scratch-")
        );
    }

    #[test]
    fn requests_need_bounded_labels_and_keys() {
        assert!(request("ana", "k").validate().is_ok());
        assert!(request("ana", "").validate().is_err());
        assert!(request("", "k").validate().is_err());
        assert!(request("ana", &"k".repeat(129)).validate().is_err());
    }

    #[test]
    fn the_budget_refuses_rows_or_bytes_over_its_caps() {
        let budget = OutputBudget {
            max_rows: 2,
            max_bytes: 20,
        };
        let row = |value: &str| HashMap::from([("v".to_string(), value.to_string())]);
        assert!(budget.admit(&[row("a"), row("b")]).is_ok());
        assert_eq!(
            budget.admit(&[row("a"), row("b"), row("c")]),
            Err(ADHOC_OUTPUT_BUDGET.into())
        );
        assert_eq!(
            budget.admit(&[row(&"x".repeat(30))]),
            Err(ADHOC_OUTPUT_BUDGET.into())
        );
    }

    fn filter(input: &str, keep: &str) -> GovernedTransform {
        use crate::sekai::governed_transform::{AnalyticalSpec, CONTRACT_VERSION, TransformStep};
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: String::new(),
            transform_id: String::new(),
            input_dataset_id: input.into(),
            output_dataset_id: String::new(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: keep.into(),
                columns: Vec::new(),
            }],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: Some(AnalyticalSpec::default()),
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
    }

    /// Run, replay, conflicting definition, output budget and a session
    /// chain on one store (#1964).
    fn adhoc_contract(db: &RuntimeDb, ns: &str) {
        let input = format!("{ns}-in");
        db.create_dataset(&crate::sekai::dataset::Dataset {
            id: input.clone(),
            name: input.clone(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        let row = |id: &str, keep: &str| {
            HashMap::from([
                ("id".to_string(), id.to_string()),
                ("keep".to_string(), keep.to_string()),
            ])
        };
        db.append_rows(&input, &[row("1", "yes"), row("2", "yes"), row("3", "no")])
            .unwrap();
        let ask = |key: &str| AdHocRequest {
            namespace: ns.into(),
            caller: "ana".into(),
            session_label: "explore".into(),
            idempotency_key: key.into(),
        };
        let bound = |request: &AdHocRequest, transform| request.bind(transform).prepare().unwrap();
        let budget = OutputBudget::default();
        let none = HashMap::new();

        let first_request = ask("k1");
        let first_definition = bound(&first_request, filter(&input, "yes"));
        let first = run(
            db,
            &first_request,
            &first_definition,
            &budget,
            &none,
            9_000,
            "",
            100,
        )
        .unwrap();
        assert!(!first.replayed);
        assert_eq!(first.run.trigger_cause, TRANSFORM_TRIGGER_ADHOC);
        assert_eq!(first.run.trigger_ref, "explore");
        let output = db
            .query_rows(&first.scratch_dataset_id, &Default::default())
            .unwrap();
        assert_eq!(output.len(), 2);

        let grants = db
            .list_grants(&format!("{}-object", first.scratch_dataset_id))
            .unwrap();
        assert_eq!(
            grants
                .iter()
                .map(|grant| grant.principal.as_str())
                .collect::<Vec<_>>(),
            ["ana"],
            "only the caller holds the scratch output"
        );

        let limited = ask("k5");
        assert_eq!(
            run(
                db,
                &limited,
                &bound(&limited, filter(&input, "yes")),
                &budget,
                &HashMap::from([(input.clone(), vec!["id".to_string()])]),
                9_000,
                "",
                150,
            )
            .unwrap_err(),
            ADHOC_COLUMN_DENIED,
            "a row key the caller may not read refuses the run"
        );
        assert!(
            db.get_dataset(&limited.scratch_dataset_id())
                .unwrap()
                .is_none()
        );

        let again = run(
            db,
            &first_request,
            &first_definition,
            &budget,
            &none,
            9_000,
            "",
            200,
        )
        .unwrap();
        assert!(again.replayed);
        assert_eq!(again.run.run_id, first.run.run_id);
        assert_eq!(
            run(
                db,
                &first_request,
                &bound(&first_request, filter(&input, "no")),
                &budget,
                &none,
                9_000,
                "",
                300
            )
            .unwrap_err(),
            ADHOC_IDENTITY_CONFLICT
        );

        let tight = ask("k2");
        let small = OutputBudget {
            max_rows: 1,
            max_bytes: 1_000,
        };
        assert_eq!(
            run(
                db,
                &tight,
                &bound(&tight, filter(&input, "yes")),
                &small,
                &none,
                9_000,
                "",
                400
            )
            .unwrap_err(),
            ADHOC_OUTPUT_BUDGET
        );
        assert!(
            db.get_dataset(&tight.scratch_dataset_id())
                .unwrap()
                .is_none()
        );

        // A later run in the session reads the first output.
        let chained_request = ask("k3");
        let chained = run(
            db,
            &chained_request,
            &bound(&chained_request, filter(&first.scratch_dataset_id, "yes")),
            &budget,
            &none,
            9_000,
            "",
            500,
        )
        .unwrap();
        assert_eq!(chained.run.rows_out, 2);

        // A marked input marks the output and the receipt.
        let marked = format!("{ns}-marked");
        db.create_object(&crate::domain::Object {
            id: format!("{marked}-object"),
            kind: "artifact".into(),
            name: marked.clone(),
            namespace: ns.into(),
            external_id: String::new(),
            properties: HashMap::from([(
                crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.to_string(),
                "internal".to_string(),
            )]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_dataset(&crate::sekai::dataset::Dataset {
            id: marked.clone(),
            name: marked.clone(),
            columns: Vec::new(),
            object_id: format!("{marked}-object"),
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
        db.append_rows(&marked, &[row("9", "yes")]).unwrap();
        let marking_request = ask("k4");
        let marked_run = run(
            db,
            &marking_request,
            &bound(&marking_request, filter(&marked, "yes")),
            &budget,
            &none,
            9_000,
            "",
            600,
        )
        .unwrap();
        assert!(marked_run.run.markings_out.contains("internal"));
        let scratch = db
            .get_dataset(&marked_run.scratch_dataset_id)
            .unwrap()
            .unwrap();
        let object = db.get_object(&scratch.object_id).unwrap().unwrap();
        assert_eq!(
            crate::sekai::markings::object_marking_token(&object),
            Some("internal")
        );
    }

    #[test]
    fn sqlite_adhoc_runs_follow_the_contract() {
        adhoc_contract(&RuntimeDb::memory(), "ops");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_adhoc_runs_follow_the_contract() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        adhoc_contract(
            &db,
            &format!(
                "adhoc-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            ),
        );
    }
}
