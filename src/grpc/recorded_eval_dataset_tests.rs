//! Recorded eval datasets (ADR 0153, #3513) through both services in one
//! process: decided Action instances become a dataset version, a run replays
//! them through the agent dry run, and every read stays inside what the
//! caller could read of the sources.

use super::*;
use crate::grpc::chisei_service::ChiseiServiceImpl;
use crate::grpc::pb::chisei as cpb;
use cpb::chisei_service_server::ChiseiService as _;

const NS: &str = "recorded-eval";
/// Parameter values that must never reach an eval table.
const GRANTED_TICKET: &str = "TICKET-ALPHA-7731";
const DENIED_TICKET: &str = "TICKET-BRAVO-9142";

struct Fixture {
    sekai: Arc<SekaiServiceImpl>,
    chisei: ChiseiServiceImpl,
    revision: String,
    evaluator: String,
    granted_instance: String,
}

/// Decides one parked instance as `alice`, a credentialed namespace admin
/// (`root` is a reserved operator name and cannot decide).
async fn decide(svc: &SekaiServiceImpl, instance_id: &str, decision: &str) {
    svc.decide_action_instance(as_decider(
        DecideActionInstanceRequest {
            instance_id: instance_id.into(),
            decision: decision.into(),
            reason: String::new(),
            ..Default::default()
        },
        "alice",
    ))
    .await
    .unwrap();
}

/// Two `Ticket.inspect` requests `tester` submitted and `alice` decided, one
/// granted and one denied, and an agent whose scripted turn proposes the
/// granted request only.
async fn fixture() -> Fixture {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    crate::chisei_store::apply_chisei_schema(&db);
    let mut svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
        db.clone(),
    ));
    let revision = seed_agent_draft(&svc, NS).await;
    seed_inspect_action_type(&svc, NS);
    grant_source_namespace(&svc, NS, "tester", security::Role::Editor);
    grant_source_namespace(&svc, NS, "outsider", security::Role::Editor);
    grant_source_namespace(&svc, NS, "alice", security::Role::Admin);
    let mut policy = action_policy::ActionPolicy::allow_all("agent:tester");
    policy.action_overrides.insert(
        crate::sekai::action_instance::SUBMIT_POLICY_ACTION.into(),
        action_policy::ActionDecision::RequireApproval,
    );
    svc.db.runtime().upsert_action_policy(&policy).unwrap();
    let mut submitted = Vec::new();
    for ticket in [GRANTED_TICKET, DENIED_TICKET] {
        let instance = svc
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: NS.into(),
                type_id: "Ticket.inspect".into(),
                version: "1".into(),
                parameters_json: serde_json::json!({ "id": ticket }).to_string(),
                idempotency_key: format!("submit-{ticket}"),
                request_id: format!("req-{ticket}"),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .instance
            .unwrap();
        submitted.push(instance.instance_id);
    }
    decide(&svc, &submitted[0], "grant").await;
    decide(&svc, &submitted[1], "deny").await;
    svc.dry_run_host = Some(Arc::new(
        crate::sekai::agent_dry_run::ScriptedHost::proposing(vec![
            crate::sekai::agent_dry_run::ProposedAction {
                action_type: "Ticket.inspect".into(),
                parameters_json: serde_json::json!({ "id": GRANTED_TICKET }).to_string(),
            },
        ]),
    ));
    let sekai = Arc::new(svc);
    let chisei = ChiseiServiceImpl::new(
        crate::chisei_store::ChiseiStore::from_shared_runtime(db),
        crate::grpc::chisei_service::tests::config(":memory:"),
    )
    .with_sekai_facts(crate::chisei::sekai_facts::SekaiFacts::in_process(
        sekai.db.clone(),
    ))
    .unwrap();
    chisei.attach_sekai_service(&sekai);
    let evaluator = chisei
        .put_evaluator_definition(with_named_principal(
            cpb::PutEvaluatorDefinitionRequest {
                definition: Some(cpb::EvaluatorDefinition {
                    contract_version:
                        crate::chisei::evaluation_plan::EVALUATOR_DEFINITION_CONTRACT.into(),
                    namespace: NS.into(),
                    evaluator_id: "decision-match".into(),
                    version: "1.0.0".into(),
                    implementation_digest: format!("sha256:{}", "a".repeat(64)),
                    execution_class:
                        crate::chisei::evaluation_plan::DETERMINISTIC_EXECUTION_CLASS.into(),
                    supported_predicate_kinds: vec!["schema_conforms".into()],
                    supported_input_schemas: vec![
                        crate::chisei::eval_dataset::EVAL_CASE_SCHEMA.into(),
                    ],
                    supported_result_schemas: vec!["schema://pass-fail/v1".into()],
                    parameter_schema_json: r#"{"type":"object","properties":{"strict":{"type":"boolean"}},"required":["strict"],"additionalProperties":false}"#.into(),
                    evidence_classifications: vec!["internal".into()],
                    resource_limits: Some(cpb::EvaluatorResourceLimits {
                        timeout_ms: 1_000,
                        max_input_bytes: 4_096,
                        max_output_bytes: 1_024,
                        max_evidence_items: 8,
                    }),
                    source_ref: "repo://evaluators/decision-match@1".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .record
        .unwrap()
        .definition
        .unwrap()
        .definition_id;
    Fixture {
        sekai,
        chisei,
        revision,
        evaluator,
        granted_instance: submitted.remove(0),
    }
}

fn selection() -> String {
    serde_json::json!({
        "contract_version": crate::chisei::eval_dataset::recorded::RECORDED_DATASET_DEFINITION_CONTRACT,
        "name": "inspect-decisions",
        "action_type": "Ticket.inspect",
        "decided_from_ms": 0,
        "decided_to_ms": i64::MAX,
    })
    .to_string()
}

async fn put(
    fixture: &Fixture,
    principal: &str,
) -> Result<cpb::EvalDatasetDefinitionRecord, Status> {
    fixture
        .chisei
        .put_eval_dataset_definition(with_named_principal(
            cpb::PutEvalDatasetDefinitionRequest {
                namespace: NS.into(),
                definition_json: selection(),
            },
            principal,
        ))
        .await
        .map(|response| response.into_inner().record.unwrap())
}

async fn cases(fixture: &Fixture, version: &str, principal: &str) -> Result<Vec<String>, Status> {
    fixture
        .chisei
        .list_eval_dataset_cases(with_named_principal(
            cpb::ListEvalDatasetCasesRequest {
                namespace: NS.into(),
                dataset: "inspect-decisions".into(),
                dataset_version: version.into(),
                ..Default::default()
            },
            principal,
        ))
        .await
        .map(|response| {
            response
                .into_inner()
                .cases
                .into_iter()
                .map(|case| case.case_id)
                .collect()
        })
}

async fn run(
    fixture: &Fixture,
    run_id: &str,
    version: &str,
    principal: &str,
) -> Result<cpb::RunEvalDatasetResponse, Status> {
    fixture
        .chisei
        .run_eval_dataset(with_named_principal(
            cpb::RunEvalDatasetRequest {
                namespace: NS.into(),
                run_id: run_id.into(),
                dataset: "inspect-decisions".into(),
                dataset_version: version.into(),
                agent: format!("triage@{}", fixture.revision),
                model: "deterministic".into(),
                tool_version: "tools@1".into(),
                evaluator_definition_id: fixture.evaluator.clone(),
                concurrency: 1,
                budget_micros: 1_000,
                max_case_cost_micros: 10,
                artifact_digest: String::new(),
            },
            principal,
        ))
        .await
        .map(Response::into_inner)
}

/// Instances and effects in the namespace, as an admin reads them.
async fn action_counts(sekai: &SekaiServiceImpl) -> (usize, usize) {
    let instances = sekai
        .list_action_instances(with_named_principal(
            ListActionInstancesRequest {
                namespace: NS.into(),
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .instances
        .len();
    let effects = sekai
        .list_action_effects(with_named_principal(
            ListActionEffectsRequest {
                namespace: NS.into(),
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .effects
        .len();
    (instances, effects)
}

/// Every text value of every eval table, for the "no values copied" check.
fn eval_table_text(sekai: &SekaiServiceImpl) -> String {
    let conn = sekai.db.runtime().conn();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%eval%'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut text = String::new();
    for table in tables {
        let mut statement = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
        let columns = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for column in 0..columns {
                if let Ok(Some(value)) = row.get::<_, Option<String>>(column) {
                    text.push_str(&value);
                    text.push('\n');
                }
            }
        }
    }
    text
}

#[tokio::test]
async fn recorded_decisions_replay_through_the_dry_run_without_acting() {
    let fixture = fixture().await;
    // Selecting decisions into a reusable labelled set is a namespace admin's.
    let refused = put(&fixture, "tester").await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    let record = put(&fixture, "root").await.unwrap();
    assert_eq!(record.source, "recorded");
    assert_eq!(record.case_count, 2);
    assert!(!record.definition_json.contains(&fixture.granted_instance));
    let listed = fixture
        .chisei
        .list_eval_dataset_definitions(with_named_principal(
            cpb::ListEvalDatasetDefinitionsRequest {
                namespace: NS.into(),
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .definitions;
    assert!(
        listed
            .iter()
            .any(|listed| listed.version == record.version && listed.source == "recorded")
    );
    assert_eq!(
        cases(&fixture, &record.version, "root")
            .await
            .unwrap()
            .len(),
        2
    );

    let before = action_counts(&fixture.sekai).await;
    let report = run(&fixture, "recorded-1", &record.version, "root")
        .await
        .unwrap();
    assert_eq!(report.cases_total, 2);
    let mut verdicts: Vec<_> = report
        .ledger
        .iter()
        .map(|line| (line.passed, line.reason.as_str()))
        .collect();
    verdicts.sort();
    assert_eq!(
        verdicts,
        [
            (true, "did not propose the denied action"),
            (true, "proposed the granted action"),
        ]
    );
    assert_eq!(
        action_counts(&fixture.sekai).await,
        before,
        "a recorded run submits nothing"
    );
    let stored = eval_table_text(&fixture.sekai);
    for ticket in [GRANTED_TICKET, DENIED_TICKET] {
        assert!(
            !stored.contains(ticket),
            "{ticket} copied into an eval table"
        );
    }
}

#[tokio::test]
async fn an_uncleared_caller_cannot_tell_a_recorded_case_from_a_missing_one() {
    let fixture = fixture().await;
    let record = put(&fixture, "root").await.unwrap();
    // `outsider` writes the namespace but neither submitted, approves nor
    // administers these instances.
    assert!(
        cases(&fixture, &record.version, "outsider")
            .await
            .unwrap()
            .is_empty()
    );
    let hidden = run(&fixture, "outsider-1", &record.version, "outsider")
        .await
        .unwrap_err();
    let missing = run(&fixture, "outsider-2", "sha256:missing", "outsider")
        .await
        .unwrap_err();
    assert_eq!(hidden.code(), tonic::Code::NotFound);
    assert_eq!(
        (hidden.code(), hidden.message()),
        (missing.code(), missing.message())
    );
}

#[tokio::test]
async fn erasing_a_source_retires_the_recorded_version() {
    let fixture = fixture().await;
    let record = put(&fixture, "root").await.unwrap();
    // Erasure rewrites the stored parameters in place and keeps the digest.
    let mut instance = fixture
        .sekai
        .db
        .runtime()
        .get_action_instance(&fixture.granted_instance)
        .unwrap()
        .unwrap();
    instance.parameters_json = r#"{"id":""}"#.into();
    instance.erased_properties = vec!["id".into()];
    fixture
        .sekai
        .db
        .runtime()
        .conn()
        .execute(
            "UPDATE sekai_action_instances SET parameters_json = ?1, body_json = ?2
             WHERE instance_id = ?3",
            rusqlite::params![
                instance.parameters_json,
                serde_json::to_string(&instance).unwrap(),
                instance.instance_id
            ],
        )
        .unwrap();
    let listed = cases(&fixture, &record.version, "root").await.unwrap_err();
    assert_eq!(listed.code(), tonic::Code::NotFound);
    let ran = run(&fixture, "after-erasure", &record.version, "root")
        .await
        .unwrap_err();
    assert_eq!(ran.code(), tonic::Code::NotFound);
}
