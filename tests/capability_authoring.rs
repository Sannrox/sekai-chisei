use std::collections::BTreeMap;

use sekai_chisei::chisei::capability::{
    CapabilityGateError, CapabilityObservation, CapabilityRegistryError,
    author_capability_proposals, gate_capability_proposal, list_capability_versions,
    register_capability, review_capability_proposal,
};
use sekai_chisei::chisei::eval::{CaseResult, EvalStore, Run};
use sekai_chisei::chisei::evolve::TaskRecord;
use sekai_chisei::db::sekai::SekaiDb;

fn observation(
    id: &str,
    status: &str,
    action_types: &[&str],
    created: i64,
) -> CapabilityObservation {
    CapabilityObservation {
        task: TaskRecord {
            id: id.to_string(),
            spec: format!("Review change {id} and report focused verification"),
            status: status.to_string(),
            namespace: "acme".to_string(),
            tokens_used: 100,
            original_spec: None,
            created,
        },
        task_class: "code review".to_string(),
        action_types: action_types
            .iter()
            .map(|action| action.to_string())
            .collect(),
    }
}

fn passing_run(proposal: &sekai_chisei::chisei::capability::CapabilityProposal) -> Run {
    Run {
        id: "capability-integration-run".to_string(),
        suite_id: proposal.eval_suite.id.clone(),
        config_ref: proposal.id.clone(),
        results: proposal
            .eval_suite
            .cases
            .iter()
            .map(|case| CaseResult {
                case_id: case.id.clone(),
                passed: true,
                status: "ok".to_string(),
                result: String::new(),
                score: 100,
                reason: String::new(),
                elapsed: 1,
            })
            .collect(),
        timestamp: 30,
    }
}

#[test]
fn capability_authoring_requires_exact_review_and_gate_proof_before_launch() {
    let db = SekaiDb::new(":memory:").expect("open in-memory database");
    let observations = vec![
        observation("task-1", "done", &["comment", "invented"], 1),
        observation("task-2", "done", &["comment"], 2),
        observation("task-3", "failed", &["delete_object", "invented"], 3),
    ];

    let mut proposal = author_capability_proposals(
        &observations,
        &["comment".to_string(), "delete_object".to_string()],
        &BTreeMap::new(),
        "chisei.author",
        10,
    )
    .pop()
    .expect("recurring successful task class should produce a proposal");

    assert_eq!(proposal.allowed_action_types, ["comment"]);
    assert!(
        list_capability_versions(&db, "acme", "code review")
            .expect("list capability versions")
            .is_empty(),
        "authoring must not persist or launch a capability"
    );

    review_capability_proposal(
        &db,
        &mut proposal,
        "human:reviewer",
        true,
        "scope and seed suite approved",
        20,
    )
    .expect("approve exact proposal");

    let mut changed_after_review = proposal.clone();
    changed_after_review.rationale = "mutated after approval".to_string();
    let changed_eval = EvalStore::new();
    changed_eval.create_run(passing_run(&changed_after_review));
    assert_eq!(
        gate_capability_proposal(
            &db,
            &changed_eval,
            &mut changed_after_review,
            "capability-integration-run",
            "chisei.gate",
            30,
        ),
        Err(CapabilityGateError::ProposalChanged)
    );

    let approved_but_ungated = proposal.clone();
    let eval = EvalStore::new();
    eval.create_run(passing_run(&proposal));
    let authorization = gate_capability_proposal(
        &db,
        &eval,
        &mut proposal,
        "capability-integration-run",
        "chisei.gate",
        30,
    )
    .expect("gate proposal")
    .expect("passing seed suite should authorize launch");

    let launch_error = register_capability(
        &db,
        &approved_but_ungated,
        &authorization,
        "human:registrar",
        40,
    )
    .expect_err("an approved but ungated proposal must not launch");
    assert_eq!(
        launch_error,
        CapabilityRegistryError::InvalidAuthorization(
            "passing gate evidence is required".to_string()
        )
    );
    assert!(
        list_capability_versions(&db, "acme", "code review")
            .expect("list capability versions")
            .is_empty(),
        "an ungated launch attempt must not persist a capability"
    );

    let registered = register_capability(&db, &proposal, &authorization, "human:registrar", 40)
        .expect("register reviewed and gated capability");
    assert_eq!(registered.version, 1);
    assert_eq!(registered.proposal.id, proposal.id);
}
