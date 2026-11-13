//! PostgreSQL conformance CI trigger (#1316).

#[test]
fn postgres_conformance_runs_on_every_pull_request() {
    let workflow = include_str!("../.github/workflows/postgres-conformance.yml");
    assert!(
        workflow.contains("pull_request:"),
        "PostgreSQL conformance must run on pull requests"
    );
    let after_pr = workflow
        .split("pull_request:")
        .nth(1)
        .expect("pull_request trigger");
    let trigger_body = after_pr.split("\nschedule:").next().unwrap_or(after_pr);
    assert!(
        !trigger_body.contains("paths:"),
        "PostgreSQL conformance must not path-filter pull requests:\n{trigger_body}"
    );
}
