//! Shrink-only SQLite-only surface list and Real backend projection (#1316).

use sekai_chisei::rpc_maturity::{MATURITY_DOCS, RpcMaturityTable};
use sekai_chisei::sqlite_only_surfaces::{
    RUNTIME_DB_SRC, SqliteOnlySurfaces, listed_methods_are_fail_closed, parity_docs_link_the_list,
    real_backend_matches_list, unlisted_fail_closed_rpcs,
};

const SEKAI_PARITY: &str = include_str!("../docs/postgres-sekai-parity.md");
const CHISEI_PARITY: &str = include_str!("../docs/postgres-chisei-parity.md");

#[test]
fn sqlite_only_list_projects_the_real_backend_column() {
    let list = SqliteOnlySurfaces::load().expect("sqlite-only list");
    let table = RpcMaturityTable::load().expect("maturity table");
    listed_methods_are_fail_closed(&list, RUNTIME_DB_SRC).unwrap();
    unlisted_fail_closed_rpcs(&table, &list, RUNTIME_DB_SRC).unwrap();
    real_backend_matches_list(&table, MATURITY_DOCS, &list).unwrap();
    parity_docs_link_the_list(SEKAI_PARITY, CHISEI_PARITY, MATURITY_DOCS).unwrap();
}

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
