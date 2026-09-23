//! ADR 0088 index and operator-boundary checks for Issue #1082.

const ADR_0088: &str =
    include_str!("../docs/decisions/0088-one-object-log-host-many-clerk-clients.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/object-type-index.md");

#[test]
fn adr_0088_is_indexed_and_keeps_944_blocked_on_a_host_release() {
    assert!(DECISIONS_INDEX.contains(
        "[ADR 0088: One object-log host owns identity; clerk processes are its clients](0088-one-object-log-host-many-clerk-clients.md)"
    ));
    assert!(ADR_0088.contains("#1082"));
    assert!(ADR_0088.contains("Accept option 2 of #1082"));
    assert!(ADR_0088.contains("**#944.** Stays blocked."));
}

#[test]
fn operator_page_limits_the_in_process_log_to_one_writer() {
    assert!(OPERATOR.contains("in-process log handle is a single writer"));
}
