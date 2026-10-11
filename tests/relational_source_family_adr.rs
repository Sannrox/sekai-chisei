//! ADR 0100 index and related-pointer checks for Issue #1410.

const ADR_0021: &str = include_str!("../docs/decisions/0021-defer-second-object-sync-source.md");
const ADR_0060: &str = include_str!("../docs/decisions/0060-additive-source-type-descriptors.md");
const ADR_0100: &str = include_str!("../docs/decisions/0100-relational-source-family.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OBJECT_SYNC: &str = include_str!("../docs/object-sync.md");

#[test]
fn adr_0100_is_indexed_and_names_the_source_issue() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0100: Bound a PostgreSQL-first relational source family](0100-relational-source-family.md)"
        ),
        "decisions index must link ADR 0100"
    );
    assert!(ADR_0100.contains("#1410"), "ADR 0100 must name Issue #1410");
    assert!(
        ADR_0100.contains("postgres.table"),
        "ADR 0100 must name the registered source token"
    );
    assert!(
        ADR_0100.contains("{source}:{instance}#{record_kind}/{immutable_key}"),
        "ADR 0100 must reuse the ADR 0060 identity grammar"
    );
    assert!(
        ADR_0100.contains("{system}/{database}/{schema}/{table}"),
        "ADR 0100 must include a stable system identifier in the instance"
    );
    assert!(
        ADR_0100.contains("Tables, schemas, and databases on that system share it"),
        "ADR 0100 must let tables on one system share the system token"
    );
    assert!(
        ADR_0100.contains("source_control.object_sync"),
        "ADR 0100 must keep the catalog family"
    );
    assert!(
        ADR_0100.contains("This ADR implements no connector"),
        "ADR 0100 must keep connectors out of Chisei"
    );
}

#[test]
fn adr_0100_does_not_supersede_github_or_descriptor_rules() {
    assert!(
        !ADR_0021.contains("Superseded by: [ADR 0100"),
        "ADR 0100 must not supersede ADR 0021"
    );
    assert!(
        !ADR_0060.contains("Superseded by: [ADR 0100"),
        "ADR 0100 must not supersede ADR 0060"
    );
    assert!(
        ADR_0021.contains("0100-relational-source-family.md"),
        "ADR 0021 must point at the later relational-source decision"
    );
    assert!(
        ADR_0060.contains("0100-relational-source-family.md"),
        "ADR 0060 must point at the later relational-source decision"
    );
}

#[test]
fn object_sync_points_at_the_relational_profile() {
    assert!(
        OBJECT_SYNC.contains("0100-relational-source-family.md"),
        "object-sync docs must name ADR 0100"
    );
    assert!(
        OBJECT_SYNC.contains("postgres.table"),
        "object-sync docs must name the postgres.table profile"
    );
    assert!(
        OBJECT_SYNC.contains("not a second adapter family"),
        "object-sync docs must keep the relational profile inside the existing family"
    );
}

#[test]
fn adr_0100_lists_family_conformance_cases() {
    assert!(
        ADR_0100.contains("### Identity")
            && ADR_0100.contains("### Handoff and checkpoints")
            && ADR_0100.contains("### Drift, quarantine, and health")
            && ADR_0100.contains("### Connector boundary"),
        "ADR 0100 must list conformance cases for the family"
    );
    assert!(
        ADR_0100.contains("warehouse table ingest"),
        "ADR 0100 must reject the warehouse snapshot profile as the change-feed contract"
    );
    assert!(
        ADR_0100.contains("sekai.source-batch/v1") && ADR_0100.contains("feed_epoch_conflict"),
        "ADR 0100 must keep snapshot-only on v1 and epoch replacement on the existing v2 conflict"
    );
}
