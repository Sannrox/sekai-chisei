//! ADR 0105 index and pointer checks for Issue #1388.

const ADR_0105: &str = include_str!("../docs/decisions/0105-partitioned-transform-io.md");
const ADR_0074: &str = include_str!("../docs/decisions/0074-plane-owned-transforms.md");
const ADR_0102: &str = include_str!("../docs/decisions/0102-isolated-process-transform-profile.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const GOVERNED: &str = include_str!("../docs/governed-transforms.md");
const PARITY: &str = include_str!("../docs/postgres-sekai-parity.md");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

#[test]
fn adr_0105_is_indexed_and_keeps_partitioned_transform_io() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0105: Partitioned streaming I/O for governed transforms](0105-partitioned-transform-io.md)"
        ),
        "decisions index must link ADR 0105"
    );
    assert!(ADR_0105.contains("#1388"), "ADR 0105 must name Issue #1388");
    assert!(
        ADR_0105.contains("sha256-partitions-v1:"),
        "ADR 0105 must name the partitioned digest prefix"
    );
    assert!(
        ADR_0105.contains("sha256-sum-v1:"),
        "ADR 0105 must keep the unpartitioned digest prefix"
    );
    assert!(
        ADR_0074.contains("0105-partitioned-transform-io.md"),
        "ADR 0074 must point at ADR 0105"
    );
    assert!(
        ADR_0102.contains("0105-partitioned-transform-io.md"),
        "ADR 0102 must point at ADR 0105"
    );
    assert!(
        GOVERNED.contains("0105-partitioned-transform-io.md"),
        "governed-transforms.md must cite ADR 0105"
    );
    assert!(
        PARITY.contains("#1388"),
        "postgres-sekai-parity.md must record #1388"
    );
    assert!(
        CHANGELOG.contains("0060_partitioned_transform_io") && CHANGELOG.contains("GATE:mig"),
        "CHANGELOG must name the PostgreSQL migration and GATE:mig"
    );
}
