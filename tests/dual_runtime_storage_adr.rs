//! ADR 0080 index and pointer checks for Issue #870.

const ADR_0080: &str = include_str!("../docs/decisions/0080-dual-community-runtime-storage.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const ENV_EXAMPLE: &str = include_str!("../.env.example");
const ENVELOPE: &str = include_str!("../docs/research/870-embedded-postgres-envelope.md");

#[test]
fn adr_0080_is_indexed_and_keeps_dual_runtime_storage() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0080: Keep dual community control-plane storage](0080-dual-community-runtime-storage.md)"
        ),
        "decisions index must link ADR 0080"
    );
    assert!(ADR_0080.contains("#870"), "ADR 0080 must name Issue #870");
    assert!(
        ADR_0080.contains("https://github.com/Sannrox/sekai-chisei/discussions/906"),
        "ADR 0080 must name Discussion 906"
    );
    assert!(
        ADR_0080.contains("Keep both community control-plane backends"),
        "ADR 0080 must keep SQLite and PostgreSQL"
    );
    assert!(
        ENV_EXAMPLE.contains("SEKAI_DB_BACKEND=sqlite"),
        ".env.example must keep SQLite as the default runtime backend"
    );
    assert!(
        ENV_EXAMPLE.contains("ADR 0080"),
        ".env.example must point at ADR 0080"
    );
    assert!(
        ENVELOPE.contains("ADR 0080"),
        "embed envelope must record that #870 closed as keep dual"
    );
}
