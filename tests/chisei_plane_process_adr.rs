//! ADR 0098 index and pointer checks for Issue #1300.

const ADR_0098: &str = include_str!("../docs/decisions/0098-keep-chisei-plane-process.md");
const ADR_0096: &str = include_str!("../docs/decisions/0096-sekai-runs-without-chisei.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const TWO_PLANE: &str = include_str!("../docs/two-plane-processes.md");
const CARGO: &str = include_str!("../Cargo.toml");

#[test]
fn adr_0098_keeps_chisei_plane_and_is_indexed() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0098: Keep a separate `chisei-plane` process](0098-keep-chisei-plane-process.md)"
        ),
        "decisions index must link ADR 0098"
    );
    assert!(ADR_0098.contains("#1300"), "ADR 0098 must name Issue #1300");
    assert!(
        ADR_0098.contains("Keep `chisei-plane`"),
        "ADR 0098 must keep the separate Chisei process"
    );
    assert!(
        ADR_0096.contains("0098-keep-chisei-plane-process.md"),
        "ADR 0096 must point at ADR 0098 for the process question"
    );
    assert!(
        TWO_PLANE.contains("0098-keep-chisei-plane-process.md"),
        "two-plane docs must cite ADR 0098"
    );
    assert!(
        CARGO.contains("name = \"chisei-plane\"") && CARGO.contains("path = \"src/bin/chisei.rs\""),
        "Cargo.toml must still declare chisei-plane"
    );
}
