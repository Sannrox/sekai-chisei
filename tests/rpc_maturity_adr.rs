//! ADR 0071 index checks for Issue #871.

const ADR_0071: &str = include_str!("../docs/decisions/0071-rpc-maturity.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const MATURITY_DOCS: &str = include_str!("../docs/rpc-maturity.md");

#[test]
fn adr_0071_is_indexed_and_names_the_projection() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0071: Classify public RPCs by backend and consumer evidence](0071-rpc-maturity.md)"
        ),
        "decisions index must link ADR 0071"
    );
    assert!(ADR_0071.contains("#871"), "ADR 0071 must name Issue #871");
    assert!(
        ADR_0071.contains("sekai.rpc.experimental"),
        "ADR 0071 must name the DiscoverCapabilities gate"
    );
    assert!(
        MATURITY_DOCS.contains("SEKAI_EXPERIMENTAL_RPCS"),
        "operator page must document the runtime flag"
    );
}
