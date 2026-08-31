//! ADR 0053 index and related-pointer checks for Issue #708.

const ADR_0042: &str = include_str!("../docs/decisions/0042-governed-federation-revocation.md");
const ADR_0053: &str = include_str!("../docs/decisions/0053-federation-network-contracts.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/federation-networks.md");

#[test]
fn adr_0053_is_indexed_and_names_network_contracts() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0053: Exchange federation traffic through bilateral network contracts](0053-federation-network-contracts.md)"
        ),
        "decisions index must link ADR 0053"
    );
    assert!(ADR_0053.contains("#708"), "ADR 0053 must name Issue #708");
    assert!(
        ADR_0053.contains("sekai.federation-network-contract/v1"),
        "ADR 0053 must name the network contract"
    );
    assert!(
        ADR_0042.contains("sekai.federation-revocation/v1"),
        "related revocation ADR must remain distinct"
    );
}

#[test]
fn operator_page_documents_the_network_cli() {
    assert!(
        OPERATOR.contains("sekaictl admin network"),
        "operator page must document the network CLI"
    );
}
