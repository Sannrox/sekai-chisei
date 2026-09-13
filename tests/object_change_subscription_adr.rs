//! ADR 0068 index and related-pointer checks for Issue #838.

const ADR_0068: &str = include_str!("../docs/decisions/0068-object-change-subscriptions.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/object-change-subscriptions.md");

#[test]
fn adr_0068_is_indexed_and_names_object_change_delivery() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0068: Deliver object-change subscriptions from committed facts](0068-object-change-subscriptions.md)"
        ),
        "decisions index must link ADR 0068"
    );
    assert!(ADR_0068.contains("#838"), "ADR 0068 must name Issue #838");
    assert!(
        ADR_0068.contains("sekai.event-subscription/v1"),
        "ADR 0068 must reuse the event-subscription contract"
    );
    assert!(
        ADR_0068.contains("ReadObjectChangeSubscription"),
        "ADR 0068 must keep ReadObjectChangeSubscription as the delivery RPC"
    );
}

#[test]
fn operator_page_documents_non_authority() {
    assert!(
        OPERATOR.contains("ReadObjectChangeSubscriptionResponse.authority"),
        "operator page must keep subscription pages from granting authority"
    );
}
