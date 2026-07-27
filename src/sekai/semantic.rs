//! Projected semantic capabilities for the governed catalog (#151).
//!
//! These names are discoverable through `DiscoverCapabilities` and invokable
//! through the receipt-attributed catalog binding (#107). They project bounded
//! resolve / expand / retrieve / explain operations; natural-language planning
//! and summarization stay with the runtime.

use crate::sekai::retrieval;

/// Contract version for the semantic capability surface metadata.
pub const SEMANTIC_CONTRACT_VERSION: &str = "1.0";
/// Reasoning profile version advertised in capability limits.
pub const REASONING_PROFILE_VERSION: u64 = 1;
/// Ontology contract version advertised in capability limits.
pub const ONTOLOGY_CONTRACT_VERSION: u64 = 1;

pub const CAPABILITY_RESOLVE_REF: &str = "sekai.semantic.resolve_ref";
pub const CAPABILITY_EXPAND_RELATIONS: &str = "sekai.semantic.expand_relations";
pub const CAPABILITY_RETRIEVE_CONTEXT: &str = "sekai.context.retrieve";
pub const CAPABILITY_EXPLAIN_DERIVATION: &str = "sekai.semantic.explain_derivation";

pub const REF_KIND_OBJECT: &str = "object";
pub const REF_KIND_ONTOLOGY_CLASS: &str = "ontology_class";
pub const REF_KIND_ONTOLOGY_RELATION: &str = "ontology_relation";
pub const REF_KIND_UNAVAILABLE: &str = "unavailable";

/// Normalize a caller-supplied reasoning mode for response echoes.
pub fn reasoning_mode_label(mode: retrieval::ReasoningMode) -> &'static str {
    match mode {
        retrieval::ReasoningMode::AssertedOnly => "asserted_only",
        retrieval::ReasoningMode::Entailment => "entailment",
    }
}

/// Count how many mutually exclusive resolve reference fields are set.
pub fn resolve_ref_field_count(
    object_id: &str,
    external_id: &str,
    ontology_class: &str,
    ontology_relation: &str,
) -> usize {
    [
        !object_id.trim().is_empty(),
        !external_id.trim().is_empty(),
        !ontology_class.trim().is_empty(),
        !ontology_relation.trim().is_empty(),
    ]
    .into_iter()
    .filter(|set| *set)
    .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_ref_requires_exactly_one_field() {
        assert_eq!(resolve_ref_field_count("", "", "", ""), 0);
        assert_eq!(resolve_ref_field_count("o", "", "", ""), 1);
        assert_eq!(resolve_ref_field_count("o", "e", "", ""), 2);
        assert_eq!(resolve_ref_field_count("", "", "c", "r"), 2);
    }

    #[test]
    fn reasoning_mode_labels_are_stable() {
        assert_eq!(
            reasoning_mode_label(retrieval::ReasoningMode::AssertedOnly),
            "asserted_only"
        );
        assert_eq!(
            reasoning_mode_label(retrieval::ReasoningMode::Entailment),
            "entailment"
        );
    }
}
