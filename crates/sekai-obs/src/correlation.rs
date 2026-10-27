//! Closed correlation-stage vocabulary for tracing control-plane work.
//!
//! The *stage* set must stay finite so span names stay bounded. Identifier
//! generation stays in the root crate because it reads HTTP headers and
//! normalizes caller operation ids through Sekai.

/// Stage of work a span describes. Closed so span names stay bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Operation,
    Attempt,
    ProviderRequest,
    Persistence,
    EvidenceProjection,
}

impl Stage {
    pub const ALL: &'static [Stage] = &[
        Stage::Operation,
        Stage::Attempt,
        Stage::ProviderRequest,
        Stage::Persistence,
        Stage::EvidenceProjection,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Operation => "operation",
            Stage::Attempt => "attempt",
            Stage::ProviderRequest => "provider_request",
            Stage::Persistence => "persistence",
            Stage::EvidenceProjection => "evidence_projection",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Stage;
    use std::collections::BTreeSet;

    #[test]
    fn stage_vocabulary_is_closed_and_snake_case() {
        assert_eq!(Stage::ALL.len(), 5);
        let distinct: BTreeSet<&str> = Stage::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(distinct.len(), Stage::ALL.len(), "duplicate stage name");
        for stage in Stage::ALL {
            let name = stage.as_str();
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "stage {name} is not snake_case"
            );
        }
    }
}
