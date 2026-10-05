//! Risk vocabulary shared by governed Action policy and admission.
//!
//! The pre-1.0 graph mutation executor and `ActionTypeDef` registry were
//! removed. Governed Action types and instances use this classification only.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskClass {
    Read,
    Write,
    Destructive,
}

impl RiskClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Destructive => "destructive",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "destructive" => Some(Self::Destructive),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_classes_are_ordered_and_parse_strictly() {
        assert!(RiskClass::Read < RiskClass::Write);
        assert!(RiskClass::Write < RiskClass::Destructive);
        assert_eq!(
            RiskClass::parse(" destructive "),
            Some(RiskClass::Destructive)
        );
        assert_eq!(RiskClass::parse("unknown"), None);
        assert_eq!(RiskClass::Write.as_str(), "write");
    }
}
