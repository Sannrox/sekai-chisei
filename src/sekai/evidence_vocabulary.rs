//! Evidence intent, lifecycle, and classification vocabulary (ADR 0096 rule 5).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceIntent {
    Upsert,
    Retract,
    MarkStale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLifecycleState {
    Received,
    Validated,
    Deduplicated,
    Authorized,
    Projected,
    Available,
    Superseded,
    Retracted,
    Stale,
    Rejected,
    Quarantined,
}

impl EvidenceLifecycleState {
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Available)
    }

    pub const fn is_admitted(self) -> bool {
        matches!(
            self,
            Self::Authorized
                | Self::Projected
                | Self::Available
                | Self::Superseded
                | Self::Retracted
                | Self::Stale
                | Self::Quarantined
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Validated => "validated",
            Self::Deduplicated => "deduplicated",
            Self::Authorized => "authorized",
            Self::Projected => "projected",
            Self::Available => "available",
            Self::Superseded => "superseded",
            Self::Retracted => "retracted",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "received" => Self::Received,
            "validated" => Self::Validated,
            "deduplicated" => Self::Deduplicated,
            "authorized" => Self::Authorized,
            "projected" => Self::Projected,
            "available" => Self::Available,
            "superseded" => Self::Superseded,
            "retracted" => Self::Retracted,
            "stale" => Self::Stale,
            "rejected" => Self::Rejected,
            "quarantined" => Self::Quarantined,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl EvidenceClassification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
        }
    }
}
