//! Impact class of a model call, resolved from the Action Work claim it
//! cites (#1910).
//!
//! A caller never declares a class. It may cite a claim, which the plane
//! resolves against Sekai's authoritative state. Anything other than a live
//! claim held by the caller resolves to unclassified, so citing a claim can
//! never raise a call's class.

use std::collections::BTreeMap;

use crate::chisei::sekai_facts::SekaiFactReader;
pub use sekai_types::impact_class::ImpactClass;

/// An Action Work claim cited by a model call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionClaimRef {
    pub effect_id: String,
    pub claim_generation: u64,
    pub fencing_token: String,
}

/// How a cited claim resolved. Only `Live` can carry a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClaimResolution {
    #[default]
    NoClaim,
    /// Live and held by the caller. `None` when the Action type is
    /// unclassified.
    Live(Option<ImpactClass>),
    /// No such effect in the call's namespace, or its instance or type is gone.
    NotFound,
    /// Not claimed, lease expired, or a stale generation or token.
    NotLive,
    /// Live, but taken by another principal.
    Foreign,
    /// Sekai could not answer: the split-plane hop, or a failed read.
    Unavailable,
}

impl ClaimResolution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoClaim => "no_claim",
            Self::Live(_) => "live",
            Self::NotFound => "not_found",
            Self::NotLive => "not_live",
            Self::Foreign => "foreign",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The resolved impact of one model call, carried on the execution context.
/// Routing by impact class (#1861) reads [`ActionImpact::class`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActionImpact {
    pub claim: Option<ActionClaimRef>,
    pub resolution: ClaimResolution,
}

impl ActionImpact {
    /// Resolve `claim` for `caller` in `namespace`. A failed or unsupported
    /// Sekai read resolves to unclassified.
    pub fn resolve(
        facts: &dyn SekaiFactReader,
        claim: Option<ActionClaimRef>,
        caller: &str,
        namespace: &str,
    ) -> Self {
        let resolution = match &claim {
            None => ClaimResolution::NoClaim,
            Some(claim) => facts
                .cited_claim_resolution(claim, caller, namespace.trim())
                .unwrap_or(ClaimResolution::Unavailable),
        };
        Self { claim, resolution }
    }

    /// The impact class, or `None` for unclassified.
    pub fn class(&self) -> Option<ImpactClass> {
        match self.resolution {
            ClaimResolution::Live(class) => class,
            _ => None,
        }
    }

    /// Receipt and decision-record attributes; empty when no claim was cited.
    pub fn record_attributes(&self) -> BTreeMap<String, String> {
        self.claim
            .as_ref()
            .map(|claim| {
                claim_record_attributes(
                    claim,
                    self.class().map(ImpactClass::as_str).unwrap_or(""),
                    self.resolution.as_str(),
                )
            })
            .unwrap_or_default()
    }
}

/// Attributes recording a cited claim and its resolution. The fencing token
/// is never recorded.
pub fn claim_record_attributes(
    claim: &ActionClaimRef,
    impact_class: &str,
    resolution: &str,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("impact_class".into(), impact_class.into()),
        ("action_claim_resolution".into(), resolution.into()),
        ("action_claim_effect_id".into(), claim.effect_id.clone()),
        (
            "action_claim_generation".into(),
            claim.claim_generation.to_string(),
        ),
    ])
}
