//! Durable, generation-fenced continuation records for parked runtime work.
//!
//! Value types live in `sekai-types`. This module keeps the ActionEffect
//! wrappers so the store can name parks without the effect host.

pub use sekai_types::parked_work::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkResult {
    pub effect: crate::sekai::action_effect::ActionEffect,
    pub park: ActionWorkPark,
    pub replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionResult {
    pub effect: crate::sekai::action_effect::ActionEffect,
    pub action: ParkedWorkResolutionAction,
    pub continuation: Option<ActionWorkContinuation>,
    pub park: ActionWorkPark,
    pub replay: bool,
}
