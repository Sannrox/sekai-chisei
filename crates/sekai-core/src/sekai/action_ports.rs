//! Sekai-owned ports that Chisei implements (ADR 0096 rule 2).
//!
//! Budget metering and System One fill provenance are Chisei decisions.
//! Sekai never names those implementations. Combined mode and the
//! authenticated hop wire the implementations in composition.

use crate::sekai::governed_action_type::GovernedActionType;

/// Spend check and debit for Action admission, preview, and workflow steps.
///
/// An absent port reports `not_configured` (or `deferred` while parked). It
/// never allows silently.
pub trait ActionBudgetPort: Send + Sync {
    fn check(&self, subject: &str, amount: i32) -> Result<(), String>;
    fn record(&self, subject: &str, amount: i32);
    /// Debits `amount` once per `idempotency_key`, in the budget period of
    /// `at_ms`: a repeat with the same key is a no-op, so a resumed
    /// admission charges once, to the period it was admitted in (#1943).
    fn record_once(
        &self,
        subject: &str,
        amount: i32,
        idempotency_key: &str,
        at_ms: i64,
    ) -> Result<(), String>;
}

/// System One fill provenance for a governed Action type.
///
/// System One stays a Chisei Function (ADR 0084). An absent port leaves
/// fill provenance empty; it does not invent a bind digest.
pub trait ActionProposalPort: Send + Sync {
    fn fill_provenance_json(
        &self,
        type_def: &GovernedActionType,
        parameters_json: &str,
    ) -> Result<String, String>;
}
