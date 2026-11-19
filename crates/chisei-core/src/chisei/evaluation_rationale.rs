//! Retained judge rationale for stochastic evaluation steps (#2630, ADR 0012).
//!
//! A `rationale/v1` policy keeps only the judge's bounded `rationale` per
//! completed trial, never the prompt, evidence or provider response. Each row
//! is keyed by (execution operation, node, trial slot), names the admitted
//! evidence the step read, and expires at a TTL frozen by the policy version.
//! A row is readable only by a principal who may read every one of those
//! evidence objects, and goes away when its TTL passes or any source evidence
//! is removed or retracted. Receipts record only the rationale digest.

use crate::chisei::sekai_facts::SekaiFactReader;

/// Evidence lifecycle states that withdraw a source, and with it the rationale.
const WITHDRAWN_EVIDENCE_STATES: [&str; 3] = ["retracted", "rejected", "quarantined"];

/// Rows the source sweep reads per page.
const SWEEP_PAGE: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationRationale {
    pub operation_id: String,
    pub node_id: String,
    pub trial_index: u32,
    pub namespace: String,
    pub rationale: String,
    pub rationale_digest: String,
    /// Admitted evidence the step read; the rationale carries their markings.
    pub evidence_object_ids: Vec<String>,
    /// The most restrictive classification among that evidence.
    pub classification: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

/// (operation, node, trial slot): one rationale's identity.
pub type RationaleKey = (String, String, u32);

impl EvaluationRationale {
    pub fn key(&self) -> RationaleKey {
        (
            self.operation_id.clone(),
            self.node_id.clone(),
            self.trial_index,
        )
    }
}

/// Storage for retained rationale on both community backends.
pub trait EvaluationRationaleStore {
    /// Records each rationale once; a repeat of a stored key changes nothing.
    fn put_evaluation_rationales(&self, rationales: &[EvaluationRationale]) -> Result<(), String>;
    fn get_evaluation_rationale(
        &self,
        operation_id: &str,
        node_id: &str,
        trial_index: u32,
    ) -> Result<Option<EvaluationRationale>, String>;
    fn delete_evaluation_rationale(
        &self,
        operation_id: &str,
        node_id: &str,
        trial_index: u32,
    ) -> Result<(), String>;
    /// Deletes every rationale whose TTL has passed; returns how many.
    fn delete_expired_evaluation_rationales(&self, now_ms: i64) -> Result<u64, String>;
    /// Rationales after `after` in key order, at most `limit`.
    fn list_evaluation_rationales(
        &self,
        after: Option<&RationaleKey>,
        limit: usize,
    ) -> Result<Vec<EvaluationRationale>, String>;
}

/// The most restrictive of `classifications`, by the evidence vocabulary order.
pub fn most_restrictive_classification<'a>(
    classifications: impl IntoIterator<Item = &'a str>,
) -> String {
    const ORDER: [&str; 4] = ["public", "internal", "confidential", "restricted"];
    classifications
        .into_iter()
        .max_by_key(|classification| {
            ORDER
                .iter()
                .position(|known| known == classification)
                // An unknown classification is treated as the most restrictive.
                .unwrap_or(ORDER.len())
        })
        .unwrap_or("public")
        .to_string()
}

/// Whether every evidence object the rationale was derived from still exists
/// and is not withdrawn.
pub fn sources_present(
    facts: &dyn SekaiFactReader,
    rationale: &EvaluationRationale,
) -> Result<bool, String> {
    for object_id in &rationale.evidence_object_ids {
        let object = facts
            .get_object(object_id)
            .map_err(|error| error.to_string())?;
        let withdrawn = object.as_ref().is_none_or(|object| {
            object
                .properties
                .get("lifecycle_state")
                .is_some_and(|state| WITHDRAWN_EVIDENCE_STATES.contains(&state.as_str()))
        });
        if withdrawn {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Deletes expired rationale and rationale whose source evidence is gone.
/// Safe on every instance at once: each delete is keyed and idempotent.
pub fn sweep_evaluation_rationales(
    store: &dyn EvaluationRationaleStore,
    facts: &dyn SekaiFactReader,
    now_ms: i64,
) -> Result<u64, String> {
    let mut removed = store.delete_expired_evaluation_rationales(now_ms)?;
    let mut after = None;
    loop {
        let page = store.list_evaluation_rationales(after.as_ref(), SWEEP_PAGE)?;
        let Some(last) = page.last() else {
            return Ok(removed);
        };
        after = Some(last.key());
        for rationale in &page {
            if !sources_present(facts, rationale)? {
                store.delete_evaluation_rationale(
                    &rationale.operation_id,
                    &rationale.node_id,
                    rationale.trial_index,
                )?;
                removed += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::most_restrictive_classification;

    #[test]
    fn classification_takes_the_most_restrictive_source() {
        assert_eq!(
            most_restrictive_classification(["internal", "confidential", "public"]),
            "confidential"
        );
        assert_eq!(
            most_restrictive_classification(["internal", "secret"]),
            "secret"
        );
        assert_eq!(most_restrictive_classification([]), "public");
    }
}
