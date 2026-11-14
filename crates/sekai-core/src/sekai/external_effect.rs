//! Admitted `external_mutate` effects as the `external_effect` work kind
//! (ADR 0148, ADR 0149).
//!
//! A pending `external_mutate` effect names its record with an object
//! `source_id` (`source:instance#external_id`). The Source that owns those
//! `source` and `source_instance` tokens routes it: the effect is claimable
//! only while that Source is active, its connector type supports `apply`,
//! and the claiming runtime's registered labels meet its placement.
//!
//! The claim record is the claim columns the effect row already carries.
//! There is no replay of a claim: a runtime that restarts while its own
//! lease is live waits for the lease to lapse and claims a new generation.
//! The executor keys permit redemption by generation, so a reclaimed effect
//! cannot redeem again; it acknowledges `outcome_unknown` instead of
//! applying a second time. `outcome_unknown` is final for the queue.
//!
//! Disabling or re-placing the Source ends a live claim at its next
//! heartbeat. An acknowledge needs only the live fence, so the outcome of a
//! change already applied is still recorded. Disabling writes no effect row,
//! so the Source is read outside the claim transaction: a claim that races a
//! disable is one granted just before it, and its next heartbeat ends it.
//! Stopping a redemption already under way is the permit kill switch's job.

use std::collections::BTreeMap;

use sekai_source_sdk::Operation;

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_effect::{
    ActionEffect, EFFECT_LIFECYCLE_CLAIMED, EFFECT_LIFECYCLE_COMPLETED, EFFECT_LIFECYCLE_FAILED,
    EFFECT_STATUS_CLAIMED, EFFECT_STATUS_COMPLETED, EFFECT_STATUS_FAILED,
    EFFECT_STATUS_OUTCOME_UNKNOWN, EFFECT_STATUS_PENDING, normalize_ttl_ms, validate_no_nul,
};
use crate::sekai::governed_action_type::EFFECT_KIND_EXTERNAL_MUTATE;
use crate::sekai::source::{Source, SourceStatus};
use crate::sekai::work_claim::{ClaimError, Fence, Hold};

const LIST_PAGE: usize = 200;
const MAX_REASON_BYTES: usize = 1024;

/// How an executor ends an external effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectOutcome {
    /// The change applied.
    Completed,
    /// The change did not apply.
    Failed,
    /// The executor cannot tell whether the change applied.
    OutcomeUnknown,
}

impl EffectOutcome {
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "outcome_unknown" => Some(Self::OutcomeUnknown),
            _ => None,
        }
    }

    const fn status(self) -> &'static str {
        match self {
            Self::Completed => EFFECT_STATUS_COMPLETED,
            Self::Failed => EFFECT_STATUS_FAILED,
            Self::OutcomeUnknown => EFFECT_STATUS_OUTCOME_UNKNOWN,
        }
    }

    const fn lifecycle(self) -> &'static str {
        match self {
            Self::Completed => EFFECT_LIFECYCLE_COMPLETED,
            Self::Failed => EFFECT_LIFECYCLE_FAILED,
            Self::OutcomeUnknown => EFFECT_STATUS_OUTCOME_UNKNOWN,
        }
    }
}

/// Why an external-effect call was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectError {
    /// No such effect in the namespace, or no routed Source admits the
    /// runtime, or nothing is claimable.
    NotFound,
    /// The claim engine refused the transition.
    Claim(ClaimError),
    Invalid(String),
    Store(String),
}

impl std::fmt::Display for EffectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("no external effect is claimable"),
            Self::Claim(error) => error.fmt(formatter),
            Self::Invalid(message) | Self::Store(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for EffectError {}

impl From<String> for EffectError {
    fn from(error: String) -> Self {
        Self::Store(error)
    }
}

/// A claimable or claimed effect with what its executor needs: the Source
/// that routes it and the admitted Action's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalEffectWork {
    pub effect: ActionEffect,
    pub source: Source,
    pub parameters_json: String,
}

/// What the effect's status means for its claim.
fn hold(effect: &ActionEffect) -> Hold {
    if effect.kind != EFFECT_KIND_EXTERNAL_MUTATE {
        return Hold::Closed;
    }
    match effect.status.as_str() {
        EFFECT_STATUS_PENDING => Hold::Open,
        EFFECT_STATUS_CLAIMED if effect.claim_expires_at_ms > 0 => Hold::Held,
        _ => Hold::Closed,
    }
}

/// The `source` and `source_instance` tokens of an object `source_id`.
pub fn record_tokens(record_source_id: &str) -> Option<(&str, &str)> {
    let (source, rest) = record_source_id.split_once(':')?;
    let (instance, external_id) = rest.rsplit_once('#')?;
    (!source.is_empty() && !instance.is_empty() && !external_id.is_empty())
        .then_some((source, instance))
}

/// The active Source that applies `effect`'s change, if one does.
pub fn route(db: &RuntimeDb, effect: &ActionEffect) -> Result<Option<Source>, String> {
    let payload: serde_json::Value = serde_json::from_str(&effect.payload_json).unwrap_or_default();
    let record = payload
        .get("source_id")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let Some((source, instance)) = record_tokens(record) else {
        return Ok(None);
    };
    Ok(db
        .get_source_by_tokens(&effect.namespace, source, instance)?
        .filter(|source| {
            source.status == SourceStatus::Active
                && source
                    .spec
                    .connector()
                    .is_some_and(|connector| connector.supports(Operation::Apply))
        }))
}

fn admits(source: &Source, labels: &BTreeMap<String, String>) -> bool {
    sekai_types::governed_transform::placement_satisfied(&source.spec.placement, labels)
}

fn work(
    db: &RuntimeDb,
    effect: ActionEffect,
    source: Source,
) -> Result<ExternalEffectWork, String> {
    let parameters_json = db
        .get_action_instance(&effect.instance_id)?
        .map(|instance| instance.parameters_json)
        .unwrap_or_default();
    Ok(ExternalEffectWork {
        effect,
        source,
        parameters_json,
    })
}

/// Up to `limit` takeable effects in `namespace` whose Source admits a
/// runtime with `labels` and passes `implements`, oldest first.
pub fn list_claimable(
    db: &RuntimeDb,
    namespace: &str,
    labels: &BTreeMap<String, String>,
    now_ms: i64,
    limit: usize,
    implements: impl Fn(&Source) -> bool,
) -> Result<Vec<ExternalEffectWork>, String> {
    let mut out = Vec::new();
    let mut cursor: Option<(i64, String)> = None;
    while out.len() < limit {
        let page = db.list_open_effects_page(
            namespace,
            EFFECT_KIND_EXTERNAL_MUTATE,
            LIST_PAGE,
            cursor.as_ref().map(|(at, id)| (*at, id.as_str())),
        )?;
        let exhausted = page.len() < LIST_PAGE;
        for effect in page {
            cursor = Some((effect.created_at_ms, effect.effect_id.clone()));
            if !effect.claim_record().is_takeable(hold(&effect), 0, now_ms) {
                continue;
            }
            let Some(source) = route(db, &effect)? else {
                continue;
            };
            if admits(&source, labels) && implements(&source) {
                out.push(work(db, effect, source)?);
                if out.len() == limit {
                    break;
                }
            }
        }
        if exhausted {
            break;
        }
    }
    Ok(out)
}

/// Claims `effect_id` for `runtime_id`, or the oldest claimable effect in
/// `namespace` when it is empty. A live claim is never replayed, even to
/// its own holder.
#[allow(clippy::too_many_arguments)]
pub fn claim(
    db: &RuntimeDb,
    namespace: &str,
    effect_id: &str,
    runtime_id: &str,
    principal: &str,
    labels: &BTreeMap<String, String>,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<ExternalEffectWork, EffectError> {
    if runtime_id.trim().is_empty() {
        return Err(EffectError::Invalid("runtime_id required".into()));
    }
    validate_no_nul("runtime_id", runtime_id).map_err(EffectError::Invalid)?;
    let ttl_ms = normalize_ttl_ms(ttl_ms).map_err(EffectError::Invalid)?;
    if !effect_id.is_empty() {
        return claim_one(
            db, namespace, effect_id, runtime_id, principal, labels, ttl_ms, now_ms,
        );
    }
    for candidate in list_claimable(db, namespace, labels, now_ms, LIST_PAGE, |_| true)? {
        match claim_one(
            db,
            namespace,
            &candidate.effect.effect_id,
            runtime_id,
            principal,
            labels,
            ttl_ms,
            now_ms,
        ) {
            // Another runtime took it between the list and the claim.
            Err(EffectError::Claim(_) | EffectError::NotFound) => continue,
            claimed => return claimed,
        }
    }
    Err(EffectError::NotFound)
}

#[allow(clippy::too_many_arguments)]
fn claim_one(
    db: &RuntimeDb,
    namespace: &str,
    effect_id: &str,
    runtime_id: &str,
    principal: &str,
    labels: &BTreeMap<String, String>,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<ExternalEffectWork, EffectError> {
    let effect = db
        .get_action_effect(effect_id)?
        .filter(|effect| effect.namespace == namespace)
        .ok_or(EffectError::NotFound)?;
    let source = route(db, &effect)?
        .filter(|source| admits(source, labels))
        .ok_or(EffectError::NotFound)?;
    let claimed = db
        .update_action_effect_with(effect_id, |effect: &mut ActionEffect| {
            let hold = hold(effect);
            let mut record = effect.claim_record();
            record
                .count_lapse(hold, 0, now_ms)
                .map_err(EffectError::Claim)?;
            record.grant(runtime_id, ttl_ms, now_ms, |generation| {
                fencing_token(&effect.effect_id, generation, runtime_id)
            });
            effect.set_claim_record(record);
            effect.status = EFFECT_STATUS_CLAIMED.into();
            effect.lifecycle_state = EFFECT_LIFECYCLE_CLAIMED.into();
            effect.claim_attempt_count = effect.claim_attempt_count.saturating_add(1);
            effect.claim_request_id.clear();
            effect.claim_principal = principal.into();
            effect.failure_reason.clear();
            effect.updated_at_ms = now_ms;
            Ok::<_, EffectError>(true)
        })?
        .ok_or(EffectError::NotFound)?;
    Ok(work(db, claimed, source)?)
}

/// Extends the live claim on `effect_id`. A Source disabled or re-placed
/// since the claim ends it: the holder reads the refusal as a lost fence.
pub fn heartbeat(
    db: &RuntimeDb,
    namespace: &str,
    effect_id: &str,
    fence: Fence<'_>,
    labels: &BTreeMap<String, String>,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<ExternalEffectWork, EffectError> {
    let ttl_ms = normalize_ttl_ms(ttl_ms).map_err(EffectError::Invalid)?;
    let effect = db
        .get_action_effect(effect_id)?
        .filter(|effect| effect.namespace == namespace)
        .ok_or(EffectError::NotFound)?;
    let source = route(db, &effect)?
        .filter(|source| admits(source, labels))
        .ok_or(EffectError::Claim(ClaimError::FenceLost))?;
    let renewed = db
        .update_action_effect_with(effect_id, |effect: &mut ActionEffect| {
            let mut record = effect.claim_record();
            record
                .heartbeat(hold(effect), fence, ttl_ms, now_ms)
                .map_err(EffectError::Claim)?;
            effect.set_claim_record(record);
            effect.updated_at_ms = now_ms;
            Ok::<_, EffectError>(true)
        })?
        .ok_or(EffectError::NotFound)?;
    Ok(work(db, renewed, source)?)
}

/// Ends the live claim on `effect_id` with `outcome`. A retry of the same
/// acknowledge under the same fence replays it.
pub fn acknowledge(
    db: &RuntimeDb,
    namespace: &str,
    effect_id: &str,
    fence: Fence<'_>,
    outcome: EffectOutcome,
    reason: &str,
    now_ms: i64,
) -> Result<ActionEffect, EffectError> {
    validate_no_nul("reason", reason).map_err(EffectError::Invalid)?;
    if reason.len() > MAX_REASON_BYTES {
        return Err(EffectError::Invalid(format!(
            "reason exceeds {MAX_REASON_BYTES} bytes"
        )));
    }
    db.update_action_effect_with(effect_id, |effect: &mut ActionEffect| {
        if effect.namespace != namespace || effect.kind != EFFECT_KIND_EXTERNAL_MUTATE {
            return Err(EffectError::NotFound);
        }
        let mut record = effect.claim_record();
        if effect.status == outcome.status() && record.matches(fence) {
            return Ok(false);
        }
        record
            .release(hold(effect), fence, now_ms)
            .map_err(EffectError::Claim)?;
        effect.set_claim_record(record);
        effect.status = outcome.status().into();
        effect.lifecycle_state = outcome.lifecycle().into();
        effect.failure_reason = reason.into();
        effect.updated_at_ms = now_ms;
        Ok(true)
    })?
    .ok_or(EffectError::NotFound)
}

fn fencing_token(effect_id: &str, generation: i64, owner: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"external_effect:");
    hasher.update(effect_id.as_bytes());
    hasher.update(b":");
    hasher.update(generation.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(owner.as_bytes());
    format!("xe-{:x}", hasher.finalize())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sekai::action_effect::plan_effects_for_admit;
    use crate::sekai::source;

    /// A GitHub Source `repo` for `acme/repo` placed in `zone=eu`, and a
    /// pending `external_mutate` effect on one of its records. Returns the
    /// effect id.
    pub(crate) fn admit_effect(db: &RuntimeDb, namespace: &str) -> String {
        source::put(db, &source::tests::github(namespace, "repo", "acme/repo")).unwrap();
        let mut effect = plan_effects_for_admit(
            &format!("{namespace}-instance"),
            namespace,
            &format!("{namespace}-operation"),
            &[EFFECT_KIND_EXTERNAL_MUTATE.into()],
            r#"{"permit_id":"permit-1","source_id":"github:acme/repo#12"}"#,
            10,
            false,
        )
        .unwrap()
        .remove(0);
        effect.effect_id = format!("{namespace}-effect");
        db.put_action_effects(std::slice::from_ref(&effect))
            .unwrap();
        effect.effect_id
    }

    fn eu() -> BTreeMap<String, String> {
        BTreeMap::from([("zone".into(), "eu".into())])
    }

    fn fence(effect: &ActionEffect) -> Fence<'_> {
        Fence {
            owner: &effect.claim_owner,
            generation: i64::try_from(effect.claim_generation).unwrap(),
            token: &effect.claim_fencing_token,
        }
    }

    fn namespace(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
    }

    /// Only a runtime the record's Source places sees or claims the effect.
    fn the_owning_source_routes_the_effect(db: &RuntimeDb, prefix: &str) {
        let ns = namespace(prefix);
        let id = admit_effect(db, &ns);
        let elsewhere = BTreeMap::from([("zone".into(), "us".into())]);
        assert!(
            list_claimable(db, &ns, &elsewhere, 100, 10, |_| true)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            claim(db, &ns, &id, "us-1", "op", &elsewhere, 1_000, 100).unwrap_err(),
            EffectError::NotFound
        );
        assert_eq!(
            claim(db, &ns, "", "us-1", "op", &elsewhere, 1_000, 100).unwrap_err(),
            EffectError::NotFound
        );
        let listed = list_claimable(db, &ns, &eu(), 100, 10, |_| true).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].source.source_id, "repo");
        let claimed = claim(db, &ns, "", "eu-1", "op", &eu(), 1_000, 100).unwrap();
        assert_eq!(claimed.effect.effect_id, id);
    }

    /// A restarted holder gets no replay of its live claim, and
    /// `outcome_unknown` is final: never claimable again, and a retry of
    /// the acknowledge replays while another outcome is refused.
    fn outcome_unknown_is_never_claimed_again(db: &RuntimeDb, prefix: &str) {
        let ns = namespace(prefix);
        let id = admit_effect(db, &ns);
        let held = claim(db, &ns, &id, "eu-1", "op", &eu(), 1_000, 100).unwrap();
        assert_eq!(
            claim(db, &ns, &id, "eu-1", "op", &eu(), 1_000, 200).unwrap_err(),
            EffectError::Claim(ClaimError::Held)
        );
        let reclaimed = claim(db, &ns, &id, "eu-1", "op", &eu(), 1_000, 1_200).unwrap();
        assert_eq!(reclaimed.effect.claim_generation, 2);
        assert_eq!(
            acknowledge(
                db,
                &ns,
                &id,
                fence(&held.effect),
                EffectOutcome::Completed,
                "",
                1_300
            )
            .unwrap_err(),
            EffectError::Claim(ClaimError::FenceLost)
        );
        let unknown = acknowledge(
            db,
            &ns,
            &id,
            fence(&reclaimed.effect),
            EffectOutcome::OutcomeUnknown,
            "permit already redeemed",
            1_300,
        )
        .unwrap();
        assert_eq!(unknown.status, EFFECT_STATUS_OUTCOME_UNKNOWN);
        let replayed = acknowledge(
            db,
            &ns,
            &id,
            fence(&reclaimed.effect),
            EffectOutcome::OutcomeUnknown,
            "permit already redeemed",
            1_400,
        )
        .unwrap();
        assert_eq!(replayed, unknown);
        assert!(
            acknowledge(
                db,
                &ns,
                &id,
                fence(&reclaimed.effect),
                EffectOutcome::Completed,
                "",
                1_400
            )
            .is_err()
        );
        assert!(
            list_claimable(db, &ns, &eu(), 9_000, 10, |_| true)
                .unwrap()
                .is_empty()
        );
        assert!(claim(db, &ns, &id, "eu-2", "op", &eu(), 1_000, 9_000).is_err());
    }

    /// Disabling the Source ends the claim at its next heartbeat, but the
    /// holder can still record what it already applied.
    fn a_disabled_source_ends_the_claim_but_not_the_acknowledge(db: &RuntimeDb, prefix: &str) {
        let ns = namespace(prefix);
        let id = admit_effect(db, &ns);
        let held = claim(db, &ns, &id, "eu-1", "op", &eu(), 1_000, 100).unwrap();
        source::disable(db, &ns, "repo", 150).unwrap();
        assert_eq!(
            heartbeat(db, &ns, &id, fence(&held.effect), &eu(), 1_000, 200).unwrap_err(),
            EffectError::Claim(ClaimError::FenceLost)
        );
        let done = acknowledge(
            db,
            &ns,
            &id,
            fence(&held.effect),
            EffectOutcome::Completed,
            "",
            300,
        )
        .unwrap();
        assert_eq!(done.status, EFFECT_STATUS_COMPLETED);
        assert_eq!(done.claim_expires_at_ms, 0);
    }

    fn contract(db: &RuntimeDb, prefix: &str) {
        the_owning_source_routes_the_effect(db, prefix);
        outcome_unknown_is_never_claimed_again(db, prefix);
        a_disabled_source_ends_the_claim_but_not_the_acknowledge(db, prefix);
    }

    #[test]
    fn record_tokens_split_at_the_first_colon_and_the_last_hash() {
        assert_eq!(
            record_tokens("github:acme/ops#12"),
            Some(("github", "acme/ops"))
        );
        assert_eq!(record_tokens("github:acme/ops"), None);
        assert_eq!(record_tokens(":acme#1"), None);
    }

    #[test]
    fn sqlite_external_effect_follows_the_contract() {
        contract(&RuntimeDb::memory(), "sqlite");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_external_effect_follows_the_contract() {
        contract(
            &crate::sekai::work_claim_conformance::postgres(),
            &format!("pg{}", std::process::id()),
        );
    }
}
