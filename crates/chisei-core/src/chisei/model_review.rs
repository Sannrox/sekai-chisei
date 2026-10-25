//! Per-namespace model review state (#1493).
//!
//! Scope is the namespace, two levels as for leak rules: the global namespace
//! (`""`) is the instance default and a named namespace may override it. Each
//! instance is one deployment environment. Identity is provider, model, and
//! artifact digest when present (#1352). Family enablement is per namespace
//! and per `ResidencyPolicy` region label; a per-model row overrides its
//! family in the same namespace. A named namespace is resolved (model, then
//! family) before the instance default. Default is `disallowed`. Route
//! admission (#1494) refuses any model that is not `enabled` for the
//! namespace, identity, and residency region before a provider call.

use std::collections::{BTreeSet, HashMap};

#[cfg(any(test, feature = "gateway-test-support"))]
use std::cell::Cell;

use crate::chisei::decision_ledger::Decision;
use crate::chisei::model_availability::AvailableModel;
use crate::chisei::policy::Policy;
use crate::chisei::routing_profiles::{HostedRoutingProfile, hosted_runtime};
use crate::chisei_store::{ChiseiDecisionStore, ChiseiModelReviewStore, ChiseiStore};
use sekai_core::enterprise::ModelIdentity;

pub const MODEL_REVIEW_CONTRACT: &str = "chisei.model-review/v1";
pub const MODEL_REVIEW_STATES: [&str; 4] = ["disallowed", "reviewed", "enabled", "revoked"];
pub const ACTION_SET: &str = "model_review.set";
pub const ACTION_REVOKE: &str = "model_review.revoke";
pub const ACTION_FAMILY_SET: &str = "model_family.set";
pub const ACTION_FAMILY_REVOKE: &str = "model_family.revoke";
pub const ACTION_ADMIT_DENIED: &str = "model_review.admit_denied";
pub const REFUSAL_NOT_ENABLED: &str = "model_review.not_enabled";
pub const REFUSAL_RESIDENCY_MISMATCH: &str = "model_review.residency_mismatch";
const BACKFILL_ACTOR: &str = "chisei.model-review.backfill";
const BACKFILL_REASON: &str = "currently routed at review-state introduction";
const TEST_SEED_ACTOR: &str = "chisei.model-review.test-seed";
const TEST_SEED_REASON: &str = "test fixture registry family enablement";

#[cfg(any(test, feature = "gateway-test-support"))]
thread_local! {
    static SKIP_REGISTRY_FAMILY_SEED: Cell<bool> = const { Cell::new(false) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelReviewStatus {
    Disallowed,
    Reviewed,
    Enabled,
    Revoked,
}

impl ModelReviewStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disallowed => "disallowed",
            Self::Reviewed => "reviewed",
            Self::Enabled => "enabled",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "disallowed" => Ok(Self::Disallowed),
            "reviewed" => Ok(Self::Reviewed),
            "enabled" => Ok(Self::Enabled),
            "revoked" => Ok(Self::Revoked),
            other => Err(format!("unknown model review status {other:?}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelReviewIdentity {
    pub provider: String,
    pub model: String,
    pub artifact_digest: String,
}

impl ModelReviewIdentity {
    pub fn new(
        provider: impl Into<String>,
        model: impl Into<String>,
        artifact_digest: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            artifact_digest: artifact_digest.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelReviewRecord {
    pub namespace: String,
    pub identity: ModelReviewIdentity,
    pub status: ModelReviewStatus,
    pub actor: String,
    pub reason: String,
    pub updated_at_ms: i64,
}

impl ModelReviewRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn from_columns(
        namespace: String,
        provider: String,
        model: String,
        artifact_digest: String,
        status: &str,
        actor: String,
        reason: String,
        updated_at_ms: i64,
    ) -> Result<Self, String> {
        Ok(Self {
            namespace,
            identity: ModelReviewIdentity::new(provider, model, artifact_digest),
            status: ModelReviewStatus::parse(status)?,
            actor,
            reason,
            updated_at_ms,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.namespace != self.namespace.trim() {
            return Err("namespace must be trimmed".into());
        }
        validate_identifier("provider", &self.identity.provider)?;
        validate_identifier("model", &self.identity.model)?;
        validate_digest(&self.identity.artifact_digest)?;
        validate_reason(&self.reason)?;
        validate_actor(&self.actor)?;
        Ok(())
    }

    pub fn target_id(&self) -> String {
        format!(
            "model-review:{}:{}:{}:{}",
            self.namespace,
            self.identity.provider,
            self.identity.model,
            self.identity.artifact_digest
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyEnablementRecord {
    pub namespace: String,
    pub region_label: String,
    pub family_id: String,
    pub status: ModelReviewStatus,
    pub actor: String,
    pub reason: String,
    pub updated_at_ms: i64,
}

impl FamilyEnablementRecord {
    pub fn from_columns(
        namespace: String,
        region_label: String,
        family_id: String,
        status: &str,
        actor: String,
        reason: String,
        updated_at_ms: i64,
    ) -> Result<Self, String> {
        Ok(Self {
            namespace,
            region_label,
            family_id,
            status: ModelReviewStatus::parse(status)?,
            actor,
            reason,
            updated_at_ms,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.namespace != self.namespace.trim() {
            return Err("namespace must be trimmed".into());
        }
        validate_region(&self.region_label)?;
        validate_identifier("family_id", &self.family_id)?;
        validate_reason(&self.reason)?;
        validate_actor(&self.actor)?;
        Ok(())
    }

    pub fn target_id(&self) -> String {
        format!(
            "model-family:{}:{}:{}",
            self.namespace, self.region_label, self.family_id
        )
    }
}

pub fn validate_identifier(field: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(format!("{field} is required"));
    }
    if trimmed.len() > 128 {
        return Err(format!("{field} exceeds 128 bytes"));
    }
    Ok(())
}

pub fn validate_digest(digest: &str) -> Result<(), String> {
    if digest.is_empty() {
        return Ok(());
    }
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err("artifact_digest must be sha256:<64 lowercase hex> or empty".into());
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err("artifact_digest must be sha256:<64 lowercase hex> or empty".into())
    }
}

pub fn validate_region(region: &str) -> Result<(), String> {
    if region.is_empty() {
        return Ok(());
    }
    if region.len() <= 64
        && region
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'-'))
    {
        Ok(())
    } else {
        Err("region_label must be a ResidencyPolicy region label".into())
    }
}

fn validate_reason(reason: &str) -> Result<(), String> {
    if reason.trim().is_empty() {
        Err("reason is required".into())
    } else {
        Ok(())
    }
}

fn validate_actor(actor: &str) -> Result<(), String> {
    if actor.trim().is_empty() {
        Err("actor is required".into())
    } else {
        Ok(())
    }
}

/// A model belongs to the family named by its provider (ADR 0106), or to a
/// model-id prefix family (`gpt-4` covers `gpt-4-turbo` and
/// `openai/gpt-4-turbo`).
pub fn model_belongs_to_family(model: &str, family: &str) -> bool {
    family_covers(model, family)
        || model
            .rsplit_once('/')
            .is_some_and(|(_, local)| family_covers(local, family))
}

fn family_covers(model: &str, family: &str) -> bool {
    model == family
        || model
            .strip_prefix(family)
            .is_some_and(|rest| rest.starts_with('-') || rest.starts_with('/'))
}

fn family_ids_overlap(left: &str, right: &str) -> bool {
    left == right
        || family_covers(left, right)
        || family_covers(right, left)
        || left
            .strip_prefix(right)
            .is_some_and(|rest| rest.starts_with('.'))
        || right
            .strip_prefix(left)
            .is_some_and(|rest| rest.starts_with('.'))
}

pub fn effective_review_status(
    models: &[ModelReviewRecord],
    families: &[FamilyEnablementRecord],
    namespace: &str,
    identity: &ModelIdentity,
    region: &str,
) -> ModelReviewStatus {
    let digest = identity.artifact_digest.clone().unwrap_or_default();
    if let Some(status) = model_status(models, namespace, identity, &digest) {
        return status;
    }
    if let Some(status) = family_status(families, namespace, identity, region) {
        return status;
    }
    if !namespace.is_empty() {
        if let Some(status) = model_status(models, "", identity, &digest) {
            return status;
        }
        if let Some(status) = family_status(families, "", identity, region) {
            return status;
        }
    }
    ModelReviewStatus::Disallowed
}

/// Stable admission refusal. `reason` is the public code; `status` is the
/// effective review state that was not `enabled`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRefusal {
    pub reason: &'static str,
    pub status: ModelReviewStatus,
    pub namespace: String,
    pub provider: String,
    pub model: String,
    pub region: String,
}

impl AdmissionRefusal {
    pub fn as_str(&self) -> &'static str {
        self.reason
    }

    pub fn matches_message(message: &str) -> bool {
        message.starts_with(REFUSAL_NOT_ENABLED) || message.starts_with(REFUSAL_RESIDENCY_MISMATCH)
    }

    pub fn message(&self) -> String {
        format!(
            "{}: model {}/{} is {} for namespace {:?} region {:?}",
            self.reason,
            self.provider,
            self.model,
            self.status.as_str(),
            self.namespace,
            self.region
        )
    }
}

/// Resolve a planned model id to the #1352 identity used by review rows.
/// Hosted ids stay identifiable when the request-scoped registry snapshot is
/// not installed (live execute re-admits from the stored plan).
pub fn identity_from_model(model: &str) -> Result<ModelIdentity, String> {
    identity_from_registry(
        model,
        &chisei_provider::provider_profile::provider_registry_snapshot(),
    )
}

pub fn identity_from_registry(
    model: &str,
    registry: &chisei_provider::provider_profile::ProviderRegistry,
) -> Result<ModelIdentity, String> {
    match registry.resolve_model(model) {
        Ok(resolved) => Ok(identity_from_resolved(&resolved, registry)),
        Err(error) => {
            let Some(provider) = chisei_provider::provider_profile::hosted_provider_of(model)
            else {
                return Err(error);
            };
            let digest = registry
                .profile(provider)
                .and_then(|profile| profile.artifact_digest.clone())
                .unwrap_or_default();
            Ok(ModelIdentity {
                provider: provider.to_string(),
                model: model.to_string(),
                upstream_model: model.to_string(),
                profile_version: String::new(),
                artifact_digest: (!digest.is_empty()).then_some(digest),
                endpoint: String::new(),
            })
        }
    }
}

fn identity_from_resolved(
    resolved: &chisei_provider::provider_profile::ResolvedProviderModel,
    registry: &chisei_provider::provider_profile::ProviderRegistry,
) -> ModelIdentity {
    let digest = registry
        .profile(&resolved.provider)
        .and_then(|profile| profile.artifact_digest.clone())
        .unwrap_or_default();
    ModelIdentity {
        provider: resolved.provider.clone(),
        model: resolved.canonical_model.clone(),
        upstream_model: resolved.upstream_model.clone(),
        profile_version: resolved.profile_version.clone(),
        artifact_digest: (!digest.is_empty()).then_some(digest),
        endpoint: String::new(),
    }
}

fn load_review_state(
    db: &ChiseiStore,
    namespace: &str,
) -> Result<(Vec<ModelReviewRecord>, Vec<FamilyEnablementRecord>), String> {
    let mut models = list_model_reviews(db, namespace)?;
    let mut families = list_family_enablement(db, namespace)?;
    if !namespace.is_empty() {
        models.extend(list_model_reviews(db, "")?);
        families.extend(list_family_enablement(db, "")?);
    }
    Ok((models, families))
}

fn family_enabled_in_other_region(
    families: &[FamilyEnablementRecord],
    namespace: &str,
    identity: &ModelIdentity,
    region: &str,
) -> bool {
    families.iter().any(|record| {
        record.status == ModelReviewStatus::Enabled
            && !record.region_label.is_empty()
            && record.region_label != region
            && (record.namespace == namespace || record.namespace.is_empty())
            && family_specificity(identity, &record.family_id).is_some()
    })
}

fn audit_admission_refusal(
    db: &ChiseiStore,
    actor: &str,
    identity: &ModelIdentity,
    namespace: &str,
    region: &str,
    refusal: &AdmissionRefusal,
) -> Result<(), String> {
    db.record_decision(&Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: actor.to_string(),
        action: ACTION_ADMIT_DENIED.into(),
        reason: refusal.reason.into(),
        evidence: HashMap::from([
            ("contract_version".into(), MODEL_REVIEW_CONTRACT.into()),
            ("namespace".into(), namespace.into()),
            ("provider".into(), identity.provider.clone()),
            ("model".into(), identity.model.clone()),
            (
                "artifact_digest".into(),
                identity.artifact_digest.clone().unwrap_or_default(),
            ),
            ("region".into(), region.into()),
            ("status".into(), refusal.status.as_str().into()),
            ("refusal".into(), refusal.reason.into()),
        ]),
        target_id: format!(
            "model-review-admit:{}:{}:{}:{}:{}",
            namespace,
            identity.provider,
            identity.model,
            identity.artifact_digest.as_deref().unwrap_or(""),
            region
        ),
        outcome: "denied".into(),
    })
}

/// Default-deny route admission: only `enabled` proceeds. Every refusal is
/// written to the decision ledger.
pub fn admit_enabled_route(
    db: &ChiseiStore,
    namespace: &str,
    identity: &ModelIdentity,
    region: &str,
    actor: &str,
) -> Result<(), AdmissionRefusal> {
    let refusal_for = |status: ModelReviewStatus, reason: &'static str| AdmissionRefusal {
        reason,
        status,
        namespace: namespace.into(),
        provider: identity.provider.clone(),
        model: identity.model.clone(),
        region: region.into(),
    };
    let (models, families) = match load_review_state(db, namespace) {
        Ok(state) => state,
        Err(_) => {
            let refusal = refusal_for(ModelReviewStatus::Disallowed, REFUSAL_NOT_ENABLED);
            let _ = audit_admission_refusal(db, actor, identity, namespace, region, &refusal);
            return Err(refusal);
        }
    };
    let status = effective_review_status(&models, &families, namespace, identity, region);
    if status == ModelReviewStatus::Enabled {
        return Ok(());
    }
    let reason = if family_enabled_in_other_region(&families, namespace, identity, region) {
        REFUSAL_RESIDENCY_MISMATCH
    } else {
        REFUSAL_NOT_ENABLED
    };
    let refusal = refusal_for(status, reason);
    let _ = audit_admission_refusal(db, actor, identity, namespace, region, &refusal);
    Err(refusal)
}

/// Whether the route would be admitted. Does not write the decision ledger:
/// unused failover candidates are filtered, not refused.
pub fn route_is_enabled(
    db: &ChiseiStore,
    namespace: &str,
    identity: &ModelIdentity,
    region: &str,
) -> bool {
    let Ok((models, families)) = load_review_state(db, namespace) else {
        return false;
    };
    effective_review_status(&models, &families, namespace, identity, region)
        == ModelReviewStatus::Enabled
}

/// Enable every provider in the live registry as an unscoped instance-default
/// family. Library and process tests use this so existing routes keep working
/// after default-deny; operators run `sekaictl admin model-review backfill`.
pub fn enable_registry_provider_families(db: &ChiseiStore) -> Result<usize, String> {
    let mut written = 0;
    for profile in chisei_provider::provider_profile::provider_registry_snapshot().profiles {
        let record = FamilyEnablementRecord {
            namespace: String::new(),
            region_label: String::new(),
            family_id: profile.provider,
            status: ModelReviewStatus::Enabled,
            actor: TEST_SEED_ACTOR.into(),
            reason: TEST_SEED_REASON.into(),
            updated_at_ms: 1,
        };
        record.validate()?;
        if db.insert_family_enablement_record_if_absent(&record)? {
            written += 1;
        }
    }
    Ok(written)
}

#[cfg(any(test, feature = "gateway-test-support"))]
pub fn without_registry_family_seed<T>(f: impl FnOnce() -> T) -> T {
    SKIP_REGISTRY_FAMILY_SEED.with(|flag| {
        let previous = flag.replace(true);
        struct Reset<'a> {
            flag: &'a Cell<bool>,
            previous: bool,
        }
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.flag.set(self.previous);
            }
        }
        let _reset = Reset { flag, previous };
        f()
    })
}

#[cfg(any(test, feature = "gateway-test-support"))]
pub fn registry_family_seed_skipped() -> bool {
    SKIP_REGISTRY_FAMILY_SEED.with(Cell::get)
}

fn model_status(
    records: &[ModelReviewRecord],
    namespace: &str,
    identity: &ModelIdentity,
    digest: &str,
) -> Option<ModelReviewStatus> {
    records.iter().find_map(|record| {
        (record.namespace == namespace
            && record.identity.provider == identity.provider
            && record.identity.model == identity.model
            && record.identity.artifact_digest == digest)
            .then_some(record.status)
    })
}

fn family_specificity(identity: &ModelIdentity, family_id: &str) -> Option<usize> {
    let local = identity
        .model
        .rsplit_once('/')
        .map_or(identity.model.as_str(), |(_, local)| local);
    if family_id == identity.provider {
        Some(1_000)
    } else if identity.model == family_id || local == family_id {
        Some(3_000 + family_id.len())
    } else if family_covers(local, family_id) || family_covers(&identity.model, family_id) {
        Some(2_000 + family_id.len())
    } else {
        None
    }
}

fn family_restrictiveness(status: ModelReviewStatus) -> u8 {
    match status {
        ModelReviewStatus::Revoked => 3,
        ModelReviewStatus::Disallowed => 2,
        ModelReviewStatus::Reviewed => 1,
        ModelReviewStatus::Enabled => 0,
    }
}

fn family_status(
    records: &[FamilyEnablementRecord],
    namespace: &str,
    identity: &ModelIdentity,
    region: &str,
) -> Option<ModelReviewStatus> {
    let mut regional: Option<(usize, u8, ModelReviewStatus)> = None;
    let mut unscoped: Option<(usize, u8, ModelReviewStatus)> = None;
    for record in records {
        if record.namespace != namespace {
            continue;
        }
        let Some(rank) = family_specificity(identity, &record.family_id) else {
            continue;
        };
        let slot = if record.region_label == region {
            &mut regional
        } else if record.region_label.is_empty() {
            &mut unscoped
        } else {
            continue;
        };
        let strict = family_restrictiveness(record.status);
        if slot.as_ref().is_none_or(|(best_rank, best_strict, _)| {
            rank > *best_rank || (rank == *best_rank && strict > *best_strict)
        }) {
            *slot = Some((rank, strict, record.status));
        }
    }
    regional.or(unscoped).map(|(_, _, status)| status)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedModelRef {
    pub namespace: String,
    pub provider: String,
    pub model: String,
    pub artifact_digest: String,
}

/// Combined Split (ADR 0083) keeps review rows on the Chisei destination and
/// decision-ledger rows on the Sekai destination, so the two writes cannot
/// share one SQLite transaction. Retrying the same mutation upserts the row
/// and records a new decision if the first audit write failed.
pub fn set_model_review(
    db: &ChiseiStore,
    record: ModelReviewRecord,
) -> Result<ModelReviewRecord, String> {
    record.validate()?;
    db.put_model_review_record(&record)?;
    audit_model(db, ACTION_SET, &record)?;
    Ok(record)
}

pub fn revoke_model_review(
    db: &ChiseiStore,
    mut record: ModelReviewRecord,
) -> Result<ModelReviewRecord, String> {
    record.status = ModelReviewStatus::Revoked;
    record.validate()?;
    db.put_model_review_record(&record)?;
    audit_model(db, ACTION_REVOKE, &record)?;
    Ok(record)
}

pub fn list_model_reviews(
    db: &ChiseiStore,
    namespace: &str,
) -> Result<Vec<ModelReviewRecord>, String> {
    db.list_model_review_records(namespace)
}

pub fn set_family_enablement(
    db: &ChiseiStore,
    record: FamilyEnablementRecord,
) -> Result<FamilyEnablementRecord, String> {
    record.validate()?;
    db.put_family_enablement_record(&record)?;
    audit_family(db, ACTION_FAMILY_SET, &record)?;
    Ok(record)
}

pub fn revoke_family_enablement(
    db: &ChiseiStore,
    mut record: FamilyEnablementRecord,
) -> Result<FamilyEnablementRecord, String> {
    record.status = ModelReviewStatus::Revoked;
    record.validate()?;
    db.put_family_enablement_record(&record)?;
    audit_family(db, ACTION_FAMILY_REVOKE, &record)?;
    Ok(record)
}

pub fn list_family_enablement(
    db: &ChiseiStore,
    namespace: &str,
) -> Result<Vec<FamilyEnablementRecord>, String> {
    db.list_family_enablement_records(namespace)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoutedFamilyRef {
    pub namespace: String,
    pub region_label: String,
    pub family_id: String,
}

fn hosted_pattern_is_literal(pattern: &str) -> bool {
    !pattern.contains('*') && !pattern.contains('?')
}

/// Hosted profiles whose origin is still on the operator endpoint allowlist.
/// Unset or empty allowlist admits none, matching listing and pinning.
pub fn hosted_candidates_for_backfill(
    profiles: Vec<HostedRoutingProfile>,
    allowlist: &[String],
) -> Vec<HostedRoutingProfile> {
    crate::chisei::routing_profiles::admissible_hosted_profiles(profiles, allowlist)
}

/// Concrete hosted patterns become per-model rows. Wildcard patterns are
/// covered by [`family_from_hosted`] so `hosted.acme/widget-1` matches the
/// family named by the hosted runtime.
pub fn routed_from_hosted(profiles: &[HostedRoutingProfile]) -> Vec<RoutedModelRef> {
    let mut routed = Vec::new();
    for profile in profiles {
        let provider = hosted_runtime(profile);
        for pattern in &profile.model_patterns {
            if !hosted_pattern_is_literal(pattern) {
                continue;
            }
            routed.push(RoutedModelRef {
                namespace: profile.namespace.clone(),
                provider: provider.clone(),
                model: format!("{provider}/{pattern}"),
                artifact_digest: registry_artifact_digest(&provider),
            });
        }
    }
    routed
}

pub fn family_from_hosted(profiles: &[HostedRoutingProfile]) -> Vec<RoutedFamilyRef> {
    let mut families: Vec<RoutedFamilyRef> = profiles
        .iter()
        .map(|profile| RoutedFamilyRef {
            namespace: profile.namespace.clone(),
            region_label: String::new(),
            family_id: hosted_runtime(profile),
        })
        .collect();
    families.sort();
    families.dedup();
    families
}

fn registry_artifact_digest(provider: &str) -> String {
    chisei_provider::provider_profile::provider_registry_snapshot()
        .profile(provider)
        .and_then(|profile| profile.artifact_digest.clone())
        .unwrap_or_default()
}

fn canonical_policy_identity(
    model: &str,
    default_runtime: &str,
) -> Option<(String, String, String)> {
    let model = model.trim();
    if model.is_empty() {
        return None;
    }
    if let Ok(resolved) = chisei_provider::provider_resolution::resolve_model(model) {
        let digest = registry_artifact_digest(&resolved.provider);
        return Some((resolved.provider, resolved.canonical_model, digest));
    }
    if !model.contains('/') && !default_runtime.trim().is_empty() {
        let qualified = format!("{}/{model}", default_runtime.trim());
        if let Ok(resolved) = chisei_provider::provider_resolution::resolve_model(&qualified) {
            let digest = registry_artifact_digest(&resolved.provider);
            return Some((resolved.provider, resolved.canonical_model, digest));
        }
    }
    None
}

pub fn routed_from_policy(namespace: &str, policy: &Policy) -> Vec<RoutedModelRef> {
    let mut models = policy.allowed_models.clone();
    if !policy.default_model.trim().is_empty() {
        models.push(policy.default_model.clone());
    }
    models.sort();
    models.dedup();
    models
        .into_iter()
        .filter_map(|model| {
            let (provider, canonical, artifact_digest) =
                canonical_policy_identity(&model, &policy.default_runtime)?;
            Some(RoutedModelRef {
                namespace: namespace.into(),
                provider,
                model: canonical,
                artifact_digest,
            })
        })
        .collect()
}

pub fn routed_from_availability(models: &[AvailableModel]) -> Vec<RoutedModelRef> {
    models
        .iter()
        .filter(|model| model.routable)
        .map(|model| RoutedModelRef {
            namespace: String::new(),
            provider: model.provider.clone(),
            model: model.canonical_model.clone(),
            artifact_digest: String::new(),
        })
        .collect()
}

pub fn policy_object_namespace(namespace: &str, external_id: &str, name: &str) -> String {
    if !namespace.trim().is_empty() {
        return namespace.trim().to_string();
    }
    for prefix in ["namespace_policy:", "policy:", "namespace:"] {
        if let Some(value) = external_id.strip_prefix(prefix)
            && !value.trim().is_empty()
        {
            return value.trim().to_string();
        }
    }
    name.trim().to_string()
}

/// Validates every candidate first, then inserts only missing keys that no
/// covering inherited row already governs, including explicit `disallowed`
/// and region-scoped family rows. A partial run can resume without
/// overwriting operator decisions or enabling a namespace row that would
/// override an inherited restriction.
pub fn backfill_enabled_if_empty(
    db: &ChiseiStore,
    routed: &[RoutedModelRef],
    families: &[RoutedFamilyRef],
    now_ms: i64,
) -> Result<usize, String> {
    let mut model_records = Vec::new();
    for item in routed {
        let record = ModelReviewRecord {
            namespace: item.namespace.clone(),
            identity: ModelReviewIdentity::new(
                item.provider.clone(),
                item.model.clone(),
                item.artifact_digest.clone(),
            ),
            status: ModelReviewStatus::Enabled,
            actor: BACKFILL_ACTOR.into(),
            reason: BACKFILL_REASON.into(),
            updated_at_ms: now_ms,
        };
        record.validate()?;
        model_records.push(record);
    }
    let mut family_records = Vec::new();
    for item in families {
        let record = FamilyEnablementRecord {
            namespace: item.namespace.clone(),
            region_label: item.region_label.clone(),
            family_id: item.family_id.clone(),
            status: ModelReviewStatus::Enabled,
            actor: BACKFILL_ACTOR.into(),
            reason: BACKFILL_REASON.into(),
            updated_at_ms: now_ms,
        };
        record.validate()?;
        family_records.push(record);
    }
    model_records.sort_by_key(|record| {
        (
            !record.namespace.is_empty(),
            record.namespace.clone(),
            record.identity.model.clone(),
        )
    });
    family_records.sort_by_key(|record| {
        (
            !record.namespace.is_empty(),
            record.namespace.clone(),
            record.family_id.clone(),
        )
    });
    let (mut existing_models, mut existing_families) = loaded_review_state(
        db,
        model_records
            .iter()
            .map(|record| record.namespace.clone())
            .chain(family_records.iter().map(|record| record.namespace.clone())),
    )?;
    let mut written = 0;
    for record in model_records {
        if model_backfill_would_override(&existing_models, &existing_families, &record) {
            repair_model_backfill_audit(db, &record)?;
            continue;
        }
        if db.insert_model_review_record_if_absent(&record)? {
            audit_model(db, ACTION_SET, &record)?;
            existing_models.push(record);
            written += 1;
            continue;
        }
        repair_model_backfill_audit(db, &record)?;
    }
    for record in family_records {
        if family_backfill_would_override(&existing_models, &existing_families, &record) {
            repair_family_backfill_audit(db, &record)?;
            continue;
        }
        if db.insert_family_enablement_record_if_absent(&record)? {
            audit_family(db, ACTION_FAMILY_SET, &record)?;
            existing_families.push(record);
            written += 1;
            continue;
        }
        repair_family_backfill_audit(db, &record)?;
    }
    Ok(written)
}

fn loaded_review_state(
    db: &ChiseiStore,
    extra_namespaces: impl IntoIterator<Item = String>,
) -> Result<(Vec<ModelReviewRecord>, Vec<FamilyEnablementRecord>), String> {
    let mut namespaces = BTreeSet::from([String::new()]);
    namespaces.extend(extra_namespaces);
    let mut models = Vec::new();
    let mut families = Vec::new();
    for namespace in namespaces {
        models.extend(list_model_reviews(db, &namespace)?);
        families.extend(list_family_enablement(db, &namespace)?);
    }
    Ok((models, families))
}

fn identity_for_review(record: &ModelReviewRecord) -> ModelIdentity {
    ModelIdentity {
        provider: record.identity.provider.clone(),
        model: record.identity.model.clone(),
        upstream_model: record.identity.model.clone(),
        profile_version: String::new(),
        artifact_digest: (!record.identity.artifact_digest.is_empty())
            .then(|| record.identity.artifact_digest.clone()),
        endpoint: String::new(),
    }
}

fn inherited_namespaces(namespace: &str) -> Vec<&str> {
    if namespace.is_empty() {
        vec![""]
    } else {
        vec![namespace, ""]
    }
}

fn covering_model_row(
    models: &[ModelReviewRecord],
    namespaces: &[&str],
    identity: &ModelIdentity,
) -> bool {
    let digest = identity.artifact_digest.clone().unwrap_or_default();
    namespaces
        .iter()
        .any(|namespace| model_status(models, namespace, identity, &digest).is_some())
}

fn covering_family_row(
    families: &[FamilyEnablementRecord],
    namespaces: &[&str],
    identity: &ModelIdentity,
) -> bool {
    families.iter().any(|family| {
        namespaces.contains(&family.namespace.as_str())
            && family_specificity(identity, &family.family_id).is_some()
    })
}

fn model_backfill_would_override(
    models: &[ModelReviewRecord],
    families: &[FamilyEnablementRecord],
    record: &ModelReviewRecord,
) -> bool {
    let identity = identity_for_review(record);
    let namespaces = inherited_namespaces(&record.namespace);
    covering_model_row(models, &namespaces, &identity)
        || covering_family_row(families, &namespaces, &identity)
}

fn family_backfill_would_override(
    models: &[ModelReviewRecord],
    families: &[FamilyEnablementRecord],
    record: &FamilyEnablementRecord,
) -> bool {
    if record.namespace.is_empty() {
        return false;
    }
    let namespaces = inherited_namespaces(&record.namespace);
    if families.iter().any(|family| {
        family.actor != BACKFILL_ACTOR
            && namespaces.contains(&family.namespace.as_str())
            && family_ids_overlap(&family.family_id, &record.family_id)
    }) {
        return true;
    }
    models.iter().any(|model| {
        model.actor != BACKFILL_ACTOR
            && model.namespace.is_empty()
            && family_specificity(&identity_for_review(model), &record.family_id).is_some()
    })
}

fn repair_model_backfill_audit(db: &ChiseiStore, record: &ModelReviewRecord) -> Result<(), String> {
    if let Some(existing) = db.get_model_review_record(
        &record.namespace,
        &record.identity.provider,
        &record.identity.model,
        &record.identity.artifact_digest,
    )? && existing.actor == BACKFILL_ACTOR
    {
        ensure_model_audit(db, &existing)?;
    }
    Ok(())
}

fn repair_family_backfill_audit(
    db: &ChiseiStore,
    record: &FamilyEnablementRecord,
) -> Result<(), String> {
    if let Some(existing) =
        db.get_family_enablement_record(&record.namespace, &record.region_label, &record.family_id)?
        && existing.actor == BACKFILL_ACTOR
    {
        ensure_family_audit(db, &existing)?;
    }
    Ok(())
}

fn has_decision(
    db: &ChiseiStore,
    actor: &str,
    action: &str,
    target_id: &str,
) -> Result<bool, String> {
    Ok(!db
        .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
            actor: Some(actor.into()),
            action: Some(action.into()),
            target_id: Some(target_id.into()),
            after: 0,
            limit: 1,
            offset: 0,
        })?
        .is_empty())
}

fn ensure_model_audit(db: &ChiseiStore, record: &ModelReviewRecord) -> Result<(), String> {
    if has_decision(db, &record.actor, ACTION_SET, &record.target_id())? {
        return Ok(());
    }
    audit_model(db, ACTION_SET, record)
}

fn ensure_family_audit(db: &ChiseiStore, record: &FamilyEnablementRecord) -> Result<(), String> {
    if has_decision(db, &record.actor, ACTION_FAMILY_SET, &record.target_id())? {
        return Ok(());
    }
    audit_family(db, ACTION_FAMILY_SET, record)
}

fn audit_model(db: &ChiseiStore, action: &str, record: &ModelReviewRecord) -> Result<(), String> {
    db.record_decision(&Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: record.updated_at_ms,
        actor: record.actor.clone(),
        action: action.into(),
        reason: record.reason.clone(),
        evidence: HashMap::from([
            ("contract_version".into(), MODEL_REVIEW_CONTRACT.into()),
            ("namespace".into(), record.namespace.clone()),
            ("provider".into(), record.identity.provider.clone()),
            ("model".into(), record.identity.model.clone()),
            (
                "artifact_digest".into(),
                record.identity.artifact_digest.clone(),
            ),
            ("status".into(), record.status.as_str().into()),
        ]),
        target_id: record.target_id(),
        outcome: record.status.as_str().into(),
    })
}

fn audit_family(
    db: &ChiseiStore,
    action: &str,
    record: &FamilyEnablementRecord,
) -> Result<(), String> {
    db.record_decision(&Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: record.updated_at_ms,
        actor: record.actor.clone(),
        action: action.into(),
        reason: record.reason.clone(),
        evidence: HashMap::from([
            ("contract_version".into(), MODEL_REVIEW_CONTRACT.into()),
            ("namespace".into(), record.namespace.clone()),
            ("region".into(), record.region_label.clone()),
            ("family".into(), record.family_id.clone()),
            ("status".into(), record.status.as_str().into()),
        ]),
        target_id: record.target_id(),
        outcome: record.status.as_str().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(model: &str, digest: Option<&str>) -> ModelIdentity {
        ModelIdentity {
            provider: "openai".into(),
            model: model.into(),
            upstream_model: model.into(),
            profile_version: "v1".into(),
            artifact_digest: digest.map(str::to_string),
            endpoint: "https://example.invalid".into(),
        }
    }

    fn model_row(
        namespace: &str,
        model: &str,
        digest: &str,
        status: ModelReviewStatus,
    ) -> ModelReviewRecord {
        ModelReviewRecord {
            namespace: namespace.into(),
            identity: ModelReviewIdentity::new("openai", model, digest),
            status,
            actor: "alice".into(),
            reason: "fixture".into(),
            updated_at_ms: 1,
        }
    }

    fn family_row(
        namespace: &str,
        family: &str,
        region: &str,
        status: ModelReviewStatus,
    ) -> FamilyEnablementRecord {
        FamilyEnablementRecord {
            namespace: namespace.into(),
            region_label: region.into(),
            family_id: family.into(),
            status,
            actor: "alice".into(),
            reason: "fixture".into(),
            updated_at_ms: 1,
        }
    }

    #[test]
    fn default_is_disallowed() {
        assert_eq!(
            effective_review_status(&[], &[], "sales", &identity("gpt-4", None), "eu"),
            ModelReviewStatus::Disallowed
        );
    }

    #[test]
    fn family_applies_to_member_models_and_per_model_wins() {
        let family = family_row("sales", "gpt-4", "eu", ModelReviewStatus::Enabled);
        let model = model_row("sales", "gpt-4-turbo", "", ModelReviewStatus::Revoked);
        assert_eq!(
            effective_review_status(
                &[],
                std::slice::from_ref(&family),
                "sales",
                &identity("gpt-4-turbo", None),
                "eu"
            ),
            ModelReviewStatus::Enabled
        );
        assert_eq!(
            effective_review_status(
                &[model],
                std::slice::from_ref(&family),
                "sales",
                &identity("gpt-4-turbo", None),
                "eu"
            ),
            ModelReviewStatus::Revoked
        );
        let provider_family = family_row("sales", "openai", "", ModelReviewStatus::Reviewed);
        assert_eq!(
            effective_review_status(
                &[],
                &[provider_family],
                "sales",
                &identity("gpt-4", None),
                ""
            ),
            ModelReviewStatus::Reviewed
        );
        let canonical = ModelIdentity {
            provider: "openai".into(),
            model: "openai/gpt-4-turbo".into(),
            upstream_model: "gpt-4-turbo".into(),
            profile_version: "v1".into(),
            artifact_digest: None,
            endpoint: "https://example.invalid".into(),
        };
        assert_eq!(
            effective_review_status(
                &[],
                std::slice::from_ref(&family),
                "sales",
                &canonical,
                "eu"
            ),
            ModelReviewStatus::Enabled
        );
    }

    #[test]
    fn overlapping_families_prefer_the_more_specific_match() {
        let provider = family_row("sales", "openai", "eu", ModelReviewStatus::Enabled);
        let prefix = family_row("sales", "gpt-4", "eu", ModelReviewStatus::Revoked);
        assert_eq!(
            effective_review_status(
                &[],
                &[provider.clone(), prefix.clone()],
                "sales",
                &identity("gpt-4-turbo", None),
                "eu"
            ),
            ModelReviewStatus::Revoked
        );
        assert_eq!(
            effective_review_status(
                &[],
                &[prefix, provider],
                "sales",
                &identity("gpt-4-turbo", None),
                "eu"
            ),
            ModelReviewStatus::Revoked
        );
        let canonical = ModelIdentity {
            provider: "openai".into(),
            model: "openai/gpt-4-turbo".into(),
            upstream_model: "gpt-4-turbo".into(),
            profile_version: "v1".into(),
            artifact_digest: None,
            endpoint: "https://example.invalid".into(),
        };
        let provider = family_row("sales", "openai", "eu", ModelReviewStatus::Enabled);
        let prefix = family_row("sales", "gpt-4", "eu", ModelReviewStatus::Revoked);
        assert_eq!(family_specificity(&canonical, "openai"), Some(1_000));
        assert_eq!(
            family_specificity(&canonical, "gpt-4"),
            Some(2_000 + "gpt-4".len())
        );
        assert_eq!(
            effective_review_status(
                &[],
                std::slice::from_ref(&prefix),
                "sales",
                &canonical,
                "eu"
            ),
            ModelReviewStatus::Revoked
        );
        assert_eq!(
            effective_review_status(&[], &[provider, prefix], "sales", &canonical, "eu"),
            ModelReviewStatus::Revoked
        );
    }

    #[test]
    fn namespace_overrides_global() {
        let global = model_row("", "gpt-4", "", ModelReviewStatus::Enabled);
        let local = model_row("sales", "gpt-4", "", ModelReviewStatus::Revoked);
        assert_eq!(
            effective_review_status(
                std::slice::from_ref(&global),
                &[],
                "sales",
                &identity("gpt-4", None),
                ""
            ),
            ModelReviewStatus::Enabled
        );
        assert_eq!(
            effective_review_status(&[global, local], &[], "sales", &identity("gpt-4", None), ""),
            ModelReviewStatus::Revoked
        );
    }

    #[test]
    fn namespace_family_overrides_global_model() {
        let global = model_row("", "gpt-4", "", ModelReviewStatus::Enabled);
        let local_family = family_row("sales", "openai", "", ModelReviewStatus::Revoked);
        assert_eq!(
            effective_review_status(
                std::slice::from_ref(&global),
                std::slice::from_ref(&local_family),
                "sales",
                &identity("gpt-4", None),
                ""
            ),
            ModelReviewStatus::Revoked
        );
    }

    #[test]
    fn backfill_hosted_candidates_require_the_endpoint_allowlist() {
        let hosted = hosted_acme(&["widget-*"]);
        assert!(hosted_candidates_for_backfill(vec![hosted.clone()], &[]).is_empty());
        assert_eq!(
            hosted_candidates_for_backfill(
                vec![hosted.clone()],
                &["https://models.example".into()]
            )
            .len(),
            1
        );
        assert!(
            hosted_candidates_for_backfill(vec![hosted], &["https://other.example".into()])
                .is_empty()
        );
    }

    #[test]
    fn backfill_inserts_hosted_family_alongside_literal_model_rows() {
        let db = ChiseiStore::memory();
        let hosted = hosted_acme(&["widget-1", "widget-*"]);
        let routed = routed_from_hosted(std::slice::from_ref(&hosted));
        let families = family_from_hosted(std::slice::from_ref(&hosted));
        assert_eq!(routed.len(), 1);
        assert_eq!(
            backfill_enabled_if_empty(&db, &routed, &families, 9).unwrap(),
            2
        );
        assert_eq!(
            list_model_reviews(&db, "sales").unwrap()[0].status,
            ModelReviewStatus::Enabled
        );
        assert_eq!(
            list_family_enablement(&db, "sales").unwrap()[0].status,
            ModelReviewStatus::Enabled
        );
        assert_eq!(
            effective_review_status(
                &list_model_reviews(&db, "sales").unwrap(),
                &list_family_enablement(&db, "sales").unwrap(),
                "sales",
                &hosted_identity("hosted.acme/widget-2"),
                ""
            ),
            ModelReviewStatus::Enabled
        );
        assert_eq!(
            backfill_enabled_if_empty(&db, &routed, &families, 10).unwrap(),
            0
        );
    }

    fn hosted_acme(patterns: &[&str]) -> HostedRoutingProfile {
        HostedRoutingProfile {
            namespace: "sales".into(),
            profile_id: "hosted:acme".into(),
            endpoint_origin: "https://models.example".into(),
            model_patterns: patterns.iter().map(|pattern| (*pattern).into()).collect(),
            credential_ref: "ACME".into(),
            artifact_digest: None,
            registered_by: "root".into(),
            registered_at_ms: 1,
            ..Default::default()
        }
    }

    fn hosted_identity(model: &str) -> ModelIdentity {
        ModelIdentity {
            provider: "hosted.acme".into(),
            model: model.into(),
            upstream_model: model.into(),
            profile_version: "v1".into(),
            artifact_digest: None,
            endpoint: "https://models.example".into(),
        }
    }

    #[test]
    fn backfill_marks_currently_routed_hosted_families_enabled() {
        let db = ChiseiStore::memory();
        let hosted = hosted_acme(&["widget-*"]);
        let routed = routed_from_hosted(std::slice::from_ref(&hosted));
        let families = family_from_hosted(std::slice::from_ref(&hosted));
        assert!(routed.is_empty());
        assert_eq!(
            backfill_enabled_if_empty(&db, &routed, &families, 9).unwrap(),
            1
        );
        assert_eq!(
            backfill_enabled_if_empty(&db, &routed, &families, 10).unwrap(),
            0
        );
        assert!(list_model_reviews(&db, "sales").unwrap().is_empty());
        let listed = list_family_enablement(&db, "sales").unwrap();
        assert_eq!(listed[0].status, ModelReviewStatus::Enabled);
        assert_eq!(listed[0].actor, BACKFILL_ACTOR);
        assert_eq!(listed[0].family_id, "hosted.acme");
        assert_eq!(
            effective_review_status(
                &[],
                &listed,
                "sales",
                &hosted_identity("hosted.acme/widget-1"),
                ""
            ),
            ModelReviewStatus::Enabled
        );
    }

    #[test]
    fn backfill_literal_hosted_model_does_not_skip_wildcard_family() {
        let db = ChiseiStore::memory();
        let hosted = hosted_acme(&["widget-1", "widget-*"]);
        let routed = routed_from_hosted(std::slice::from_ref(&hosted));
        let families = family_from_hosted(std::slice::from_ref(&hosted));
        assert_eq!(routed.len(), 1);
        assert_eq!(
            backfill_enabled_if_empty(&db, &routed, &families, 9).unwrap(),
            2
        );
        assert_eq!(
            list_model_reviews(&db, "sales").unwrap()[0].identity.model,
            "hosted.acme/widget-1"
        );
        assert_eq!(
            list_family_enablement(&db, "sales").unwrap()[0].family_id,
            "hosted.acme"
        );
        assert_eq!(
            effective_review_status(
                &list_model_reviews(&db, "sales").unwrap(),
                &list_family_enablement(&db, "sales").unwrap(),
                "sales",
                &hosted_identity("hosted.acme/widget-2"),
                ""
            ),
            ModelReviewStatus::Enabled
        );
    }

    #[test]
    fn backfill_fills_missing_rows_without_overwriting() {
        let db = ChiseiStore::memory();
        set_family_enablement(
            &db,
            family_row("sales", "openai", "", ModelReviewStatus::Reviewed),
        )
        .unwrap();
        let hosted = hosted_acme(&["widget-*"]);
        assert_eq!(
            backfill_enabled_if_empty(
                &db,
                &routed_from_hosted(std::slice::from_ref(&hosted)),
                &family_from_hosted(std::slice::from_ref(&hosted)),
                9
            )
            .unwrap(),
            1
        );
        let listed = list_family_enablement(&db, "sales").unwrap();
        assert!(
            listed
                .iter()
                .any(|row| row.family_id == "openai" && row.status == ModelReviewStatus::Reviewed)
        );
        assert!(
            listed
                .iter()
                .any(|row| row.family_id == "hosted.acme"
                    && row.status == ModelReviewStatus::Enabled)
        );
        set_family_enablement(
            &db,
            family_row("sales", "hosted.acme", "", ModelReviewStatus::Reviewed),
        )
        .unwrap();
        assert_eq!(
            backfill_enabled_if_empty(
                &db,
                &[],
                &family_from_hosted(std::slice::from_ref(&hosted)),
                10
            )
            .unwrap(),
            0
        );
        assert_eq!(
            list_family_enablement(&db, "sales")
                .unwrap()
                .into_iter()
                .find(|row| row.family_id == "hosted.acme")
                .unwrap()
                .status,
            ModelReviewStatus::Reviewed
        );
    }

    #[test]
    fn backfill_does_not_overwrite_operator_model_row() {
        let db = ChiseiStore::memory();
        set_model_review(
            &db,
            model_row("ops", "gpt-5.5", "", ModelReviewStatus::Revoked),
        )
        .unwrap();
        let routed = [RoutedModelRef {
            namespace: "ops".into(),
            provider: "openai".into(),
            model: "gpt-5.5".into(),
            artifact_digest: String::new(),
        }];
        assert_eq!(backfill_enabled_if_empty(&db, &routed, &[], 9).unwrap(), 0);
        assert_eq!(
            list_model_reviews(&db, "ops").unwrap()[0].status,
            ModelReviewStatus::Revoked
        );
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: Some(BACKFILL_ACTOR.into()),
                action: None,
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert!(decisions.is_empty());
    }

    #[test]
    fn backfill_does_not_enable_model_that_overrides_revoked_family() {
        let db = ChiseiStore::memory();
        set_family_enablement(
            &db,
            family_row("sales", "hosted.acme", "", ModelReviewStatus::Revoked),
        )
        .unwrap();
        let hosted = hosted_acme(&["widget-1"]);
        let routed = routed_from_hosted(std::slice::from_ref(&hosted));
        let families = family_from_hosted(std::slice::from_ref(&hosted));
        assert_eq!(routed.len(), 1);
        assert_eq!(
            backfill_enabled_if_empty(&db, &routed, &families, 9).unwrap(),
            0
        );
        assert!(list_model_reviews(&db, "sales").unwrap().is_empty());
        assert_eq!(
            list_family_enablement(&db, "sales").unwrap()[0].status,
            ModelReviewStatus::Revoked
        );
        assert_eq!(
            effective_review_status(
                &[],
                &list_family_enablement(&db, "sales").unwrap(),
                "sales",
                &hosted_identity("hosted.acme/widget-1"),
                ""
            ),
            ModelReviewStatus::Revoked
        );
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: Some(BACKFILL_ACTOR.into()),
                action: None,
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert!(decisions.is_empty());
    }

    #[test]
    fn backfill_does_not_enable_namespace_family_that_overrides_global_revocation() {
        let db = ChiseiStore::memory();
        set_family_enablement(
            &db,
            family_row("", "hosted.acme", "", ModelReviewStatus::Revoked),
        )
        .unwrap();
        let hosted = hosted_acme(&["widget-*"]);
        let routed = routed_from_hosted(std::slice::from_ref(&hosted));
        let families = family_from_hosted(std::slice::from_ref(&hosted));
        assert!(routed.is_empty());
        assert_eq!(
            backfill_enabled_if_empty(&db, &routed, &families, 9).unwrap(),
            0
        );
        assert!(list_family_enablement(&db, "sales").unwrap().is_empty());
        assert_eq!(
            list_family_enablement(&db, "").unwrap()[0].status,
            ModelReviewStatus::Revoked
        );
        assert_eq!(
            effective_review_status(
                &[],
                &list_family_enablement(&db, "").unwrap(),
                "sales",
                &hosted_identity("hosted.acme/widget-1"),
                ""
            ),
            ModelReviewStatus::Revoked
        );
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: Some(BACKFILL_ACTOR.into()),
                action: None,
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert!(decisions.is_empty());
    }

    #[test]
    fn backfill_does_not_enable_namespace_family_that_hides_global_model_revocation() {
        let db = ChiseiStore::memory();
        set_model_review(
            &db,
            ModelReviewRecord {
                namespace: String::new(),
                identity: ModelReviewIdentity::new("hosted.acme", "hosted.acme/widget-1", ""),
                status: ModelReviewStatus::Revoked,
                actor: "alice".into(),
                reason: "fixture".into(),
                updated_at_ms: 1,
            },
        )
        .unwrap();
        let hosted = hosted_acme(&["widget-*"]);
        assert_eq!(
            backfill_enabled_if_empty(
                &db,
                &routed_from_hosted(std::slice::from_ref(&hosted)),
                &family_from_hosted(std::slice::from_ref(&hosted)),
                9
            )
            .unwrap(),
            0
        );
        assert!(list_family_enablement(&db, "sales").unwrap().is_empty());
        assert_eq!(
            list_model_reviews(&db, "").unwrap()[0].status,
            ModelReviewStatus::Revoked
        );
        assert_eq!(
            effective_review_status(
                &list_model_reviews(&db, "").unwrap(),
                &[],
                "sales",
                &hosted_identity("hosted.acme/widget-1"),
                ""
            ),
            ModelReviewStatus::Revoked
        );
    }

    #[test]
    fn backfill_does_not_override_explicit_disallowed_family() {
        let db = ChiseiStore::memory();
        set_family_enablement(
            &db,
            family_row("", "hosted.acme", "", ModelReviewStatus::Disallowed),
        )
        .unwrap();
        let hosted = hosted_acme(&["widget-1"]);
        assert_eq!(
            backfill_enabled_if_empty(
                &db,
                &routed_from_hosted(std::slice::from_ref(&hosted)),
                &family_from_hosted(std::slice::from_ref(&hosted)),
                9
            )
            .unwrap(),
            0
        );
        assert!(list_model_reviews(&db, "sales").unwrap().is_empty());
        assert!(list_family_enablement(&db, "sales").unwrap().is_empty());
        assert_eq!(
            list_family_enablement(&db, "").unwrap()[0].status,
            ModelReviewStatus::Disallowed
        );
    }

    #[test]
    fn backfill_does_not_override_regional_family_revocation() {
        let db = ChiseiStore::memory();
        set_family_enablement(
            &db,
            family_row("", "hosted.acme", "eu", ModelReviewStatus::Revoked),
        )
        .unwrap();
        let hosted = hosted_acme(&["widget-1"]);
        assert_eq!(
            backfill_enabled_if_empty(
                &db,
                &routed_from_hosted(std::slice::from_ref(&hosted)),
                &family_from_hosted(std::slice::from_ref(&hosted)),
                9
            )
            .unwrap(),
            0
        );
        assert!(list_model_reviews(&db, "sales").unwrap().is_empty());
        assert!(list_family_enablement(&db, "sales").unwrap().is_empty());
        assert_eq!(
            effective_review_status(
                &[],
                &list_family_enablement(&db, "").unwrap(),
                "sales",
                &hosted_identity("hosted.acme/widget-1"),
                "eu"
            ),
            ModelReviewStatus::Revoked
        );
    }

    #[test]
    fn backfill_does_not_enable_more_specific_family_under_broader_restriction() {
        let db = ChiseiStore::memory();
        set_family_enablement(
            &db,
            family_row("", "hosted", "", ModelReviewStatus::Revoked),
        )
        .unwrap();
        let hosted = hosted_acme(&["widget-*"]);
        assert_eq!(
            backfill_enabled_if_empty(
                &db,
                &[],
                &family_from_hosted(std::slice::from_ref(&hosted)),
                9
            )
            .unwrap(),
            0
        );
        assert!(list_family_enablement(&db, "sales").unwrap().is_empty());
        set_family_enablement(&db, family_row("", "gpt-4", "", ModelReviewStatus::Revoked))
            .unwrap();
        let prefix = [RoutedFamilyRef {
            namespace: "sales".into(),
            region_label: String::new(),
            family_id: "gpt-4-turbo".into(),
        }];
        assert_eq!(backfill_enabled_if_empty(&db, &[], &prefix, 9).unwrap(), 0);
        assert!(
            list_family_enablement(&db, "sales")
                .unwrap()
                .iter()
                .all(|row| row.family_id != "gpt-4-turbo")
        );
    }

    #[test]
    fn backfill_repairs_missing_audit_for_existing_backfill_row() {
        let db = ChiseiStore::memory();
        let hosted = hosted_acme(&["widget-*"]);
        let families = family_from_hosted(std::slice::from_ref(&hosted));
        db.put_family_enablement_record(&FamilyEnablementRecord {
            namespace: "sales".into(),
            region_label: String::new(),
            family_id: "hosted.acme".into(),
            status: ModelReviewStatus::Enabled,
            actor: BACKFILL_ACTOR.into(),
            reason: BACKFILL_REASON.into(),
            updated_at_ms: 8,
        })
        .unwrap();
        assert_eq!(
            backfill_enabled_if_empty(&db, &[], &families, 9).unwrap(),
            0
        );
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: Some(BACKFILL_ACTOR.into()),
                action: Some(ACTION_FAMILY_SET.into()),
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(
            list_family_enablement(&db, "sales").unwrap()[0].updated_at_ms,
            8
        );
    }

    #[test]
    fn policy_object_namespace_recovers_legacy_scope() {
        assert_eq!(
            policy_object_namespace("", "namespace_policy:sales", "ignored"),
            "sales"
        );
        assert_eq!(
            policy_object_namespace("ops", "namespace_policy:sales", ""),
            "ops"
        );
        assert_eq!(policy_object_namespace("", "", "finance"), "finance");
    }

    #[test]
    fn same_millisecond_mutations_keep_distinct_audit_rows() {
        let db = ChiseiStore::memory();
        set_model_review(
            &db,
            model_row("sales", "gpt-4", "", ModelReviewStatus::Reviewed),
        )
        .unwrap();
        set_model_review(
            &db,
            model_row("sales", "gpt-4", "", ModelReviewStatus::Enabled),
        )
        .unwrap();
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: Some("alice".into()),
                action: Some(ACTION_SET.into()),
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert_eq!(decisions.len(), 2);
        assert_ne!(decisions[0].id, decisions[1].id);
    }

    #[test]
    fn policy_routes_and_availability_feed_backfill() {
        let policy = Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["openai/gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5-mini".into(),
            data_class: "unclassified".into(),
        };
        let from_policy = routed_from_policy("ops", &policy);
        assert!(from_policy.iter().any(|row| {
            row.namespace == "ops" && row.provider == "openai" && row.model == "openai/gpt-5.5"
        }));
        assert!(from_policy.iter().any(|row| {
            row.namespace == "ops" && row.provider == "openai" && row.model == "openai/gpt-5.5-mini"
        }));
        let available = AvailableModel {
            provider: "anthropic".into(),
            upstream_model: "claude-sonnet-4-20250514".into(),
            canonical_model: "claude-sonnet-4-20250514".into(),
            lifecycle: "ga".into(),
            routable: true,
            discovery_source: "builtin".into(),
            capabilities: None,
            pricing: None,
            cost_rank: None,
            capability_rank: None,
        };
        let from_avail = routed_from_availability(&[available]);
        assert_eq!(from_avail[0].namespace, "");
        assert_eq!(from_avail[0].provider, "anthropic");
    }

    #[test]
    fn set_revoke_records_actor_and_reason() {
        let db = ChiseiStore::memory();
        set_model_review(
            &db,
            model_row("sales", "gpt-4", "", ModelReviewStatus::Reviewed),
        )
        .unwrap();
        revoke_model_review(
            &db,
            model_row("sales", "gpt-4", "", ModelReviewStatus::Enabled),
        )
        .unwrap();
        let listed = list_model_reviews(&db, "sales").unwrap();
        assert_eq!(listed[0].status, ModelReviewStatus::Revoked);
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: Some("alice".into()),
                action: None,
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert!(decisions.iter().any(|row| row.action == ACTION_SET));
        assert!(decisions.iter().any(|row| row.action == ACTION_REVOKE));
        assert!(decisions.iter().all(|row| !row.reason.is_empty()));
    }

    #[test]
    fn unreviewed_model_is_refused_and_audited() {
        let db = ChiseiStore::memory();
        let identity = identity("gpt-4", None);
        let error = admit_enabled_route(&db, "sales", &identity, "", "alice").unwrap_err();
        assert_eq!(error.reason, REFUSAL_NOT_ENABLED);
        assert_eq!(error.status, ModelReviewStatus::Disallowed);
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: Some("alice".into()),
                action: Some(ACTION_ADMIT_DENIED.into()),
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, REFUSAL_NOT_ENABLED);
        assert_eq!(decisions[0].outcome, "denied");
    }

    #[test]
    fn enabled_model_is_admitted() {
        let db = ChiseiStore::memory();
        set_model_review(
            &db,
            model_row("sales", "gpt-4", "", ModelReviewStatus::Enabled),
        )
        .unwrap();
        admit_enabled_route(&db, "sales", &identity("gpt-4", None), "", "alice").unwrap();
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: Some("alice".into()),
                action: Some(ACTION_ADMIT_DENIED.into()),
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert!(decisions.is_empty());
    }

    #[test]
    fn unreviewed_sibling_is_not_an_enabled_failover_route() {
        let db = ChiseiStore::memory();
        set_model_review(
            &db,
            model_row("sales", "gpt-5.5", "", ModelReviewStatus::Enabled),
        )
        .unwrap();
        assert!(route_is_enabled(
            &db,
            "sales",
            &identity("gpt-5.5", None),
            ""
        ));
        assert!(!route_is_enabled(
            &db,
            "sales",
            &identity("gpt-5.5-mini", None),
            ""
        ));
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: None,
                action: Some(ACTION_ADMIT_DENIED.into()),
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert!(decisions.is_empty(), "{decisions:?}");
    }

    #[test]
    fn residency_mismatch_is_refused_even_when_the_family_is_enabled() {
        let db = ChiseiStore::memory();
        set_family_enablement(
            &db,
            family_row("sales", "openai", "us", ModelReviewStatus::Enabled),
        )
        .unwrap();
        let error =
            admit_enabled_route(&db, "sales", &identity("gpt-4", None), "eu", "alice").unwrap_err();
        assert_eq!(error.reason, REFUSAL_RESIDENCY_MISMATCH);
        let decisions = db
            .list_decisions(&crate::chisei::decision_ledger::DecisionFilter {
                actor: Some("alice".into()),
                action: Some(ACTION_ADMIT_DENIED.into()),
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert_eq!(decisions[0].reason, REFUSAL_RESIDENCY_MISMATCH);
    }

    #[test]
    fn hosted_identity_uses_the_same_admission_check() {
        let db = ChiseiStore::memory();
        let identity = hosted_identity("hosted.acme/widget-1");
        let error = admit_enabled_route(&db, "sales", &identity, "", "alice").unwrap_err();
        assert_eq!(error.reason, REFUSAL_NOT_ENABLED);
        set_family_enablement(
            &db,
            family_row("sales", "hosted.acme", "", ModelReviewStatus::Enabled),
        )
        .unwrap();
        admit_enabled_route(&db, "sales", &identity, "", "alice").unwrap();
    }

    #[test]
    fn identity_from_model_keeps_hosted_ids_without_a_registry_snapshot() {
        let identity = identity_from_model("hosted.acme/widget-1").unwrap();
        assert_eq!(identity.provider, "hosted.acme");
        assert_eq!(identity.model, "hosted.acme/widget-1");
    }

    #[test]
    fn backfilled_family_keeps_the_route_admitted() {
        let db = ChiseiStore::memory();
        let hosted = hosted_acme(&["widget-*"]);
        backfill_enabled_if_empty(
            &db,
            &[],
            &family_from_hosted(std::slice::from_ref(&hosted)),
            1,
        )
        .unwrap();
        admit_enabled_route(
            &db,
            "sales",
            &hosted_identity("hosted.acme/widget-1"),
            "",
            "alice",
        )
        .unwrap();
    }
}
