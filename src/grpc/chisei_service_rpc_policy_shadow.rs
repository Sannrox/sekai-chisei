//! Live policy shadow RPCs (#1630). Control-plane admin only, like
//! `SetNamespacePolicy`. Start, stop, and activation are recorded as
//! decisions before the state changes, so a failed audit changes nothing.

use super::*;
use crate::chisei::policy_shadow::{
    self as shadow_domain, POLICY_SHADOW_CONTRACT, PolicyShadow,
    PolicyShadowReport as ShadowReport, RouteOutcome, ShadowSample,
};
use crate::chisei_store::ChiseiPolicyShadowStore;

fn shadow_store_status(error: String) -> Status {
    if error == shadow_domain::ACTIVATION_IN_PROGRESS {
        Status::aborted(error)
    } else if error.contains("required")
        || error.contains("must")
        || error.contains("does not match")
    {
        Status::invalid_argument(error)
    } else {
        Status::internal("policy shadow unavailable")
    }
}

fn canonical_shadow_namespace(namespace: &str) -> Result<&str, Status> {
    if namespace.trim().is_empty() || namespace != namespace.trim() {
        return Err(Status::invalid_argument(
            "namespace is required and must be trimmed",
        ));
    }
    Ok(namespace)
}

pub(super) fn to_proto_report(report: ShadowReport) -> PolicyShadowReport {
    let verdict = report.verdict();
    let match_rate_bps = report.match_rate_bps();
    let ShadowReport {
        shadow,
        counts,
        samples,
    } = report;
    PolicyShadowReport {
        contract_version: POLICY_SHADOW_CONTRACT.into(),
        namespace: shadow.namespace,
        candidate_policy_version: shadow.candidate_version,
        active_policy_version: shadow.active_version,
        min_evaluations: shadow.min_evaluations,
        min_match_rate_bps: shadow.min_match_rate_bps,
        started_by: shadow.started_by,
        started_at_ms: shadow.started_at_ms,
        evaluated: counts.evaluated,
        unchanged: counts.unchanged,
        re_routed: counts.re_routed,
        would_deny: counts.would_deny,
        would_allow: counts.would_allow,
        match_rate_bps,
        passing: verdict.is_ok(),
        verdict_reason: verdict.err().unwrap_or_default(),
        samples: samples
            .into_iter()
            .map(|sample| PolicyShadowSample {
                delta: sample.delta.as_str().into(),
                preferred_runtime: sample.preferred_runtime,
                preferred_model: sample.preferred_model,
                active: sample.active,
                candidate: sample.candidate,
                observed_at_ms: sample.observed_at_ms,
            })
            .collect(),
        shadow_id: shadow.shadow_id,
    }
}

fn record_shadow_decision(
    service: &ChiseiServiceImpl,
    actor: &str,
    action: &str,
    shadow: &PolicyShadow,
    reason: &str,
) -> Result<(), Status> {
    // The timestamp keeps a retried activation from colliding with its first
    // attempt's record.
    let timestamp = chrono::Utc::now().timestamp_millis();
    service
        .db
        .record_decision(&crate::sekai::audit::Decision {
            id: format!("{action}:{}:{timestamp}", shadow.shadow_id),
            timestamp,
            actor: actor.into(),
            action: action.into(),
            reason: reason.into(),
            evidence: HashMap::from([
                ("namespace".into(), shadow.namespace.clone()),
                ("shadow_id".into(), shadow.shadow_id.clone()),
                (
                    "candidate_policy_version".into(),
                    shadow.candidate_version.clone(),
                ),
            ]),
            target_id: shadow.namespace.clone(),
            outcome: "completed".into(),
        })
        .map_err(|_| Status::internal("policy shadow audit unavailable"))
}

/// A baseline's version after the normalization applied when policies are
/// loaded from storage, so the cached and the persisted form of one policy
/// compare equal.
fn baseline_version(policy: Policy) -> String {
    normalize_persisted_legacy_policy(policy).version()
}

/// The namespace's own cached policy version, or empty when it has none.
fn own_policy_version(service: &ChiseiServiceImpl, namespace: &str) -> String {
    service
        .policy
        .effective_policy(namespace)
        .map(baseline_version)
        .unwrap_or_default()
}

/// The namespace's own policy version as persisted, so start and admission
/// do not depend on this instance's cache. A shadow pins this at start,
/// because activating the candidate replaces it. Falls back to the cache when no canonical
/// policy object exists.
fn persisted_policy_version(
    service: &ChiseiServiceImpl,
    namespace: &str,
) -> Result<String, Status> {
    let store = service
        .sekai_facts
        .reader()
        .in_process_store()
        .map(crate::db::store::SekaiStore::runtime)
        .unwrap_or_else(|_| service.db.fact_runtime());
    let persisted = store
        .find_by_external_id(&format!("policy:{namespace}"))
        .map_err(|_| Status::internal("namespace policy unavailable"))?;
    Ok(match persisted {
        Some(object) => baseline_version(policy_from_properties(&object.properties)),
        None => own_policy_version(service, namespace),
    })
}

pub(super) async fn start_policy_shadow(
    service: &ChiseiServiceImpl,
    req: Request<StartPolicyShadowRequest>,
) -> Result<Response<StartPolicyShadowResponse>, Status> {
    require_control_plane_admin(&req, "policy shadow mutation")?;
    let actor = authenticated_actor(&req);
    service.require_in_process_namespace_policy()?;
    let registry = service.refresh_provider_registry_for_resolution().await?;
    crate::provider_profile::with_provider_registry_snapshot(registry, async {
        let r = req.into_inner();
        let namespace = canonical_shadow_namespace(&r.namespace)?.to_string();
        let candidate = normalize_legacy_policy_provider_pairs(Policy {
            allowed_runtimes: r.allowed_runtimes,
            allowed_models: r.allowed_models,
            default_runtime: r.default_runtime,
            default_model: r.default_model,
            data_class: DataClass::parse(&r.data_class).as_str().into(),
        });
        validate_policy_provider_pairs(&candidate).map_err(Status::invalid_argument)?;
        // SetNamespacePolicy refuses a policy whose own default does not
        // route, so such a candidate could never be activated.
        service
            .policy
            .apply_policy(
                &candidate,
                &candidate.default_runtime,
                &candidate.default_model,
            )
            .map_err(Status::invalid_argument)?;
        let shadow = PolicyShadow {
            shadow_id: uuid::Uuid::new_v4().simple().to_string(),
            active_version: persisted_policy_version(service, &namespace)?,
            namespace,
            candidate_version: candidate.version(),
            candidate,
            min_evaluations: r.min_evaluations,
            min_match_rate_bps: r.min_match_rate_bps,
            started_by: actor.clone(),
            started_at_ms: chrono::Utc::now().timestamp_millis(),
        };
        shadow.validate().map_err(Status::invalid_argument)?;
        record_shadow_decision(
            service,
            &actor,
            "policy.shadow_start",
            &shadow,
            "live policy shadow started",
        )?;
        service
            .db
            .start_policy_shadow(&shadow)
            .map_err(shadow_store_status)?;
        let report = service
            .db
            .policy_shadow_report(&shadow.namespace)
            .map_err(shadow_store_status)?
            .ok_or_else(|| Status::aborted("policy shadow changed concurrently"))?;
        Ok(Response::new(StartPolicyShadowResponse {
            report: Some(to_proto_report(report)),
        }))
    })
    .await
}

pub(super) async fn get_policy_shadow_report(
    service: &ChiseiServiceImpl,
    req: Request<GetPolicyShadowReportRequest>,
) -> Result<Response<GetPolicyShadowReportResponse>, Status> {
    require_control_plane_admin(&req, "policy shadow report")?;
    let namespace = canonical_shadow_namespace(&req.get_ref().namespace)?;
    let report = service
        .db
        .policy_shadow_report(namespace)
        .map_err(shadow_store_status)?
        .ok_or_else(|| Status::not_found("no policy shadow for namespace"))?;
    Ok(Response::new(GetPolicyShadowReportResponse {
        report: Some(to_proto_report(report)),
    }))
}

pub(super) async fn stop_policy_shadow(
    service: &ChiseiServiceImpl,
    req: Request<StopPolicyShadowRequest>,
) -> Result<Response<StopPolicyShadowResponse>, Status> {
    require_control_plane_admin(&req, "policy shadow mutation")?;
    let actor = authenticated_actor(&req);
    let r = req.into_inner();
    let namespace = canonical_shadow_namespace(&r.namespace)?;
    let Some(report) = service
        .db
        .policy_shadow_report(namespace)
        .map_err(shadow_store_status)?
    else {
        return Ok(Response::new(StopPolicyShadowResponse { stopped: false }));
    };
    let reason = match r.reason.trim() {
        "" => "live policy shadow stopped",
        reason => reason,
    };
    record_shadow_decision(
        service,
        &actor,
        "policy.shadow_stop",
        &report.shadow,
        reason,
    )?;
    let stopped = service
        .db
        .stop_policy_shadow(
            namespace,
            Some(&report.shadow.shadow_id),
            Some(chrono::Utc::now().timestamp_millis()),
        )
        .map_err(shadow_store_status)?;
    Ok(Response::new(StopPolicyShadowResponse { stopped }))
}

/// The parts of a live route decision a shadow is evaluated against.
pub(super) struct ShadowRequest<'a> {
    /// The request's ranked policy scopes.
    pub scopes: &'a [String],
    /// The scope whose policy decided, if any; only scopes up to it can
    /// change the decision.
    pub effective_scope: Option<&'a str>,
    pub preferred_runtime: &'a str,
    /// The model the caller asked for, before any policy rewrote it.
    pub requested_model: &'a str,
    pub route_override: &'a str,
}

impl ChiseiServiceImpl {
    /// Evaluates a shadowed candidate beside a live route decision and counts
    /// the comparison. The first scope with a shadow, up to the effective
    /// one, is observed. `candidate_model` gives the model preference the
    /// candidate sees, as the active policy saw its own, and a route override
    /// must be admitted by the candidate as it was by the active policy. It
    /// never changes `active` and never fails the caller: store errors are
    /// logged and the decision proceeds. A shadow whose namespace policy
    /// changed since it started is skipped.
    pub(super) fn observe_policy_shadow(
        &self,
        request: ShadowRequest<'_>,
        candidate_model: impl FnOnce(&Policy) -> String,
        active: &RouteOutcome,
    ) {
        let ShadowRequest {
            scopes,
            effective_scope,
            preferred_runtime,
            requested_model,
            route_override,
        } = request;
        let reachable = match effective_scope
            .and_then(|scope| scopes.iter().position(|candidate| candidate == scope))
        {
            Some(index) => &scopes[..=index],
            None => scopes,
        };
        let shadow = match self.db.find_policy_shadow(reachable) {
            Ok(Some(shadow)) => shadow,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "policy shadow read failed");
                return;
            }
        };
        if shadow.active_version != own_policy_version(self, &shadow.namespace) {
            return;
        }
        let candidate = if !route_override.is_empty()
            && !super::live_model::route_override_allowed(Some(&shadow.candidate), route_override)
        {
            Err(format!(
                "route override {route_override:?} is not allowed by policy"
            ))
        } else {
            self.policy.apply_policy(
                &shadow.candidate,
                preferred_runtime,
                &candidate_model(&shadow.candidate),
            )
        };
        let sample = ShadowSample::new(
            shadow_domain::classify(active, &candidate),
            preferred_runtime,
            requested_model,
            active,
            &candidate,
            chrono::Utc::now().timestamp_millis(),
        );
        if let Err(error) = self
            .db
            .record_policy_shadow_observation(&shadow.shadow_id, &sample)
        {
            tracing::warn!(namespace = %shadow.namespace, %error, "policy shadow record failed");
        }
    }
}

/// Admitting the candidate claims the checked run for
/// `ACTIVATION_CLAIM_MS`; `StartPolicyShadow` cannot replace a claimed run, so
/// the run stays the one checked until the policy is written. The claim is
/// confirmed again after the audit write, immediately before the caller's
/// synchronous policy write; the policy store itself takes no fencing token.
/// A concurrent `SetNamespacePolicy` on another instance stays
/// last-writer-wins.
///
/// Runs before `SetNamespacePolicy` persists a policy. Activating the
/// shadowed candidate needs a passing report measured against the namespace
/// policy that is still active, and is recorded before the write,
/// so a refused or failed audit leaves the policy unchanged. Returns the run
/// to end once the policy is written. Store and audit errors fail closed.
pub(super) fn admit_policy_activation(
    service: &ChiseiServiceImpl,
    actor: &str,
    namespace: &str,
    policy_version: &str,
) -> Result<Option<PolicyShadow>, Status> {
    let Some(report) = service
        .db
        .policy_shadow_report(namespace)
        .map_err(|_| Status::internal("policy shadow unavailable"))?
    else {
        return Ok(None);
    };
    if report.shadow.candidate_version == policy_version {
        if report.shadow.active_version != persisted_policy_version(service, namespace)? {
            return Err(Status::failed_precondition(format!(
                "{}: the report was measured against a namespace policy that is no longer active",
                shadow_domain::REFUSAL_NOT_PASSING
            )));
        }
        report.verdict().map_err(Status::failed_precondition)?;
        let unavailable = |_| Status::internal("policy shadow unavailable");
        let changed = || Status::aborted("policy shadow changed concurrently");
        let claimed_at_ms = chrono::Utc::now().timestamp_millis();
        if !service
            .db
            .claim_policy_shadow_activation(namespace, &report.shadow.shadow_id, claimed_at_ms)
            .map_err(unavailable)?
        {
            return Err(changed());
        }
        record_shadow_decision(
            service,
            actor,
            "policy.shadow_activation",
            &report.shadow,
            "shadowed candidate admitted on a passing report",
        )?;
        // The caller writes the policy right after this, without awaiting.
        if !service
            .db
            .confirm_policy_shadow_activation(
                namespace,
                &report.shadow.shadow_id,
                claimed_at_ms,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(unavailable)?
        {
            return Err(changed());
        }
    }
    Ok(Some(report.shadow))
}

/// Ends the run checked by [`admit_policy_activation`] after the policy is
/// written: the candidate is now active or its baseline changed. A run that a
/// restart replaced meanwhile stays; its pinned baseline no longer matches, so
/// it is not observed again. A crash before this step leaves the same stale
/// run. Failures here are logged, not returned,
/// because the policy is already written.
pub(super) fn end_policy_shadow(service: &ChiseiServiceImpl, actor: &str, shadow: &PolicyShadow) {
    let ended = record_shadow_decision(
        service,
        actor,
        "policy.shadow_stop",
        shadow,
        "namespace policy changed",
    )
    .and_then(|()| {
        service
            .db
            .stop_policy_shadow(&shadow.namespace, Some(&shadow.shadow_id), None)
            .map_err(Status::internal)
    });
    if let Err(error) = ended {
        tracing::warn!(namespace = %shadow.namespace, %error, "policy shadow end failed");
    }
}
