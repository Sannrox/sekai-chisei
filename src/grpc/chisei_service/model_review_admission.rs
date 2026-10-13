//! Model-review default-deny at route admission (#1494).
//! Opt-in model-release evidence for hosted routes (#1396).

use super::*;
use crate::chisei::model_release_evidence::{self, ModelReleaseEvidenceFailure};
use crate::chisei::model_review::{self, AdmissionRefusal};
use crate::db::store::ChiseiRoutingProfileStore;

impl ChiseiServiceImpl {
    pub(super) async fn with_execution_registry<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, Status>>,
        on_refresh_error: impl FnOnce() -> Result<(), String>,
    ) -> Result<T, Status> {
        let registry = match self.refresh_provider_registry_for_resolution().await {
            Ok(registry) => registry,
            Err(status) => {
                on_refresh_error().map_err(Status::internal)?;
                return Err(status);
            }
        };
        crate::provider_profile::with_provider_registry_snapshot(registry, future).await
    }

    pub(super) fn enforce_model_review_admission(
        &self,
        namespace: &str,
        model: &str,
        actor: &str,
    ) -> Result<(), Status> {
        let identity =
            model_review::identity_from_model(model).map_err(Status::failed_precondition)?;
        let region = self
            .policy
            .admission_region(namespace, &identity.provider, &identity.model);
        model_review::admit_enabled_route(&self.db, namespace, &identity, &region, actor)
            .map_err(model_review_denied)
    }

    pub(super) fn review_admits_candidate(&self, namespace: &str, model: &str) -> bool {
        let Ok(identity) = model_review::identity_from_model(model) else {
            return false;
        };
        let region = self
            .policy
            .admission_region(namespace, &identity.provider, &identity.model);
        model_review::route_is_enabled(&self.db, namespace, &identity, &region)
    }

    pub(super) fn hosted_profile_for_model(
        &self,
        namespace: &str,
        model: &str,
    ) -> Result<Option<crate::chisei::routing_profiles::HostedRoutingProfile>, Status> {
        let Ok(runtime) = crate::provider_profile::resolve_provider_id(model) else {
            return Ok(None);
        };
        if !crate::provider_profile::is_hosted_provider(runtime) {
            return Ok(None);
        }
        let stored = self
            .db
            .list_hosted_routing_profiles(namespace)
            .map_err(|_| Status::internal("routing profiles unavailable"))?;
        Ok(crate::chisei::routing_profiles::admissible_hosted_profiles(
            stored,
            &self.config.routing_endpoint_allowlist,
        )
        .into_iter()
        .find(|profile| crate::chisei::routing_profiles::hosted_runtime(profile) == runtime))
    }

    pub(super) fn enforce_model_release_evidence_admission(
        &self,
        namespace: &str,
        model: &str,
        actor: &str,
    ) -> Result<(), Status> {
        let Some(profile) = self.hosted_profile_for_model(namespace, model)? else {
            return Ok(());
        };
        self.enforce_model_release_evidence_for_profile(&profile, model, actor)
    }

    pub(super) fn enforce_model_release_evidence_for_profile(
        &self,
        profile: &crate::chisei::routing_profiles::HostedRoutingProfile,
        model: &str,
        actor: &str,
    ) -> Result<(), Status> {
        model_release_evidence::admit_hosted_runtime_evidence(
            &self.db,
            profile,
            Some(model),
            chrono::Utc::now().timestamp_millis(),
            Some(actor),
        )
        .map(|_| ())
        .map_err(model_release_denied)
    }

    pub(super) fn evidence_admits_candidate(&self, namespace: &str, model: &str) -> bool {
        match self.hosted_profile_for_model(namespace, model) {
            Ok(None) => true,
            Ok(Some(profile)) => model_release_evidence::route_runtime_evidence_allows(
                &self.db,
                &profile,
                model,
                chrono::Utc::now().timestamp_millis(),
            ),
            Err(_) => false,
        }
    }

    pub(super) fn hosted_admission_failure_reason(&self, status: &Status) -> &'static str {
        if ModelReleaseEvidenceFailure::matches_message(status.message()) {
            "model_release_denied"
        } else {
            "hosted_route_unavailable"
        }
    }
}

fn model_review_denied(refusal: AdmissionRefusal) -> Status {
    Status::permission_denied(refusal.message())
}

fn model_release_denied(failure: ModelReleaseEvidenceFailure) -> Status {
    Status::permission_denied(failure.as_str())
}
