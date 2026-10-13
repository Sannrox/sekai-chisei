//! Model-review default-deny at route admission (#1494).

use super::*;
use crate::chisei::model_review::{self, AdmissionRefusal};

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
}

fn model_review_denied(refusal: AdmissionRefusal) -> Status {
    Status::permission_denied(refusal.message())
}
