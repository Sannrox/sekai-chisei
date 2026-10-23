//! Hosted routes for stored embedding specs (#1609): admitted and guarded
//! like hosted execution, so scheduled embedding sends nothing a model call
//! could not.

use super::*;
use crate::chisei::privacy::{DataClass, TaskClass};
use crate::grpc::provider_execution::HostedExecution;
use chisei_provider::embedding::Embedder;

/// Actor recorded on admission and privacy decisions for embedding catch-up.
pub(crate) const EMBEDDING_CATCH_UP_ACTOR: &str = "system:embedding-catch-up";

/// The route embedder, readmitted from live state before every outbound
/// request and every source text it screens.
struct GuardedEmbedder {
    service: Arc<ChiseiServiceImpl>,
    inner: chisei_provider::llm::openai::OpenAiEmbedder,
    namespace: String,
    /// The endpoint the client was built for; a readmission that resolves
    /// to another origin, pinned weights or model patterns refuses.
    endpoint: chisei_provider::provider_profile::HostedEndpoint,
    /// Digest of the credential the client sends; a rotated or rebound
    /// credential refuses, and the next pass builds a new client.
    credential_digest: [u8; 32],
}

fn credential_digest(hosted: &HostedExecution) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(hosted.credential.expose().as_bytes()).into()
}

impl GuardedEmbedder {
    fn readmit(&self) -> Result<DataClass, String> {
        let (hosted, data_class, _) = self
            .service
            .admit_embedding_route(&self.namespace, self.inner.model())
            .map_err(|status| status.message().to_string())?;
        // The model was resolved against these patterns; any change to the
        // admitted endpoint invalidates that resolution.
        if hosted.endpoint.origin != self.endpoint.origin
            || hosted.endpoint.artifact_digest != self.endpoint.artifact_digest
            || hosted.endpoint.model_patterns != self.endpoint.model_patterns
            || credential_digest(&hosted) != self.credential_digest
        {
            return Err("embedding route changed since it was admitted".into());
        }
        Ok(data_class)
    }
}

#[async_trait::async_trait]
impl Embedder for GuardedEmbedder {
    fn model(&self) -> &str {
        self.inner.model()
    }

    fn model_version(&self) -> &str {
        self.inner.model_version()
    }

    fn external(&self) -> bool {
        self.inner.external()
    }

    fn screen(&self, text: &str) -> Result<(), String> {
        let data_class = self.readmit()?;
        let provider = crate::llm::provider_name(self.inner.model());
        let findings = self
            .service
            .leak_findings_for_payload(&self.namespace, provider, data_class, text)
            .map_err(|status| status.message().to_string())?;
        if let Some(refusal) = crate::chisei::privacy::blocking_refusal(&findings) {
            self.service.record_leak_audit(
                "embedding_leak_check",
                EMBEDDING_CATCH_UP_ACTOR,
                provider,
                &findings,
            );
            return Err(refusal.to_string());
        }
        Ok(())
    }

    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        self.readmit()?;
        self.inner.embed(texts).await
    }
}

impl ChiseiServiceImpl {
    /// Admit a stored embedding spec's hosted route from live state, as
    /// hosted execution is admitted: the namespace policy lists the model,
    /// residency and the provider privacy gate pass for the namespace's data
    /// class, the live provider registry resolves the model (the profile's
    /// model patterns and lifecycle), and the route, credential and model
    /// review admit it. Returns the route, that data class and the upstream
    /// model name.
    fn admit_embedding_route(
        &self,
        namespace: &str,
        model: &str,
    ) -> Result<(HostedExecution, DataClass, String), Status> {
        let policy = self.policy.effective_policy(namespace);
        if !policy
            .as_ref()
            .is_some_and(|policy| policy.allowed_models.iter().any(|allowed| allowed == model))
        {
            return Err(Status::failed_precondition(
                "embedding model is not allowed by the namespace policy",
            ));
        }
        let data_class = self.data_class(policy.as_ref());
        let provider = crate::llm::provider_name(model);
        // Fail closed before any provider contact, as for execution.
        self.policy
            .enforce_residency(namespace, provider, model, data_class.as_str())
            .map_err(Status::permission_denied)?;
        let safe = crate::chisei::privacy::safe_providers(&self.config);
        if !crate::chisei::privacy::external_allowed(data_class, TaskClass::Private)
            && !crate::chisei::privacy::provider_safe_to_send(provider, &safe)
        {
            self.record_privacy_audit(
                "blocked",
                EMBEDDING_CATCH_UP_ACTOR,
                provider,
                data_class,
                TaskClass::Private,
                "embedding_unsafe_provider",
            );
            return Err(Status::failed_precondition(
                crate::chisei::privacy::gate_reason(data_class, TaskClass::Private, provider),
            ));
        }
        // Model review identifies a hosted model by the artifact its route
        // pins, so admission runs with the live endpoint in the registry.
        let profile = self
            .hosted_profile_for_model(namespace, model)?
            .ok_or_else(|| Status::failed_precondition("routing profile unavailable"))?;
        let registry = crate::provider_profile::provider_registry_snapshot().with_hosted_endpoints(
            &crate::chisei::routing_profiles::hosted_endpoints(std::slice::from_ref(&profile)),
        );
        // Resolution applies the profile's model patterns and the provider
        // and model lifecycle; review alone would fall back past a refusal.
        let upstream_model = registry
            .resolve_model(model)
            .map_err(Status::failed_precondition)?
            .upstream_model;
        let hosted =
            crate::provider_profile::with_provider_registry_snapshot_sync(registry, || {
                self.admit_hosted_execution(namespace, model, false, EMBEDDING_CATCH_UP_ACTOR)
            })?;
        Ok((hosted, data_class, upstream_model))
    }

    /// Embedder for a stored embedding spec's hosted route: admitted by
    /// [`Self::admit_embedding_route`] and readmitted before every request. The route is external unless its
    /// origin is loopback; vectors are versioned by the weights digest it pins.
    pub(crate) fn hosted_embedder(
        self: &Arc<Self>,
        namespace: &str,
        model: &str,
    ) -> Result<Box<dyn Embedder>, Status> {
        let (hosted, _, upstream_model) = self.admit_embedding_route(namespace, model)?;
        let inner = chisei_provider::llm::openai::OpenAiEmbedder::new(
            hosted.credential.expose(),
            &hosted.endpoint.origin,
            model,
            &upstream_model,
            hosted
                .endpoint
                .artifact_digest
                .as_deref()
                .unwrap_or_default(),
            !crate::chisei::routing_profiles::is_loopback_url(&hosted.endpoint.origin),
        );
        Ok(Box::new(GuardedEmbedder {
            service: self.clone(),
            inner,
            namespace: namespace.into(),
            credential_digest: credential_digest(&hosted),
            endpoint: hosted.endpoint,
        }))
    }
}
