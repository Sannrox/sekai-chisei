//! The `external_effect` kind of the claimable-work family (ADR 0148,
//! ADR 0149): an admitted Action's pending `external_mutate` effect, routed
//! to the Source that owns its record.
//!
//! Every call needs what claiming Source sync work needs, and the caller
//! must be cleared for the Action's markings, since the work carries its
//! parameters. Placement matches the labels the runtime registered with
//! `RegisterTransformRuntime`.

use super::*;
use crate::sekai::external_effect::{self, EffectError, EffectOutcome, ExternalEffectWork as Work};
use crate::sekai::work_claim::{ClaimError, Fence};

fn effect_status(error: EffectError) -> Status {
    match error {
        EffectError::NotFound => Status::not_found("no external effect is claimable"),
        EffectError::Invalid(message) => Status::invalid_argument(message),
        EffectError::Claim(ClaimError::FenceLost) => {
            Status::failed_precondition("claim is not current")
        }
        EffectError::Claim(error) => Status::failed_precondition(error.to_string()),
        _ => Status::internal("action effect store unavailable"),
    }
}

impl SekaiServiceImpl {
    fn external_effect_work<T: std::any::Any>(
        &self,
        req: &Request<T>,
        work: Work,
    ) -> Result<ExternalEffectWork, Status> {
        rpc_actions::require_cleared_for_effect(self, &caller_principals(req), &work.effect)?;
        Ok(ExternalEffectWork {
            effect: Some(to_proto_action_effect(&work.effect)),
            source: Some(source_rpc::source_to_proto(work.source)),
            parameters_json: work.parameters_json,
        })
    }

    pub(super) fn list_claimable_external_effects<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        runtime_id: &str,
        limit: i32,
        options: ExternalEffectWorkOptions,
    ) -> Result<Vec<ExternalEffectWork>, Status> {
        self.source_sync_runtime(req, namespace)?;
        let labels = self.runtime_labels(namespace, runtime_id)?;
        let limit = usize::try_from(limit)
            .ok()
            .filter(|limit| *limit > 0)
            .unwrap_or(50)
            .min(500);
        let implements = |source: &crate::sekai::source::Source| {
            options.connector_types.is_empty()
                || options.connector_types.iter().any(|ty| {
                    ty.name == source.spec.connector_type
                        && ty.version == source.spec.connector_version
                })
        };
        let listed = external_effect::list_claimable(
            self.db.runtime(),
            namespace,
            &labels,
            now_millis(),
            limit,
            implements,
        )
        .map_err(|_| Status::internal("action effect store unavailable"))?;
        // Work the caller is not cleared for is left to a runtime that is.
        Ok(listed
            .into_iter()
            .filter_map(|work| self.external_effect_work(req, work).ok())
            .collect())
    }

    pub(super) fn claim_external_effect<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        runtime_id: &str,
        effect_id: &str,
        ttl_ms: i64,
    ) -> Result<ExternalEffectWork, Status> {
        self.source_sync_runtime(req, namespace)?;
        let labels = self.runtime_labels(namespace, runtime_id)?;
        let principals = caller_principals(req);
        if !effect_id.is_empty() {
            let effect = self
                .db
                .runtime()
                .get_action_effect(effect_id)
                .map_err(|_| Status::internal("action effect store unavailable"))?
                .filter(|effect| effect.namespace == namespace)
                .ok_or_else(|| effect_status(EffectError::NotFound))?;
            rpc_actions::require_cleared_for_effect(self, &principals, &effect)?;
        }
        let work = external_effect::claim(
            self.db.runtime(),
            namespace,
            effect_id,
            runtime_id,
            principals.first().map(String::as_str).unwrap_or_default(),
            &labels,
            ttl_ms,
            now_millis(),
        )
        .map_err(effect_status)?;
        self.external_effect_work(req, work)
    }

    pub(super) fn heartbeat_external_effect<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        effect_id: &str,
        fence: Fence<'_>,
        ttl_ms: i64,
    ) -> Result<ExternalEffectWork, Status> {
        self.source_sync_runtime(req, namespace)?;
        let labels = self.runtime_labels(namespace, fence.owner)?;
        let work = external_effect::heartbeat(
            self.db.runtime(),
            namespace,
            effect_id,
            fence,
            &labels,
            ttl_ms,
            now_millis(),
        )
        .map_err(effect_status)?;
        self.external_effect_work(req, work)
    }

    /// `AckWork` for an external effect: `completed`, `failed` or
    /// `outcome_unknown`, each final.
    pub(super) fn ack_external_effect<T: std::any::Any>(
        &self,
        req: &Request<T>,
        namespace: &str,
        effect_id: &str,
        fence: Fence<'_>,
        outcome: &str,
        reason: &str,
    ) -> Result<ActionEffect, Status> {
        self.source_sync_runtime(req, namespace)?;
        let outcome = EffectOutcome::from_wire_name(outcome).ok_or_else(|| {
            Status::invalid_argument(
                "an external effect is acknowledged as completed, failed or outcome_unknown",
            )
        })?;
        external_effect::acknowledge(
            self.db.runtime(),
            namespace,
            effect_id,
            fence,
            outcome,
            reason,
            now_millis(),
        )
        .map(|effect| to_proto_action_effect(&effect))
        .map_err(effect_status)
    }
}
