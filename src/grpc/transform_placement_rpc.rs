//! Experimental RegisterTransformRuntime RPC (#1733): placement labels a
//! worker registers for its runtime id.
//!
//! An isolated-process transform may declare `requires`. Listing and claiming
//! read the claiming runtime's registered labels inside the claim transaction
//! and skip runs whose every required pair the labels do not carry, so a stale
//! listing or a targeted claim cannot bypass placement. A runtime that never
//! registered has no labels and sees only runs without requirements.
//! Each registration is recorded on the decision ledger in the transaction
//! that stores it; a refused registration writes nothing, as for other
//! governance calls.

use super::*;
use crate::sekai::governed_transform::placement_labels;
use std::collections::BTreeMap;

pub(super) async fn register_transform_runtime(
    service: &SekaiServiceImpl,
    req: Request<RegisterTransformRuntimeRequest>,
) -> Result<Response<RegisterTransformRuntimeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    check_team_namespace(service.db.runtime(), &principals, &input.namespace, true)?;
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(
            service.db.runtime(),
            Some(context),
            &input.namespace,
            true,
        )?;
    }
    let labels = labels_from_proto("labels", &input.labels)?;
    let runtime = service
        .db
        .runtime()
        .register_transform_runtime(
            &input.namespace,
            &input.runtime_id,
            &labels,
            principals.first().map(String::as_str).unwrap_or_default(),
            now_millis(),
        )
        .map_err(Status::invalid_argument)?;
    Ok(Response::new(RegisterTransformRuntimeResponse {
        runtime: Some(TransformRuntime {
            namespace: runtime.namespace,
            runtime_id: runtime.runtime_id,
            labels: labels_to_proto(&runtime.labels),
            updated_at_ms: runtime.updated_at_ms,
        }),
    }))
}

/// Validated label set from the wire; a repeated key is refused.
pub(super) fn labels_from_proto(
    field: &str,
    labels: &[TransformLabel],
) -> Result<BTreeMap<String, String>, Status> {
    placement_labels(
        field,
        labels
            .iter()
            .map(|label| (label.key.clone(), label.value.clone())),
    )
    .map_err(|error| Status::invalid_argument(error.message()))
}

pub(super) fn labels_to_proto(labels: &BTreeMap<String, String>) -> Vec<TransformLabel> {
    labels
        .iter()
        .map(|(key, value)| TransformLabel {
            key: key.clone(),
            value: value.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, ISOLATED_CLASS};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        let db = RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new(":memory:").unwrap(),
        ));
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
            db,
        )))
    }

    fn as_admin<T>(payload: T) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::from_static("local"));
        req
    }

    fn label(key: &str, value: &str) -> TransformLabel {
        TransformLabel {
            key: key.into(),
            value: value.into(),
        }
    }

    fn isolated(transform_id: &str, requires: Vec<TransformLabel>) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: transform_id.into(),
            input_dataset_id: "in".into(),
            output_dataset_id: format!("out-{transform_id}"),
            profile: ISOLATED_CLASS.into(),
            code: "SELECT * FROM input".into(),
            engine: "python".into(),
            runtime_image: "runner:1".into(),
            requires,
            ..Default::default()
        }
    }

    /// Seeds the input, puts the transform over the RPC and admits one run.
    async fn admit(svc: &SekaiServiceImpl, transform: GovernedTransform) -> String {
        let runtime = svc.db.runtime();
        for id in ["in".to_string(), transform.output_dataset_id.clone()] {
            let _ = runtime.create_dataset(&Dataset {
                id: id.clone(),
                name: id,
                columns: vec![ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            });
        }
        runtime
            .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
            .unwrap();
        let transform_id = transform.transform_id.clone();
        svc.put_governed_transform(as_admin(PutGovernedTransformRequest {
            transform: Some(transform),
        }))
        .await
        .unwrap();
        runtime
            .run_governed_transform("ops", &transform_id, false, 20)
            .unwrap()
            .run_id
    }

    async fn register(svc: &SekaiServiceImpl, runtime_id: &str, labels: Vec<TransformLabel>) {
        svc.register_transform_runtime(as_admin(RegisterTransformRuntimeRequest {
            namespace: "ops".into(),
            runtime_id: runtime_id.into(),
            labels,
        }))
        .await
        .unwrap();
    }

    async fn listed(svc: &SekaiServiceImpl, runtime_id: &str) -> Vec<String> {
        svc.list_claimable_transform_work(as_admin(ListClaimableTransformWorkRequest {
            namespace: "ops".into(),
            runtime_id: runtime_id.into(),
            limit: 10,
        }))
        .await
        .unwrap()
        .into_inner()
        .work
        .into_iter()
        .map(|work| work.run_id)
        .collect()
    }

    async fn claim(
        svc: &SekaiServiceImpl,
        runtime_id: &str,
        run_id: &str,
    ) -> Result<String, Status> {
        svc.claim_transform_work(as_admin(ClaimTransformWorkRequest {
            namespace: "ops".into(),
            runtime_id: runtime_id.into(),
            run_id: run_id.into(),
            ttl_ms: 60_000,
        }))
        .await
        .map(|response| response.into_inner().work.unwrap().run_id)
    }

    #[tokio::test]
    async fn gpu_run_is_hidden_from_and_refused_to_a_runtime_without_the_label() {
        let svc = service();
        let run_id = admit(&svc, isolated("gpu", vec![label("accelerator", "gpu")])).await;
        register(&svc, "cpu-runner", vec![label("accelerator", "cpu")]).await;
        register(
            &svc,
            "gpu-runner",
            vec![label("accelerator", "gpu"), label("zone", "a")],
        )
        .await;

        assert!(listed(&svc, "cpu-runner").await.is_empty());
        assert!(listed(&svc, "never-registered").await.is_empty());
        // A targeted claim, as from a stale or borrowed listing, is refused too.
        let refused = claim(&svc, "cpu-runner", &run_id).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::NotFound);
        assert_eq!(
            claim(&svc, "never-registered", "")
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        // The refused run stays queued and untouched for a runtime that may claim it.
        let run = svc
            .db
            .runtime()
            .get_governed_transform_run(&run_id)
            .unwrap()
            .unwrap();
        assert_eq!(run.dispatch_status, "pending");

        assert_eq!(listed(&svc, "gpu-runner").await, vec![run_id.clone()]);
        assert_eq!(claim(&svc, "gpu-runner", "").await.unwrap(), run_id);
    }

    #[tokio::test]
    async fn unconstrained_runs_stay_claimable_by_any_runtime() {
        let svc = service();
        let run_id = admit(&svc, isolated("plain", Vec::new())).await;
        assert_eq!(listed(&svc, "never-registered").await, vec![run_id.clone()]);
        assert_eq!(claim(&svc, "never-registered", "").await.unwrap(), run_id);
    }

    #[tokio::test]
    async fn a_registration_update_applies_at_the_next_claim() {
        let svc = service();
        let run_id = admit(&svc, isolated("gpu", vec![label("accelerator", "gpu")])).await;
        register(&svc, "runner", Vec::new()).await;
        assert!(claim(&svc, "runner", "").await.is_err());
        register(&svc, "runner", vec![label("accelerator", "gpu")]).await;
        assert_eq!(claim(&svc, "runner", "").await.unwrap(), run_id);
    }

    #[tokio::test]
    async fn labels_and_requires_are_validated() {
        let svc = service();
        for labels in [
            vec![label("accelerator", "gpu"), label("accelerator", "cpu")],
            vec![label("", "gpu")],
            vec![label("accelerator", "g p u")],
            vec![label("-accelerator", "gpu")],
            vec![label("accelerator", &"g".repeat(64))],
        ] {
            let error = svc
                .register_transform_runtime(as_admin(RegisterTransformRuntimeRequest {
                    namespace: "ops".into(),
                    runtime_id: "runner".into(),
                    labels,
                }))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        // Refused registrations leave no ledger record.
        let recorded = svc
            .db
            .runtime()
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some(crate::sekai::governed_transform::TRANSFORM_RUNTIME_REGISTERED.into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert!(recorded.is_empty());
        let duplicate = svc
            .put_governed_transform(as_admin(PutGovernedTransformRequest {
                transform: Some(isolated(
                    "dup",
                    vec![label("accelerator", "gpu"), label("accelerator", "gpu")],
                )),
            }))
            .await
            .unwrap_err();
        assert_eq!(duplicate.code(), tonic::Code::InvalidArgument);
        let in_process = svc
            .put_governed_transform(as_admin(PutGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    contract_version: CONTRACT_VERSION.into(),
                    namespace: "ops".into(),
                    transform_id: "proj".into(),
                    input_dataset_id: "in".into(),
                    output_dataset_id: "out".into(),
                    steps: vec![TransformStep {
                        kind: "project".into(),
                        columns: vec!["id".into()],
                        ..Default::default()
                    }],
                    requires: vec![label("accelerator", "gpu")],
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(
            in_process.message(),
            "requires applies only to the isolated_process profile"
        );
    }

    /// An isolated-process put needs code; code on any other profile is
    /// refused rather than dropped (#1605).
    #[tokio::test]
    async fn isolated_code_is_required_and_profile_bound() {
        let svc = service();
        let mut missing = isolated("nocode", Vec::new());
        missing.code.clear();
        let error = svc
            .put_governed_transform(as_admin(PutGovernedTransformRequest {
                transform: Some(missing),
            }))
            .await
            .unwrap_err();
        assert_eq!(
            error.message(),
            "an isolated_process transform requires code for its engine"
        );
        let in_process = svc
            .put_governed_transform(as_admin(PutGovernedTransformRequest {
                transform: Some(GovernedTransform {
                    contract_version: CONTRACT_VERSION.into(),
                    namespace: "ops".into(),
                    transform_id: "proj".into(),
                    input_dataset_id: "in".into(),
                    output_dataset_id: "out".into(),
                    steps: vec![TransformStep {
                        kind: "project".into(),
                        columns: vec!["id".into()],
                        ..Default::default()
                    }],
                    code: "SELECT 1".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(
            in_process.message(),
            "code applies only to the isolated_process profile"
        );
    }

    #[tokio::test]
    async fn registration_requires_credential_admin() {
        let svc = service();
        let mut req = Request::new(RegisterTransformRuntimeRequest {
            namespace: "ops".into(),
            runtime_id: "runner".into(),
            labels: vec![label("accelerator", "gpu")],
        });
        req.metadata_mut()
            .insert("x-principal", MetadataValue::from_static("tester"));
        let denied = svc.register_transform_runtime(req).await.unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    }
}
