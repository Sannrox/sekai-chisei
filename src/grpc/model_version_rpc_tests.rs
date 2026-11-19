//! Model version reads (#3020): a version carries its training run and
//! dataset versions, and a reader without its marking sees it as missing.

use super::*;

pub(super) fn store_version(svc: &SekaiServiceImpl, digest: &str, marking: &str) -> String {
    let column = |name: &str| crate::sekai::model_version::ModelColumn {
        name: name.into(),
        col_type: "float".into(),
    };
    let registration = crate::sekai::model_version::ModelVersionRegistration {
        namespace: "ml".into(),
        model_name: "churn".into(),
        digest: digest.into(),
        adapter_id: "tabular-classifier".into(),
        adapter_version: "1".into(),
        registry_locator: format!("churn/{digest}"),
        contract: crate::sekai::model_version::AdapterContract {
            inputs: vec![crate::sekai::model_version::ModelInput {
                name: "features".into(),
                columns: vec![column("tenure")],
            }],
            output: vec![column("score")],
        },
        run_id: format!("run-{digest}"),
        actor: "trainer".into(),
    };
    let inputs = std::collections::BTreeMap::from([("customers".to_string(), "v4".to_string())]);
    let version = crate::sekai::model_version::ModelVersion::from_run(
        registration,
        "ml",
        marking,
        &inputs,
        1,
    )
    .unwrap();
    svc.db
        .runtime()
        .insert_model_version(&version)
        .unwrap()
        .version_id
}

async fn listed(svc: &SekaiServiceImpl, principal: &str) -> Vec<String> {
    svc.list_model_versions(with_named_principal(
        ListModelVersionsRequest {
            namespace: "ml".into(),
            model_name: "churn".into(),
            ..Default::default()
        },
        principal,
    ))
    .await
    .unwrap()
    .into_inner()
    .versions
    .into_iter()
    .map(|version| version.digest)
    .collect()
}

#[tokio::test]
async fn marked_version_is_missing_for_a_reader_without_clearance() {
    let svc = service();
    store_version(&svc, "sha256:open", "");
    let marked = store_version(&svc, "sha256:marked", "confidential");
    sealed_principal_profile(&svc, "cleared", "confidential");

    let get = |principal: &'static str| {
        svc.get_model_version(with_named_principal(
            GetModelVersionRequest {
                namespace: "ml".into(),
                version_id: marked.clone(),
            },
            principal,
        ))
    };
    let hidden = get("uncleared").await.unwrap_err();
    assert_eq!(hidden.code(), tonic::Code::NotFound);
    assert_eq!(listed(&svc, "uncleared").await, ["sha256:open"]);

    let version = get("cleared").await.unwrap().into_inner().version.unwrap();
    assert_eq!(version.marking, "confidential");
    assert_eq!(version.run_id, "run-sha256:marked");
    assert_eq!(
        version
            .training_inputs
            .iter()
            .map(|input| (input.dataset_id.as_str(), input.version_id.as_str()))
            .collect::<Vec<_>>(),
        [("customers", "v4")]
    );
    let mut both = listed(&svc, "cleared").await;
    both.sort();
    assert_eq!(both, ["sha256:marked", "sha256:open"]);
}

#[tokio::test]
async fn list_pages_by_version_id() {
    let svc = service();
    for digest in ["sha256:a", "sha256:b", "sha256:c"] {
        store_version(&svc, digest, "");
    }
    let page = |token: String| {
        svc.list_model_versions(with_principal(ListModelVersionsRequest {
            namespace: "ml".into(),
            page_size: 2,
            page_token: token,
            ..Default::default()
        }))
    };
    let first = page(String::new()).await.unwrap().into_inner();
    assert_eq!(first.versions.len(), 2);
    let second = page(first.next_page_token).await.unwrap().into_inner();
    assert_eq!(second.versions.len(), 1);
    assert!(second.next_page_token.is_empty());
}

#[tokio::test]
async fn deny_unmarked_namespace_hides_unmarked_versions() {
    let svc = service();
    svc.db
        .runtime()
        .create_object(&domain::Object {
            id: "namespace-ml".into(),
            kind: "namespace".into(),
            name: "ml".into(),
            namespace: "ml".into(),
            external_id: "namespace:ml".into(),
            properties: HashMap::from([(markings::DENY_UNMARKED_PROPERTY.into(), "true".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
    store_version(&svc, "sha256:open", "");
    assert!(listed(&svc, "uncleared").await.is_empty());
}

/// A transform cannot pin a model version its writer may not see, nor one
/// that does not exist; both read as missing (#3074).
#[tokio::test]
async fn model_inputs_refuse_a_hidden_or_missing_version() {
    use crate::sekai::governed_transform::{CONTRACT_VERSION, IsolatedProcessSpec};
    let svc = service();
    let marked = store_version(&svc, "sha256:marked", "confidential");
    sealed_principal_profile(&svc, "cleared", "confidential");
    let transform = |version_id: &str| crate::sekai::governed_transform::GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ml".into(),
        transform_id: "score".into(),
        input_dataset_id: "features".into(),
        output_dataset_id: "scores".into(),
        steps: Vec::new(),
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: Some(IsolatedProcessSpec {
            model_inputs: std::collections::BTreeMap::from([("scorer".into(), version_id.into())]),
            ..Default::default()
        }),
        schedule: None,
        trigger: None,
    };
    let authorize = |principal: &str, version_id: &str| {
        super::model_version_rpc::authorize_model_inputs(
            &svc,
            &[principal.to_string()],
            &transform(version_id),
        )
    };
    let hidden = authorize("uncleared", &marked).unwrap_err();
    assert_eq!(hidden.code(), tonic::Code::NotFound);
    authorize("cleared", &marked).unwrap();
    let missing = authorize("cleared", "mv_missing").unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
}
