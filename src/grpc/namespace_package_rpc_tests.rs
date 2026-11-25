//! Namespace packages (#3093) through the gRPC service: the export lists
//! what the caller may read with digests, counts the rest by kind, carries no
//! data, and refuses a selected dataset it cannot package by name.

use super::namespace_package_rpc::export_namespace_package_as;
use super::rpc_definition_package::{PackageSigner, package_keyring_from_json};
use super::*;
use crate::sekai::namespace_package::{
    self as package_domain, EntryRole, KIND_DATASET_VERSION, KIND_DEFINITION_PACKAGE, WithheldCount,
};

const NAMESPACE: &str = "pkg-ns";

fn signer() -> PackageSigner {
    PackageSigner {
        identity: "plane-a".into(),
        key_id: "k1".into(),
        key: ed25519_dalek::SigningKey::from_bytes(&[5; 32]),
    }
}

/// Binds a dataset to a new object in `namespace`; `reader` alone may read it.
fn bound_dataset(svc: &SekaiServiceImpl, id: &str, namespace: &str, reader: &str) {
    let object_id = format!("{id}-binding");
    svc.db
        .runtime()
        .create_object(&crate::domain::Object {
            id: object_id.clone(),
            kind: "widget".into(),
            name: "binding".into(),
            namespace: namespace.into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    grant_object_role(svc, &object_id, reader, security::Role::Viewer);
    svc.db
        .runtime()
        .create_dataset(&crate::sekai::dataset::Dataset {
            id: id.into(),
            name: id.into(),
            columns: vec![crate::sekai::dataset::ColumnDef {
                name: "title".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id,
            created: 1,
            partition_keys: Vec::new(),
        })
        .unwrap();
}

/// Ticket and Incident published in `NAMESPACE`; only Ticket is readable by
/// `tester`. `tickets` holds a row; `elsewhere` and `hidden` cannot be packaged.
async fn fixture(svc: &SekaiServiceImpl) {
    let member = |id: &str| DefinitionMemberInput {
        member_kind: "object_type".into(),
        member_id: id.into(),
        definition_json: format!(
            r#"{{"name":"{id}","properties":["title"],"lint_suppressions":[{{"rule":"orphan_object_type","reason":"test fixture"}}]}}"#
        ),
        member_digest: String::new(),
    };
    let parent = seed_definition_parent(svc, NAMESPACE);
    publish_definition_history_entry(
        svc,
        NAMESPACE,
        &parent.revision_digest,
        "pkg-1",
        "pkg-cs-1",
        vec![member("Ticket"), member("Incident")],
    )
    .await;
    grant_object_role(
        svc,
        &definition_member_object_id("object_type", "Incident"),
        "someone-else",
        security::Role::Viewer,
    );
    bound_dataset(svc, "tickets", NAMESPACE, "tester");
    svc.db
        .runtime()
        .append_rows(
            "tickets",
            &[[("title".to_string(), "row-data-marker".to_string())].into()],
        )
        .unwrap();
    bound_dataset(svc, "elsewhere", "other-ns", "tester");
    bound_dataset(svc, "hidden", NAMESPACE, "someone-else");
}

fn export(
    svc: &SekaiServiceImpl,
    name: &str,
    dataset_ids: &[&str],
) -> Result<ExportNamespacePackageResponse, Status> {
    export_namespace_package_as(
        svc,
        with_principal(ExportNamespacePackageRequest {
            namespace: NAMESPACE.into(),
            package_name: name.into(),
            package_version: 1,
            dataset_ids: dataset_ids.iter().map(|id| id.to_string()).collect(),
        }),
        &signer(),
    )
    .map(Response::into_inner)
}

#[tokio::test]
async fn export_lists_readable_resources_and_counts_the_rest_by_kind() {
    let svc = service();
    fixture(&svc).await;
    let exported = export(&svc, "support-desk", &["tickets"]).unwrap();

    let public_key: String = signer()
        .key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let keyring = package_keyring_from_json(&format!(
        r#"[{{"identity":"plane-a","key_id":"k1","public_key":"{public_key}"}}]"#
    ))
    .unwrap();
    let envelope =
        package_domain::verify_namespace_envelope(&exported.envelope_json, &keyring).unwrap();
    let package = envelope.package;
    assert_eq!(package.package_digest, exported.package_digest);
    assert_eq!(package.ontology_digest, exported.ontology_digest);
    let entries: Vec<_> = package
        .entries
        .iter()
        .map(|entry| (entry.kind.as_str(), entry.id.as_str(), entry.role))
        .collect();
    assert_eq!(
        entries,
        [
            (KIND_DATASET_VERSION, "tickets", EntryRole::Output),
            (KIND_DEFINITION_PACKAGE, "definitions", EntryRole::Output),
        ]
    );
    // Incident is counted, never named; no row leaves the plane.
    assert_eq!(
        package.withheld,
        [WithheldCount {
            kind: "object_type".into(),
            count: 1
        }]
    );
    assert!(!exported.envelope_json.contains("Incident"));
    assert!(!exported.envelope_json.contains("row-data-marker"));
    assert_eq!(envelope.provenance.source_namespace, NAMESPACE);
}

#[tokio::test]
async fn a_dataset_the_caller_cannot_package_is_refused_by_name() {
    let svc = service();
    fixture(&svc).await;
    // Missing and unreadable are refused alike.
    for id in ["hidden", "missing"] {
        let refused = export(&svc, "desk", &["tickets", id]).unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);
        assert_eq!(refused.message(), format!("dataset {id} is not readable"));
    }
    let refused = export(&svc, "desk", &["elsewhere"]).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused.message().contains("dataset elsewhere"),
        "{}",
        refused.message()
    );

    let refused = export(&svc, "Desk", &[]).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
}
