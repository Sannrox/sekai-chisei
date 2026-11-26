//! Namespace packages (#3093) through the gRPC service: the export lists
//! what the caller may read with digests, counts the rest by kind, carries no
//! data, and refuses a selected dataset it cannot package by name. Install
//! checks everything before its first write, reproduces the digests once the
//! definitions proposal merges, and changes nothing the second time. A later
//! version upgrades what the installation created and refuses what changed
//! outside it.

use super::namespace_package_rpc::{export_namespace_package_as, install_namespace_package_with};
use super::rpc_definition_package::{PackageSigner, package_keyring_from_json};
use super::*;
use crate::sekai::namespace_package::{
    self as package_domain, EntryRole, KIND_DATASET_VERSION, KIND_DEFINITION_PACKAGE, WithheldCount,
};

const NAMESPACE: &str = "pkg-ns";
const TARGET: &str = "pkg-target";

fn signer() -> PackageSigner {
    PackageSigner {
        identity: "plane-a".into(),
        key_id: "k1".into(),
        key: ed25519_dalek::SigningKey::from_bytes(&[5; 32]),
    }
}

/// Binds a dataset to a new object in `namespace`; `reader` alone may read it.
fn bound_dataset(svc: &SekaiServiceImpl, id: &str, namespace: &str, reader: &str) {
    bound_dataset_with(svc, id, namespace, reader, &[("title", "public")]);
}

/// As [`bound_dataset`], with string columns of these classifications.
fn bound_dataset_with(
    svc: &SekaiServiceImpl,
    id: &str,
    namespace: &str,
    reader: &str,
    columns: &[(&str, &str)],
) {
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
            columns: columns
                .iter()
                .map(|(name, classification)| crate::sekai::dataset::ColumnDef {
                    name: name.to_string(),
                    col_type: "string".into(),
                    classification: classification.to_string(),
                })
                .collect(),
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
            content_dataset_ids: Vec::new(),
        }),
        &signer(),
    )
    .map(Response::into_inner)
}

/// Export with rows for `content` of `dataset_ids`.
fn export_with_content(
    svc: &SekaiServiceImpl,
    dataset_ids: &[&str],
    content: &[&str],
) -> Result<ExportNamespacePackageResponse, Status> {
    export_version(svc, 1, dataset_ids, content)
}

/// As [`export_with_content`], as `version` of the package.
fn export_version(
    svc: &SekaiServiceImpl,
    version: u32,
    dataset_ids: &[&str],
    content: &[&str],
) -> Result<ExportNamespacePackageResponse, Status> {
    export_namespace_package_as(
        svc,
        with_principal(ExportNamespacePackageRequest {
            namespace: NAMESPACE.into(),
            package_name: "support-desk".into(),
            package_version: version,
            dataset_ids: dataset_ids.iter().map(|id| id.to_string()).collect(),
            content_dataset_ids: content.iter().map(|id| id.to_string()).collect(),
        }),
        &signer(),
    )
    .map(Response::into_inner)
}

fn grant_export_to_tester(svc: &SekaiServiceImpl) {
    crate::sekai::data_export::grant_export(
        svc.db.runtime(),
        NAMESPACE,
        "tester",
        "package content test",
        "root",
        1,
    )
    .unwrap();
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

fn keyring() -> crate::shomei::TrustedKeyring {
    let public_key: String = signer()
        .key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    package_keyring_from_json(&format!(
        r#"[{{"identity":"plane-a","key_id":"k1","public_key":"{public_key}"}}]"#
    ))
    .unwrap()
}

/// An object in [`TARGET`] for installed datasets to bind to.
fn target_object(svc: &SekaiServiceImpl, id: &str) {
    svc.db
        .runtime()
        .create_object(&crate::domain::Object {
            id: id.into(),
            kind: "widget".into(),
            name: "binding".into(),
            namespace: TARGET.into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
}

fn install(
    svc: &SekaiServiceImpl,
    envelope_json: &str,
    datasets: &[(&str, &str, &str)],
) -> Result<NamespacePackageInstallation, Status> {
    install_namespace_package_with(
        svc,
        with_named_principal(
            InstallNamespacePackageRequest {
                namespace: TARGET.into(),
                envelope_json: envelope_json.into(),
                datasets: datasets
                    .iter()
                    .map(|(entry, dataset_id, object_id)| {
                        (
                            entry.to_string(),
                            NamespacePackageDatasetTarget {
                                dataset_id: dataset_id.to_string(),
                                object_id: object_id.to_string(),
                            },
                        )
                    })
                    .collect(),
            },
            "root",
        ),
        &keyring(),
    )
    .map(|response| response.into_inner().installation.unwrap())
}

async fn installation(
    svc: &SekaiServiceImpl,
    package_name: &str,
) -> Result<NamespacePackageInstallation, Status> {
    svc.get_namespace_package_installation(with_named_principal(
        GetNamespacePackageInstallationRequest {
            namespace: TARGET.into(),
            package_name: package_name.into(),
        },
        "root",
    ))
    .await
    .map(|response| response.into_inner().installation.unwrap())
}

/// Approves and merges an installation's definitions proposal in [`TARGET`].
async fn merge(svc: &SekaiServiceImpl, proposal_id: &str) {
    let proposal = svc
        .db
        .runtime()
        .get_definition_proposal(TARGET, proposal_id)
        .unwrap()
        .unwrap();
    svc.approve_definition_proposal(with_named_principal(
        ApproveDefinitionProposalRequest {
            namespace: TARGET.into(),
            proposal_id: proposal_id.into(),
            idempotency_key: format!("{proposal_id}-approve"),
        },
        "root",
    ))
    .await
    .unwrap();
    svc.merge_definition_proposal(with_named_principal(
        MergeDefinitionProposalRequest {
            namespace: TARGET.into(),
            proposal_id: proposal_id.into(),
            expected_published_digest: proposal.base_digest,
            idempotency_key: format!("{proposal_id}-merge"),
        },
        "root",
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn install_reproduces_the_package_once_its_definitions_merge_and_only_once() {
    let svc = service();
    fixture(&svc).await;
    let exported = export(&svc, "support-desk", &["tickets"]).unwrap();
    target_object(&svc, "desk-binding");

    let installed = install(
        &svc,
        &exported.envelope_json,
        &[("tickets", "desk-tickets", "desk-binding")],
    )
    .unwrap();
    assert_eq!(installed.status, "pending_definitions");
    assert_eq!(installed.package_digest, exported.package_digest);
    assert_eq!(installed.source_namespace, NAMESPACE);
    // The dataset is created bound in the target, with the schema digest and
    // no rows.
    let dataset = svc
        .db
        .runtime()
        .get_dataset("desk-tickets")
        .unwrap()
        .unwrap();
    assert_eq!(dataset.object_id, "desk-binding");
    let source = svc.db.runtime().get_dataset("tickets").unwrap().unwrap();
    assert_eq!(
        package_domain::DatasetDocument::of(&dataset).schema_digest(),
        package_domain::DatasetDocument::of(&source).schema_digest()
    );
    assert!(
        svc.db
            .runtime()
            .query_rows("desk-tickets", &Default::default())
            .unwrap()
            .is_empty()
    );

    // The definitions go through the target's normal review.
    merge(&svc, &installed.proposal_id).await;
    let merged = installation(&svc, "support-desk").await.unwrap();
    assert_eq!(merged.status, "installed");

    // The same package again changes nothing.
    let again = install(
        &svc,
        &exported.envelope_json,
        &[("tickets", "desk-tickets", "desk-binding")],
    )
    .unwrap();
    assert_eq!(again, merged);
}

#[tokio::test]
async fn install_refuses_a_tampered_or_unmapped_package_before_any_write() {
    let svc = service();
    fixture(&svc).await;
    let exported = export(&svc, "support-desk", &["tickets"]).unwrap();
    target_object(&svc, "desk-binding");
    let mapped = [("tickets", "desk-tickets", "desk-binding")];

    let tampered = exported.envelope_json.replace("Ticket", "Tickey");
    assert_ne!(tampered, exported.envelope_json);
    let refused = install(&svc, &tampered, &mapped).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused
            .message()
            .starts_with(package_domain::REFUSAL_TAMPERED),
        "{}",
        refused.message()
    );
    let refused = install(&svc, &exported.envelope_json, &[]).unwrap_err();
    assert_eq!(
        refused.message(),
        "entry dataset_version/tickets is not mapped to a dataset"
    );
    let refused = install(
        &svc,
        &exported.envelope_json,
        &[mapped[0], ("other", "x", "desk-binding")],
    )
    .unwrap_err();
    assert_eq!(
        refused.message(),
        "package has no entry dataset_version/other"
    );
    let refused = install(
        &svc,
        &exported.envelope_json,
        &[("tickets", "desk-tickets", "tickets-binding")],
    )
    .unwrap_err();
    assert!(
        refused.message().contains("dataset_version/tickets"),
        "{}",
        refused.message()
    );

    // None of them wrote anything.
    assert_eq!(
        installation(&svc, "support-desk").await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    assert!(
        svc.db
            .runtime()
            .get_dataset("desk-tickets")
            .unwrap()
            .is_none()
    );
    assert!(
        svc.db
            .runtime()
            .get_published_definition_revision(TARGET)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn an_input_installs_only_when_mapped_to_a_dataset_of_its_schema() {
    let svc = service();
    fixture(&svc).await;
    let source = svc.db.runtime().get_dataset("tickets").unwrap().unwrap();
    let package = package_domain::build_namespace_package(
        "with-input",
        1,
        &crate::sekai::definition_package::build_package(Vec::<(String, String, String)>::new())
            .unwrap(),
        &[],
        std::slice::from_ref(&source),
        Default::default(),
    )
    .unwrap();
    let envelope = package_domain::sign_namespace_package(
        package,
        crate::sekai::definition_package::PackageProvenance {
            source_namespace: NAMESPACE.into(),
            source_revision_digest: String::new(),
            exported_at_ms: 1,
        },
        "plane-a",
        "k1",
        &signer().key,
    )
    .unwrap();
    let envelope_json = serde_json::to_string(&envelope).unwrap();
    // Same shape under another name, and a different shape, both in TARGET.
    bound_dataset(&svc, "local-tickets", TARGET, "root");
    target_object(&svc, "other-binding");
    svc.db
        .runtime()
        .create_dataset(&crate::sekai::dataset::Dataset {
            id: "other-shape".into(),
            name: "other".into(),
            columns: Vec::new(),
            object_id: "other-binding".into(),
            created: 1,
            partition_keys: vec![],
        })
        .unwrap();

    let refused = install(&svc, &envelope_json, &[("tickets", "other-shape", "")]).unwrap_err();
    assert_eq!(
        refused.message(),
        "entry dataset_version/tickets: dataset other-shape does not match its schema"
    );
    let installed = install(&svc, &envelope_json, &[("tickets", "local-tickets", "")]).unwrap();
    // No definitions to review, so it is installed at once.
    assert_eq!(installed.status, "installed");
    assert!(installed.proposal_id.is_empty());
    assert_eq!(installed.resources.len(), 1);
    assert_eq!(installed.resources[0].role, "input");
    assert_eq!(installed.resources[0].resource_id, "local-tickets");
}

#[tokio::test]
async fn opted_in_rows_install_as_one_new_version_and_only_once() {
    let svc = service();
    fixture(&svc).await;
    grant_export_to_tester(&svc);
    let exported = export_with_content(&svc, &["tickets"], &["tickets"]).unwrap();
    assert!(exported.envelope_json.contains("row-data-marker"));
    target_object(&svc, "desk-binding");
    let mapped = [("tickets", "desk-tickets", "desk-binding")];

    install(&svc, &exported.envelope_json, &mapped).unwrap();
    let versions = || {
        svc.db
            .runtime()
            .list_dataset_versions("desk-tickets")
            .unwrap()
            .len()
    };
    let titles = || {
        svc.db
            .runtime()
            .query_rows("desk-tickets", &Default::default())
            .unwrap()
            .into_iter()
            .map(|row| row["title"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(versions(), 1);
    assert_eq!(titles(), ["row-data-marker"]);

    // Reinstalling the same package appends nothing.
    install(&svc, &exported.envelope_json, &mapped).unwrap();
    assert_eq!(versions(), 1);
    assert_eq!(titles(), ["row-data-marker"]);
}

#[tokio::test]
async fn a_retry_finding_other_rows_in_its_dataset_is_refused_by_name() {
    let svc = service();
    fixture(&svc).await;
    grant_export_to_tester(&svc);
    let exported = export_with_content(&svc, &["tickets"], &["tickets"]).unwrap();
    target_object(&svc, "desk-binding");
    // A crash left the dataset created; someone then wrote other rows to it.
    let source = svc.db.runtime().get_dataset("tickets").unwrap().unwrap();
    svc.db
        .runtime()
        .create_dataset(&crate::sekai::dataset::Dataset {
            id: "desk-tickets".into(),
            object_id: "desk-binding".into(),
            ..source
        })
        .unwrap();
    svc.db
        .runtime()
        .append_rows(
            "desk-tickets",
            &[[("title".to_string(), "written-elsewhere".to_string())].into()],
        )
        .unwrap();

    let refused = install(
        &svc,
        &exported.envelope_json,
        &[("tickets", "desk-tickets", "desk-binding")],
    )
    .unwrap_err();
    assert_eq!(
        refused.message(),
        "entry dataset_version/tickets: dataset desk-tickets changed outside the installation"
    );
    assert_eq!(
        svc.db
            .runtime()
            .query_rows("desk-tickets", &Default::default())
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn content_needs_an_export_grant_and_leaves_out_unreleased_columns() {
    let mut svc = service();
    fixture(&svc).await;
    // Read alone packages the definition, not the rows.
    let refused = export_with_content(&svc, &["tickets"], &["tickets"]).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        refused.message(),
        "dataset tickets content needs an export grant on namespace pkg-ns"
    );
    assert!(export_with_content(&svc, &["tickets"], &[]).is_ok());
    let refused = export_with_content(&svc, &[], &["tickets"]).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);

    grant_export_to_tester(&svc);
    bound_dataset_with(
        &svc,
        "contacts",
        NAMESPACE,
        "tester",
        &[("name", "public"), ("email", "sensitive")],
    );
    svc.db
        .runtime()
        .append_rows(
            "contacts",
            &[[
                ("name".to_string(), "Ada".to_string()),
                ("email".to_string(), "ada@example.test".to_string()),
            ]
            .into()],
        )
        .unwrap();
    let egress = crate::composition::gateway_egress_policy::EgressPolicies::new(["edge".into()]);
    egress
        .load(
            "edge",
            serde_json::json!({
                "format": "chisei.gateway-policy/v1",
                "generation": 1,
                "principals": [
                    {"name": "tester", "routes": [{"provider": "hosted", "models": ["*"]}]},
                ],
                "egress": [{"provider": "hosted", "data_classes": ["public"]}],
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    svc.set_egress_policies(egress);

    let exported = export_with_content(&svc, &["contacts"], &["contacts"]).unwrap();
    assert!(exported.envelope_json.contains("Ada"));
    assert!(!exported.envelope_json.contains("ada@example.test"));
    let package = package_domain::verify_namespace_envelope(&exported.envelope_json, &keyring())
        .unwrap()
        .package;
    assert!(package.withheld.contains(&WithheldCount {
        kind: package_domain::WITHHELD_DATASET_COLUMN.into(),
        count: 1,
    }));
    // The withheld column stays in the schema, so the digest is unchanged.
    let carried = package
        .entries
        .iter()
        .find(|entry| entry.id == "contacts")
        .unwrap();
    let source = svc.db.runtime().get_dataset("contacts").unwrap().unwrap();
    assert_eq!(
        carried.digest,
        package_domain::DatasetDocument::of(&source)
            .schema_digest()
            .unwrap()
    );
}

/// Version 1 with `tickets` (rows included) and `notes`, installed into
/// [`TARGET`] with its definitions merged.
async fn installed_v1(svc: &SekaiServiceImpl) {
    fixture(svc).await;
    grant_export_to_tester(svc);
    bound_dataset(svc, "notes", NAMESPACE, "tester");
    let v1 = export_version(svc, 1, &["notes", "tickets"], &["tickets"]).unwrap();
    target_object(svc, "desk-binding");
    target_object(svc, "desk-notes-binding");
    let installed = install(
        svc,
        &v1.envelope_json,
        &[
            ("tickets", "desk-tickets", "desk-binding"),
            ("notes", "desk-notes", "desk-notes-binding"),
        ],
    )
    .unwrap();
    merge(svc, &installed.proposal_id).await;
}

/// The titles in the latest version of `dataset_id`.
fn titles(svc: &SekaiServiceImpl, dataset_id: &str) -> Vec<String> {
    let db = svc.db.runtime();
    let version = db.latest_dataset_version_id(dataset_id).unwrap();
    let mut titles: Vec<String> = db
        .dataset_version_rows_after(dataset_id, &version, i64::MIN, 100)
        .unwrap()
        .into_iter()
        .map(|(_, row)| row["title"].clone())
        .collect();
    titles.sort();
    titles
}

#[tokio::test]
async fn an_upgrade_updates_what_it_installed_and_keeps_what_it_dropped() {
    let svc = service();
    installed_v1(&svc).await;
    // Version 2 carries new rows for tickets and drops notes.
    svc.db
        .runtime()
        .append_rows(
            "tickets",
            &[
                [("title".to_string(), "second-a".to_string())].into(),
                [("title".to_string(), "second-b".to_string())].into(),
            ],
        )
        .unwrap();
    let v2 = export_version(&svc, 2, &["tickets"], &["tickets"]).unwrap();

    // Datasets it installed need no mapping.
    let upgraded = install(&svc, &v2.envelope_json, &[]).unwrap();
    assert_eq!(upgraded.package_version, 2);
    // The definitions did not change, so the merged proposal stays.
    assert_eq!(upgraded.status, "installed");
    assert_eq!(upgraded.proposal_id, "package/support-desk/v1");
    let resources: Vec<_> = upgraded
        .resources
        .iter()
        .map(|resource| (resource.entry_id.as_str(), resource.resource_id.as_str()))
        .collect();
    assert_eq!(
        resources,
        [
            ("definitions", "package/support-desk/v1"),
            ("tickets", "desk-tickets")
        ]
    );
    let retained: Vec<_> = upgraded
        .retained_resources
        .iter()
        .map(|resource| (resource.entry_id.as_str(), resource.resource_id.as_str()))
        .collect();
    assert_eq!(retained, [("notes", "desk-notes")]);
    assert!(
        svc.db
            .runtime()
            .get_dataset("desk-notes")
            .unwrap()
            .is_some()
    );
    let versions = || {
        svc.db
            .runtime()
            .list_dataset_versions("desk-tickets")
            .unwrap()
            .len()
    };
    // One new version, appending only the rows version 1 lacked.
    assert_eq!(versions(), 2);
    assert_eq!(
        titles(&svc, "desk-tickets"),
        ["row-data-marker", "second-a", "second-b"]
    );

    // The upgrade again changes nothing; an older version is refused.
    assert_eq!(install(&svc, &v2.envelope_json, &[]).unwrap(), upgraded);
    assert_eq!(versions(), 2);
    let v1 = export_version(&svc, 1, &["tickets"], &[]).unwrap();
    assert_eq!(
        install(&svc, &v1.envelope_json, &[]).unwrap_err().message(),
        "namespace pkg-target already holds version 2 of package support-desk; an upgrade needs a later version"
    );
}

#[tokio::test]
async fn an_upgrade_refuses_what_changed_outside_the_installation() {
    let svc = service();
    installed_v1(&svc).await;
    let v2 = export_version(&svc, 2, &["tickets"], &["tickets"]).unwrap();

    // A target that moves an installed dataset is refused.
    let refused = install(
        &svc,
        &v2.envelope_json,
        &[("tickets", "elsewhere-tickets", "desk-binding")],
    )
    .unwrap_err();
    assert_eq!(
        refused.message(),
        "entry dataset_version/tickets is installed as dataset desk-tickets, not elsewhere-tickets"
    );
    // Rows written to an installed dataset are not overwritten.
    svc.db
        .runtime()
        .append_rows(
            "desk-tickets",
            &[[("title".to_string(), "written-elsewhere".to_string())].into()],
        )
        .unwrap();
    let refused = install(&svc, &v2.envelope_json, &[]).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        refused.message(),
        "entry dataset_version/tickets: dataset desk-tickets changed outside the installation"
    );
    assert_eq!(
        titles(&svc, "desk-tickets"),
        ["row-data-marker", "written-elsewhere"]
    );
    assert_eq!(
        installation(&svc, "support-desk")
            .await
            .unwrap()
            .package_version,
        1
    );
}

#[tokio::test]
async fn an_upgrade_waits_for_the_installed_versions_proposal() {
    let svc = service();
    fixture(&svc).await;
    target_object(&svc, "desk-binding");
    let v1 = export_version(&svc, 1, &["tickets"], &[]).unwrap();
    install(
        &svc,
        &v1.envelope_json,
        &[("tickets", "desk-tickets", "desk-binding")],
    )
    .unwrap();
    let v2 = export_version(&svc, 2, &["tickets"], &[]).unwrap();
    assert_eq!(
        install(&svc, &v2.envelope_json, &[]).unwrap_err().message(),
        "proposal package/support-desk/v1 of version 1 is still open; merge or close it before upgrading"
    );
}
