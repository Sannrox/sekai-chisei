use super::*;
use crate::sekai::dataset::ColumnDef;
use crate::sekai::definition_package::build_package;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn keyring() -> TrustedKeyring {
    let mut keyring = TrustedKeyring::new();
    keyring
        .trust("exporter", "k1", key().verifying_key())
        .unwrap();
    keyring
}

fn dataset(id: &str, name: &str) -> Dataset {
    Dataset {
        id: id.into(),
        name: name.into(),
        columns: vec![
            ColumnDef {
                name: "id".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
            ColumnDef {
                name: "email".into(),
                col_type: "string".into(),
                classification: "sensitive".into(),
            },
        ],
        object_id: format!("obj-{id}"),
        created: 1,
        partition_keys: vec!["id".into()],
    }
}

fn definitions() -> DefinitionPackage {
    build_package([
        (
            "object_type".to_string(),
            "Ticket".to_string(),
            r#"{"name":"Ticket"}"#.to_string(),
        ),
        (
            "link_type".to_string(),
            "assigned_to".to_string(),
            r#"{"name":"assigned_to"}"#.to_string(),
        ),
    ])
    .unwrap()
}

fn envelope_json() -> String {
    let package = build_namespace_package(
        "support-desk",
        1,
        &definitions(),
        &[dataset("tickets", "Tickets")],
        &[dataset("raw", "Raw")],
        BTreeMap::from([("policy".to_string(), 2)]),
    )
    .unwrap();
    let provenance = PackageProvenance {
        source_namespace: "team-a".into(),
        source_revision_digest: format!("sha256:{}", "a".repeat(64)),
        exported_at_ms: 1,
    };
    serde_json::to_string(
        &sign_namespace_package(package, provenance, "exporter", "k1", &key()).unwrap(),
    )
    .unwrap()
}

#[test]
fn a_package_lists_definitions_outputs_inputs_and_withheld_counts() {
    let envelope = verify_namespace_envelope(&envelope_json(), &keyring()).unwrap();
    let package = envelope.package;
    let entries: Vec<_> = package
        .entries
        .iter()
        .map(|entry| (entry.kind.as_str(), entry.id.as_str(), entry.role))
        .collect();
    assert_eq!(
        entries,
        [
            (KIND_DATASET_VERSION, "raw", EntryRole::Input),
            (KIND_DATASET_VERSION, "tickets", EntryRole::Output),
            (
                KIND_DEFINITION_PACKAGE,
                DEFINITIONS_ENTRY_ID,
                EntryRole::Output
            ),
        ]
    );
    assert_eq!(package.ontology_digest, definitions().package_digest);
    assert_eq!(
        package.withheld,
        [WithheldCount {
            kind: "policy".into(),
            count: 2
        }]
    );
    // An input names its schema digest only; the installer maps it.
    assert!(package.entries[0].document_json.is_empty());
    assert!(package.entries.iter().all(|entry| !entry.content_included));
}

#[test]
fn the_schema_digest_ignores_the_dataset_name_but_not_its_columns() {
    let digest = |dataset: &Dataset| DatasetDocument::of(dataset).schema_digest().unwrap();
    let tickets = dataset("tickets", "Tickets");
    assert_eq!(digest(&tickets), digest(&dataset("other", "Elsewhere")));
    let mut reclassified = tickets.clone();
    reclassified.columns[1].classification = "public".into();
    assert_ne!(digest(&tickets), digest(&reclassified));
    let mut reordered = tickets.clone();
    reordered.columns.reverse();
    assert_ne!(digest(&tickets), digest(&reordered));
}

/// Re-serializes the signed envelope after `edit`, without re-signing.
fn tampered(edit: impl FnOnce(&mut NamespacePackageEnvelope)) -> String {
    let mut envelope: NamespacePackageEnvelope = serde_json::from_str(&envelope_json()).unwrap();
    edit(&mut envelope);
    let json = serde_json::to_string(&envelope).unwrap();
    verify_namespace_envelope(&json, &keyring()).unwrap_err()
}

fn entry<'a>(envelope: &'a mut NamespacePackageEnvelope, id: &str) -> &'a mut PackageEntry {
    envelope
        .package
        .entries
        .iter_mut()
        .find(|entry| entry.id == id)
        .unwrap()
}

#[test]
fn a_tampered_package_is_refused_by_name_before_it_is_trusted() {
    // A dataset schema edited without its digest.
    let refused = tampered(|envelope| {
        let entry = entry(envelope, "tickets");
        entry.document_json = entry.document_json.replace("sensitive", "public");
    });
    assert!(refused.starts_with(REFUSAL_TAMPERED), "{refused}");
    assert!(refused.contains("dataset_version/tickets"), "{refused}");
    // A definition edited without its digests.
    let refused = tampered(|envelope| {
        let entry = entry(envelope, DEFINITIONS_ENTRY_ID);
        let mut carried: DefinitionPackage = serde_json::from_str(&entry.document_json).unwrap();
        carried.members[0].definition_json = r#"{"name":"Tickez"}"#.into();
        entry.document_json = serde_json::to_string(&carried).unwrap();
    });
    assert!(refused.starts_with(REFUSAL_TAMPERED), "{refused}");
    assert!(refused.contains(DEFINITIONS_ENTRY_ID), "{refused}");
    // A dataset renamed: its schema digest still holds, the manifest digest does not.
    let refused = tampered(|envelope| {
        let entry = entry(envelope, "tickets");
        entry.document_json = entry.document_json.replace("Tickets", "Ticketz");
    });
    assert!(
        refused.starts_with(&format!("{REFUSAL_TAMPERED}: package digest")),
        "{refused}"
    );
    // A withheld count lowered, or the version bumped, without re-signing.
    let refused = tampered(|envelope| envelope.package.withheld[0].count = 1);
    assert!(refused.starts_with(REFUSAL_TAMPERED), "{refused}");
    let refused = tampered(|envelope| envelope.package.version = 2);
    assert!(refused.starts_with(REFUSAL_TAMPERED), "{refused}");
    // A re-digested package is still refused without a fresh signature.
    let refused = tampered(|envelope| {
        envelope.package.version = 2;
        envelope.package.package_digest = manifest_digest(&envelope.package).unwrap();
    });
    assert!(refused.starts_with(REFUSAL_UNVERIFIED), "{refused}");
}

#[test]
fn a_package_signed_by_an_untrusted_key_or_claiming_content_it_lacks_is_refused() {
    let refused = verify_namespace_envelope(&envelope_json(), &TrustedKeyring::new()).unwrap_err();
    assert!(refused.starts_with(REFUSAL_UNVERIFIED), "{refused}");

    let refused = tampered(|envelope| entry(envelope, "tickets").content_included = true);
    assert!(refused.starts_with(REFUSAL_INCOMPATIBLE), "{refused}");

    // v1 has no object_set kind; an unknown kind is refused by name.
    let refused = tampered(|envelope| entry(envelope, "raw").kind = "object_set".into());
    assert!(
        refused.contains("unsupported entry object_set/raw"),
        "{refused}"
    );
}

#[test]
fn names_and_versions_are_bounded() {
    assert!(validate_name_and_version("support-desk.v2_x", 1).is_ok());
    for name in [
        "",
        "Support",
        "a b",
        &"a".repeat(MAX_PACKAGE_NAME_BYTES + 1),
    ] {
        assert!(validate_name_and_version(name, 1).is_err(), "{name}");
    }
    assert!(validate_name_and_version("desk", 0).is_err());
    let duplicate = build_namespace_package(
        "desk",
        1,
        &definitions(),
        &[dataset("raw", "Raw")],
        &[dataset("raw", "Raw")],
        BTreeMap::new(),
    )
    .unwrap_err();
    assert!(duplicate.contains("twice"), "{duplicate}");
}

fn row(id: &str, email: &str) -> ContentRow {
    BTreeMap::from([
        ("id".to_string(), id.to_string()),
        ("email".to_string(), email.to_string()),
    ])
}

fn content_package(rows: Vec<ContentRow>) -> Result<NamespacePackage, String> {
    build_namespace_package_with_content(
        "support-desk",
        1,
        &definitions(),
        &[dataset("tickets", "Tickets")],
        &[],
        BTreeMap::from([("tickets".to_string(), rows)]),
        BTreeMap::new(),
    )
}

fn signed(package: NamespacePackage) -> NamespacePackageEnvelope {
    let provenance = PackageProvenance {
        source_namespace: "team-a".into(),
        source_revision_digest: String::new(),
        exported_at_ms: 1,
    };
    sign_namespace_package(package, provenance, "exporter", "k1", &key()).unwrap()
}

#[test]
fn opted_in_rows_travel_inside_the_signed_entry_under_their_digest() {
    let package = content_package(vec![row("t-1", "a@example.test")]).unwrap();
    let schema_only = build_namespace_package(
        "support-desk",
        1,
        &definitions(),
        &[dataset("tickets", "Tickets")],
        &[],
        BTreeMap::new(),
    )
    .unwrap();
    let carried = &package.entries[0];
    assert!(carried.content_included);
    // Rows do not change the schema digest an input is matched by.
    assert_eq!(carried.digest, schema_only.entries[0].digest);
    let envelope = signed(package);
    let verified =
        verify_namespace_envelope(&serde_json::to_string(&envelope).unwrap(), &keyring()).unwrap();
    let document: DatasetContentDocument =
        serde_json::from_str(&verified.package.entries[0].document_json).unwrap();
    assert_eq!(document.rows, [row("t-1", "a@example.test")]);

    // A changed row is caught by the content digest, a recomputed content
    // digest by the package digest.
    let edit = |change: &dyn Fn(&mut DatasetContentDocument)| {
        let mut envelope = envelope.clone();
        let mut document: DatasetContentDocument =
            serde_json::from_str(&envelope.package.entries[0].document_json).unwrap();
        change(&mut document);
        envelope.package.entries[0].document_json = serde_json::to_string(&document).unwrap();
        verify_namespace_envelope(&serde_json::to_string(&envelope).unwrap(), &keyring())
            .unwrap_err()
    };
    let refused = edit(&|document| document.rows[0] = row("t-1", "b@example.test"));
    assert!(
        refused.contains("does not match its content digest"),
        "{refused}"
    );
    let refused = edit(&|document| {
        document.rows[0] = row("t-1", "b@example.test");
        document.content_digest = content_digest(&document.rows).unwrap();
    });
    assert!(
        refused.contains("package digest does not match"),
        "{refused}"
    );
}

#[test]
fn content_is_bounded_typed_and_only_for_outputs() {
    let one_row = row_bytes(&row("t", &"x".repeat(1024))).unwrap();
    let rows = vec![row("t", &"x".repeat(1024)); MAX_PACKAGE_CONTENT_BYTES / one_row + 1];
    let refused = content_package(rows).unwrap_err();
    assert!(
        refused.starts_with(&format!("{REFUSAL_CONTENT_TOO_LARGE}: dataset tickets")),
        "{refused}"
    );

    let mut typed = dataset("tickets", "Tickets");
    typed.columns[0].col_type = "int".into();
    let refused = build_namespace_package_with_content(
        "support-desk",
        1,
        &definitions(),
        &[typed],
        &[],
        BTreeMap::from([("tickets".to_string(), vec![row("seven", "")])]),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert!(
        refused.contains("dataset tickets: row 0 column id is not a int value"),
        "{refused}"
    );
    let refused = content_package(vec![BTreeMap::from([(
        "phone".to_string(),
        "1".to_string(),
    )])])
    .unwrap_err();
    assert!(refused.contains("names column phone"), "{refused}");

    let refused = build_namespace_package_with_content(
        "support-desk",
        1,
        &definitions(),
        &[],
        &[dataset("raw", "Raw")],
        BTreeMap::from([("raw".to_string(), Vec::new())]),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert!(refused.contains("content for raw"), "{refused}");
}
