//! Shared SQLite/PostgreSQL conformance for versioned client packages (#1477).

use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::client_package::{
    ClientPackage, LANG_PYTHON, LANG_RUST, LANG_TYPESCRIPT, PACKAGE_CONTRACT, PACKAGE_UNAVAILABLE,
    PackageArtifacts, artifacts_from, get_client_package, publish_client_package,
};

use crate::postgres_scratch::ScratchDatabase;

fn artifacts() -> PackageArtifacts {
    artifacts_from("proto-v1", "source-v1", b"pkg-v1").unwrap()
}

fn package(id: &str, version: &str, language: &str, artifacts: &PackageArtifacts) -> ClientPackage {
    ClientPackage {
        contract_version: PACKAGE_CONTRACT.into(),
        package_id: id.into(),
        namespace: "sdk".into(),
        owner: String::new(),
        language: language.into(),
        package_name: "sekai-client".into(),
        package_version: version.into(),
        protocol_digest: artifacts.protocol.clone(),
        source_digest: artifacts.source.clone(),
        package_digest: artifacts.package.clone(),
        catalog_version: "catalog-v1".into(),
        operation_id: format!("op:{id}"),
        predecessor_id: String::new(),
        superseded_by: String::new(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    }
}

fn exercise(db: &RuntimeDb) {
    let first_artifacts = artifacts();
    let first = publish_client_package(
        db,
        "integrator",
        &package("pkg:rust-0.1.0", "0.1.0", LANG_RUST, &first_artifacts),
        &first_artifacts,
        1_000,
    )
    .unwrap();
    assert_eq!(first.owner, "integrator");
    assert_eq!(
        get_client_package(db, "integrator", "sdk", "pkg:rust-0.1.0")
            .unwrap()
            .package_id,
        "pkg:rust-0.1.0"
    );
    let replay = publish_client_package(
        db,
        "integrator",
        &package("pkg:rust-0.1.0", "0.1.0", LANG_RUST, &first_artifacts),
        &first_artifacts,
        2_000,
    )
    .unwrap();
    assert_eq!(first, replay);

    // Only reads by the owner of an existing package succeed.
    for (actor, id) in [
        ("someone-else", "pkg:rust-0.1.0"),
        ("integrator", "pkg:missing"),
    ] {
        assert_eq!(
            get_client_package(db, actor, "sdk", id).unwrap_err(),
            PACKAGE_UNAVAILABLE,
            "{actor} reading {id}"
        );
    }

    // Same name, language and version under another id is refused for its
    // identity, not a shared digest: its artifacts share none with the first.
    // (Both the live-identity and the later-version rule refuse it.)
    let colliding_artifacts = artifacts_from("proto-dup", "source-dup", b"pkg-dup").unwrap();
    assert_ne!(colliding_artifacts.package, first_artifacts.package);
    assert_eq!(
        publish_client_package(
            db,
            "integrator",
            &package("pkg:rust-dup", "0.1.0", LANG_RUST, &colliding_artifacts),
            &colliding_artifacts,
            2_500,
        )
        .unwrap_err(),
        PACKAGE_UNAVAILABLE
    );
    assert_eq!(db.get_client_package("sdk", "pkg:rust-dup").unwrap(), None);

    for language in [LANG_TYPESCRIPT, LANG_PYTHON] {
        publish_client_package(
            db,
            "integrator",
            &package(
                &format!("pkg:{language}"),
                "0.1.0",
                language,
                &first_artifacts,
            ),
            &first_artifacts,
            3_000,
        )
        .unwrap();
    }
    let listed = db.list_client_packages("sdk").unwrap();
    assert_eq!(listed.len(), 3);

    // The package digest is not an identity key: a later version reusing the
    // first version's digest is admitted as its successor.
    let mut successor = package("pkg:rust-0.2.0", "0.2.0", LANG_RUST, &first_artifacts);
    successor.predecessor_id = first.package_id.clone();
    let published =
        publish_client_package(db, "integrator", &successor, &first_artifacts, 4_000).unwrap();
    assert_eq!(published.predecessor_id, "pkg:rust-0.1.0");
    assert_eq!(published.package_digest, first.package_digest);
    let superseded = db
        .get_client_package("sdk", "pkg:rust-0.1.0")
        .unwrap()
        .unwrap();
    assert_eq!(superseded.superseded_by, "pkg:rust-0.2.0");
}

#[test]
fn sqlite_client_package_backend_conformance() {
    exercise(&RuntimeDb::memory());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_client_package_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise(&db);
}
