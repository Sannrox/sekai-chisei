use sekai_chisei::db::capability_package::CapabilityPackageBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::capability_package::CapabilityPackageManifest;
use std::sync::{Arc, Barrier};

fn manifest(bytes: &[u8]) -> CapabilityPackageManifest {
    serde_json::from_slice(bytes).expect("valid checked-in package manifest")
}

fn exercise(db: &dyn CapabilityPackageBackend, namespace: &str, package_name: &str) {
    let mut v1 = manifest(include_bytes!(
        "../examples/capability-packages/reference-v1.json"
    ));
    let mut v2 = manifest(include_bytes!(
        "../examples/capability-packages/reference-v2.json"
    ));
    v1.name = package_name.into();
    v2.name = package_name.into();
    let other = format!("{namespace}-other");

    let installed = db
        .install_capability_package(namespace, &v1, "human:operator", "install-1", 10)
        .expect("install package");
    assert_eq!(
        (installed.current_version.as_str(), installed.state.as_str()),
        ("1.0.0", "active")
    );
    assert_eq!(installed.installed_by, "human:operator");
    assert!(
        db.get_capability_package(&other, package_name)
            .unwrap()
            .is_none(),
        "installations must stay namespace-isolated"
    );
    assert!(
        db.evaluate_capability_package(
            namespace,
            package_name,
            "agent:evaluator",
            "evaluate-1",
            20
        )
        .expect("evaluate package")
    );

    let upgraded = db
        .upgrade_capability_package(namespace, &v2, "human:operator", "upgrade-1", 30)
        .expect("upgrade package");
    assert_eq!(
        (
            upgraded.current_version.as_str(),
            upgraded.previous_version.as_str()
        ),
        ("1.1.0", "1.0.0")
    );
    assert!(
        db.upgrade_capability_package(namespace, &v1, "human:operator", "downgrade-1", 31)
            .is_err(),
        "older versions must use rollback"
    );
    let install_replay = db
        .install_capability_package(namespace, &v1, "human:operator", "install-1", 35)
        .expect("replay install response");
    assert_eq!(install_replay.current_version, "1.0.0");

    let rolled_back = db
        .rollback_capability_package(namespace, package_name, "human:operator", "rollback-1", 40)
        .expect("roll back package");
    assert_eq!(rolled_back.current_version, "1.0.0");
    assert!(
        db.rollback_capability_package(namespace, package_name, "human:operator", "rollback-2", 41)
            .is_err(),
        "rollback target must be consumed rather than toggled"
    );

    let disabled = db
        .disable_capability_package(namespace, package_name, "human:operator", "disable-1", 50)
        .expect("disable package");
    assert_eq!(disabled.state, "disabled");
    assert!(
        db.evaluate_capability_package(
            namespace,
            package_name,
            "agent:evaluator",
            "evaluate-disabled",
            55
        )
        .is_err()
    );

    db.uninstall_capability_package(namespace, package_name, "human:operator", "uninstall-1", 60)
        .expect("uninstall package");
    assert!(
        db.get_capability_package(namespace, package_name)
            .unwrap()
            .is_none()
    );
    db.uninstall_capability_package(namespace, package_name, "human:operator", "uninstall-1", 61)
        .expect("uninstall retry");
    db.install_capability_package(namespace, &v1, "human:operator", "install-2", 62)
        .expect("reinstall package");
    assert!(
        db.uninstall_capability_package(
            namespace,
            package_name,
            "human:operator",
            "uninstall-1",
            63
        )
        .is_err(),
        "stale uninstall retry must not report success for a new installation"
    );
    db.uninstall_capability_package(namespace, package_name, "human:operator", "uninstall-2", 64)
        .expect("remove reinstalled package");

    assert_eq!(
        db.get_capability_package_manifest(namespace, package_name, "1.0.0")
            .expect("retained manifest"),
        Some(v1)
    );
    let events = db
        .list_capability_package_events(namespace, package_name)
        .expect("retained evidence");
    assert_eq!(
        events
            .iter()
            .map(|event| event.action.as_str())
            .collect::<Vec<_>>(),
        [
            "install",
            "evaluate",
            "upgrade",
            "rollback",
            "disable",
            "uninstall",
            "install",
            "uninstall"
        ]
    );
    assert!(events.iter().all(|event| !event.actor.is_empty()));
    assert!(
        events
            .iter()
            .all(|event| event.manifest_digest.starts_with("sha256:"))
    );
    let audit = db
        .list_capability_package_decisions(namespace, package_name)
        .expect("retained audit ledger");
    assert_eq!(audit.len(), 8);
    assert!(audit.iter().all(|decision| {
        decision.actor.contains(':') && decision.action.starts_with("capability_package.")
    }));
}

fn exercise_fail_closed(db: &dyn CapabilityPackageBackend, namespace: &str, package_name: &str) {
    let mut package = manifest(include_bytes!(
        "../examples/capability-packages/reference-v1.json"
    ));
    package.name = package_name.into();
    package.components[0].definition = serde_json::json!({ "api_token": "hidden" });
    assert!(
        db.install_capability_package(namespace, &package, "human:operator", "bad-1", 1)
            .is_err(),
        "corrupt manifests must fail closed"
    );
    assert!(
        db.get_capability_package(namespace, package_name)
            .unwrap()
            .is_none()
    );
    assert!(
        db.list_capability_package_events(namespace, package_name)
            .unwrap()
            .is_empty()
    );
    assert!(
        db.list_capability_package_decisions(namespace, package_name)
            .unwrap()
            .is_empty()
    );

    package = manifest(include_bytes!(
        "../examples/capability-packages/reference-v1.json"
    ));
    package.name = package_name.into();
    db.install_capability_package(namespace, &package, "human:operator", "ok-1", 2)
        .unwrap();
    assert!(
        db.disable_capability_package(namespace, package_name, "human:operator", "disable-a", 3)
            .is_ok()
    );
    assert!(
        db.disable_capability_package(namespace, package_name, "human:operator", "disable-b", 4)
            .is_err(),
        "invalid transitions must fail closed"
    );
    let installation = db
        .get_capability_package(namespace, package_name)
        .unwrap()
        .unwrap();
    assert_eq!(installation.state, "disabled");
}

#[test]
fn sqlite_capability_package_conformance() {
    let db = SekaiDb::new(":memory:").expect("database");
    exercise(&db, "acme-sqlite", "reference-review");
    exercise_fail_closed(&db, "acme-sqlite-fail", "reference-review");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_capability_package_conformance_and_restart() {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("pg-cap-{suffix}");
    let package_name = format!("pkg-{suffix}");
    exercise(&postgres(), &namespace, &package_name);
    let restarted = postgres();
    assert_eq!(
        restarted
            .get_capability_package_manifest(&namespace, &package_name, "1.0.0")
            .unwrap()
            .unwrap()
            .version,
        "1.0.0"
    );
    assert_eq!(
        restarted
            .list_capability_package_events(&namespace, &package_name)
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        restarted
            .list_capability_package_decisions(&namespace, &package_name)
            .unwrap()
            .len(),
        8
    );
    exercise_fail_closed(
        &restarted,
        &format!("{namespace}-fail"),
        &format!("{package_name}-fail"),
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_conflicting_installs_have_one_winner() {
    let db = Arc::new(postgres());
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace = format!("pg-race-{suffix}");
    let package_name = format!("pkg-{suffix}");
    let mut package = manifest(include_bytes!(
        "../examples/capability-packages/reference-v1.json"
    ));
    package.name = package_name.clone();
    let barrier = Arc::new(Barrier::new(3));
    let handles = ["race-a", "race-b"].map(|request_id| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let package = package.clone();
        let namespace = namespace.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.install_capability_package(&namespace, &package, "human:operator", request_id, 10)
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert!(
        db.get_capability_package(&namespace, &package_name)
            .unwrap()
            .is_some()
    );
}
