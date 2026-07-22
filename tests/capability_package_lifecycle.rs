use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::sekai::audit::DecisionFilter;
use sekai_chisei::sekai::capability_package::CapabilityPackageManifest;

fn manifest(bytes: &[u8]) -> CapabilityPackageManifest {
    serde_json::from_slice(bytes).expect("valid checked-in package manifest")
}

#[test]
fn reference_package_completes_a_namespace_isolated_attributed_lifecycle() {
    let db = SekaiDb::new(":memory:").expect("database");
    let v1 = manifest(include_bytes!(
        "../examples/capability-packages/reference-v1.json"
    ));
    let v2 = manifest(include_bytes!(
        "../examples/capability-packages/reference-v2.json"
    ));

    let installed = db
        .install_capability_package("acme", &v1, "human:operator", "install-1", 10)
        .expect("install package");
    assert_eq!(
        (installed.current_version.as_str(), installed.state.as_str()),
        ("1.0.0", "active")
    );
    assert!(
        db.get_capability_package("other", "reference-review")
            .unwrap()
            .is_none()
    );
    assert!(
        db.evaluate_capability_package(
            "acme",
            "reference-review",
            "agent:evaluator",
            "evaluate-1",
            20
        )
        .expect("evaluate package")
    );

    let upgraded = db
        .upgrade_capability_package("acme", &v2, "human:operator", "upgrade-1", 30)
        .expect("upgrade package");
    assert_eq!(
        (
            upgraded.current_version.as_str(),
            upgraded.previous_version.as_str()
        ),
        ("1.1.0", "1.0.0")
    );
    assert!(
        db.upgrade_capability_package("acme", &v1, "human:operator", "downgrade-1", 31)
            .is_err(),
        "older versions must use rollback"
    );
    let install_replay = db
        .install_capability_package("acme", &v1, "human:operator", "install-1", 35)
        .expect("replay install response");
    assert_eq!(install_replay.current_version, "1.0.0");
    let rolled_back = db
        .rollback_capability_package(
            "acme",
            "reference-review",
            "human:operator",
            "rollback-1",
            40,
        )
        .expect("roll back package");
    assert_eq!(rolled_back.current_version, "1.0.0");
    assert!(
        db.rollback_capability_package(
            "acme",
            "reference-review",
            "human:operator",
            "rollback-2",
            41
        )
        .is_err(),
        "rollback target must be consumed rather than toggled"
    );
    let disabled = db
        .disable_capability_package(
            "acme",
            "reference-review",
            "human:operator",
            "disable-1",
            50,
        )
        .expect("disable package");
    assert_eq!(disabled.state, "disabled");
    assert!(
        db.evaluate_capability_package(
            "acme",
            "reference-review",
            "agent:evaluator",
            "evaluate-disabled",
            55
        )
        .is_err()
    );

    db.uninstall_capability_package(
        "acme",
        "reference-review",
        "human:operator",
        "uninstall-1",
        60,
    )
    .expect("uninstall package");
    assert!(
        db.get_capability_package("acme", "reference-review")
            .unwrap()
            .is_none()
    );
    db.uninstall_capability_package(
        "acme",
        "reference-review",
        "human:operator",
        "uninstall-1",
        61,
    )
    .expect("uninstall retry");
    db.install_capability_package("acme", &v1, "human:operator", "install-2", 62)
        .expect("reinstall package");
    assert!(
        db.uninstall_capability_package(
            "acme",
            "reference-review",
            "human:operator",
            "uninstall-1",
            63
        )
        .is_err(),
        "stale uninstall retry must not report success for a new installation"
    );
    db.uninstall_capability_package(
        "acme",
        "reference-review",
        "human:operator",
        "uninstall-2",
        64,
    )
    .expect("remove reinstalled package");
    assert_eq!(
        db.get_capability_package_manifest("acme", "reference-review", "1.0.0")
            .expect("retained manifest"),
        Some(v1)
    );
    let events = db
        .list_capability_package_events("acme", "reference-review")
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
        .list_decisions(&DecisionFilter {
            target_id: Some("capability-package:acme:reference-review".into()),
            ..DecisionFilter::default()
        })
        .expect("retained audit ledger");
    assert_eq!(audit.len(), 8);
    assert!(audit.iter().all(|decision| {
        decision.actor.contains(':') && decision.action.starts_with("capability_package.")
    }));
}

#[test]
fn packages_reject_authority_secrets_and_executable_content() {
    let mut package = manifest(include_bytes!(
        "../examples/capability-packages/reference-v1.json"
    ));
    for (key, value) in [
        ("api_token", "hidden"),
        ("script", "run"),
        ("grant", "admin"),
    ] {
        package.components[0].definition = serde_json::json!({ key: value });
        assert!(package.validate().is_err(), "{key} must be rejected");
    }
    package.components[0].definition = serde_json::json!({ "properties": ["sk-live-example"] });
    assert!(
        package.validate().is_err(),
        "credential-shaped values must be rejected"
    );
    package.components[0].definition =
        serde_json::json!({ "properties": ["abcdefghijklmnopqrst"] });
    assert!(
        package.validate().is_err(),
        "opaque high-entropy slots must be rejected"
    );
    let mut duplicate = manifest(include_bytes!(
        "../examples/capability-packages/reference-v1.json"
    ));
    duplicate.components.push(duplicate.components[0].clone());
    assert!(
        duplicate.validate().unwrap_err().contains("duplicate"),
        "component identities must be unique"
    );
}
