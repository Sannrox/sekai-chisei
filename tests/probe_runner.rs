//! Isolation probe runner against a live in-process plane.
//!
//! These tests need `SekaiServiceImpl` and `TokenAuthInterceptor`, so they
//! stay in the server integration crate and drive `sekaictl::probe_runner`.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::grpc::TokenAuthInterceptor;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
use sekai_chisei::sekai::credentials::PrincipalCredentialStore;
use sekai_chisei::sekai::security::{Grant, Role};
use sekai_chisei::sekai::synthetic::{
    SizePreset, Spec, SupplyChain, SyntheticPlan, apply, generate,
};
use sekai_domain::gateway_keys::hash_gateway_key;
use sekaictl::probe_runner::*;
use sekaictl::probe_spec::ProbeSpec;

const WEEK_MS: i64 = 7 * 86_400_000;

/// A deployment-like target: the real service behind token
/// authentication on an ephemeral port, with two synthetic tenants.
struct Deployment {
    endpoint: String,
    db: Arc<RuntimeDb>,
    north: SyntheticPlan,
    south: SyntheticPlan,
    _stop: tokio::sync::oneshot::Sender<()>,
}

fn viewer(plan: &SyntheticPlan) -> String {
    plan.principals
        .iter()
        .find(|principal| principal.role == "viewer")
        .unwrap()
        .id
        .clone()
}

async fn deployment(extra: impl FnOnce(&RuntimeDb, &SyntheticPlan, &SyntheticPlan)) -> Deployment {
    let db = Arc::new(RuntimeDb::memory());
    let tenant = |namespace: &str, seed| {
        generate(
            &SupplyChain,
            &Spec {
                namespace: namespace.into(),
                seed,
                preset: SizePreset::Demo,
            },
        )
        .unwrap()
    };
    let north = tenant("probe-north", 21);
    let south = tenant("probe-south", 22);
    apply(&db, &north).unwrap();
    apply(&db, &south).unwrap();
    db.create_principal_credential(&viewer(&north), &hash_gateway_key("north-token"), 1)
        .unwrap();
    db.create_principal_credential(&viewer(&south), &hash_gateway_key("south-token"), 1)
        .unwrap();
    extra(&db, &north, &south);
    let credentials = PrincipalCredentialStore::new();
    credentials.load(&db.list_active_credentials().unwrap());
    let store = sekai_core::db::store::SekaiStore::from_shared_runtime(db.clone());
    let service = SekaiServiceServer::with_interceptor(
        sekai_chisei::grpc::sekai_service::SekaiServiceImpl::new(store.clone()),
        TokenAuthInterceptor::new(Arc::new(credentials), store),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stopped.await;
                },
            )
            .await
            .unwrap()
    });
    Deployment {
        endpoint,
        db,
        north,
        south,
        _stop: stop,
    }
}

fn target(deployment: &Deployment) -> ProbeTarget {
    ProbeTarget {
        endpoint: deployment.endpoint.clone(),
        tenant: deployment.north.namespace.clone(),
        tenant_token: "north-token".into(),
        foreign_tenant: deployment.south.namespace.clone(),
        foreign_token: "south-token".into(),
        foreign_object_id: deployment.south.objects[0].id.clone(),
    }
}

fn ledger_lines(ledger: &Path) -> Vec<Attempt> {
    fs::read_to_string(ledger)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn an_isolating_target_denies_every_probe_and_the_ledger_records_it() {
    let deployment = deployment(|_, _, _| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let guard = TargetGuard::parse(Some(&deployment.endpoint));
    let report = run(
        guard,
        &target(&deployment),
        Ok(Vec::new()),
        &ledger,
        &dir.path().join("advisories"),
    )
    .await
    .unwrap();
    let outcomes: Vec<_> = report
        .attempts
        .iter()
        .map(|attempt| attempt.outcome.clone())
        .collect();
    assert_eq!(outcomes, [ProbeOutcome::Denied, ProbeOutcome::Denied]);
    assert!(report.advisories.is_empty());
    assert_eq!(ledger_lines(&ledger), report.attempts);
    // A torn last line from a crash is dropped before the next append.
    let mut torn = fs::OpenOptions::new().append(true).open(&ledger).unwrap();
    torn.write_all(b"{\"schema\":\"sekai.probe-led").unwrap();
    drop(torn);
    run(
        TargetGuard::parse(Some(&deployment.endpoint)),
        &target(&deployment),
        Ok(Vec::new()),
        &ledger,
        &dir.path().join("advisories"),
    )
    .await
    .unwrap();
    assert_eq!(ledger_lines(&ledger).len(), 4);
}

#[tokio::test]
async fn the_guard_refuses_a_target_off_the_allow_list_or_a_real_tenant() {
    let deployment = deployment(|db, north, _| {
        // A tenant that exists but is not synthetic, with a credential.
        db.create_object(&sekai_domain::domain::Object {
            id: "namespace:real-tenant".into(),
            kind: "namespace".into(),
            name: "real-tenant".into(),
            namespace: "real-tenant".into(),
            external_id: "namespace:real-tenant".into(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_grant(&Grant {
            id: "real-grant".into(),
            object_id: "namespace:real-tenant".into(),
            principal: viewer(north),
            role: Role::Viewer,
            created: 1,
            ..Default::default()
        })
        .unwrap();
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let advisories = dir.path().join("advisories");

    let elsewhere = TargetGuard::parse(Some("https://elsewhere.example.test:443"));
    let refused = run(
        elsewhere,
        &target(&deployment),
        Ok(Vec::new()),
        &ledger,
        &advisories,
    )
    .await
    .unwrap_err();
    assert!(refused.contains("not on the allow-list"), "{refused}");
    let missing = run(
        TargetGuard::parse(None),
        &target(&deployment),
        Ok(Vec::new()),
        &ledger,
        &advisories,
    )
    .await
    .unwrap_err();
    assert!(missing.contains(ALLOWLIST_ENV), "{missing}");

    let mut real = target(&deployment);
    real.foreign_tenant = "real-tenant".into();
    real.foreign_token = "north-token".into();
    let refused = run(
        TargetGuard::parse(Some(&deployment.endpoint)),
        &real,
        Ok(Vec::new()),
        &ledger,
        &advisories,
    )
    .await
    .unwrap_err();
    assert!(refused.contains("not synthetic"), "{refused}");

    let mut stale = target(&deployment);
    stale.foreign_object_id = "no-such-object".into();
    let refused = run(
        TargetGuard::parse(Some(&deployment.endpoint)),
        &stale,
        Ok(Vec::new()),
        &ledger,
        &advisories,
    )
    .await
    .unwrap_err();
    assert!(refused.contains("probe object"), "{refused}");

    // Refusals are attempts too; no probe ran.
    let lines = ledger_lines(&ledger);
    assert_eq!(lines.len(), 4);
    assert!(
        lines.iter().all(|attempt| attempt.probe.is_none()
            && matches!(attempt.outcome, ProbeOutcome::Refused(_)))
    );
    assert!(!advisories.exists());
}

#[tokio::test]
async fn a_seeded_bypass_produces_a_private_advisory_draft_and_the_summary_counts_it() {
    // A staging-like target with an isolation bug: the north viewer was
    // granted the south tenant's object.
    let deployment = deployment(|db, north, south| {
        db.create_grant(&Grant {
            id: "seeded-bypass".into(),
            object_id: south.objects[0].id.clone(),
            principal: viewer(north),
            role: Role::Viewer,
            created: 1,
            ..Default::default()
        })
        .unwrap();
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let advisories = dir.path().join("advisories");
    let target = target(&deployment);
    let report = run(
        TargetGuard::parse(Some(&deployment.endpoint)),
        &target,
        Ok(Vec::new()),
        &ledger,
        &advisories,
    )
    .await
    .unwrap();
    assert_eq!(report.attempts[1].probe, Some(ProbeKind::CrossTenantRead));
    assert_eq!(report.attempts[1].outcome, ProbeOutcome::Bypass);
    assert_eq!(report.advisories.len(), 1);
    let draft: AdvisoryDraft =
        serde_json::from_slice(&fs::read(&report.advisories[0]).unwrap()).unwrap();
    assert_eq!(draft.severity, "high");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&report.advisories[0]), 0o600);
        assert_eq!(mode(&advisories), 0o700);
        // A directory others can reach is refused, even when it exists.
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        let refused = run(
            TargetGuard::parse(Some(&deployment.endpoint)),
            &target,
            Ok(Vec::new()),
            &dir.path().join("ledger-2.jsonl"),
            &shared,
        )
        .await
        .unwrap_err();
        assert!(refused.contains("owner-only"), "{refused}");
    }
    assert!(draft.description.contains("### Reproduction"));
    assert!(draft.description.contains(&target.foreign_object_id));
    assert!(draft.description.contains(&report.attempts[1].attempt_id));
    // Nothing in the draft names the endpoint or a credential.
    for private in [target.endpoint.as_str(), "north-token", "south-token"] {
        assert!(!draft.description.contains(private), "{private}");
    }

    let summary = weekly_summary(&ledger, report.attempts[0].at_ms - 1_000).unwrap();
    assert_eq!(summary.attempts, 2);
    assert_eq!(summary.by_probe["CrossTenantRead"]["bypass"], 1);
    assert_eq!(summary.by_probe["UnauthenticatedRead"]["denied"], 1);
    assert_eq!(
        summary.bypass_attempts,
        [report.attempts[1].attempt_id.clone()]
    );
    // A torn final line is ignored; a corrupt complete line is not.
    let mut torn = fs::OpenOptions::new().append(true).open(&ledger).unwrap();
    torn.write_all(b"{\"schema\":").unwrap();
    drop(torn);
    assert_eq!(
        weekly_summary(&ledger, report.attempts[0].at_ms - 1_000)
            .unwrap()
            .attempts,
        2
    );
    let mut corrupt = fs::OpenOptions::new().append(true).open(&ledger).unwrap();
    corrupt.write_all(b"\n").unwrap();
    drop(corrupt);
    assert!(weekly_summary(&ledger, report.attempts[0].at_ms - 1_000).is_err());
    let next_week = weekly_summary(&ledger, report.attempts[0].at_ms + WEEK_MS);
    assert!(next_week.is_err());
    let next_week = weekly_summary(&dir.path().join("ledger-2.jsonl"), 0);
    assert_eq!(next_week.unwrap().attempts, 0);
    drop(deployment.db);
}

#[tokio::test]
async fn a_ledger_that_fails_after_the_first_attempt_still_reports_the_bypass() {
    let deployment = deployment(|db, north, south| {
        db.create_grant(&Grant {
            id: "seeded-bypass".into(),
            object_id: south.objects[0].id.clone(),
            principal: viewer(north),
            role: Role::Viewer,
            created: 1,
            ..Default::default()
        })
        .unwrap();
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let advisories = dir.path().join("advisories");
    let target = target(&deployment);
    let watch = ledger.clone();
    let stopper = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        while started.elapsed() < std::time::Duration::from_secs(10) {
            if fs::read_to_string(&watch)
                .ok()
                .is_some_and(|body| body.contains('\n'))
            {
                let mut permissions = fs::metadata(&watch).unwrap().permissions();
                permissions.set_readonly(true);
                fs::set_permissions(&watch, permissions).unwrap();
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("ledger never received the first attempt");
    });
    let report = run(
        TargetGuard::parse(Some(&deployment.endpoint)),
        &target,
        Ok(Vec::new()),
        &ledger,
        &advisories,
    )
    .await
    .unwrap();
    stopper.join().unwrap();
    assert_eq!(report.attempts.len(), ProbeKind::ALL.len());
    assert_eq!(report.attempts[1].probe, Some(ProbeKind::CrossTenantRead));
    assert_eq!(report.attempts[1].outcome, ProbeOutcome::Bypass);
    assert!(
        report
            .advisory_failures
            .iter()
            .any(|failure| failure.contains("ledger append failed")),
        "{:?}",
        report.advisory_failures
    );
    drop(deployment.db);
}

fn catalogue() -> Vec<ProbeSpec> {
    sekaictl::probe_spec::load_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe_specs"),
    )
    .unwrap()
}

#[tokio::test]
async fn every_catalogued_spec_is_denied_by_an_isolating_target() {
    // The regression catalogue's declarative probes: a promoted finding
    // fails here until the bypass it reproduces is fixed.
    let deployment = deployment(|_, _, _| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let specs = catalogue();
    let expected = specs.len();
    assert!(expected >= 10);
    let report = run(
        TargetGuard::parse(Some(&deployment.endpoint)),
        &target(&deployment),
        Ok(specs),
        &dir.path().join("ledger.jsonl"),
        &dir.path().join("advisories"),
    )
    .await
    .unwrap();
    let spec_attempts: Vec<_> = report
        .attempts
        .iter()
        .filter(|attempt| attempt.spec.is_some())
        .collect();
    assert_eq!(spec_attempts.len(), expected);
    for attempt in spec_attempts {
        assert_eq!(attempt.outcome, ProbeOutcome::Denied, "{:?}", attempt.spec);
    }
}

#[tokio::test]
async fn a_spec_against_a_seeded_bypass_is_a_finding_reproduced_by_the_spec() {
    let deployment = deployment(|db, north, south| {
        db.create_grant(&Grant {
            id: "seeded-bypass".into(),
            object_id: south.objects[0].id.clone(),
            principal: viewer(north),
            role: Role::Viewer,
            created: 1,
            ..Default::default()
        })
        .unwrap();
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let target = target(&deployment);
    let cross_tenant = catalogue()
        .into_iter()
        .find(|spec| spec.id == "get-object-cross-tenant")
        .unwrap();
    // Denied, but not as this spec says: a mismatch, not a pass.
    let mut strict = catalogue()
        .into_iter()
        .find(|spec| spec.id == "get-object-anonymous")
        .unwrap();
    strict.expect.reason = Some("never this message".into());
    let report = run(
        TargetGuard::parse(Some(&deployment.endpoint)),
        &target,
        Ok(vec![cross_tenant.clone(), strict]),
        &ledger,
        &dir.path().join("advisories"),
    )
    .await
    .unwrap();
    let spec = |id: &str| {
        report
            .attempts
            .iter()
            .find(|attempt| attempt.spec.as_deref() == Some(id))
            .unwrap()
    };
    assert_eq!(
        spec("get-object-cross-tenant").outcome,
        ProbeOutcome::Bypass
    );
    assert!(matches!(
        spec("get-object-anonymous").outcome,
        ProbeOutcome::Mismatch(_)
    ));
    // One draft for the built-in probe's bypass, one for the spec's.
    assert_eq!(report.advisories.len(), 2);
    let drafts: Vec<AdvisoryDraft> = report
        .advisories
        .iter()
        .map(|path| serde_json::from_slice(&fs::read(path).unwrap()).unwrap())
        .collect();
    let draft = drafts
        .iter()
        .find(|draft| draft.summary.contains("get-object-cross-tenant"))
        .unwrap();
    assert!(draft.description.contains("### Probe spec"));
    assert!(draft.description.contains("tests/fixtures/probe_specs/"));
    let embedded = draft
        .description
        .split("```json\n")
        .nth(1)
        .and_then(|rest| rest.split("\n```").next())
        .unwrap();
    assert_eq!(ProbeSpec::parse(embedded).unwrap(), cross_tenant);
    for private in [target.endpoint.as_str(), "north-token", "south-token"] {
        assert!(!draft.description.contains(private), "{private}");
    }
    let summary = weekly_summary(&ledger, report.attempts[0].at_ms - 1_000).unwrap();
    assert_eq!(
        summary.by_probe["spec:get-object-cross-tenant"]["bypass"],
        1
    );
    assert_eq!(summary.by_probe["spec:get-object-anonymous"]["mismatch"], 1);
}

#[tokio::test]
async fn an_imported_agent_report_finds_a_seeded_bypass_through_the_guard() {
    // The red-team agent's report goes through `probes import`; its specs
    // then run behind the same guard and fail the way a catalogue probe does.
    let deployment = deployment(|db, north, south| {
        db.create_grant(&Grant {
            id: "seeded-bypass".into(),
            object_id: south.objects[0].id.clone(),
            principal: viewer(north),
            role: Role::Viewer,
            created: 1,
            ..Default::default()
        })
        .unwrap();
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let specs = dir.path().join("specs");
    let report = r#"{
        "specs": [{
            "schema": "sekai.probe-spec/v1",
            "id": "agent-get-linked-objects-cross-tenant",
            "as": "tenant",
            "call": {"rpc": "GetLinkedObjects", "direction": "outgoing"},
            "expect": {"codes": ["PermissionDenied", "NotFound"]}
        }],
        "unsupported": [{"rpc": "NewRpc", "why": "not object-scoped"}]
    }"#;
    let outcome = sekaictl::probe_spec::import_report(report, &specs).unwrap();
    assert_eq!(outcome.written, ["agent-get-linked-objects-cross-tenant"]);
    assert_eq!(outcome.unsupported[0].rpc, "NewRpc");
    let report = run(
        TargetGuard::parse(Some(&deployment.endpoint)),
        &target(&deployment),
        sekaictl::probe_spec::load_dir(&specs),
        &dir.path().join("ledger.jsonl"),
        &dir.path().join("advisories"),
    )
    .await
    .unwrap();
    let attempt = report
        .attempts
        .iter()
        .find(|attempt| attempt.spec.as_deref() == Some("agent-get-linked-objects-cross-tenant"))
        .unwrap();
    assert_eq!(attempt.outcome, ProbeOutcome::Bypass);
}

#[tokio::test]
async fn a_malformed_spec_refuses_the_run_before_any_call() {
    let deployment = deployment(|_, _, _| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let mut malformed = catalogue().remove(0);
    malformed.expect.codes = vec!["Ok".into()];
    let refused = run(
        TargetGuard::parse(Some(&deployment.endpoint)),
        &target(&deployment),
        Ok(vec![malformed]),
        &ledger,
        &dir.path().join("advisories"),
    )
    .await
    .unwrap_err();
    assert!(refused.contains("not a denial code"), "{refused}");
    let lines = ledger_lines(&ledger);
    assert_eq!(lines.len(), 1);
    assert!(matches!(lines[0].outcome, ProbeOutcome::Refused(_)));
    // A spec file that names a target is refused when the set loads.
    let specs = dir.path().join("specs");
    fs::create_dir(&specs).unwrap();
    fs::write(
        specs.join("aimed.json"),
        r#"{"schema":"sekai.probe-spec/v1","id":"aimed","as":"tenant",
                "target":"https://prod.example.test","call":{"rpc":"GetObject"},
                "expect":{"codes":["NotFound"]}}"#,
    )
    .unwrap();
    let loaded = sekaictl::probe_spec::load_dir(&specs);
    assert!(loaded.is_err());
    // As `--specs` does: the failed load is a refused run, ledgered.
    assert!(
        run(
            TargetGuard::parse(Some(&deployment.endpoint)),
            &target(&deployment),
            loaded,
            &ledger,
            &dir.path().join("advisories"),
        )
        .await
        .is_err()
    );
    let lines = ledger_lines(&ledger);
    assert_eq!(lines.len(), 2);
    assert!(
        matches!(&lines[1].outcome, ProbeOutcome::Refused(reason) if reason.contains("aimed.json"))
    );
}
