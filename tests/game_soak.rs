//! A short game soak against the shipped binary (#1626).
//!
//! Two bounded runs with one seed, in two namespaces of one deployment,
//! go through the same public gRPC path as a real soak: bots propose
//! governed Actions, intake applies battle batches, and the statistics
//! transform runs with lineage. Both runs apply exactly the scripted
//! Action sequence, and the harness writes the throughput document.
#![cfg(unix)]

use std::collections::HashMap;

use sekai_chisei::game_soak::{HardwareProfile, SoakSpec, run, script};
use sekai_chisei::grpc::pb::sekai::ListActionInstancesRequest;
use sekai_chisei::sekai::synthetic::SizePreset;

use crate::product_loop_backend_conformance::{Backend, LoopServer};

#[tokio::test(flavor = "multi_thread")]
async fn one_seed_applies_one_action_sequence_and_writes_the_document() {
    let server = LoopServer::spawn(&Backend::Sqlite);
    let spec = SoakSpec {
        seed: 7,
        preset: SizePreset::Demo,
        bots: 2,
        rounds: 3,
        batch_records: 5,
    };
    let hardware = HardwareProfile {
        description: "test runner".into(),
        cores: 1,
        operating_system: "test os".into(),
        rustc: "rustc test".into(),
        build_profile: "debug".into(),
    };
    let mut sekai = server.sekai().await;
    let mut digests = Vec::new();
    for namespace in ["soak-first", "soak-second"] {
        let script = script(&spec, namespace).unwrap();
        let report = run(
            &server.socket_str(),
            &script,
            hardware.clone(),
            "2026-01-01T00:00:00Z".into(),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}\n{}", server.logs()));
        assert_eq!(report.actions.proposed, 6);
        assert_eq!(report.actions.applied, 6);
        assert_eq!(report.intake.batches, 3);
        assert_eq!(report.intake.records, 15);
        assert!(report.transform.runs >= 1);
        assert!(report.transform.lineage_chained);
        assert!(report.transform.output_rows > 0);

        // The plane holds exactly the scripted proposals, each applied
        // under its bot's own principal.
        let applied: HashMap<String, _> = sekai
            .list_action_instances(ListActionInstancesRequest {
                namespace: namespace.into(),
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .instances
            .into_iter()
            .map(|instance| (instance.idempotency_key.clone(), instance))
            .collect();
        assert_eq!(applied.len(), 6);
        for (bot, proposals) in script.proposals().into_iter().enumerate() {
            for proposal in proposals {
                let instance = &applied[&proposal.idempotency_key];
                assert_eq!(instance.status, "admitted");
                assert_eq!(instance.principal, script.bot_principal(bot));
                assert_eq!(instance.parameters_json, proposal.parameters_json);
            }
        }

        let out = tempfile::tempdir().unwrap();
        report.write(out.path()).unwrap();
        let document = std::fs::read_to_string(out.path().join("report.md")).unwrap();
        assert!(document.contains("Actions/s"), "{document}");
        assert!(document.contains(&script.action_digest));
        assert!(!document.contains(&server.socket_str()));
        assert!(!document.contains(namespace));
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.path().join("report.json")).unwrap())
                .unwrap();
        assert_eq!(json["contract_version"], "sekai.game-soak-report/v1");
        digests.push(report.workload.action_digest);
    }
    assert_eq!(digests[0], digests[1]);
    assert_eq!(server.panics(), 0, "{}", server.logs());
}
