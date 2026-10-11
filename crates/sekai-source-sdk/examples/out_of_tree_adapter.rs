//! Out-of-tree adapter: depends only on `sekai-source-sdk`.
//!
//! Builds one snapshot batch from a fake source, persists it in the outbox,
//! and runs the offline conformance kit.

use sekai_source_sdk::{
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, GitHubObjectFixture, SDK_VERSION, SourceAdapterConfig,
    SourceOutbox, assert_deterministic_batch, assert_files_omit, build_source_batch,
    conformance_suite_digest, github_issue_lifecycle_fixture, run_lifecycle_fixture,
    translate_github_fixture,
};
use std::collections::BTreeMap;
use std::env;
use std::fs;

fn main() -> Result<(), String> {
    let fixture = GitHubObjectFixture {
        repository: "sannrox/sekai-chisei".into(),
        kind: "Issue".into(),
        number: 674,
        revision: "issue-674-v1".into(),
        title: "Connector lifecycle conformance".into(),
        state: "open".into(),
        deleted: false,
        observed_at_ms: 1_787_510_500_000,
        properties: BTreeMap::from([("author".into(), "sannrox".into())]),
    };
    let record = translate_github_fixture(fixture, "sannrox/sekai-chisei")?;
    let config = SourceAdapterConfig {
        namespace: "acme".into(),
        producer_identity: "connector/out-of-tree".into(),
        source_instance: "sannrox/sekai-chisei".into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
    };
    let first = build_source_batch(
        &config,
        "",
        "cursor-1",
        record.observed_at_ms,
        vec![record.clone()],
    )?;
    let second = build_source_batch(&config, "", "cursor-1", record.observed_at_ms, vec![record])?;
    assert_deterministic_batch(&first, &second)?;

    let root = env::temp_dir().join(format!(
        "sekai-source-sdk-out-of-tree-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock")?
            .as_nanos()
    ));
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let outbox = SourceOutbox::open(&root, Default::default())?;
    outbox.enqueue(&first)?;
    assert_files_omit(&root, &["BEGIN PRIVATE KEY", "github_pat_"])?;

    let report = run_lifecycle_fixture("adapter.github.object_sync", |observation| {
        let number = observation
            .external_id
            .parse::<u64>()
            .map_err(|_| "id".to_string())?;
        translate_github_fixture(
            GitHubObjectFixture {
                repository: observation.source_instance.clone(),
                kind: observation.type_name.clone(),
                number,
                revision: observation.source_version.clone(),
                title: observation.display_name.clone(),
                state: observation.state.clone(),
                deleted: observation.deleted,
                observed_at_ms: observation.observed_at_ms,
                properties: observation.properties.clone(),
            },
            &observation.source_instance,
        )
    })?;
    assert_eq!(
        report.projections.len(),
        github_issue_lifecycle_fixture().observations.len()
    );

    println!("sdk_version={SDK_VERSION}");
    println!("conformance_suite_digest={}", conformance_suite_digest());
    println!("idempotency_key={}", first.idempotency_key);
    let _ = fs::remove_dir_all(&root);
    Ok(())
}
