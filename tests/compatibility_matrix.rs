//! Compatibility matrix projection and consumer pin check (#873).

use sekai_chisei::compatibility_matrix::{
    self, CompatibilityMatrix, MATRIX_CONTRACT, check_consumer, protocol_revision,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn workspace_matrix() -> CompatibilityMatrix {
    CompatibilityMatrix::from_workspace(".").expect("workspace matrix")
}

#[test]
fn committed_matrix_matches_workspace_projection_and_proto_revision() {
    let generated = workspace_matrix();
    let committed =
        CompatibilityMatrix::from_path("compatibility.json").expect("committed compatibility.json");
    assert_eq!(generated.contract_version, MATRIX_CONTRACT);
    assert_eq!(generated, committed);
    assert_eq!(
        generated.proto_revision,
        protocol_revision(".").expect("proto revision")
    );
    assert_eq!(
        generated.to_pretty_json().expect("encode"),
        fs::read_to_string("compatibility.json").expect("read committed matrix")
    );
}

#[test]
fn public_rust_consumers_pass_after_one_coordinated_bump() {
    let matrix = workspace_matrix();
    let delivery = check_consumer(&matrix, Path::new("crates/sekai-client")).unwrap();
    assert!(
        delivery.is_on_matrix(),
        "sekai-client must pin the on-matrix proto revision: {}",
        delivery.report()
    );
    let admin = check_consumer(&matrix, Path::new("crates/sekai-admin-client")).unwrap();
    assert!(
        admin.is_on_matrix(),
        "sekai-admin-client must pin the on-matrix proto revision after the coordinated bump: {}",
        admin.report()
    );

    let root = TempDir::new().unwrap();
    let harness = root.path().join("agent-harness");
    fs::create_dir_all(&harness).unwrap();
    fs::write(
        harness.join("Cargo.toml"),
        format!(
            "[package]\nname = \"agent-harness\"\nversion = \"0.0.1\"\nedition = \"2024\"\n\n[dependencies]\nsekai-client = \"={}\"\nsekai-proto = \"={}\"\n",
            matrix.packages.sekai_client, matrix.packages.sekai_proto
        ),
    )
    .unwrap();
    let harness_check = check_consumer(&matrix, &harness).unwrap();
    assert!(
        harness_check.is_on_matrix(),
        "coordinated rust consumer must pass: {}",
        harness_check.report()
    );
}

#[test]
fn tampered_git_rev_pin_names_the_expected_on_matrix_revision() {
    let matrix = workspace_matrix();
    let root = TempDir::new().unwrap();
    let consumer = root.path().join("stale-harness");
    fs::create_dir_all(&consumer).unwrap();
    fs::write(
        consumer.join("Cargo.toml"),
        "[package]\nname = \"stale-harness\"\nversion = \"0.0.1\"\n\n[dependencies]\nsekai-client = { git = \"https://github.com/Sannrox/sekai-chisei\", rev = \"deadbeefcafebabe\" }\n",
    )
    .unwrap();
    let check = check_consumer(&matrix, &consumer).unwrap();
    assert!(!check.is_on_matrix());
    assert!(
        check.summary.contains("deadbeefcafebabe"),
        "{}",
        check.summary
    );
    assert!(
        check.summary.contains(&matrix.packages.sekai_client),
        "{}",
        check.summary
    );
    assert!(
        check.summary.contains(&matrix.proto_revision),
        "{}",
        check.summary
    );
}

#[test]
fn vendored_typescript_copy_is_off_matrix_until_replaced() {
    let matrix = workspace_matrix();
    let sdk = check_consumer(&matrix, Path::new("sdk/typescript")).unwrap();
    assert!(
        !sdk.is_on_matrix(),
        "in-repo TypeScript source must stay off-matrix until replaced by a package pin: {}",
        sdk.report()
    );
    assert!(
        sdk.summary.contains("vendored TypeScript copy"),
        "{}",
        sdk.summary
    );
    assert!(
        sdk.summary.contains(&matrix.proto_revision),
        "{}",
        sdk.summary
    );
}

#[test]
fn generate_round_trips_the_committed_matrix() {
    let matrix = workspace_matrix();
    let root = TempDir::new().unwrap();
    let out = root.path().join("compatibility.json");
    compatibility_matrix::write_matrix(&out, &matrix).unwrap();
    assert_eq!(
        CompatibilityMatrix::from_path(&out).unwrap(),
        CompatibilityMatrix::from_path("compatibility.json").unwrap()
    );
}
