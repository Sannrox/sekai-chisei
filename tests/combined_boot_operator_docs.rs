//! Combined first-success docs must name dest-pair boot, not a lone DB_PATH.

use std::fs;
use std::path::Path;

fn read(rel: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(rel)).unwrap_or_else(|error| {
        panic!("read {rel}: {error}");
    })
}

fn assert_dest_pair(rel: &str) {
    let text = read(rel);
    assert!(
        text.contains("SEKAI_DB_PATH") && text.contains("CHISEI_DB_PATH"),
        "{rel} must name Combined dest-pair SEKAI_DB_PATH and CHISEI_DB_PATH"
    );
}

#[test]
fn combined_first_success_docs_name_dest_pair() {
    for rel in [
        "README.md",
        "CONTRIBUTING.md",
        "AGENTS.md",
        "docs/docker.md",
        "docs/operator-console.md",
        "docs/ontology.md",
        "examples/README.md",
        "docs/configuration.md",
        "docs/two-plane-processes.md",
    ] {
        assert_dest_pair(rel);
    }
}

#[test]
fn docker_image_and_docs_never_boot_a_single_store() {
    let image = read("build/server-image/Dockerfile");
    assert!(
        image.contains("SEKAI_DATA_DIR=/data") && !image.contains("DB_PATH"),
        "the server image must derive split stores from SEKAI_DATA_DIR, not export DB_PATH"
    );
    let docker = read("docs/docker.md");
    assert!(
        docker.contains("store relocate"),
        "docs/docker.md must point a legacy single-file volume at store relocate"
    );
    let compose = read("docker-compose.yml");
    assert!(
        compose.contains("SEKAI_DB_PATH=/data/sekai.db")
            && compose.contains("CHISEI_DB_PATH=/data/chisei.db"),
        "docker-compose.yml must set Combined dest-pair on /data"
    );
}

#[test]
fn readme_combined_cargo_run_boots_split_without_env() {
    let readme = read("README.md");
    assert!(
        readme.contains("SEKAI_INSECURE=1 cargo run") && readme.contains("SEKAI_DATA_DIR"),
        "README Combined cargo run must boot split under SEKAI_DATA_DIR without .env"
    );
    assert!(
        readme.contains(
            "SEKAI_INSECURE=1 SEKAI_DB_PATH=./data/sekai.db CHISEI_DB_PATH=./data/chisei.db cargo run"
        ),
        "README must show the explicit dest-pair override"
    );
    assert!(
        readme.contains("cargo run") && readme.contains("does not load `.env`"),
        "README must say cargo run does not load .env"
    );
}
