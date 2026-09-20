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
fn docker_operator_docs_name_shared_store_hatch() {
    let docker = read("docs/docker.md");
    assert!(
        docker.contains("SEKAI_SHARED_STORE"),
        "docs/docker.md must name SEKAI_SHARED_STORE; the image still sets DB_PATH"
    );
    let compose = read("docker-compose.yml");
    assert!(
        compose.contains("SEKAI_DB_PATH=/data/sekai.db")
            && compose.contains("CHISEI_DB_PATH=/data/chisei.db"),
        "docker-compose.yml must set Combined dest-pair on /data"
    );
}

#[test]
fn readme_combined_cargo_run_exports_dest_pair() {
    let readme = read("README.md");
    assert!(
        readme.contains(
            "SEKAI_INSECURE=1 SEKAI_DB_PATH=./data/sekai.db CHISEI_DB_PATH=./data/chisei.db cargo run"
        ),
        "README Combined cargo run must export dest-pair; cargo run does not load .env"
    );
    assert!(
        readme.contains("cargo run") && readme.contains("does not load `.env`"),
        "README must say cargo run does not load .env"
    );
}
