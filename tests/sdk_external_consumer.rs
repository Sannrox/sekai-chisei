//! Isolated SDK consumer installation and core-loop parity (#840).

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::client_package::{
    ClientPackage, LANG_PYTHON, LANG_RUST, LANG_TYPESCRIPT, PACKAGE_CONTRACT, PACKAGE_UNAVAILABLE,
    artifacts_from, publish_client_package, smoke_client_package, verify_client_package,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const FIXTURE: &str = include_str!("../tests/fixtures/sdk_core_loop/v1.json");
const ACTOR: &str = "integrator";

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some("node_modules" | "target" | "dist" | "__pycache__")
        ) {
            continue;
        }
        let dest = to.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

fn stage_consumers() -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let root = TempDir::new().unwrap();
    let rust = root.path().join("rust");
    let typescript = root.path().join("typescript");
    let python = root.path().join("python");
    let proto = root.path().join("proto");
    let proto_crate = root.path().join("sekai-proto");
    copy_tree(Path::new("crates/sekai-client"), &rust);
    copy_tree(Path::new("crates/sekai-proto"), &proto_crate);
    copy_tree(Path::new("sdk/typescript"), &typescript);
    copy_tree(Path::new("sdk/python"), &python);
    copy_tree(Path::new("proto"), &proto);
    fs::write(root.path().join("core-loop.json"), FIXTURE).unwrap();
    fs::copy(
        "tests/fixtures/sdk_core_loop/v1.json",
        python.join("v1.json"),
    )
    .unwrap();
    fs::copy(
        "tests/fixtures/sdk_core_loop/v1.json",
        typescript.join("v1.json"),
    )
    .unwrap();
    fs::copy("tests/fixtures/sdk_core_loop/v1.json", rust.join("v1.json")).unwrap();
    (root, rust, typescript, python, proto, proto_crate)
}

fn protocol_from_disk(proto: &Path) -> String {
    let mut protocol = String::new();
    for name in ["sekai.proto", "chisei.proto"] {
        protocol.push_str(&fs::read_to_string(proto.join(name)).unwrap());
        protocol.push('\n');
    }
    protocol
}

fn artifacts_from_disk(
    proto: &Path,
    source_root: &Path,
    package_file: &Path,
) -> sekai_chisei::sekai::client_package::PackageArtifacts {
    artifacts_from(
        &protocol_from_disk(proto),
        &tree_text(source_root),
        &fs::read(package_file).unwrap(),
    )
    .unwrap()
}

fn require_tool(name: &str) {
    Command::new(name)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("{name} is required for isolated consumer proof: {error}"));
}

fn run_in(dir: &Path, program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("{program} failed to spawn in {}: {error}", dir.display()));
    assert!(
        output.status.success(),
        "{program} {:?} in {} failed: {}\n{}",
        args,
        dir.display(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn assert_live_identity(label: &str, stdout: &str) {
    for needle in ["operation-1", "service-1", "plan-1"] {
        assert!(
            stdout.contains(needle),
            "{label} stdout missing {needle}: {stdout}"
        );
    }
}

fn package(
    id: &str,
    language: &str,
    name: &str,
    artifacts: &sekai_chisei::sekai::client_package::PackageArtifacts,
) -> ClientPackage {
    ClientPackage {
        contract_version: PACKAGE_CONTRACT.into(),
        package_id: id.into(),
        namespace: "sdk".into(),
        owner: String::new(),
        language: language.into(),
        package_name: name.into(),
        package_version: "0.1.0".into(),
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

fn tree_text(root: &Path) -> String {
    let mut blob = String::new();
    fn walk(path: &Path, blob: &mut String) {
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(&entry.unwrap().path(), blob);
            }
            return;
        }
        if let Ok(text) = fs::read_to_string(path) {
            blob.push_str(&text);
            blob.push('\n');
        }
    }
    walk(root, &mut blob);
    blob
}

#[test]
fn isolated_consumers_install_pinned_artifacts_and_share_core_loop_identity() {
    let (_root, rust, typescript, python, proto, proto_crate) = stage_consumers();
    rewrite_python_fixture(&python);
    rewrite_typescript_fixture(&typescript);
    assert!(proto_crate.join("Cargo.toml").is_file());
    let rust_manifest = fs::read_to_string(rust.join("Cargo.toml")).unwrap();
    assert!(
        rust_manifest.contains("path = \"../sekai-proto\""),
        "staged sekai-client must pin sekai-proto as a sibling path"
    );
    assert!(
        rust.join("..")
            .join("sekai-proto")
            .join("Cargo.toml")
            .is_file()
    );

    let rust_src = tree_text(&rust);
    let ts_src = tree_text(&typescript);
    let py_src = tree_text(&python);
    for blob in [&rust_src, &ts_src, &py_src] {
        assert!(
            !blob.contains("sekai_chisei::"),
            "consumer imported server implementation"
        );
        assert!(!blob.contains("src/grpc/sekai_service.rs"));
        assert!(
            !blob.contains("../../tests/fixtures/sdk_core_loop/v1.json"),
            "staged consumer still points at the repository fixture"
        );
    }
    assert!(rust_src.contains("sekai.sdk-core-loop/v1"));
    assert!(ts_src.contains("sekai.sdk-core-loop/v1"));
    assert!(py_src.contains("sekai.sdk-core-loop/v1"));

    let rust_lib = fs::read(rust.join("src/lib.rs")).unwrap();
    let db = RuntimeDb::memory();
    let rust_art = artifacts_from_disk(&proto, &rust, &rust.join("src/lib.rs"));
    let ts_art = artifacts_from_disk(&proto, &typescript, &typescript.join("client.ts"));
    let py_art = artifacts_from_disk(&proto, &python, &python.join("sekai_client.py"));
    publish_client_package(
        &db,
        ACTOR,
        &package("pkg:rust-0.1.0", LANG_RUST, "sekai-client", &rust_art),
        &rust_art,
        1_000,
    )
    .unwrap();
    publish_client_package(
        &db,
        ACTOR,
        &package(
            "pkg:typescript-0.1.0",
            LANG_TYPESCRIPT,
            "@sannrox/sekai-chisei-sdk",
            &ts_art,
        ),
        &ts_art,
        1_100,
    )
    .unwrap();
    publish_client_package(
        &db,
        ACTOR,
        &package("pkg:python-0.1.0", LANG_PYTHON, "sekai-chisei-sdk", &py_art),
        &py_art,
        1_200,
    )
    .unwrap();

    let rust_art_disk = artifacts_from_disk(&proto, &rust, &rust.join("src/lib.rs"));
    let ts_art_disk = artifacts_from_disk(&proto, &typescript, &typescript.join("client.ts"));
    let py_art_disk = artifacts_from_disk(&proto, &python, &python.join("sekai_client.py"));
    assert_eq!(rust_art.protocol, rust_art_disk.protocol);
    assert_eq!(rust_art.source, rust_art_disk.source);
    assert_eq!(rust_art.package, rust_art_disk.package);
    assert_eq!(ts_art.protocol, ts_art_disk.protocol);
    assert_eq!(py_art.protocol, py_art_disk.protocol);

    for (id, artifacts) in [
        ("pkg:rust-0.1.0", &rust_art_disk),
        ("pkg:typescript-0.1.0", &ts_art_disk),
        ("pkg:python-0.1.0", &py_art_disk),
    ] {
        let verified = verify_client_package(&db, ACTOR, "sdk", id, artifacts).unwrap();
        assert_eq!(verified.catalog_version, "catalog-v1");
        smoke_client_package(&db, ACTOR, "sdk", id, artifacts).unwrap();
    }

    let mut tampered = rust_lib.clone();
    tampered[0] ^= 0xff;
    let bad = artifacts_from(&protocol_from_disk(&proto), &tree_text(&rust), &tampered).unwrap();
    assert_eq!(
        verify_client_package(&db, ACTOR, "sdk", "pkg:rust-0.1.0", &bad).unwrap_err(),
        PACKAGE_UNAVAILABLE
    );

    let foreign_proto = artifacts_from("other-protocol", &tree_text(&rust), &rust_lib).unwrap();
    assert_eq!(
        verify_client_package(&db, ACTOR, "sdk", "pkg:rust-0.1.0", &foreign_proto).unwrap_err(),
        PACKAGE_UNAVAILABLE
    );

    require_tool("python3");
    require_tool("node");
    require_tool("rustc");

    run_in(
        &python,
        "python3",
        &["-m", "unittest", "test_sekai_client.py", "-v"],
    );

    fs::write(
        rust.join("identity_probe.rs"),
        r#"fn first_string_field(text: &str, key: &str) -> String {
    let needle = format!("\"{key}\": \"");
    let start = text.find(&needle).unwrap_or_else(|| panic!("{key}")) + needle.len();
    let end = text[start..].find('"').expect("closing quote");
    text[start..start + end].to_string()
}

fn main() {
    let text = std::fs::read_to_string("v1.json").expect("v1.json");
    println!("{}", first_string_field(&text, "operation_id"));
    println!("{}", first_string_field(&text, "id"));
    println!("{}", first_string_field(&text, "plan_id"));
}
"#,
    )
    .unwrap();
    run_in(
        &rust,
        "rustc",
        &["identity_probe.rs", "-o", "identity_probe"],
    );
    let rust_out = run_in(&rust, "./identity_probe", &[]);
    assert_live_identity("rust", &rust_out);

    let ts_out = run_in(
        &typescript,
        "node",
        &[
            "--input-type=module",
            "-e",
            "import fs from 'node:fs'; const j = JSON.parse(fs.readFileSync('v1.json','utf8')); for (const v of [j.operation_id, j.objects[0].id, j.plan.plan_id]) console.log(v);",
        ],
    );
    assert_live_identity("typescript", &ts_out);

    let python_ids = run_in(
        &python,
        "python3",
        &[
            "-c",
            "import json; j=json.load(open('v1.json')); print(j['operation_id']); print(j['objects'][0]['id']); print(j['plan']['plan_id'])",
        ],
    );
    assert_live_identity("python", &python_ids);
    assert_eq!(
        rust_out
            .lines()
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>(),
        python_ids
            .lines()
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        ts_out.lines().filter(|l| !l.is_empty()).collect::<Vec<_>>(),
        python_ids
            .lines()
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
    );
}

fn rewrite_python_fixture(python: &Path) {
    let path = python.join("test_sekai_client.py");
    let source = fs::read_to_string(&path).unwrap();
    let rewritten = source.replace(
        "(Path(__file__).parents[2] / \"tests/fixtures/sdk_core_loop/v1.json\")",
        "(Path(__file__).with_name(\"v1.json\"))",
    );
    assert_ne!(source, rewritten, "python fixture path was not isolated");
    fs::write(path, rewritten).unwrap();
}

fn rewrite_typescript_fixture(typescript: &Path) {
    let path = typescript.join("client.test.ts");
    let source = fs::read_to_string(&path).unwrap();
    let rewritten = source.replace(
        "new URL(\"../../tests/fixtures/sdk_core_loop/v1.json\", import.meta.url)",
        "new URL(\"./v1.json\", import.meta.url)",
    );
    assert_ne!(
        source, rewritten,
        "typescript fixture path was not isolated"
    );
    fs::write(path, rewritten).unwrap();
}
