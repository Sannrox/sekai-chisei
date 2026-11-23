//! Isolated SDK consumer installation and core-loop parity (#840).

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::client_package::{
    ClientPackage, LANG_PYTHON, LANG_RUST, LANG_TYPESCRIPT, PACKAGE_CONTRACT, PACKAGE_UNAVAILABLE,
    artifacts_from, publish_client_package, smoke_client_package, verify_client_package,
};
use sekai_client::{
    CallOptions, ClientConfig, CoreLoopClient, CoreLoopTransport, ExecutePlanRequest,
    ExecutePlanStreamEvent, ExecutionInput, ExecutionPlan, GetOperationReceiptRequest,
    GetOperationReceiptResponse, PlanExecutionRequest, PlanExecutionResponse,
    ReportOperationEventRequest, ReportOperationEventResponse,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use tonic::{Request, Response, Status};

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

/// The tarball name from `npm pack --json` output. Lifecycle scripts print
/// banner lines before the JSON array, so parsing starts at the array.
fn packed_filename(pack_out: &str) -> String {
    let start = if pack_out.starts_with('[') {
        0
    } else {
        pack_out
            .find("\n[")
            .map(|at| at + 1)
            .unwrap_or_else(|| panic!("npm pack printed no JSON array: {pack_out}"))
    };
    let rows: serde_json::Value = serde_json::from_str(&pack_out[start..])
        .unwrap_or_else(|error| panic!("npm pack JSON did not parse ({error}): {pack_out}"));
    rows[0]["filename"]
        .as_str()
        .unwrap_or_else(|| panic!("npm pack JSON names no filename: {pack_out}"))
        .to_string()
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
#[ignore = "requires python3 and node on PATH; CI runs it with --ignored"]
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

    for (id, artifacts) in [
        ("pkg:rust-0.1.0", &rust_art),
        ("pkg:typescript-0.1.0", &ts_art),
        ("pkg:python-0.1.0", &py_art),
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

    // The staged SDK test suites run against the isolated fixture copy.
    run_in(
        &python,
        "python3",
        &["-m", "unittest", "test_sekai_client.py", "-v"],
    );
    run_in(&typescript, "node", &["--test", "client.test.ts"]);

    // Each SDK runs its own core loop against the fixture, so parity compares
    // the identity every SDK derives rather than a reread of the shared JSON.
    let expected = ["operation-1", "request-1", "plan-1"]
        .map(String::from)
        .to_vec();
    assert_eq!(rust_core_loop_identity(), expected, "rust");
    fs::write(python.join("core_loop_probe.py"), PYTHON_CORE_LOOP_PROBE).unwrap();
    let python_ids = run_in(&python, "python3", &["core_loop_probe.py"]);
    assert_eq!(identity_lines(&python_ids), expected, "python");
    fs::write(
        typescript.join("core_loop_probe.ts"),
        TYPESCRIPT_CORE_LOOP_PROBE,
    )
    .unwrap();
    let ts_ids = run_in(&typescript, "node", &["core_loop_probe.ts"]);
    assert_eq!(identity_lines(&ts_ids), expected, "typescript");
}

/// The non-empty lines a core-loop probe prints: operation id, request id, plan id.
fn identity_lines(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect()
}

/// Runs the staged Python SDK's `run_core_loop` against `v1.json` through a
/// transport that answers each call from the fixture.
const PYTHON_CORE_LOOP_PROBE: &str = r#"import json
from pathlib import Path

from sekai_client import ClientConfig, SekaiChiseiClient

FIXTURE = json.loads(Path("v1.json").read_text())


class Transport:
    def unary(self, service, method, request, options):
        if method == "CreateSchemaType":
            return {"type": request["type"]}
        if method == "CreateObject":
            return {"object": request["object"]}
        if method == "CreateLink":
            return {"link": request["link"]}
        if method == "PlanExecution":
            return {"plan": FIXTURE["plan"]}
        if method == "GetOperationReceipt":
            return FIXTURE["receipt"]
        raise AssertionError(f"unexpected {service}.{method}")

    def stream(self, service, method, request, options):
        if method != "ExecutePlanStream":
            raise AssertionError(f"unexpected {service}.{method}")
        return iter(FIXTURE["stream_events"])

    def close(self):
        pass


client = SekaiChiseiClient(
    ClientConfig(
        principal=FIXTURE["principal"],
        token=FIXTURE["token"],
        namespace=FIXTURE["namespace"],
        catalog_version=FIXTURE["catalog_version"],
    ),
    Transport(),
)
result = client.run_core_loop(
    FIXTURE["namespace"],
    FIXTURE["objects"],
    FIXTURE["execution"],
    schema=FIXTURE["schema"],
    links=FIXTURE["links"],
    operation_id=FIXTURE["operation_id"],
)
assert result["events"] == FIXTURE["stream_events"], result["events"]
assert result["receipt"] == FIXTURE["receipt"], result["receipt"]
print(result["operation_id"])
print(result["request_id"])
print(result["plan"]["plan_id"])
"#;

/// Runs the staged TypeScript SDK's `runCoreLoop` against `v1.json` through a
/// transport that answers each call from the fixture.
const TYPESCRIPT_CORE_LOOP_PROBE: &str = r#"import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { SekaiChiseiClient } from "./client.ts";

const fixture = JSON.parse(readFileSync(new URL("./v1.json", import.meta.url), "utf8"));
const transport = {
  async unary(service, method, request) {
    if (method === "CreateSchemaType") return { type: request.type };
    if (method === "CreateObject") return { object: request.object };
    if (method === "CreateLink") return { link: request.link };
    if (method === "PlanExecution") return { plan: fixture.plan };
    if (method === "GetOperationReceipt") return fixture.receipt;
    throw new Error(`unexpected ${service}.${method}`);
  },
  stream(service, method) {
    if (method !== "ExecutePlanStream") throw new Error(`unexpected ${service}.${method}`);
    return (async function* () {
      yield* fixture.stream_events;
    })();
  },
};
const client = new SekaiChiseiClient({
  principal: fixture.principal,
  token: fixture.token,
  namespace: fixture.namespace,
  catalogVersion: fixture.catalog_version,
  transport,
});
const result = await client.runCoreLoop({
  namespace: fixture.namespace,
  schema: fixture.schema,
  objects: fixture.objects,
  links: fixture.links,
  execution: fixture.execution,
  operationId: fixture.operation_id,
});
assert.deepEqual(result.events, fixture.stream_events);
assert.deepEqual(result.receipt, fixture.receipt);
console.log(result.operationId);
console.log(result.requestId);
console.log(result.plan.plan_id);
"#;

/// Answers the Rust SDK's plan, stream and receipt calls from `v1.json`.
struct RustFixtureTransport(serde_json::Value);

#[async_trait::async_trait]
impl CoreLoopTransport for RustFixtureTransport {
    type Stream = futures::stream::Iter<std::vec::IntoIter<Result<ExecutePlanStreamEvent, Status>>>;

    async fn plan_execution(
        &self,
        request: Request<PlanExecutionRequest>,
    ) -> Result<Response<PlanExecutionResponse>, Status> {
        let plan = &self.0["plan"];
        Ok(Response::new(PlanExecutionResponse {
            plan: Some(ExecutionPlan {
                plan_id: plan["plan_id"].as_str().unwrap().into(),
                input: request.into_inner().input,
                resolved_model: plan["resolved_model"].as_str().unwrap().into(),
                executable: plan["executable"].as_bool().unwrap(),
                ..Default::default()
            }),
        }))
    }

    async fn execute_plan_stream(
        &self,
        _request: Request<ExecutePlanRequest>,
    ) -> Result<Response<Self::Stream>, Status> {
        let events: Vec<_> = self.0["stream_events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| {
                Ok(ExecutePlanStreamEvent {
                    content_delta: event["content_delta"].as_str().unwrap().into(),
                    done: event["done"].as_bool().unwrap(),
                    ..Default::default()
                })
            })
            .collect();
        Ok(Response::new(futures::stream::iter(events)))
    }

    async fn report_operation_event(
        &self,
        _request: Request<ReportOperationEventRequest>,
    ) -> Result<Response<ReportOperationEventResponse>, Status> {
        Err(Status::unimplemented("the core loop reports no events"))
    }

    async fn get_operation_receipt(
        &self,
        _request: Request<GetOperationReceiptRequest>,
    ) -> Result<Response<GetOperationReceiptResponse>, Status> {
        let receipt = &self.0["receipt"];
        Ok(Response::new(GetOperationReceiptResponse {
            receipt_json: receipt["receipt_json"].as_str().unwrap().into(),
            complete: receipt["complete"].as_bool().unwrap(),
            missing_surfaces: Vec::new(),
        }))
    }
}

/// Runs the Rust SDK's `run_core_loop` against `v1.json` and returns the
/// operation id, request id and plan id it reports.
fn rust_core_loop_identity() -> Vec<String> {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let text = |value: &serde_json::Value| value.as_str().unwrap().to_string();
    let config = ClientConfig::for_injected(text(&fixture["principal"]))
        .with_token(text(&fixture["token"]))
        .unwrap()
        .with_namespace(text(&fixture["namespace"]))
        .with_catalog_version(text(&fixture["catalog_version"]));
    let execution = &fixture["execution"];
    let input = ExecutionInput {
        request_id: text(&execution["request_id"]),
        namespace: text(&execution["namespace"]),
        spec: text(&execution["spec"]),
        task_type: text(&execution["task_type"]),
        max_tokens: execution["max_tokens"].as_i64().unwrap() as i32,
        logical_operation_id: text(&execution["logical_operation_id"]),
        ..Default::default()
    };
    let client = CoreLoopClient::new(config, RustFixtureTransport(fixture.clone())).unwrap();
    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(client.run_core_loop(
            input,
            CallOptions::new().with_operation_id(text(&fixture["operation_id"])),
        ))
        .unwrap();
    let deltas: Vec<_> = result
        .events
        .iter()
        .map(|event| event.content_delta.as_str())
        .collect();
    assert_eq!(deltas, ["incident ", "summary"]);
    assert!(result.receipt.complete);
    vec![result.operation_id, result.request_id, result.plan.plan_id]
}

/// Pack TypeScript and Python SDKs and install them into a directory that
/// has no in-repo path. Clerk publication records are not the install source.
#[test]
#[ignore = "requires network access to the public package registries plus python3, node, and npm; CI runs it with --ignored"]
fn isolated_registry_packs_install_without_an_in_repo_path() {
    let (root, _rust, typescript, python, _proto, _proto_crate) = stage_consumers();
    require_tool("python3");
    require_tool("node");
    require_tool("npm");

    run_in(&typescript, "npm", &["install", "--ignore-scripts"]);
    run_in(&typescript, "npm", &["run", "build"]);
    let pack_out = run_in(&typescript, "npm", &["pack", "--json"]);
    let tarball = packed_filename(&pack_out);
    let tarball_path = typescript.join(&tarball);
    assert!(
        tarball_path.is_file(),
        "npm pack did not write {tarball}: {pack_out}"
    );

    let ts_consumer = root.path().join("ts-from-pack");
    fs::create_dir_all(&ts_consumer).unwrap();
    fs::write(
        ts_consumer.join("package.json"),
        r#"{"name":"sekai-sdk-pack-consumer","type":"module","private":true}"#,
    )
    .unwrap();
    run_in(
        &ts_consumer,
        "npm",
        &[
            "install",
            tarball_path.to_str().expect("tarball path"),
            "@grpc/grpc-js",
            "@grpc/proto-loader",
        ],
    );
    let ts_import = run_in(
        &ts_consumer,
        "node",
        &[
            "--input-type=module",
            "-e",
            "import { SDK_CONTRACT_VERSION, SekaiChiseiClient } from '@sannrox/sekai-chisei-sdk'; import { HTTP_PROJECTION_CONTRACT } from '@sannrox/sekai-chisei-sdk/http'; if (typeof SekaiChiseiClient.connect !== 'function') throw new Error('runCoreLoop client missing'); console.log(SDK_CONTRACT_VERSION); console.log(HTTP_PROJECTION_CONTRACT);",
        ],
    );
    assert!(
        ts_import.contains("sekai.sdk-core-loop/v1"),
        "typescript pack install missing contract: {ts_import}"
    );
    assert!(
        ts_import.contains("sekai.http-projection/v1"),
        "typescript pack install missing HTTP client: {ts_import}"
    );
    // The lockfile must resolve the SDK to the packed tarball, never to a
    // linked source directory.
    let ts_lock: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(ts_consumer.join("package-lock.json"))
            .expect("npm install writes package-lock.json"),
    )
    .expect("package-lock.json is JSON");
    let sdk_entry = &ts_lock["packages"]["node_modules/@sannrox/sekai-chisei-sdk"];
    let resolved = sdk_entry["resolved"].as_str().unwrap_or_default();
    assert!(
        resolved.ends_with(&format!("/{tarball}")) && sdk_entry.get("link").is_none(),
        "typescript consumer does not resolve the SDK to {tarball}: {sdk_entry}"
    );

    let py_wheel = root.path().join("py-wheels");
    fs::create_dir_all(&py_wheel).unwrap();
    run_in(
        &python,
        "python3",
        &[
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            py_wheel.to_str().expect("wheel dir"),
            ".",
        ],
    );
    let wheel = fs::read_dir(&py_wheel)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".whl"))
        })
        .expect("python wheel");
    let py_consumer = root.path().join("py-from-wheel");
    fs::create_dir_all(&py_consumer).unwrap();
    run_in(
        &py_consumer,
        "python3",
        &[
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            py_consumer.to_str().expect("py consumer"),
            wheel.to_str().expect("wheel path"),
        ],
    );
    let py_import = Command::new("python3")
        .env("PYTHONPATH", &py_consumer)
        .args([
            "-c",
            "from sekai_client import SDK_CONTRACT_VERSION, SekaiChiseiClient; from sekai_http import HTTP_PROJECTION_CONTRACT; assert hasattr(SekaiChiseiClient, 'run_core_loop'); print(SDK_CONTRACT_VERSION); print(HTTP_PROJECTION_CONTRACT)",
        ])
        .output()
        .expect("python import from wheel");
    assert!(
        py_import.status.success(),
        "python wheel import failed: {}\n{}",
        String::from_utf8_lossy(&py_import.stderr),
        String::from_utf8_lossy(&py_import.stdout)
    );
    let py_out = String::from_utf8(py_import.stdout).expect("utf8");
    assert!(
        py_out.contains("sekai.sdk-core-loop/v1"),
        "python pack install missing contract: {py_out}"
    );
    assert!(
        py_out.contains("sekai.http-projection/v1"),
        "python pack install missing HTTP client: {py_out}"
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
