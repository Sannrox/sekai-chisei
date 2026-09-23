//! Process-level proof that `sekaictl ontology context`, `expand`, and
//! `explain` are real consumers of the promoted `RetrieveContext`,
//! `ExpandRelations`, and `ExplainDerivation` RPCs (#1087). The server runs
//! with the default gate, so the RPCs must not need `SEKAI_EXPERIMENTAL_RPCS`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const WAIT_BUDGET: Duration = Duration::from_secs(20);

struct Running {
    child: Child,
    socket: PathBuf,
    log_path: PathBuf,
    _dir: tempfile::TempDir,
}

impl Running {
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("sekai.sock");
        let log_path = dir.path().join("server.log");
        let log = std::fs::File::create(&log_path).expect("server log");
        let child = Command::new(env!("CARGO_BIN_EXE_sekai-chisei"))
            .env("SEKAI_SOCKET", &socket)
            .env("DB_PATH", dir.path().join("sekai.db"))
            .env("SEKAI_SHARED_STORE", "1")
            .env("GRPC_PORT", free_tcp_port().to_string())
            .env("OPS_PORT", "")
            .env("OPS_BIND", "127.0.0.1")
            .env("RUST_LOG", "error")
            .env_remove("SEKAI_EXPERIMENTAL_RPCS")
            .env_remove("SEKAI_INSECURE")
            .env_remove("SEKAI_CREDENTIAL")
            .env_remove("SEKAI_BIND")
            .env_remove("SEKAI_ALLOW_PLAINTEXT")
            .env_remove("SEKAI_DB_BACKEND")
            .env_remove("DATABASE_URL")
            .env_remove("SEKAI_DB_PATH")
            .env_remove("CHISEI_DB_PATH")
            .env_remove("OLLAMA_URL")
            .env_remove("OPENAI_API_KEY")
            .env_remove("ANTHROPIC_API_KEY")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn sekai-chisei");
        let mut running = Self {
            child,
            socket,
            log_path,
            _dir: dir,
        };
        let deadline = Instant::now() + WAIT_BUDGET;
        loop {
            if std::os::unix::net::UnixStream::connect(&running.socket).is_ok() {
                return running;
            }
            if let Some(status) = running.child.try_wait().expect("poll server") {
                panic!("server exited {status}\n{}", running.logs());
            }
            assert!(
                Instant::now() < deadline,
                "server not ready\n{}",
                running.logs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn sekaictl(&self, args: &[&str]) -> Output {
        let socket = self.socket.to_str().expect("utf8 socket").to_string();
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--target", socket.as_str()]);
        Command::new(env!("CARGO_BIN_EXE_sekaictl"))
            .args(&full)
            .env("SEKAI_SOCKET", &self.socket)
            .env_remove("CHISEI_GRPC_URL")
            .env_remove("SEKAI_CREDENTIAL")
            .output()
            .expect("run sekaictl")
    }

    fn ok(&self, args: &[&str]) -> String {
        let output = self.sekaictl(args);
        assert!(
            output.status.success(),
            "{args:?} failed\nstdout: {}\nstderr: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            self.logs()
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn fixture(relative: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(relative)
        .to_str()
        .expect("utf8 fixture")
        .to_string()
}

#[test]
fn sekaictl_reads_context_expansion_and_derivation_without_the_experimental_gate() {
    let server = Running::start();
    server.ok(&[
        "ontology",
        "apply",
        "--file",
        &fixture("tests/fixtures/product_loop/domain-v1.json"),
    ]);
    server.ok(&[
        "ontology",
        "seed",
        "--file",
        &fixture("tests/fixtures/product_loop/seed-v1.json"),
    ]);

    let context = server.ok(&["ontology", "context", "--object", "inc-1", "--depth", "1"]);
    assert!(context.contains("object: inc-1"), "{context}");
    assert!(context.contains("object: svc-api"), "{context}");
    assert!(context.contains("-[affects]-> svc-api"), "{context}");

    let expanded = server.ok(&[
        "ontology",
        "expand",
        "--namespace",
        "demo",
        "--object",
        "inc-1",
        "--relation",
        "affects",
    ]);
    assert!(expanded.contains("object: svc-api"), "{expanded}");
    assert!(expanded.contains("mode=asserted_only"), "{expanded}");

    let explained = server.ok(&[
        "ontology",
        "explain",
        "--namespace",
        "demo",
        "--from",
        "inc-1",
        "--to",
        "svc-api",
    ]);
    assert!(explained.contains("found=true"), "{explained}");
}
