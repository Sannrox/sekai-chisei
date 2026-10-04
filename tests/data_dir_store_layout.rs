//! `SEKAI_DATA_DIR` derives the Sekai and Chisei SQLite files when no store
//! variable is set; each plane process opens only its own file (#1238).

use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::tempdir;

const STORE_VARS: &[&str] = &[
    "SEKAI_DATA_DIR",
    "DB_PATH",
    "SEKAI_DB_PATH",
    "CHISEI_DB_PATH",
    "DATABASE_URL",
    "SEKAI_DATABASE_URL",
    "CHISEI_DATABASE_URL",
    "SEKAI_DB_BACKEND",
    "SEKAI_SHARED_STORE",
    "SEKAI_STORE_PEER",
    "CHISEI_PROVIDER_REGISTRY_STATE_PATH",
    "SEKAI_CREDENTIAL",
];

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start `bin` with no store variable except `extras`, wait until it serves,
/// then stop it.
fn boot(bin: &str, cwd: &Path, extras: &[(&str, &str)]) {
    let port = free_port();
    let mut command = Command::new(bin);
    command
        .current_dir(cwd)
        .env("SEKAI_INSECURE", "1")
        .env("SEKAI_BIND", "127.0.0.1")
        .env("GRPC_PORT", port.to_string())
        .env("SEKAI_SOCKET", "")
        .env("OPS_PORT", "")
        .env("SEKAI_HTTP_PORT", "")
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for key in STORE_VARS {
        command.env_remove(key);
    }
    for (key, value) in extras {
        command.env(key, value);
    }
    let mut child = Running(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("{bin} exited before serving: {status}");
        }
        assert!(Instant::now() < deadline, "{bin} did not become ready");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn combined_without_store_vars_boots_split_under_default_data_dir() {
    let cwd = tempdir().unwrap();
    boot(env!("CARGO_BIN_EXE_sekai-chisei"), cwd.path(), &[]);
    assert!(cwd.path().join("data/sekai.db").is_file());
    assert!(cwd.path().join("data/chisei.db").is_file());
}

#[test]
fn each_plane_derives_only_its_own_file_from_the_data_dir() {
    let cwd = tempdir().unwrap();
    let sekai_dir = cwd.path().join("sekai-data");
    let chisei_dir = cwd.path().join("chisei-data");

    boot(
        env!("CARGO_BIN_EXE_sekai-plane"),
        cwd.path(),
        &[("SEKAI_DATA_DIR", sekai_dir.to_str().unwrap())],
    );
    assert!(sekai_dir.join("sekai.db").is_file());
    assert!(!sekai_dir.join("chisei.db").exists());

    boot(
        env!("CARGO_BIN_EXE_chisei-plane"),
        cwd.path(),
        &[
            ("SEKAI_DATA_DIR", chisei_dir.to_str().unwrap()),
            ("SEKAI_ENDPOINT", "http://127.0.0.1:1"),
        ],
    );
    assert!(chisei_dir.join("chisei.db").is_file());
    assert!(!chisei_dir.join("sekai.db").exists());
}

#[test]
fn explicit_store_paths_override_the_data_dir() {
    let cwd = tempdir().unwrap();
    let data_dir = cwd.path().join("data-dir");
    let sekai = cwd.path().join("explicit/s.db");
    let chisei = cwd.path().join("explicit/c.db");
    std::fs::create_dir_all(sekai.parent().unwrap()).unwrap();

    boot(
        env!("CARGO_BIN_EXE_sekai-chisei"),
        cwd.path(),
        &[
            ("SEKAI_DATA_DIR", data_dir.to_str().unwrap()),
            ("SEKAI_DB_PATH", sekai.to_str().unwrap()),
            ("CHISEI_DB_PATH", chisei.to_str().unwrap()),
        ],
    );
    assert!(sekai.is_file());
    assert!(chisei.is_file());
    assert!(!data_dir.join("sekai.db").exists());
    assert!(!data_dir.join("chisei.db").exists());
}
