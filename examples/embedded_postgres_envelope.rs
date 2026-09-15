//! Measure the Discussion 906 embedded-PostgreSQL envelope.
//!
//! Cold start ≤ 5 s, on-disk ≤ 200 MB, Linux and macOS CI feasibility.
//! Uses a local `initdb`/`pg_ctl` install when present, and Docker
//! `postgres:17-alpine` when `docker` is available. Not a runtime engine pick.
//!
//! ```text
//! cargo run --release --example embedded_postgres_envelope
//! ```

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    println!("profile=Apple M2 Pro 32GiB Darwin arm64");
    if let Some(bin) = find_postgres_bin() {
        match measure_local(&bin) {
            Ok(()) => {}
            Err(error) => eprintln!("local postgres: {error}"),
        }
    } else {
        println!("local_postgres=absent");
    }
    match measure_docker() {
        Ok(()) => {}
        Err(error) => eprintln!("docker postgres: {error}"),
    }
}

fn find_postgres_bin() -> Option<PathBuf> {
    which("postgres")
        .or_else(|| {
            let homebrew = PathBuf::from("/opt/homebrew/opt/postgresql@17/bin/postgres");
            homebrew.exists().then_some(homebrew)
        })
        .and_then(|path| path.canonicalize().ok().or(Some(path)))
}

fn which(name: &str) -> Option<PathBuf> {
    let output = Command::new("which").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    let path = path.trim();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn measure_local(postgres: &Path) -> Result<(), String> {
    let bin_dir = postgres.parent().ok_or("postgres has no parent")?;
    let prefix = bin_dir.parent().ok_or("postgres prefix missing")?;
    let initdb = bin_dir.join("initdb");
    let pg_ctl = bin_dir.join("pg_ctl");
    let pg_isready = bin_dir.join("pg_isready");
    let root = std::env::temp_dir().join(format!("sekai-pg-envelope-{}", std::process::id()));
    let data = root.join("data");
    let socket = root.join("socket");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&socket).map_err(|e| e.to_string())?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let log = root.join("pg.log");
    let init_started = Instant::now();
    let init = Command::new(&initdb)
        .args([
            "-D",
            data.to_str().unwrap(),
            "-A",
            "trust",
            "-U",
            "postgres",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|e| e.to_string())?;
    if !init.success() {
        return Err("initdb failed".into());
    }
    let initdb_ms = init_started.elapsed().as_millis();
    let socket_dir = socket.to_str().unwrap().to_string();
    let start_existing = |label: &str| -> Result<u128, String> {
        let started = Instant::now();
        let status = Command::new(&pg_ctl)
            .args([
                "-D",
                data.to_str().unwrap(),
                "-l",
                log.to_str().unwrap(),
                "-o",
                &format!("-c listen_addresses='' -c unix_socket_directories='{socket_dir}'"),
                "start",
            ])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("{label} pg_ctl start failed"));
        }
        wait_ready(&pg_isready, &socket_dir)?;
        Ok(started.elapsed().as_millis())
    };
    let first_start_ms = start_existing("first")?;
    let _ = Command::new(&pg_ctl)
        .args(["-D", data.to_str().unwrap(), "stop", "-m", "fast"])
        .status();
    thread::sleep(Duration::from_millis(250));
    let cold_start_ms = start_existing("cold")?;
    let _ = Command::new(&pg_ctl)
        .args(["-D", data.to_str().unwrap(), "stop", "-m", "fast"])
        .status();
    let data_bytes = dir_size(&data)?;
    let prefix_bytes = dir_size(prefix)?;
    let dylib_bytes = linked_library_bytes(postgres)?;
    let complete_bytes = data_bytes
        .saturating_add(prefix_bytes)
        .saturating_add(dylib_bytes);
    println!("local_bin={}", postgres.display());
    println!("local_initdb_ms={initdb_ms}");
    println!("local_first_start_ms={first_start_ms}");
    println!("local_cold_start_ms={cold_start_ms}");
    println!("local_datadir_bytes={data_bytes}");
    println!("local_prefix_bytes={prefix_bytes}");
    println!("local_runtime_dylib_bytes={dylib_bytes}");
    println!("local_complete_footprint_bytes={complete_bytes}");
    println!("local_cold_start_hold={}", cold_start_ms <= 5_000);
    println!(
        "local_footprint_hold={}",
        complete_bytes <= 200 * 1024 * 1024
    );
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

fn wait_ready(pg_isready: &Path, socket_dir: &str) -> Result<(), String> {
    for _ in 0..50 {
        let status = Command::new(pg_isready)
            .args(["-h", socket_dir, "-U", "postgres"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("postgres did not become ready".into())
}

fn linked_library_bytes(postgres: &Path) -> Result<u64, String> {
    let output = Command::new("otool")
        .args(["-L", postgres.to_str().unwrap()])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("otool -L failed".into());
    }
    let text = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    let mut paths = std::collections::BTreeSet::new();
    for line in text.lines().skip(1) {
        let Some(raw) = line.split_whitespace().next() else {
            continue;
        };
        let path = PathBuf::from(raw);
        if let Ok(real) = path.canonicalize() {
            paths.insert(real);
            if let Some(name) = path.file_name().and_then(|name| name.to_str())
                && name.contains("icuuc")
                && let Some(parent) = path.parent()
            {
                for candidate in ["libicudata.78.3.dylib", "libicudata.78.dylib"] {
                    let data = parent.join(candidate);
                    if let Ok(real) = data.canonicalize() {
                        paths.insert(real);
                    }
                }
            }
        }
    }
    let mut total = 0u64;
    for path in paths {
        if let Ok(meta) = fs::metadata(&path) {
            total = total.saturating_add(meta.len());
        }
    }
    Ok(total)
}

fn dir_size(path: &Path) -> Result<u64, String> {
    let output = Command::new("du")
        .args(["-sk", path.to_str().unwrap()])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!("du failed for {}", path.display()));
    }
    let text = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    let kb: u64 = text
        .split_whitespace()
        .next()
        .ok_or("du output empty")?
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    Ok(kb.saturating_mul(1024))
}

fn measure_docker() -> Result<(), String> {
    let inspect = Command::new("docker")
        .args([
            "image",
            "inspect",
            "postgres:17-alpine",
            "--format",
            "{{.Size}}",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !inspect.status.success() {
        return Err("docker image postgres:17-alpine missing".into());
    }
    let image_bytes: u64 = String::from_utf8(inspect.stdout)
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let name = format!("sekai-pg-envelope-{}", std::process::id());
    let _ = Command::new("docker")
        .args(["rm", "-f", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let started = Instant::now();
    let run = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--name",
            &name,
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "postgres:17-alpine",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !run.status.success() {
        return Err(String::from_utf8_lossy(&run.stderr).into());
    }
    let mut ready = false;
    for _ in 0..80 {
        let status = Command::new("docker")
            .args([
                "exec",
                &name,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if !ready {
        let _ = Command::new("docker")
            .args(["rm", "-f", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        return Err("docker postgres did not become ready on 127.0.0.1".into());
    }
    let start_ms = started.elapsed().as_millis();
    let _ = Command::new("docker")
        .args(["rm", "-f", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    println!("docker_image=postgres:17-alpine");
    println!("docker_image_bytes={image_bytes}");
    println!("docker_first_start_ms={start_ms}");
    println!("docker_image_hold={}", image_bytes <= 200 * 1024 * 1024);
    println!("docker_start_hold={}", start_ms <= 5_000);
    Ok(())
}
