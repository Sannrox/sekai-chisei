use std::process::Command;

pub fn emit() {
    println!("cargo:rerun-if-env-changed=SEKAI_GIT_VERSION");
    println!("cargo:rerun-if-env-changed=SEKAI_GIT_COMMIT");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");

    let pkg = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let version = first_nonempty(&[
        env_nonempty("SEKAI_GIT_VERSION"),
        git(&["describe", "--tags", "--always", "--dirty"]),
    ])
    .unwrap_or(pkg);
    let commit = first_nonempty(&[
        env_nonempty("SEKAI_GIT_COMMIT"),
        git(&["rev-parse", "HEAD"]),
    ])
    .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SEKAI_GIT_VERSION={version}");
    println!("cargo:rustc-env=SEKAI_GIT_COMMIT={commit}");
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn first_nonempty(candidates: &[Option<String>]) -> Option<String> {
    candidates.iter().cloned().find_map(|value| value)
}
