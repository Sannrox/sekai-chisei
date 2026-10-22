//! sekaictl admin assurance probes run/summary commands (#1621).
//!
//! `run` is what a scheduler calls: it executes the remote isolation probes
//! once against one allow-listed target and appends to the ledger. Tokens
//! are read from files so they never appear in arguments or logs.

use std::path::{Path, PathBuf};

use crate::probe_runner::{ProbeTarget, TargetGuard, run, weekly_summary};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin assurance probes run --target <endpoint> --tenant <ns> --tenant-token-file <file> \
     --foreign-tenant <ns> --foreign-token-file <file> --foreign-object <id> --ledger <file> --advisories <dir>\n  \
     sekaictl admin assurance probes summary --ledger <file> --week-start-ms <ms>\n  \
     (targets must be listed in SEKAI_PROBE_TARGET_ALLOWLIST; both tenants must be synthetic)"
}

fn flag(args: &[String], name: &str) -> Result<String, BoxErr> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .ok_or_else(|| std::io::Error::other(format!("{name} required\n{}", usage())).into())
}

fn token(path: &Path) -> Result<String, BoxErr> {
    let value = std::fs::read_to_string(path).map_err(|_| {
        std::io::Error::other(format!("token file {} is unreadable", path.display()))
    })?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(
            std::io::Error::other(format!("token file {} is empty", path.display())).into(),
        );
    }
    Ok(value)
}

pub async fn run_probes_command(args: Vec<String>) -> Result<(), BoxErr> {
    let rest = args.get(1..).unwrap_or_default();
    match args.first().map(String::as_str) {
        Some("run") => {
            let target = ProbeTarget {
                endpoint: flag(rest, "--target")?,
                tenant: flag(rest, "--tenant")?,
                tenant_token: token(&PathBuf::from(flag(rest, "--tenant-token-file")?))?,
                foreign_tenant: flag(rest, "--foreign-tenant")?,
                foreign_token: token(&PathBuf::from(flag(rest, "--foreign-token-file")?))?,
                foreign_object_id: flag(rest, "--foreign-object")?,
            };
            let ledger = PathBuf::from(flag(rest, "--ledger")?);
            let advisories = PathBuf::from(flag(rest, "--advisories")?);
            let report = run(TargetGuard::from_env(), &target, &ledger, &advisories)
                .await
                .map_err(std::io::Error::other)?;
            for attempt in &report.attempts {
                println!(
                    "{}",
                    serde_json::to_string(attempt).map_err(std::io::Error::other)?
                );
            }
            let inconclusive = report
                .attempts
                .iter()
                .filter(|attempt| {
                    matches!(attempt.outcome, crate::probe_runner::ProbeOutcome::Error(_))
                })
                .count();
            for failure in &report.advisory_failures {
                eprintln!("{failure}");
            }
            let bypasses = report
                .attempts
                .iter()
                .filter(|attempt| attempt.outcome == crate::probe_runner::ProbeOutcome::Bypass)
                .count();
            if bypasses > 0 {
                // A bypass is a failed run; the drafts stay local and private.
                return Err(std::io::Error::other(format!(
                    "{bypasses} isolation bypass(es); private advisory drafts in {}",
                    advisories.display()
                ))
                .into());
            }
            if inconclusive > 0 {
                // Isolation was not verified; the scheduler must see a failure.
                return Err(std::io::Error::other(format!(
                    "{inconclusive} probe(s) could not decide; see the ledger"
                ))
                .into());
            }
            Ok(())
        }
        Some("summary") => {
            let ledger = PathBuf::from(flag(rest, "--ledger")?);
            let from_ms: i64 = flag(rest, "--week-start-ms")?
                .parse()
                .map_err(|_| std::io::Error::other("--week-start-ms must be milliseconds"))?;
            let summary = weekly_summary(&ledger, from_ms).map_err(std::io::Error::other)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).map_err(std::io::Error::other)?
            );
            Ok(())
        }
        _ => Err(std::io::Error::other(usage()).into()),
    }
}
