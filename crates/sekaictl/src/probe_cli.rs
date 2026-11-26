//! sekaictl admin assurance probes run/summary commands (#1621).
//!
//! `run` is what a scheduler calls: it executes the remote isolation probes
//! once against one allow-listed target and appends to the ledger, then any
//! declarative probe specs from `--specs <dir>` (#1680), all validated before
//! the first call. Tokens are read from files so they never appear in
//! arguments or logs. `import` turns an agent's proposal report (#1622) into
//! the spec files `--specs` reads.

use std::path::{Path, PathBuf};

use crate::probe_runner::{
    LEDGER_APPEND_FAILED, ProbeTarget, RunReport, TargetGuard, run, weekly_summary,
};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin assurance probes run --target <endpoint> --tenant <ns> --tenant-token-file <file> \
     --foreign-tenant <ns> --foreign-token-file <file> --foreign-object <id> --ledger <file> --advisories <dir> \
     [--specs <dir>]\n  \
     sekaictl admin assurance probes summary --ledger <file> --week-start-ms <ms>\n  \
     sekaictl admin assurance probes import --report <file> --specs <dir>\n  \
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
            // Given without a directory is an error, never a run without
            // specs. A set that fails to load is a refused run, ledgered.
            let specs = if rest.iter().any(|arg| arg == "--specs") {
                let dir = flag(rest, "--specs")?;
                crate::probe_spec::load_dir(Path::new(&dir))
            } else {
                Ok(Vec::new())
            };
            let report = run(
                TargetGuard::from_env(),
                &target,
                specs,
                &ledger,
                &advisories,
            )
            .await
            .map_err(std::io::Error::other)?;
            for attempt in &report.attempts {
                println!(
                    "{}",
                    serde_json::to_string(attempt).map_err(std::io::Error::other)?
                );
            }
            for failure in &report.advisory_failures {
                eprintln!("{failure}");
            }
            if let Some(error) = run_error(&report, &advisories) {
                return Err(std::io::Error::other(error).into());
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
        Some("import") => {
            let report = PathBuf::from(flag(rest, "--report")?);
            let json = std::fs::read_to_string(&report).map_err(|error| {
                std::io::Error::other(format!("report {}: {error}", report.display()))
            })?;
            let outcome =
                crate::probe_spec::import_report(&json, Path::new(&flag(rest, "--specs")?))
                    .map_err(std::io::Error::other)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&outcome).map_err(std::io::Error::other)?
            );
            Ok(())
        }
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

/// Bypass findings take the exit message; ledger append failures still fail
/// the run when nothing more severe was found.
fn run_error(report: &RunReport, advisories: &Path) -> Option<String> {
    let inconclusive = report
        .attempts
        .iter()
        .filter(|attempt| matches!(attempt.outcome, crate::probe_runner::ProbeOutcome::Error(_)))
        .count();
    let mismatches = report
        .attempts
        .iter()
        .filter(|attempt| {
            matches!(
                attempt.outcome,
                crate::probe_runner::ProbeOutcome::Mismatch(_)
            )
        })
        .count();
    let bypasses = report
        .attempts
        .iter()
        .filter(|attempt| attempt.outcome == crate::probe_runner::ProbeOutcome::Bypass)
        .count();
    let ledger_failures = report
        .advisory_failures
        .iter()
        .filter(|failure| failure.contains(LEDGER_APPEND_FAILED))
        .count();
    if bypasses > 0 {
        return Some(format!(
            "{bypasses} isolation bypass(es); private advisory drafts in {}",
            advisories.display()
        ));
    }
    if mismatches > 0 {
        return Some(format!(
            "{mismatches} probe spec(s) were denied otherwise than expected; see the ledger"
        ));
    }
    if inconclusive > 0 {
        return Some(format!(
            "{inconclusive} probe(s) could not decide; see the ledger"
        ));
    }
    if ledger_failures > 0 {
        return Some(format!("{ledger_failures} ledger append(s) failed"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe_runner::{Attempt, PROBE_LEDGER_VERSION, ProbeOutcome};

    fn attempt(outcome: ProbeOutcome) -> Attempt {
        Attempt {
            schema: PROBE_LEDGER_VERSION.into(),
            attempt_id: "a1".into(),
            at_ms: 1,
            endpoint: "http://probe.example.test".into(),
            tenant: "ns".into(),
            probe: None,
            spec: None,
            outcome,
        }
    }

    fn report(attempts: Vec<Attempt>, advisory_failures: Vec<String>) -> RunReport {
        RunReport {
            attempts,
            advisories: Vec::new(),
            advisory_failures,
        }
    }

    #[test]
    fn bypasses_are_reported_before_ledger_failures() {
        let report = report(
            vec![attempt(ProbeOutcome::Bypass)],
            vec![format!("attempt a1: {LEDGER_APPEND_FAILED}: disk full")],
        );
        let error = run_error(&report, Path::new("advisories")).expect("exit error");
        assert!(
            error.starts_with("1 isolation bypass(es); private advisory drafts in advisories"),
            "{error}"
        );
        assert!(!error.contains("ledger"), "{error}");
    }

    #[test]
    fn a_run_whose_ledger_appends_fail_still_exits_nonzero() {
        let report = report(
            vec![attempt(ProbeOutcome::Denied)],
            vec![format!("attempt a1: {LEDGER_APPEND_FAILED}: disk full")],
        );
        assert_eq!(
            run_error(&report, Path::new("advisories")).as_deref(),
            Some("1 ledger append(s) failed")
        );
    }
}
