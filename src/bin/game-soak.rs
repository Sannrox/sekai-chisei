//! Play the game soak against a running deployment and write the
//! throughput document (#1626).
//!
//! ```text
//! game-soak --target <socket> --seed <n> --out <dir>
//!     [--bots 4] [--rounds 50] [--batch-records 50] [--preset demo|onboarding|load_test]
//!     [--namespace <ns>]
//! ```
//!
//! The environment metadata variables documented in
//! `docs/performance-benchmarks.md` are mandatory, so a report cannot omit
//! the hardware it was measured on.

use std::path::PathBuf;
use std::process::ExitCode;

use sekai_chisei::game_soak::{HardwareProfile, SoakSpec, run, script};
use sekai_chisei::sekai::synthetic::SizePreset;

const USAGE: &str = "game-soak --target <socket> --seed <n> --out <dir> [--bots <n>] \
    [--rounds <n>] [--batch-records <n>] [--preset demo|onboarding|load_test] [--namespace <ns>]";

#[tokio::main]
async fn main() -> ExitCode {
    match play().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("game-soak: {error}");
            ExitCode::FAILURE
        }
    }
}

fn required_metadata(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required for reproducible soak metadata"))
}

fn number<T: std::str::FromStr>(flag: &str, value: Option<String>) -> Result<T, String> {
    value
        .ok_or_else(|| format!("{flag} requires a value"))?
        .parse()
        .map_err(|_| format!("{flag} must be a number"))
}

async fn play() -> Result<(), String> {
    let mut target = None;
    let mut out = None;
    let mut namespace = None;
    let mut seed = None;
    let mut spec = SoakSpec {
        seed: 0,
        preset: SizePreset::Demo,
        bots: 4,
        rounds: 50,
        batch_records: 50,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => target = args.next(),
            "--out" => out = args.next().map(PathBuf::from),
            "--namespace" => namespace = args.next(),
            "--seed" => seed = Some(number(&arg, args.next())?),
            "--bots" => spec.bots = number(&arg, args.next())?,
            "--rounds" => spec.rounds = number(&arg, args.next())?,
            "--batch-records" => spec.batch_records = number(&arg, args.next())?,
            "--preset" => {
                spec.preset = match args.next().as_deref() {
                    Some("demo") => SizePreset::Demo,
                    Some("onboarding") => SizePreset::Onboarding,
                    Some("load_test") => SizePreset::LoadTest,
                    _ => {
                        return Err(format!(
                            "--preset must be demo, onboarding or load_test\n{USAGE}"
                        ));
                    }
                }
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let (Some(target), Some(out), Some(seed)) = (target, out, seed) else {
        return Err(format!("--target, --seed and --out are required\n{USAGE}"));
    };
    spec.seed = seed;
    let hardware = HardwareProfile {
        description: required_metadata("SEKAI_BENCH_HARDWARE")?,
        cores: std::thread::available_parallelism().map_or(0, usize::from),
        operating_system: required_metadata("SEKAI_BENCH_OS")?,
        rustc: required_metadata("SEKAI_BENCH_RUSTC")?,
        build_profile: required_metadata("SEKAI_BENCH_PROFILE")?,
    };
    let recorded_at = required_metadata("SEKAI_BENCH_RECORDED_AT")?;
    // A fresh namespace per run by default, so a long-lived deployment can
    // be soaked repeatedly; the Action sequence does not depend on it.
    let namespace = namespace
        .unwrap_or_else(|| format!("game-soak-{seed}-{}", chrono::Utc::now().timestamp_millis()));
    let script = script(&spec, &namespace).map_err(|error| error.to_string())?;
    let report = run(&target, &script, hardware, recorded_at)
        .await
        .map_err(|error| error.to_string())?;
    report.write(&out).map_err(|error| error.to_string())?;
    println!(
        "{} Actions/s, {} batches/s, statistics p95 {} ms; action digest {}",
        report.actions.per_second,
        report.intake.batches_per_second,
        report.transform.latency.p95_ms,
        report.workload.action_digest
    );
    Ok(())
}
