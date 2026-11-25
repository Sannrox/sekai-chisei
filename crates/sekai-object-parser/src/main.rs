//! `sekai-object-parser <csv|parquet> <max_rows>`: the bounded worker the
//! `object_storage` connector type runs for each CSV or Parquet object.
//! The protocol is in the library's documentation. The parent bounds wall
//! time and output; this process also caps its own CPU time and memory and
//! writes no core file, where the platform allows.

use std::io::{BufWriter, Read, Write};
use std::process::ExitCode;

use sekai_object_parser::{Format, MAX_INPUT_BYTES, Refusal, parse};

/// CPU seconds and address space the worker may use.
const CPU_SECONDS: u64 = 10;
const ADDRESS_SPACE_BYTES: u64 = 1024 * 1024 * 1024;

fn main() -> ExitCode {
    limit_resources();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(refusal) => {
            eprintln!("{}", refusal.reason());
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), Refusal> {
    let mut args = std::env::args().skip(1);
    let format = args
        .next()
        .as_deref()
        .and_then(Format::parse)
        .ok_or(Refusal::Malformed)?;
    let max_rows: usize = args
        .next()
        .and_then(|rows| rows.parse().ok())
        .ok_or(Refusal::Malformed)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::Malformed)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Refusal::TooLarge);
    }
    let rows = parse(format, &bytes, max_rows)?;
    let mut out = BufWriter::new(std::io::stdout().lock());
    for row in rows {
        // A closed pipe means the parent gave up; there is no one to tell.
        if serde_json::to_writer(&mut out, &row).is_err() || out.write_all(b"\n").is_err() {
            return Ok(());
        }
    }
    let _ = out.flush();
    Ok(())
}

#[cfg(unix)]
fn limit_resources() {
    let limit = |resource, value: u64| {
        let limit = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        // SAFETY: setrlimit reads the struct it is given and has no other
        // effect on this process's memory. A refusal leaves the parent's
        // bounds in force.
        unsafe { libc::setrlimit(resource, &limit) };
    };
    limit(libc::RLIMIT_CPU, CPU_SECONDS);
    limit(libc::RLIMIT_AS, ADDRESS_SPACE_BYTES);
    limit(libc::RLIMIT_CORE, 0);
}

#[cfg(not(unix))]
fn limit_resources() {}
