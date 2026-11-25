//! Runs the bounded parser worker, `sekai-object-parser`, for one CSV or
//! Parquet object, so those formats never parse in the runtime's address
//! space. The protocol is documented in that crate: object bytes on stdin,
//! one JSON object per row on stdout, exit 0; a refusal exits 2.
//!
//! The runtime bounds the worker from outside: an empty environment, a
//! wall-time limit after which it is killed, and a cap on the bytes it may
//! write. A worker that crashes, overruns either bound or refuses fails
//! the page as invalid; the worker also caps its own CPU time and memory.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sekai_source_sdk::ConnectorFailure;

/// The worker's executable name, installed beside the runtime's.
pub const WORKER_NAME: &str = "sekai-object-parser";

/// How long one object's parse may take before the worker is killed.
pub const MAX_WORKER_SECONDS: u64 = 30;

/// The most bytes of rows one object's parse may produce.
pub const MAX_WORKER_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

/// The formats that parse in the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkerFormat {
    Csv,
    Parquet,
}

impl WorkerFormat {
    fn arg(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Parquet => "parquet",
        }
    }
}

pub(super) struct Worker {
    pub(super) path: PathBuf,
    /// Arguments before the protocol's own: none for the installed worker;
    /// tests run a shell script this way instead of writing an executable.
    pub(super) leading_args: Vec<String>,
    pub(super) timeout: Duration,
}

impl Worker {
    /// The worker installed beside this runtime's executable, if there is
    /// one.
    pub(super) fn beside_runtime() -> Option<Self> {
        let path = std::env::current_exe()
            .ok()?
            .with_file_name(format!("{WORKER_NAME}{}", std::env::consts::EXE_SUFFIX));
        path.is_file().then_some(Self {
            path,
            leading_args: Vec::new(),
            timeout: Duration::from_secs(MAX_WORKER_SECONDS),
        })
    }

    /// The worker's output for `bytes`: one JSON object per row, at most
    /// `max_rows` rows.
    pub(super) fn rows(
        &self,
        format: WorkerFormat,
        bytes: &[u8],
        max_rows: usize,
    ) -> Result<Vec<u8>, ConnectorFailure> {
        let mut child = Command::new(&self.path)
            .args(&self.leading_args)
            .args([format.arg(), &max_rows.to_string()])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ConnectorFailure::Unreachable)?;
        let mut stdin = child.stdin.take().ok_or(ConnectorFailure::Unreachable)?;
        let mut stdout = child.stdout.take().ok_or(ConnectorFailure::Unreachable)?;
        // Feed and drain on their own threads so neither pipe can stall the
        // other. A worker that stops reading early just closes its stdin.
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let _ = stdin.write_all(bytes);
            });
            // Reading stops one byte past the cap and closes the pipe, so an
            // oversize worker cannot block on a full pipe.
            let output = scope.spawn(move || {
                let mut output = Vec::new();
                let read = (&mut stdout)
                    .take(MAX_WORKER_OUTPUT_BYTES + 1)
                    .read_to_end(&mut output);
                read.map(|_| output)
            });
            let deadline = Instant::now() + self.timeout;
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                }
            };
            let output = output.join().ok().and_then(Result::ok);
            match (status, output) {
                (Some(status), Some(output))
                    if status.success() && output.len() as u64 <= MAX_WORKER_OUTPUT_BYTES =>
                {
                    Ok(output)
                }
                _ => Err(ConnectorFailure::Invalid),
            }
        })
    }
}
