//! Runs the bounded parser worker, `sekai-object-parser`, for one CSV or
//! Parquet object, so those formats never parse in the runtime's address
//! space. The protocol is documented in that crate: object bytes on stdin,
//! one JSON object per row on stdout, exit 0; a refusal exits 2.
//!
//! The runtime bounds the worker from outside ([`crate::child`]). A worker
//! that crashes, overruns either bound or refuses fails the page as
//! invalid; the worker also caps its own CPU time and memory.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use sekai_source_sdk::ConnectorFailure;

use crate::child::{self, Bounds, ChildError};

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
        child::beside_runtime(WORKER_NAME).map(|path| Self {
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
        let mut command = Command::new(&self.path);
        command
            .args(&self.leading_args)
            .args([format.arg(), &max_rows.to_string()]);
        let bounds = Bounds {
            timeout: self.timeout,
            max_output: MAX_WORKER_OUTPUT_BYTES,
        };
        match child::run_bounded(command, bytes, bounds) {
            Ok(finished) if finished.status.success() => Ok(finished.output),
            Err(ChildError::Spawn) => Err(ConnectorFailure::Unreachable),
            _ => Err(ConnectorFailure::Invalid),
        }
    }
}
