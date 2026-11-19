//! Runs a pinned model version in its own process (#3075, ADR 0147).
//!
//! A transform worker that claims a run with model inputs resolves each
//! version through a [`ModelRegistry`], which refuses state whose bytes no
//! longer match the recorded digest, and starts the model as a child process
//! with [`ModelProcess::start`]. The child calls [`serve_model`] with its
//! [`ModelAdapter`]: it loads the state directory named by
//! [`MODEL_STATE_DIR_ENV`], announces its contract, and answers one predict
//! request per line until its stdin closes. The parent refuses a child whose
//! contract differs from the version's, and output rows whose columns differ
//! from the contract output. Dropping the [`ModelProcess`] ends the child, so
//! the model process lives exactly as long as the run.
//!
//! Protocol messages on the child's stdout follow [`PROTOCOL_PREFIX`] to the
//! end of a line; anything else the model prints is passed to the parent's
//! stderr.

use crate::model_registry::{ModelAdapter, ModelRegistry, ModelRow};
use prost::Message;
use sekai_proto::sekai::{ModelAdapterContract, ModelVersion};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// The state directory the child loads its adapter from.
pub const MODEL_STATE_DIR_ENV: &str = "SEKAI_MODEL_STATE_DIR";
/// Marks a protocol line on the child's stdout.
pub const PROTOCOL_PREFIX: &str = "sekai-model/v1 ";

/// Why a pinned model could not score. [`ModelRunError::code`] is the reason
/// a worker fails the run with, so the run names the cause.
#[derive(Debug)]
#[non_exhaustive]
pub enum ModelRunError {
    /// The registry's bytes do not match the version's digest.
    DigestMismatch,
    /// The model's contract, its inputs, or its output rows do not match the
    /// version's contract.
    ContractMismatch(String),
    /// The model process could not start, failed, or broke the protocol.
    Process(io::Error),
}

impl ModelRunError {
    /// A reason code for failing the run.
    pub fn code(&self) -> &'static str {
        match self {
            Self::DigestMismatch => "model_digest_mismatch",
            Self::ContractMismatch(_) => "model_contract_mismatch",
            Self::Process(_) => "model_process_failed",
        }
    }
}

impl std::fmt::Display for ModelRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DigestMismatch => f.write_str("stored model does not match its digest"),
            Self::ContractMismatch(detail) => write!(f, "model contract mismatch: {detail}"),
            Self::Process(error) => write!(f, "model process failed: {error}"),
        }
    }
}

impl std::error::Error for ModelRunError {}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChildMessage {
    /// The adapter's contract, protobuf-encoded as hex.
    Ready {
        contract: String,
    },
    Rows {
        rows: Vec<ModelRow>,
    },
    Error {
        message: String,
    },
}

#[derive(Serialize, Deserialize)]
struct PredictRequest {
    inputs: HashMap<String, Vec<ModelRow>>,
}

/// The child side: loads `A` from [`MODEL_STATE_DIR_ENV`], announces its
/// contract, and answers predict requests from `input` until it closes.
pub fn serve_model<A: ModelAdapter>(input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let dir = std::env::var_os(MODEL_STATE_DIR_ENV)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "model state directory not set"))?;
    let adapter = A::load(Path::new(&dir))?;
    let contract = hex(&adapter.contract().encode_to_vec());
    write_line(&mut output, &ChildMessage::Ready { contract })?;
    for line in input.lines() {
        let request: PredictRequest = serde_json::from_str(&line?).map_err(io::Error::other)?;
        let reply = match adapter.predict(&request.inputs) {
            Ok(rows) => ChildMessage::Rows { rows },
            Err(error) => ChildMessage::Error {
                message: error.to_string(),
            },
        };
        write_line(&mut output, &reply)?;
    }
    Ok(())
}

fn write_line(output: &mut impl Write, message: &impl Serialize) -> io::Result<()> {
    let json = serde_json::to_string(message).map_err(io::Error::other)?;
    writeln!(output, "{PROTOCOL_PREFIX}{json}")?;
    output.flush()
}

/// A pinned model running in its own process. Dropping it ends the process.
pub struct ModelProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    contract: ModelAdapterContract,
}

impl ModelProcess {
    /// Resolves `version` through `registry`, refusing bytes that do not match
    /// its digest, then runs `command` as the model with the resolved state
    /// directory and checks that it serves the version's contract.
    pub fn start(
        registry: &impl ModelRegistry,
        version: &ModelVersion,
        mut command: Command,
    ) -> Result<Self, ModelRunError> {
        let dir = registry
            .resolve(&version.registry_locator, &version.digest)
            .map_err(|error| match error.kind() {
                io::ErrorKind::InvalidData => ModelRunError::DigestMismatch,
                _ => ModelRunError::Process(error),
            })?;
        let expected = version.contract.clone().unwrap_or_default();
        let mut child = command
            .env(MODEL_STATE_DIR_ENV, &dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(ModelRunError::Process)?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ModelRunError::Process(io::Error::other("no model pipes")));
        };
        let mut process = Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            contract: expected,
        };
        let ChildMessage::Ready { contract } = process.receive()? else {
            return Err(protocol_error("the model did not announce its contract"));
        };
        let served = unhex(&contract)
            .and_then(|bytes| ModelAdapterContract::decode(bytes.as_slice()).ok())
            .ok_or_else(|| protocol_error("the model announced an unreadable contract"))?;
        if served != process.contract {
            return Err(ModelRunError::ContractMismatch(
                "the model serves a different contract than the version records".into(),
            ));
        }
        Ok(process)
    }

    /// Scores one batch. Inputs must name exactly the contract's inputs, and
    /// every output row must carry exactly the contract's output columns.
    pub fn predict(
        &mut self,
        inputs: HashMap<String, Vec<ModelRow>>,
    ) -> Result<Vec<ModelRow>, ModelRunError> {
        let expected: BTreeSet<&str> = self
            .contract
            .inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect();
        let given: BTreeSet<&str> = inputs.keys().map(String::as_str).collect();
        if given != expected {
            return Err(ModelRunError::ContractMismatch(format!(
                "inputs {given:?} do not match the contract's {expected:?}"
            )));
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| protocol_error("the model input is closed"))?;
        write_line_raw(stdin, &PredictRequest { inputs }).map_err(ModelRunError::Process)?;
        let rows = match self.receive()? {
            ChildMessage::Rows { rows } => rows,
            ChildMessage::Error { message } => {
                return Err(ModelRunError::Process(io::Error::other(message)));
            }
            ChildMessage::Ready { .. } => return Err(protocol_error("unexpected announcement")),
        };
        let columns: BTreeSet<&str> = self
            .contract
            .output
            .iter()
            .map(|column| column.name.as_str())
            .collect();
        if let Some(row) = rows
            .iter()
            .find(|row| row.keys().map(String::as_str).collect::<BTreeSet<_>>() != columns)
        {
            return Err(ModelRunError::ContractMismatch(format!(
                "output row columns {:?} do not match the contract's {columns:?}",
                row.keys().collect::<BTreeSet<_>>()
            )));
        }
        Ok(rows)
    }

    /// The next protocol message; other output goes to stderr.
    fn receive(&mut self) -> Result<ChildMessage, ModelRunError> {
        loop {
            let mut line = String::new();
            if self
                .stdout
                .read_line(&mut line)
                .map_err(ModelRunError::Process)?
                == 0
            {
                let status = self.child.wait().map_err(ModelRunError::Process)?;
                return Err(protocol_error(&format!("the model exited ({status})")));
            }
            // The model may print without a trailing newline before a
            // protocol line, so the prefix may start mid-line.
            match line.trim_end().split_once(PROTOCOL_PREFIX) {
                Some((noise, json)) => {
                    if !noise.is_empty() {
                        eprintln!("{noise}");
                    }
                    return serde_json::from_str(json)
                        .map_err(|_| protocol_error("the model sent an unreadable message"));
                }
                None => eprint!("{line}"),
            }
        }
    }
}

impl Drop for ModelProcess {
    fn drop(&mut self) {
        // Closing stdin asks the model to finish; kill covers one that does not.
        drop(self.stdin.take());
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn write_line_raw(stdin: &mut ChildStdin, request: &PredictRequest) -> io::Result<()> {
    let mut json = serde_json::to_vec(request).map_err(io::Error::other)?;
    json.push(b'\n');
    stdin.write_all(&json)?;
    stdin.flush()
}

fn protocol_error(message: &str) -> ModelRunError {
    ModelRunError::Process(io::Error::new(
        io::ErrorKind::InvalidData,
        message.to_string(),
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}
