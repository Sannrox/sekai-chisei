//! Durable outbox for workflow-action adapters (#709).
//!
//! Adapters persist the exact command before calling the plane. The SDK never
//! writes ActionInstance, policy, budget, or receipt state.

use fs2::FileExt;
use sekai_chisei::sekai::workflow_action::{
    WorkflowActionBinding, WorkflowReceiptReconciliation, WorkflowStepEnvelope,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const OUTBOX_FORMAT_VERSION: &str = "sekai.workflow-outbox/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCommand {
    pub format_version: String,
    pub command: String,
    pub envelope: WorkflowStepEnvelope,
    #[serde(default)]
    pub payload_digest: String,
}

pub trait WorkflowTransport {
    fn submit(&mut self, envelope: &WorkflowStepEnvelope) -> Result<WorkflowActionBinding, String>;
    fn park(&mut self, envelope: &WorkflowStepEnvelope) -> Result<WorkflowActionBinding, String>;
    fn resume(&mut self, envelope: &WorkflowStepEnvelope) -> Result<WorkflowActionBinding, String>;
    fn cancel(&mut self, envelope: &WorkflowStepEnvelope) -> Result<WorkflowActionBinding, String>;
    fn callback(
        &mut self,
        envelope: &WorkflowStepEnvelope,
        payload_digest: &str,
    ) -> Result<WorkflowActionBinding, String>;
    fn reconcile(
        &mut self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<WorkflowReceiptReconciliation, String>;
}

pub fn command(
    command: &str,
    envelope: WorkflowStepEnvelope,
    payload_digest: &str,
) -> WorkflowCommand {
    WorkflowCommand {
        format_version: OUTBOX_FORMAT_VERSION.into(),
        command: command.into(),
        envelope,
        payload_digest: payload_digest.into(),
    }
}

pub fn enqueue(dir: &Path, item: &WorkflowCommand) -> Result<PathBuf, String> {
    fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let encoded = serde_json::to_vec_pretty(item).map_err(|error| error.to_string())?;
    let path = dir.join(entry_name(item)?);
    if path.exists() {
        replay_existing(&path, &encoded)?;
        return Ok(path);
    }
    let tmp = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    {
        let mut file = options.open(&tmp).map_err(|error| error.to_string())?;
        file.lock_exclusive().map_err(|error| error.to_string())?;
        if file
            .write_all(&encoded)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(&tmp);
            return Err("failed to persist workflow outbox temporary file".into());
        }
    }
    match fs::hard_link(&tmp, &path) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp);
            if let Ok(dir_file) = File::open(dir) {
                let _ = dir_file.sync_all();
            }
            Ok(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp);
            replay_existing(&path, &encoded)?;
            Ok(path)
        }
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            Err(error.to_string())
        }
    }
}

pub fn flush<T: WorkflowTransport>(
    path: &Path,
    transport: &mut T,
) -> Result<WorkflowActionBinding, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    file.lock_exclusive().map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let item: WorkflowCommand =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if item.format_version != OUTBOX_FORMAT_VERSION {
        return Err("workflow outbox revision is unsupported".into());
    }
    match item.command.as_str() {
        "submit" => transport.submit(&item.envelope),
        "park" => transport.park(&item.envelope),
        "resume" => transport.resume(&item.envelope),
        "cancel" => transport.cancel(&item.envelope),
        "callback" => transport.callback(&item.envelope, &item.payload_digest),
        other => Err(format!("unknown workflow command {other}")),
    }
}

fn entry_name(item: &WorkflowCommand) -> Result<String, String> {
    let pin = serde_json::to_vec(item).map_err(|error| error.to_string())?;
    Ok(format!("{:x}.json", Sha256::digest(pin)))
}

fn replay_existing(path: &Path, encoded: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.lock_exclusive().map_err(|error| error.to_string())?;
    let mut existing = Vec::new();
    file.read_to_end(&mut existing)
        .map_err(|error| error.to_string())?;
    if existing != encoded {
        return Err("workflow outbox entry conflict".into());
    }
    Ok(())
}
