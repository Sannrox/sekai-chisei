//! Policy-mode egress log (ADR 0152 decision 6, #3095).
//!
//! In policy mode the gateway appends an admission record before provider
//! contact and a usage record after the call ends. A failed admission append
//! denies the request. Chisei reads records by sequence over
//! `GET /_chisei/log` and acknowledges what it has committed with
//! `POST /_chisei/log/ack`; only acknowledged records are ever dropped.
//!
//! On disk the log is a directory of segment files named by their first
//! sequence (`<seq>.jsonl`). Each line is `<checksum> <record json>`, the
//! checksum being the first 16 hex digits of the JSON's SHA-256, and each
//! append is synced before the gateway continues. Sequences are gapless across
//! restarts. Opening the log truncates a torn final line and refuses any other
//! bad line. The highest acknowledged sequence lives in `ACK`, replaced
//! atomically. One process owns a directory at a time (`LOCK`).

use super::*;
use axum::extract::Query;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex as StdMutex, PoisonError};

/// Directory of the log; defaults to `chisei-gateway-log` beside the policy file.
pub(super) const LOG_DIR_ENV: &str = "CHISEI_GATEWAY_LOG_DIR";
/// Format of the records `GET /_chisei/log` returns.
pub(super) const LOG_FORMAT: &str = "chisei.gateway-log/v1";
/// A segment at or past this size is closed and the next append starts a new one.
#[cfg(not(test))]
const SEGMENT_MAX_BYTES: u64 = 8 << 20;
/// Small enough that tests cross segments every two records.
#[cfg(test)]
const SEGMENT_MAX_BYTES: u64 = 256;
const READ_LIMIT_DEFAULT: usize = 100;
const READ_LIMIT_MAX: usize = 1000;

/// The log directory for a policy file: `CHISEI_GATEWAY_LOG_DIR`, or
/// `chisei-gateway-log` beside the policy file.
pub(super) fn log_dir_from_env(policy_path: &Path) -> PathBuf {
    std::env::var(LOG_DIR_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            policy_path
                .parent()
                .unwrap_or(Path::new("."))
                .join("chisei-gateway-log")
        })
}

/// What one record says happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum LogEntry {
    /// Written before provider contact.
    Admission {
        request_id: String,
        operation_id: String,
        principal: String,
        provider: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        data_class: String,
        policy_version: String,
        at_ms: i64,
    },
    /// Written when a provider attempt of an admitted request ends.
    Usage {
        request_id: String,
        operation_id: String,
        provider_ordinal: u32,
        status: u16,
        /// `success`, `incomplete`, `failed`, `interrupted`, `accounting_only`
        /// or `refused`.
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        input_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
        latency_ms: i64,
        at_ms: i64,
        /// The Operation Receipt the gateway builds for this attempt (#3132).
        /// Absent on an accounting-only attempt, which has none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt: Option<Box<OperationReceipt>>,
        /// The attempt's `llm_calls` row, as the gateway builds it (#3132).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        llm_calls_row: Option<BTreeMap<String, String>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LogRecord {
    pub(super) seq: u64,
    #[serde(flatten)]
    pub(super) entry: LogEntry,
}

struct LogState {
    /// First sequence of each segment, ascending; the last one is active.
    segments: Vec<u64>,
    next_seq: u64,
    acked: u64,
    active_bytes: u64,
    /// The last append's failure, cleared by the next success; `/readyz`
    /// reports it.
    last_error: Option<String>,
    /// A failed append could not be undone, so the active segment may end in a
    /// partial line. Appends are refused until a restart truncates it.
    broken: bool,
}

/// The gateway's durable egress log. Cloning shares the same log.
#[derive(Clone)]
pub(super) struct EgressLog {
    dir: PathBuf,
    state: Arc<StdMutex<LogState>>,
    /// Held for the life of the process.
    _owner: Arc<File>,
}

impl EgressLog {
    /// Opens or creates the log in `dir`, recovering from a torn final line.
    pub(super) fn open(dir: &Path) -> Result<Self, String> {
        let context = |what: &str, error: std::io::Error| {
            format!("gateway log {}: {what}: {error}", dir.display())
        };
        std::fs::create_dir_all(dir).map_err(|e| context("cannot create", e))?;
        let owner = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("LOCK"))
            .map_err(|e| context("cannot open LOCK", e))?;
        owner
            .try_lock()
            .map_err(|_| format!("gateway log {} is owned by another process", dir.display()))?;
        let acked = match std::fs::read_to_string(dir.join("ACK")) {
            Ok(text) => text
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("gateway log {}: ACK is not a sequence", dir.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(context("cannot read ACK", error)),
        };
        let mut segments = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(|e| context("cannot list", e))? {
            let path = entry.map_err(|e| context("cannot list", e))?.path();
            if path.extension().is_some_and(|ext| ext == "jsonl")
                && let Some(first) = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .and_then(|stem| stem.parse::<u64>().ok())
            {
                segments.push(first);
            }
        }
        segments.sort_unstable();
        let mut log = LogState {
            segments,
            next_seq: acked + 1,
            acked,
            active_bytes: 0,
            last_error: None,
            broken: false,
        };
        let count = log.segments.len();
        for (index, first) in log.segments.clone().into_iter().enumerate() {
            let path = segment_path(dir, first);
            let bytes = std::fs::read(&path).map_err(|e| context("cannot read segment", e))?;
            let last = index + 1 == count;
            let scan = scan_segment(&bytes, first, last)
                .map_err(|error| format!("gateway log {}: {error}", path.display()))?;
            if index > 0 && first != log.next_seq {
                return Err(format!(
                    "gateway log {}: segment {first} does not continue at {}",
                    dir.display(),
                    log.next_seq
                ));
            }
            if scan.valid_bytes < bytes.len() as u64 {
                warn!(path = %path.display(), "truncating a torn final gateway log record");
                let file = OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(|e| context("cannot truncate", e))?;
                file.set_len(scan.valid_bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|e| context("cannot truncate", e))?;
            }
            log.next_seq = first + scan.records;
            log.active_bytes = scan.valid_bytes;
        }
        if log.next_seq <= log.acked {
            return Err(format!(
                "gateway log {} ends at {} before its acknowledged sequence {}",
                dir.display(),
                log.next_seq.saturating_sub(1),
                log.acked
            ));
        }
        prune_acknowledged(dir, &mut log);
        Ok(Self {
            dir: dir.to_path_buf(),
            state: Arc::new(StdMutex::new(log)),
            _owner: Arc::new(owner),
        })
    }

    // Every write leaves the state consistent, so a poisoned lock is still safe.
    fn lock(&self) -> std::sync::MutexGuard<'_, LogState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Appends one record and syncs it. Returns its sequence.
    pub(super) async fn append(&self, entry: LogEntry) -> Result<u64, String> {
        let log = self.clone();
        tokio::task::spawn_blocking(move || log.append_blocking(entry))
            .await
            .map_err(|error| format!("gateway log append task failed: {error}"))?
    }

    fn append_blocking(&self, entry: LogEntry) -> Result<u64, String> {
        let mut state = self.lock();
        if state.broken {
            return Err("gateway log has a partial record; restart the gateway".into());
        }
        let seq = state.next_seq;
        let result = self.write_record(&mut state, LogRecord { seq, entry });
        match &result {
            Ok(()) => {
                state.next_seq += 1;
                state.last_error = None;
            }
            Err(error) => {
                warn!(error = %error, "gateway log append failed");
                state.last_error = Some(error.clone());
            }
        }
        result.map(|()| seq)
    }

    fn write_record(&self, state: &mut LogState, record: LogRecord) -> Result<(), String> {
        if state.segments.is_empty() || state.active_bytes >= SEGMENT_MAX_BYTES {
            let path = segment_path(&self.dir, record.seq);
            create_segment(&self.dir, &path)
                .map_err(|error| format!("cannot start segment {}: {error}", path.display()))?;
            state.segments.push(record.seq);
            state.active_bytes = 0;
        }
        let line = encode_record(&record);
        let path = segment_path(&self.dir, *state.segments.last().expect("active segment"));
        let written = OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| {
                file.write_all(&line)?;
                file.sync_data()
            });
        if let Err(error) = written {
            // Cut a partial line off so the next append starts on a boundary.
            let undone = OpenOptions::new().write(true).open(&path).and_then(|file| {
                file.set_len(state.active_bytes)?;
                file.sync_data()
            });
            if undone.is_err() {
                state.broken = true;
            }
            return Err(format!("cannot append to {}: {error}", path.display()));
        }
        state.active_bytes += line.len() as u64;
        Ok(())
    }

    /// Records after `after` and past the acknowledged sequence, at most `limit`.
    pub(super) async fn read(&self, after: u64, limit: usize) -> Result<LogPage, String> {
        let log = self.clone();
        tokio::task::spawn_blocking(move || log.read_blocking(after, limit))
            .await
            .map_err(|error| format!("gateway log read task failed: {error}"))?
    }

    fn read_blocking(&self, after: u64, limit: usize) -> Result<LogPage, String> {
        // Lines below `next_seq` are complete and synced, so the files are read
        // without holding the lock and appends keep flowing.
        let (segments, next_seq, acked) = {
            let state = self.lock();
            (state.segments.clone(), state.next_seq, state.acked)
        };
        let from = after.max(acked) + 1;
        let start = segments
            .partition_point(|first| *first <= from)
            .saturating_sub(1);
        let mut records = Vec::new();
        for first in &segments[start..] {
            if records.len() >= limit {
                break;
            }
            let bytes = match std::fs::read(segment_path(&self.dir, *first)) {
                Ok(bytes) => bytes,
                // Pruned by an acknowledgement since the snapshot.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("cannot read gateway log: {error}")),
            };
            for line in bytes.split_inclusive(|byte| *byte == b'\n') {
                let Some(record) = decode_line(line) else {
                    break;
                };
                if record.seq >= next_seq || records.len() >= limit {
                    break;
                }
                if record.seq >= from {
                    records.push(record);
                }
            }
        }
        Ok(LogPage {
            format: LOG_FORMAT,
            records,
            acked,
            next_seq,
        })
    }

    /// Records that Chisei committed every record up to `seq`. Returns the
    /// acknowledged sequence afterwards.
    pub(super) async fn acknowledge(&self, seq: u64) -> Result<u64, AckError> {
        let log = self.clone();
        tokio::task::spawn_blocking(move || log.acknowledge_blocking(seq))
            .await
            .map_err(|error| AckError::Io(format!("gateway log ack task failed: {error}")))?
    }

    fn acknowledge_blocking(&self, seq: u64) -> Result<u64, AckError> {
        let mut state = self.lock();
        if seq >= state.next_seq {
            return Err(AckError::NotWritten(state.next_seq.saturating_sub(1)));
        }
        if seq <= state.acked {
            return Ok(state.acked);
        }
        write_ack(&self.dir, seq).map_err(|error| AckError::Io(error.to_string()))?;
        state.acked = seq;
        prune_acknowledged(&self.dir, &mut state);
        Ok(seq)
    }

    /// The last append's failure, if the most recent append failed.
    pub(super) fn last_error(&self) -> Option<String> {
        self.lock().last_error.clone()
    }
}

/// One page of `GET /_chisei/log`.
#[derive(Debug, Serialize)]
pub(super) struct LogPage {
    format: &'static str,
    pub(super) records: Vec<LogRecord>,
    /// Highest sequence the gateway may drop.
    acked: u64,
    /// Sequence the next record will take.
    next_seq: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AckError {
    /// The sequence is past the last written record, named here.
    NotWritten(u64),
    Io(String),
}

fn segment_path(dir: &Path, first: u64) -> PathBuf {
    dir.join(format!("{first:020}.jsonl"))
}

fn checksum(json: &[u8]) -> String {
    Sha256::digest(json)[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn encode_record(record: &LogRecord) -> Vec<u8> {
    let json = serde_json::to_vec(record).expect("log records serialize");
    let mut line = checksum(&json).into_bytes();
    line.push(b' ');
    line.extend_from_slice(&json);
    line.push(b'\n');
    line
}

/// A complete line whose checksum matches, decoded.
fn decode_line(line: &[u8]) -> Option<LogRecord> {
    let line = line.strip_suffix(b"\n")?;
    let (sum, json) = line.split_at_checked(16)?;
    let json = json.strip_prefix(b" ")?;
    if sum != checksum(json).as_bytes() {
        return None;
    }
    serde_json::from_slice(json).ok()
}

struct SegmentScan {
    records: u64,
    valid_bytes: u64,
}

/// Checks a segment's records run gapless from `first`. Only the final
/// segment may end in bad bytes, and only when no good record follows them.
fn scan_segment(bytes: &[u8], first: u64, last: bool) -> Result<SegmentScan, String> {
    let mut scan = SegmentScan {
        records: 0,
        valid_bytes: 0,
    };
    let mut lines = bytes.split_inclusive(|byte| *byte == b'\n');
    for line in lines.by_ref() {
        match decode_line(line) {
            Some(record) if record.seq == first + scan.records => {
                scan.records += 1;
                scan.valid_bytes += line.len() as u64;
            }
            Some(record) => {
                return Err(format!(
                    "record {} where {} was expected",
                    record.seq,
                    first + scan.records
                ));
            }
            None if last => {
                if lines.any(|rest| decode_line(rest).is_some()) {
                    return Err("a bad record is followed by good ones".into());
                }
                return Ok(scan);
            }
            None => return Err("a closed segment holds a bad record".into()),
        }
    }
    Ok(scan)
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

fn create_segment(dir: &Path, path: &Path) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.sync_all()?;
    sync_dir(dir)
}

fn write_ack(dir: &Path, seq: u64) -> std::io::Result<()> {
    let tmp = dir.join("ACK.tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(seq.to_string().as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, dir.join("ACK"))?;
    sync_dir(dir)
}

/// Deletes closed segments whose records are all acknowledged. A failed
/// delete leaves the file for the next open to prune.
fn prune_acknowledged(dir: &Path, state: &mut LogState) {
    while state.segments.len() > 1 && state.segments[1] <= state.acked + 1 {
        let _ = std::fs::remove_file(segment_path(dir, state.segments[0]));
        state.segments.remove(0);
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct LogQuery {
    #[serde(default)]
    after: u64,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AckBody {
    seq: u64,
}

/// The log, when the caller is a principal the policy names as a log reader.
fn log_for_reader<'a>(
    state: &'a GatewayState,
    headers: &HeaderMap,
) -> Result<&'a EgressLog, Box<Response<Body>>> {
    let (Some(policy), Some(log)) = (&state.runtime.policy, &state.runtime.egress_log) else {
        return Err(Box::new(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "the gateway is not in policy mode",
        )));
    };
    let key = client_key(headers).ok_or_else(|| Box::new(IdentityError::MissingKey.response()))?;
    let identity = policy
        .identify(key, &state.config.default_project)
        .map_err(|error| Box::new(error.response()))?;
    if !policy.is_log_reader(&identity.agent) {
        return Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "policy_denied",
            "principal may not read the gateway log",
        )));
    }
    Ok(log)
}

/// `GET /_chisei/log?after=<seq>&limit=<n>`: records after a sequence, in order.
pub(super) async fn read_egress_log(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Query(query): Query<LogQuery>,
) -> Response<Body> {
    let log = match log_for_reader(&state, &headers) {
        Ok(log) => log,
        Err(response) => return *response,
    };
    let limit = query
        .limit
        .unwrap_or(READ_LIMIT_DEFAULT)
        .clamp(1, READ_LIMIT_MAX);
    match log.read(query.after, limit).await {
        Ok(page) => json_response(
            StatusCode::OK,
            serde_json::to_value(page).expect("log pages serialize"),
        ),
        Err(error) => json_error(StatusCode::SERVICE_UNAVAILABLE, "log_unavailable", &error),
    }
}

/// `POST /_chisei/log/ack` with `{"seq": N}`: lets the gateway drop records up to N.
pub(super) async fn acknowledge_egress_log(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<AckBody>,
) -> Response<Body> {
    let log = match log_for_reader(&state, &headers) {
        Ok(log) => log,
        Err(response) => return *response,
    };
    match log.acknowledge(body.seq).await {
        Ok(acked) => json_response(StatusCode::OK, serde_json::json!({ "acked": acked })),
        Err(AckError::NotWritten(last)) => json_error(
            StatusCode::CONFLICT,
            "invalid_ack",
            &format!("cannot acknowledge past the last written record {last}"),
        ),
        Err(AckError::Io(error)) => {
            json_error(StatusCode::SERVICE_UNAVAILABLE, "log_unavailable", &error)
        }
    }
}

/// Appends the usage record of a provider attempt whose admission was logged,
/// with the receipt and `llm_calls` row built for it, if any.
/// A failure shows on `/readyz`; the response already sent stands.
pub(super) async fn log_attempt_usage(
    runtime: &GatewayRuntime,
    context: &UsageContext,
    status: StatusCode,
    outcome: &str,
    reason: Option<&str>,
    usage: Option<&ResponseUsage>,
    built: Option<(&OperationReceipt, &HashMap<String, String>)>,
) {
    let Some(log) = runtime
        .egress_log
        .as_ref()
        .filter(|_| context.logged_admission)
    else {
        return;
    };
    let tokens = |count: Option<i32>| count.map_or(0, |count| count.max(0) as u64);
    let now = Utc::now().timestamp_millis();
    let entry = LogEntry::Usage {
        request_id: context.request_id.clone(),
        operation_id: context.operation_id.clone(),
        provider_ordinal: context.provider_ordinal,
        status: status.as_u16(),
        outcome: outcome.to_string(),
        reason: reason.map(str::to_string),
        input_tokens: tokens(usage.map(|usage| usage.input_tokens)),
        output_tokens: tokens(usage.map(|usage| usage.output_tokens)),
        total_tokens: tokens(usage.map(|usage| usage.total_tokens)),
        latency_ms: now - context.started_ms,
        at_ms: now,
        receipt: built.map(|(receipt, _)| Box::new(receipt.clone())),
        llm_calls_row: built.map(|(_, row)| row.clone().into_iter().collect()),
    };
    let _ = log.append(entry).await;
}
