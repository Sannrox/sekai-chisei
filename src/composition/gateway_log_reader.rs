//! Chisei reads each configured gateway's egress log into receipts,
//! `llm_calls` rows, and the decision log (ADR 0152 decision 6, #3096).
//!
//! Per gateway one task repeats [`read_once`]: read the durable cursor, fetch
//! the records after it from `GET /_chisei/log`, write them, then acknowledge
//! the committed sequence with `POST /_chisei/log/ack`.
//!
//! - A usage record's Operation Receipt goes to the Chisei store first. The
//!   upsert is a no-op for an identical receipt, so a retry after a crash
//!   leaves exactly one.
//! - Its `llm_calls` row and every record's decision entry are then written
//!   on the Sekai store in the transaction that moves the cursor by
//!   compare-and-set. A reader that loses that race writes nothing and
//!   rereads.
//! - The gateway drops only what is acknowledged, and only committed
//!   sequences are acknowledged.
//!
//! An admission record yields one decision entry; a usage record yields the
//! receipt, the row, and one decision entry. A failing gateway is reported as
//! `NOT_SERVING` under the gRPC health service `chisei.gateway_log.<name>`
//! and retried with backoff; other gateways keep their own tasks.

use crate::chisei::receipt::OperationReceipt;
use crate::chisei_store::{ChiseiReceiptStore, ChiseiStore};
use crate::db::gateway_log_cursor::{GatewayLogBatch, LLM_CALLS_DATASET};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::audit::Decision;
use crate::sekai::dataset::{ColumnDef, Dataset, llm_call_column_classification};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tonic_health::ServingStatus;
use tonic_health::server::HealthReporter;

/// Gateways Chisei reads: comma-separated `name=base_url`.
pub const GATEWAY_LOGS_ENV: &str = "CHISEI_GATEWAY_LOGS";
/// Reader keys of those gateways: comma-separated `name=key`, one per gateway.
pub const GATEWAY_LOG_KEYS_ENV: &str = "CHISEI_GATEWAY_LOG_KEYS";

const LOG_FORMAT: &str = "chisei.gateway-log/v1";
const PAGE_LIMIT: usize = 500;
const IDLE_POLL: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Decision action of an admission record.
const ADMISSION_ACTION: &str = "gateway.admission";
/// Decision action of a usage record's receipt, as gateway receipt admission writes it.
const RECEIPT_ACTION: &str = "operation.receipt.upsert";

/// One gateway whose log Chisei reads, with a `log_reader` principal's key.
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayLogSource {
    pub name: String,
    pub base_url: String,
    reader_key: String,
}

impl std::fmt::Debug for GatewayLogSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayLogSource")
            .field("name", &self.name)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl GatewayLogSource {
    pub fn new(name: &str, base_url: &str, reader_key: &str) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.trim_end_matches('/').into(),
            reader_key: reader_key.into(),
        }
    }

    /// Key of the gateway's `log_reader` principal; it also reads the policy.
    pub(crate) fn reader_key(&self) -> &str {
        &self.reader_key
    }

    fn health_service(&self) -> String {
        format!("chisei.gateway_log.{}", self.name)
    }
}

/// The configured gateways, empty when [`GATEWAY_LOGS_ENV`] is unset.
pub fn sources_from_env() -> Result<Vec<GatewayLogSource>, String> {
    parse_sources(
        &std::env::var(GATEWAY_LOGS_ENV).unwrap_or_default(),
        &std::env::var(GATEWAY_LOG_KEYS_ENV).unwrap_or_default(),
    )
}

fn parse_pairs<'a>(env: &str, value: &'a str) -> Result<BTreeMap<&'a str, &'a str>, String> {
    let mut pairs = BTreeMap::new();
    for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (name, rest) = entry
            .split_once('=')
            .map(|(name, rest)| (name.trim(), rest.trim()))
            .filter(|(name, rest)| !name.is_empty() && !rest.is_empty())
            .ok_or_else(|| format!("{env}: expected name=value, got an entry without one"))?;
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "{env}: gateway name {name:?} may use only letters, digits, '-' and '_'"
            ));
        }
        if pairs.insert(name, rest).is_some() {
            return Err(format!("{env}: gateway {name:?} is named twice"));
        }
    }
    Ok(pairs)
}

fn parse_sources(gateways: &str, keys: &str) -> Result<Vec<GatewayLogSource>, String> {
    let gateways = parse_pairs(GATEWAY_LOGS_ENV, gateways)?;
    let keys = parse_pairs(GATEWAY_LOG_KEYS_ENV, keys)?;
    if let Some(extra) = keys.keys().find(|name| !gateways.contains_key(*name)) {
        return Err(format!(
            "{GATEWAY_LOG_KEYS_ENV} names {extra:?}, which {GATEWAY_LOGS_ENV} does not"
        ));
    }
    gateways
        .into_iter()
        .map(|(name, url)| {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(format!(
                    "{GATEWAY_LOGS_ENV}: gateway {name:?} needs an http:// or https:// base URL"
                ));
            }
            let key = keys
                .get(name)
                .ok_or_else(|| format!("{GATEWAY_LOG_KEYS_ENV} has no reader key for {name:?}"))?;
            Ok(GatewayLogSource::new(name, url, key))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct LogPage {
    format: String,
    records: Vec<LogRecord>,
    acked: u64,
    next_seq: u64,
}

#[derive(Debug, Deserialize)]
struct LogRecord {
    seq: u64,
    #[serde(flatten)]
    entry: LogEntry,
}

/// Mirror of the gateway's `chisei.gateway-log/v1` record; fields Chisei
/// does not write are ignored.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum LogEntry {
    Admission {
        request_id: String,
        operation_id: String,
        principal: String,
        provider: String,
        #[serde(default)]
        model: Option<String>,
        data_class: String,
        policy_version: String,
        at_ms: i64,
    },
    Usage {
        request_id: String,
        outcome: String,
        status: u16,
        at_ms: i64,
        #[serde(default)]
        receipt: Option<Box<OperationReceipt>>,
        #[serde(default)]
        llm_calls_row: Option<HashMap<String, String>>,
    },
}

/// The writes of a run of records, in log order.
#[derive(Default)]
struct Writes {
    receipts: Vec<OperationReceipt>,
    batch: GatewayLogBatch,
}

fn plan_writes(gateway: &str, after_seq: u64, records: Vec<LogRecord>) -> Writes {
    let mut writes = Writes {
        receipts: Vec::new(),
        batch: GatewayLogBatch {
            gateway: gateway.into(),
            after_seq,
            through_seq: records.last().map_or(after_seq, |record| record.seq),
            ..GatewayLogBatch::default()
        },
    };
    for LogRecord { seq, entry } in records {
        // Keyed on the record, so each one yields exactly one entry even when
        // a client reuses a request id.
        let id = format!("gateway-log:{gateway}:{seq}");
        match entry {
            LogEntry::Admission {
                request_id,
                operation_id,
                principal,
                provider,
                model,
                data_class,
                policy_version,
                at_ms,
            } => {
                let mut evidence = HashMap::from([
                    ("gateway".into(), gateway.into()),
                    ("request_id".into(), request_id),
                    ("operation_id".into(), operation_id.clone()),
                    ("provider".into(), provider),
                    ("data_class".into(), data_class),
                    ("policy_version".into(), policy_version),
                ]);
                if let Some(model) = model {
                    evidence.insert("model".into(), model);
                }
                writes.batch.decisions.push(Decision {
                    id,
                    timestamp: at_ms,
                    actor: principal,
                    action: ADMISSION_ACTION.into(),
                    reason: "gateway admitted the request before provider contact".into(),
                    evidence,
                    target_id: operation_id,
                    outcome: "admitted".into(),
                });
            }
            LogEntry::Usage {
                request_id,
                outcome,
                status,
                at_ms,
                receipt,
                llm_calls_row,
            } => {
                writes.batch.llm_calls_rows.extend(llm_calls_row);
                // An accounting-only attempt has no receipt and nothing to record.
                let Some(receipt) = receipt else {
                    continue;
                };
                writes.batch.decisions.push(Decision {
                    id,
                    timestamp: at_ms,
                    actor: receipt.initiating_actor.clone(),
                    action: RECEIPT_ACTION.into(),
                    reason: "gateway operation completed".into(),
                    evidence: HashMap::from([
                        ("gateway".into(), gateway.into()),
                        ("request_id".into(), request_id),
                        ("operation_id".into(), receipt.operation_id.clone()),
                        ("outcome".into(), outcome),
                        ("status".into(), status.to_string()),
                    ]),
                    target_id: receipt.operation_id.clone(),
                    outcome: "recorded".into(),
                });
                writes.receipts.push(*receipt);
            }
        }
    }
    writes
}

/// Defines the `llm_calls` columns the rows carry and the dataset lacks,
/// creating the dataset on first use.
fn ensure_llm_calls_columns(
    sekai: &RuntimeDb,
    rows: &[HashMap<String, String>],
) -> Result<(), String> {
    if rows.is_empty() {
        return Ok(());
    }
    let names: BTreeSet<&str> = rows
        .iter()
        .flat_map(|row| row.keys())
        .map(String::as_str)
        .collect();
    let columns: Vec<ColumnDef> = names
        .into_iter()
        .map(|name| ColumnDef {
            name: name.into(),
            col_type: "string".into(),
            classification: llm_call_column_classification(name).into(),
        })
        .collect();
    if sekai.get_dataset(LLM_CALLS_DATASET)?.is_none() {
        let created = sekai.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "LLM calls".into(),
            columns: columns.clone(),
            object_id: String::new(),
            created: chrono::Utc::now().timestamp_millis(),
            partition_keys: Vec::new(),
        });
        // Another reader may have created it meanwhile; the columns below
        // converge either way.
        if created.is_ok() {
            return Ok(());
        }
    }
    sekai.add_dataset_columns(LLM_CALLS_DATASET, &columns)
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| format!("gateway log store task failed: {error}"))?
}

/// One read of `source`'s log: writes the records after the cursor and
/// acknowledges what is committed. Returns how many records this call
/// committed (0 when caught up or when another reader got there first).
pub async fn read_once(
    client: &reqwest::Client,
    source: &GatewayLogSource,
    chisei: &ChiseiStore,
    sekai: &Arc<RuntimeDb>,
) -> Result<usize, String> {
    let cursor = blocking({
        let (sekai, name) = (sekai.clone(), source.name.clone());
        move || sekai.gateway_log_cursor(&name)
    })
    .await?;
    let page: LogPage = client
        .get(format!("{}/_chisei/log", source.base_url))
        .query(&[("after", cursor), ("limit", PAGE_LIMIT as u64)])
        .bearer_auth(&source.reader_key)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| format!("read gateway log: {}", error.without_url()))?
        .json()
        .await
        .map_err(|error| format!("decode gateway log: {}", error.without_url()))?;
    if page.format != LOG_FORMAT {
        return Err(format!(
            "gateway log format {:?} is not {LOG_FORMAT}",
            page.format
        ));
    }
    let last_written = page.next_seq.saturating_sub(1);
    if last_written < cursor {
        return Err(format!(
            "gateway log ends at {last_written}, before the committed cursor {cursor}; \
             was the gateway log replaced?"
        ));
    }
    if page.acked > cursor {
        // Another reader may have committed and acknowledged since the cursor
        // was read. Anything else means records were dropped unread here.
        let now = blocking({
            let (sekai, name) = (sekai.clone(), source.name.clone());
            move || sekai.gateway_log_cursor(&name)
        })
        .await?;
        if now >= page.acked {
            return Ok(0);
        }
        return Err(format!(
            "gateway acknowledged through {} but only {now} is committed here",
            page.acked
        ));
    }
    let records: Vec<LogRecord> = page
        .records
        .into_iter()
        .filter(|record| record.seq > cursor)
        .collect();
    if let Some((index, record)) = records
        .iter()
        .enumerate()
        .find(|(index, record)| record.seq != cursor + 1 + *index as u64)
    {
        return Err(format!(
            "gateway log skipped from {} to {}",
            cursor + index as u64,
            record.seq
        ));
    }
    let count = records.len();
    let mut committed = cursor;
    if count > 0 {
        let writes = plan_writes(&source.name, cursor, records);
        let through = writes.batch.through_seq;
        let applied = blocking({
            let (sekai, chisei) = (sekai.clone(), chisei.clone());
            move || {
                for receipt in &writes.receipts {
                    chisei.put_operation_receipt(receipt)?;
                }
                ensure_llm_calls_columns(&sekai, &writes.batch.llm_calls_rows)?;
                sekai.apply_gateway_log_batch(&writes.batch)
            }
        })
        .await?;
        if !applied {
            return Ok(0);
        }
        committed = through;
    }
    if committed > page.acked {
        client
            .post(format!("{}/_chisei/log/ack", source.base_url))
            .bearer_auth(&source.reader_key)
            .json(&serde_json::json!({ "seq": committed }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| format!("acknowledge gateway log: {}", error.without_url()))?;
    }
    Ok(count)
}

/// Starts one reader task per gateway. Each reports its own health service
/// and backs off on failure without affecting the others.
pub fn spawn(
    sources: Vec<GatewayLogSource>,
    chisei: ChiseiStore,
    sekai: Arc<RuntimeDb>,
    health: HealthReporter,
) {
    let client = match reqwest::Client::builder().timeout(HTTP_TIMEOUT).build() {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(%error, "gateway log reader cannot build its HTTP client");
            return;
        }
    };
    for source in sources {
        let (client, chisei, sekai, health) = (
            client.clone(),
            chisei.clone(),
            sekai.clone(),
            health.clone(),
        );
        tokio::spawn(async move {
            let service = source.health_service();
            let mut backoff = IDLE_POLL;
            loop {
                match read_once(&client, &source, &chisei, &sekai).await {
                    Ok(count) => {
                        health
                            .set_service_status(&service, ServingStatus::Serving)
                            .await;
                        backoff = IDLE_POLL;
                        if count < PAGE_LIMIT {
                            tokio::time::sleep(IDLE_POLL).await;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(gateway = %source.name, %error, "gateway log read failed");
                        health
                            .set_service_status(&service, ServingStatus::NotServing)
                            .await;
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_gateway_needs_a_url_and_a_key() {
        let sources = parse_sources(
            "edge=https://gw.test/, lab=http://127.0.0.1:1",
            "lab=k2,edge=k1",
        )
        .unwrap();
        assert_eq!(
            sources,
            vec![
                GatewayLogSource::new("edge", "https://gw.test", "k1"),
                GatewayLogSource::new("lab", "http://127.0.0.1:1", "k2"),
            ]
        );
        assert!(!format!("{:?}", sources[0]).contains("k1"));
        assert!(parse_sources("", "").unwrap().is_empty());
        for (gateways, keys) in [
            ("edge=https://gw.test", ""),
            ("edge=https://gw.test", "edge=k,lab=k"),
            ("edge=gw.test", "edge=k"),
            ("edge=https://a,edge=https://b", "edge=k"),
            ("e dge=https://gw.test", "e dge=k"),
            ("https://gw.test", ""),
        ] {
            assert!(
                parse_sources(gateways, keys).is_err(),
                "{gateways} / {keys}"
            );
        }
    }
}
