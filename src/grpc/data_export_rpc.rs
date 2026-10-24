//! Governed export (#1627, #1695, ADR 0130): export grants, receipts, and
//! the streaming pipeline every export runs through.

use super::*;
use std::cell::RefCell;

/// Objects resolved and encoded per batch, and bytes buffered per message.
pub(super) const EXPORT_BATCH: usize = 256;
const EXPORT_CHUNK_BYTES: usize = 64 * 1024;

fn grant_status(error: String) -> Status {
    if error == crate::sekai::data_export::GRANT_CHANGED {
        Status::aborted(error)
    } else if error.starts_with("reason") || error.starts_with("principal") {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}

fn to_proto_export_grant(grant: crate::sekai::data_export::ExportGrant) -> NamespaceExportGrant {
    NamespaceExportGrant {
        namespace: grant.namespace,
        principal: grant.principal,
        granted_by: grant.granted_by,
        granted_at_ms: grant.granted_at_ms,
        reason: grant.reason,
        revoked_by: grant.revoked_by,
        revoked_at_ms: grant.revoked_at_ms,
        revocation_reason: grant.revocation_reason,
    }
}

/// What the export producer hands the response stream. Data carries the
/// time it must reach the client by (before the lease could lapse); the
/// receipt itself comes last, so it completes only once the stream has
/// passed every byte on.
enum ExportItem {
    Data(ExportObjectSetChunk, i64),
    Finish(Box<crate::sekai::data_export::ExportReceipt>),
    Fail(Status),
}

/// Sends export bytes in bounded messages, counting them toward the
/// receipt's digest as they leave. A send fails once the client is gone or
/// would outlast the lease.
pub(super) struct ExportWriter {
    receipt: crate::sekai::data_export::ExportReceipt,
    sink: ExportSink,
    buffer: Vec<u8>,
    buffered_rows: u64,
}

/// Where an export's bytes go.
enum ExportSink {
    /// To the response stream, through a bounded channel.
    Stream(tokio::sync::mpsc::Sender<ExportItem>),
    /// Into the run's durable artifact, one chunk after another.
    Artifact {
        db: crate::db::runtime_db::RuntimeDb,
        next_seq: i64,
    },
}

/// Who an export runs for: a request's caller, or a saved definition's
/// owner alone.
pub(super) struct ExportCaller {
    pub(super) principals: Vec<String>,
    pub(super) policy_context: crate::sekai::object_security::PrincipalPolicyContext,
    pub(super) purpose: Option<crate::sekai::purpose_authorization::PurposePresentation>,
    pub(super) tenant_context: Option<RequestEnterpriseContext>,
}

impl ExportCaller {
    pub(super) fn from_request<T>(
        service: &SekaiServiceImpl,
        req: &Request<T>,
    ) -> Result<Self, Status>
    where
        T: std::any::Any,
    {
        let principals = caller_principals(req);
        require_authenticated(&principals)?;
        Ok(Self {
            policy_context: principal_policy_context(req),
            purpose: request_purpose_presentation(req, &principals),
            tenant_context: request_tenant_context(service.db.runtime(), req)?,
            principals,
        })
    }

    /// A saved definition's owner, alone: no tenant assertion and no
    /// purpose presentation, so a purpose-gated source refuses the run.
    pub(super) fn owner(owner: &str) -> Self {
        let principals = vec![owner.to_string()];
        Self {
            policy_context: principal_policy_context_from(&principals, None),
            purpose: None,
            tenant_context: None,
            principals,
        }
    }
}

/// An export checked and ready to run.
pub(super) struct PreparedExport {
    pub(super) actor: String,
    pub(super) source: crate::sekai::data_export::ExportSource,
    pub(super) header: Vec<u8>,
    pub(super) rows: ExportRows,
}

/// Writes every row; true when it wrote them all.
pub(super) type ExportRows = Box<dyn FnOnce(&RefCell<ExportWriter>) -> Result<bool, Status> + Send>;

impl ExportWriter {
    pub(super) fn operation_id(&self) -> &str {
        self.receipt.operation_id()
    }

    /// Renews the lease between rows; false once it is lost.
    pub(super) fn keep_alive(&mut self) -> bool {
        self.receipt.record(&[], 0)
    }

    pub(super) fn write(&mut self, bytes: Vec<u8>, rows: u64) -> bool {
        self.buffer.extend(bytes);
        self.buffered_rows += rows;
        self.buffer.len() < EXPORT_CHUNK_BYTES || self.flush()
    }

    fn flush(&mut self) -> bool {
        if self.buffer.is_empty() {
            return true;
        }
        let data = std::mem::take(&mut self.buffer);
        let mut rows = std::mem::take(&mut self.buffered_rows);
        // A row may be larger than a message; rows span messages freely.
        // Each message renews the lease as it goes, and a lost lease means
        // another instance closed this export.
        data.chunks(EXPORT_CHUNK_BYTES).all(|part| {
            self.receipt.record(part, std::mem::take(&mut rows))
                && self.send(ExportObjectSetChunk {
                    data: part.to_vec(),
                    ..Default::default()
                })
        })
    }

    fn send(&mut self, chunk: ExportObjectSetChunk) -> bool {
        match &mut self.sink {
            ExportSink::Stream(tx) => {
                let deadline = self.receipt.deadline_ms();
                send_item(tx, ExportItem::Data(chunk, deadline), &self.receipt)
            }
            // Only bytes go into the artifact; the receipt id is its key.
            ExportSink::Artifact { db, next_seq } => {
                if chunk.data.is_empty() {
                    return true;
                }
                let seq = *next_seq;
                *next_seq += 1;
                db.put_export_artifact_chunk(self.receipt.operation_id(), seq, &chunk.data)
                    .is_ok()
            }
        }
    }
}

/// Queues an item, waiting for a slow client no longer than the lease
/// allows.
fn send_item(
    tx: &tokio::sync::mpsc::Sender<ExportItem>,
    item: ExportItem,
    receipt: &crate::sekai::data_export::ExportReceipt,
) -> bool {
    let Some(budget) = receipt.send_budget() else {
        return false;
    };
    tokio::runtime::Handle::current()
        .block_on(tx.send_timeout(item, budget))
        .is_ok()
}

/// The response stream: passes data on while its deadline holds, and
/// completes the receipt when it reaches it. Dropped early (the client
/// left), the receipt it has not reached closes as aborted.
fn export_response_stream(
    mut rx: tokio::sync::mpsc::Receiver<ExportItem>,
) -> impl futures_util::Stream<Item = Result<ExportObjectSetChunk, Status>> {
    async_stream::stream! {
        let mut ended = false;
        while let Some(item) = rx.recv().await {
            match item {
                ExportItem::Data(chunk, deadline) => {
                    if now_millis() >= deadline {
                        yield Err(Status::aborted("export lease expired"));
                        ended = true;
                        break;
                    }
                    yield Ok(chunk);
                }
                ExportItem::Finish(receipt) => {
                    if now_millis() >= receipt.deadline_ms() {
                        yield Err(Status::aborted("export lease expired"));
                        ended = true;
                        break;
                    }
                    let completed =
                        tokio::task::spawn_blocking(move || receipt.complete(now_millis())).await;
                    match completed {
                        Ok(Ok((row_count, content_digest))) => {
                            yield Ok(ExportObjectSetChunk {
                                done: true,
                                row_count: i64::try_from(row_count).unwrap_or(i64::MAX),
                                content_digest,
                                ..Default::default()
                            });
                        }
                        _ => yield Err(Status::aborted("export could not be completed")),
                    }
                    ended = true;
                    break;
                }
                ExportItem::Fail(status) => {
                    yield Err(status);
                    ended = true;
                    break;
                }
            }
        }
        // The producer stopped without finishing: never end as success.
        if !ended {
            yield Err(Status::aborted("export ended before completion"));
        }
    }
}

impl SekaiServiceImpl {
    /// Grants a principal export on a namespace. Needs namespace admin.
    pub(super) async fn grant_namespace_export_rpc(
        &self,
        req: Request<GrantNamespaceExportRequest>,
    ) -> Result<Response<GrantNamespaceExportResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let inner = req.into_inner();
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &inner.namespace,
            true,
        )?;
        let actor = authorize_source_type_namespace_admin(self, &principals, &inner.namespace)?;
        let grant = crate::sekai::data_export::grant_export(
            self.db.runtime(),
            &inner.namespace,
            &inner.principal,
            &inner.reason,
            &actor,
            now_millis(),
        )
        .map_err(grant_status)?;
        Ok(Response::new(GrantNamespaceExportResponse {
            grant: Some(to_proto_export_grant(grant)),
        }))
    }

    /// Revokes a principal's export on a namespace. Needs namespace admin.
    pub(super) async fn revoke_namespace_export_rpc(
        &self,
        req: Request<RevokeNamespaceExportRequest>,
    ) -> Result<Response<RevokeNamespaceExportResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let inner = req.into_inner();
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &inner.namespace,
            true,
        )?;
        let actor = authorize_source_type_namespace_admin(self, &principals, &inner.namespace)?;
        let grant = crate::sekai::data_export::revoke_export(
            self.db.runtime(),
            &inner.namespace,
            &inner.principal,
            &inner.reason,
            &actor,
            now_millis(),
        )
        .map_err(grant_status)?
        .ok_or_else(|| Status::not_found("export grant not found"))?;
        Ok(Response::new(RevokeNamespaceExportResponse {
            grant: Some(to_proto_export_grant(grant)),
        }))
    }

    /// Reads an export's receipt. Only its initiating caller or an
    /// administrator of its namespace sees it; anyone else gets not found.
    pub(super) async fn get_export_receipt_rpc(
        &self,
        req: Request<GetExportReceiptRequest>,
    ) -> Result<Response<GetExportReceiptResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let operation_id = req.into_inner().operation_id;
        let unavailable = || Status::not_found("export receipt unavailable");
        let receipt = crate::sekai::data_export::export_receipt(self.db.runtime(), &operation_id)
            .map_err(Status::internal)?
            .ok_or_else(unavailable)?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &receipt.namespace,
            false,
        )
        .map_err(|_| unavailable())?;
        if !principals.contains(&receipt.initiating_actor)
            && authorize_source_type_namespace_admin(self, &principals, &receipt.namespace).is_err()
        {
            return Err(unavailable());
        }
        let outcome = receipt
            .events
            .iter()
            .rev()
            .find_map(|event| event.attributes.get("outcome"))
            .cloned();
        let attribute = |key: &str| {
            receipt
                .events
                .iter()
                .rev()
                .find_map(|event| event.attributes.get(key))
                .cloned()
                .unwrap_or_default()
        };
        Ok(Response::new(GetExportReceiptResponse {
            operation_id: receipt.operation_id.clone(),
            namespace: receipt.namespace.clone(),
            initiating_actor: receipt.initiating_actor.clone(),
            outcome: outcome.unwrap_or_default(),
            row_count: attribute("row_count").parse().unwrap_or(0),
            content_digest: attribute("content_digest"),
            started_at_ms: receipt.started_at_ms,
            completed_at_ms: receipt.completed_at_ms.unwrap_or(0),
            receipt_json: serde_json::to_string(&receipt)
                .map_err(|_| Status::internal("export receipt unavailable"))?,
        }))
    }

    /// Sets the fingerprint allowlist for one marking. Needs namespace admin.
    pub(super) async fn put_export_fingerprint_policy_rpc(
        &self,
        req: Request<PutExportFingerprintPolicyRequest>,
    ) -> Result<Response<PutExportFingerprintPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let policy = req
            .into_inner()
            .policy
            .ok_or_else(|| Status::invalid_argument("policy required"))?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &policy.namespace,
            true,
        )?;
        let actor = authorize_source_type_namespace_admin(self, &principals, &policy.namespace)?;
        let stored = crate::sekai::export_fingerprint::put_fingerprint_policy(
            self.db.runtime(),
            &policy.namespace,
            &policy.marking,
            policy.fingerprint_properties,
            &actor,
            now_millis(),
        )
        .map_err(fingerprint_status)?;
        Ok(Response::new(PutExportFingerprintPolicyResponse {
            policy: Some(to_proto_fingerprint_policy(stored)),
        }))
    }

    /// Reads the fingerprint allowlist for one marking. Needs namespace admin.
    pub(super) async fn get_export_fingerprint_policy_rpc(
        &self,
        req: Request<GetExportFingerprintPolicyRequest>,
    ) -> Result<Response<GetExportFingerprintPolicyResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let inner = req.into_inner();
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &inner.namespace,
            false,
        )?;
        authorize_source_type_namespace_admin(self, &principals, &inner.namespace)?;
        let policy = crate::sekai::export_fingerprint::get_fingerprint_policy(
            self.db.runtime(),
            &inner.namespace,
            &inner.marking,
        )
        .map_err(fingerprint_status)?;
        Ok(Response::new(GetExportFingerprintPolicyResponse {
            policy: Some(to_proto_fingerprint_policy(policy)),
        }))
    }

    /// Scores a leaked sample against fingerprinted exports in a namespace.
    pub(super) async fn trace_export_rpc(
        &self,
        req: Request<TraceExportRequest>,
    ) -> Result<Response<TraceExportResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let inner = req.into_inner();
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &inner.namespace,
            false,
        )?;
        let format = crate::sekai::data_export::ExportFormat::parse(&inner.format)
            .ok_or_else(|| Status::invalid_argument("format must be csv or jsonl"))?;
        let actor = principals[0].clone();
        let admin =
            authorize_source_type_namespace_admin(self, &principals, &inner.namespace).is_ok();
        let matches = crate::sekai::export_fingerprint::trace_export(
            self.db.runtime(),
            &inner.namespace,
            format,
            &inner.sample,
            &actor,
            now_millis(),
            admin,
        )
        .map_err(fingerprint_status)?;
        Ok(Response::new(TraceExportResponse {
            matches: matches
                .into_iter()
                .map(|found| TraceExportMatch {
                    receipt_id: found.receipt_id,
                    score: found.score,
                })
                .collect(),
        }))
    }
}

fn fingerprint_status(error: String) -> Status {
    if error == crate::sekai::data_export::EXPORT_DENIED {
        Status::permission_denied(error)
    } else if error.starts_with("sample")
        || error.starts_with("namespace")
        || error.starts_with("marking")
        || error.starts_with("property")
        || error.starts_with("at most")
        || error.starts_with("fingerprint property")
    {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}

fn record_fingerprint(
    db: &crate::db::runtime_db::RuntimeDb,
    operation_id: &str,
    source: &crate::sekai::data_export::ExportSource,
) -> Result<(), Status> {
    if source.fingerprint_properties.is_empty() {
        return Ok(());
    }
    crate::sekai::export_fingerprint::record_export_fingerprint(
        db,
        &crate::sekai::export_fingerprint::ExportFingerprintRecord {
            operation_id: operation_id.into(),
            namespace: source.namespace.clone(),
            columns: source.fingerprint_properties.clone(),
            group_size: source.fingerprint_group_size,
            id_column: source.source_kind == "object_set",
        },
    )
    .map_err(Status::internal)
}

fn to_proto_fingerprint_policy(
    policy: crate::sekai::export_fingerprint::ExportFingerprintPolicy,
) -> ExportFingerprintPolicy {
    ExportFingerprintPolicy {
        namespace: policy.namespace,
        marking: policy.marking,
        fingerprint_properties: policy.fingerprint_properties,
        updated_by: policy.updated_by,
        updated_at_ms: policy.updated_at_ms,
    }
}

pub(super) type ExportStream = std::pin::Pin<
    Box<dyn futures_util::Stream<Item = Result<ExportObjectSetChunk, Status>> + Send>,
>;

/// Runs an export on a blocking thread: begins its receipt, sends the
/// receipt id and `header`, lets `rows` write every row (true when it wrote
/// them all), then queues the receipt behind the last byte for the response
/// stream to complete. Anything short of that leaves the receipt aborted and
/// ends the stream in an error.
pub(super) fn run_export(
    db: crate::db::runtime_db::RuntimeDb,
    prepared: PreparedExport,
) -> ExportStream {
    let PreparedExport {
        actor,
        source,
        header,
        rows,
    } = prepared;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let receipt = match crate::sekai::data_export::ExportReceipt::begin(
            db.clone(),
            &actor,
            &source,
            now_millis(),
        ) {
            Ok(receipt) => receipt,
            Err(_) => {
                // Nothing is queued yet, so this send cannot wait.
                let _ = tx.try_send(ExportItem::Fail(Status::internal(
                    "export receipt unavailable",
                )));
                return;
            }
        };
        let receipt_id = receipt.operation_id().to_string();
        if let Err(status) = record_fingerprint(&db, &receipt_id, &source) {
            let _ = tx.try_send(ExportItem::Fail(status));
            return;
        }
        let mut writer = ExportWriter {
            receipt,
            sink: ExportSink::Stream(tx.clone()),
            buffer: Vec::new(),
            buffered_rows: 0,
        };
        if !writer.send(ExportObjectSetChunk {
            receipt_id,
            ..Default::default()
        }) || !writer.write(header, 0)
        {
            return;
        }
        let writer = RefCell::new(writer);
        let written = rows(&writer);
        let mut writer = writer.into_inner();
        match written {
            // A scan the lease stopped is never a complete export.
            Ok(true) if writer.receipt.live() && writer.flush() => {
                // The stream completes the receipt once it reaches it.
                let ExportWriter { receipt, .. } = writer;
                if let Some(budget) = receipt.send_budget() {
                    let _ = tokio::runtime::Handle::current()
                        .block_on(tx.send_timeout(ExportItem::Finish(Box::new(receipt)), budget));
                }
            }
            // The client left, or the lease ran short: the receipt drops as
            // aborted.
            Ok(_) => {}
            Err(status) => {
                let _ = send_item(&tx, ExportItem::Fail(status), &writer.receipt);
            }
        }
    });
    Box::pin(export_response_stream(rx))
}

/// What a run into an artifact produced.
pub(super) struct ArtifactRun {
    pub(super) receipt_id: String,
    pub(super) row_count: u64,
    pub(super) content_digest: String,
}

/// Runs an export into a durable artifact (#1628), blocking: the receipt is
/// begun first, the bytes are stored chunk by chunk under its lease, and the
/// receipt completes only after the last chunk is stored. The receipt is the
/// artifact's record: it is whole exactly when its receipt completed, with
/// that digest. Anything short of that leaves the receipt aborted and the
/// artifact for the retention sweep.
pub(super) fn run_to_artifact(
    db: crate::db::runtime_db::RuntimeDb,
    definition_id: &str,
    prepared: PreparedExport,
) -> Result<ArtifactRun, Status> {
    let PreparedExport {
        actor,
        source,
        header,
        rows,
    } = prepared;
    let now = now_millis();
    crate::sekai::data_export::sweep_expired_artifacts(&db, now).map_err(Status::internal)?;
    let receipt = crate::sekai::data_export::ExportReceipt::begin(db.clone(), &actor, &source, now)
        .map_err(|_| Status::internal("export receipt unavailable"))?;
    let receipt_id = receipt.operation_id().to_string();
    record_fingerprint(&db, &receipt_id, &source)?;
    db.open_export_artifact(&receipt_id, &source.namespace, definition_id, now)
        .map_err(Status::internal)?;
    let mut writer = ExportWriter {
        receipt,
        sink: ExportSink::Artifact {
            db: db.clone(),
            next_seq: 0,
        },
        buffer: Vec::new(),
        buffered_rows: 0,
    };
    if !writer.write(header, 0) {
        return Err(Status::aborted("export artifact could not be written"));
    }
    let writer = RefCell::new(writer);
    let written = rows(&writer)?;
    let mut writer = writer.into_inner();
    if !(written && writer.receipt.live() && writer.flush()) {
        return Err(Status::aborted("export did not complete"));
    }
    let ExportWriter { receipt, .. } = writer;
    let (row_count, content_digest) = receipt
        .complete(now_millis())
        .map_err(|_| Status::aborted("export did not complete"))?;
    Ok(ArtifactRun {
        receipt_id,
        row_count,
        content_digest,
    })
}

/// The caller principal holding an active export grant on `namespace`;
/// otherwise records the refusal and fails closed.
pub(super) fn export_grantee(
    db: &crate::db::runtime_db::RuntimeDb,
    principals: &[String],
    namespace: &str,
    source_kind: &str,
    source_id: &str,
) -> Result<String, Status> {
    for principal in principals {
        if db
            .get_export_grant(namespace, principal)
            .map_err(Status::internal)?
            .is_some_and(|grant| grant.active())
        {
            return Ok(principal.clone());
        }
    }
    crate::sekai::data_export::record_refusal(
        db,
        &principals[0],
        namespace,
        source_kind,
        source_id,
        now_millis(),
    )
    .map_err(|_| Status::internal("export refusal unrecorded"))?;
    Err(Status::permission_denied(
        crate::sekai::data_export::EXPORT_DENIED,
    ))
}

/// Version rows read per page.
const DATASET_EXPORT_PAGE: usize = 1_000;

impl SekaiServiceImpl {
    /// Streams one dataset version as CSV or JSON Lines (#1695). The caller
    /// needs read on the dataset, the full read policy of the object it is
    /// bound to, and an export grant on that object's namespace. Columns the
    /// bound object's property grants withhold are written empty (CSV) or
    /// left out (JSON Lines); restricted columns are redacted as a read of
    /// that object redacts restricted properties.
    pub(super) async fn export_dataset_version_rpc(
        &self,
        req: Request<ExportDatasetVersionRequest>,
    ) -> Result<Response<ExportStream>, Status> {
        let caller = ExportCaller::from_request(self, &req)?;
        let inner = req.into_inner();
        let prepared = self.prepare_dataset_version_export(caller, inner)?;
        Ok(Response::new(run_export(
            self.db.runtime().clone(),
            prepared,
        )))
    }

    /// What `caller` may export of this source, checked now: the export's
    /// receipt source, its header, and the row writer to run.
    pub(super) fn prepare_dataset_version_export(
        &self,
        caller: ExportCaller,
        request: ExportDatasetVersionRequest,
    ) -> Result<PreparedExport, Status> {
        use crate::sekai::data_export::{ExportFormat, ExportSource, RowEncoder};
        let ExportCaller {
            principals,
            policy_context,
            purpose,
            tenant_context,
        } = caller;
        let inner = request;
        let format = ExportFormat::parse(&inner.format)
            .ok_or_else(|| Status::invalid_argument("format must be csv or jsonl"))?;
        let db = self.db.runtime().clone();
        let dataset = db
            .get_dataset(&inner.dataset_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("dataset not found"))?;
        check_dataset_access(&db, &self.security, &principals, &dataset, false)?;
        // The grant lives on a namespace: only a dataset bound to an object
        // has one, and the caller must read that object in full.
        if dataset.object_id.is_empty() {
            return Err(Status::failed_precondition(
                "export needs a dataset bound to an object",
            ));
        }
        let unavailable = || Status::permission_denied("dataset export unavailable");
        let object = db
            .get_object_with_policy_context(&dataset.object_id, &policy_context)
            .map_err(Status::internal)?
            .ok_or_else(unavailable)?;
        enforce_namespace_tenant_context(&db, tenant_context.as_ref(), &object.namespace, false)?;
        let namespace = object.namespace.clone();
        let (object, _) = require_visible_object_contents(
            &db,
            &self.security,
            object,
            &principals,
            tenant_context.as_ref(),
            &format!("dataset_export:{}", dataset.id),
            purpose.as_ref(),
        )
        .map_err(|_| unavailable())?;
        // An empty version is the latest one, as a saved export reruns it.
        let version_id = if inner.version_id.is_empty() {
            db.latest_dataset_version_id(&dataset.id)
                .map_err(Status::internal)?
        } else {
            inner.version_id.clone()
        };
        let version = db
            .get_dataset_version(&dataset.id, &version_id, 0)
            .map_err(map_dataset_version_error)?;
        if version.purged {
            return Err(Status::failed_precondition(
                crate::sekai::dataset_version::DATASET_VERSION_PAST_RETENTION,
            ));
        }
        let columns = if inner.columns.is_empty() {
            dataset
                .columns
                .iter()
                .map(|column| column.name.clone())
                .collect()
        } else {
            inner.columns
        };
        if let Some(unknown) = columns
            .iter()
            .find(|name| !dataset.columns.iter().any(|column| &column.name == *name))
        {
            return Err(Status::invalid_argument(format!(
                "dataset has no column {unknown:?}"
            )));
        }
        let encoder =
            RowEncoder::new(format, columns.clone(), false).map_err(Status::invalid_argument)?;
        // Cell grants name object value instances, which dataset rows do not
        // carry: a dataset under them is refused rather than exported whole.
        if db
            .active_object_policy(&object.namespace, &object.kind)
            .map_err(|_| Status::unavailable("object authorization unavailable"))?
            .is_some_and(|policy| policy.value_instance_grants_enforced())
        {
            return Err(Status::failed_precondition(
                "a dataset whose bound object type has cell grants cannot be exported",
            ));
        }
        let readable = super::rpc_data::preview_column_allowlist(self, &dataset)?;
        // Restricted columns read as a restricted property of the bound
        // object reads: redacted unless the caller, and any actor it acts
        // for, may read restricted properties of that object.
        let restricted_readable =
            can_read_restricted_properties(&self.security, &object, &principals)
                && tenant_context
                    .as_ref()
                    .and_then(|context| context.act.as_ref())
                    .is_none_or(|actor| {
                        can_read_restricted_properties(
                            &self.security,
                            &object,
                            std::slice::from_ref(actor),
                        )
                    });
        let redacted: std::collections::HashSet<String> = if restricted_readable {
            std::collections::HashSet::new()
        } else {
            let schema = self
                .schema_definitions
                .snapshot()
                .map_err(map_schema_definition_lifecycle_error)?;
            let mut restricted = restricted_property_names_for_kind(&schema, &object.kind);
            restricted.extend(
                dataset
                    .columns
                    .iter()
                    .filter(|column| {
                        crate::sekai::schema::is_restricted_property_classification(
                            &column.classification,
                        )
                    })
                    .map(|column| column.name.clone()),
            );
            restricted
        };
        let granted_via =
            export_grantee(&db, &principals, &namespace, "dataset_version", &dataset.id)?;
        let plan = crate::sekai::export_fingerprint::namespace_plan(&db, &namespace)
            .map_err(Status::internal)?;
        let fingerprint_properties = plan
            .as_ref()
            .map(crate::sekai::export_fingerprint::FingerprintPlan::properties)
            .unwrap_or_default();
        let fingerprint_group_size = if plan.is_some() {
            crate::sekai::export_fingerprint::FINGERPRINT_GROUP_SIZE as u32
        } else {
            0
        };
        let source = ExportSource {
            namespace,
            source_kind: "dataset_version",
            source_id: dataset.id.clone(),
            source_version: version.version_id.clone(),
            definition_digest: String::new(),
            format,
            columns,
            granted_via,
            fingerprint_properties,
            fingerprint_group_size,
        };
        let dataset_id = dataset.id;
        let version_id = version.version_id;
        let reader = db.clone();
        let bound_marking = crate::sekai::markings::object_marking_token(&object)
            .unwrap_or("")
            .to_string();
        Ok(PreparedExport {
            actor: principals[0].clone(),
            source,
            header: encoder.header(),
            rows: Box::new(move |writer: &RefCell<ExportWriter>| {
                let export_id = writer.borrow().operation_id().to_string();
                let mut sink = crate::sekai::export_fingerprint::FingerprintSink::new(
                    export_id, encoder, plan,
                );
                let mut after = i64::MIN;
                loop {
                    let page = reader
                        .dataset_version_rows_after(
                            &dataset_id,
                            &version_id,
                            after,
                            DATASET_EXPORT_PAGE,
                        )
                        .map_err(Status::internal)?;
                    let Some((last, _)) = page.last() else {
                        break;
                    };
                    after = *last;
                    let mut writer = writer.borrow_mut();
                    for (_, mut values) in page {
                        if let Some(readable) = &readable {
                            values.retain(|name, _| readable.contains(name));
                        }
                        for (name, value) in values.iter_mut() {
                            if redacted.contains(name) {
                                *value = REDACTED_VALUE.to_string();
                            }
                        }
                        let encoded = sink
                            .push("", &bound_marking, values)
                            .map_err(Status::invalid_argument)?;
                        for row in encoded {
                            if !writer.write(row, 1) {
                                return Ok(false);
                            }
                        }
                    }
                    if !writer.keep_alive() {
                        return Ok(false);
                    }
                }
                {
                    let mut writer = writer.borrow_mut();
                    for row in sink.finish() {
                        if !writer.write(row, 1) {
                            return Ok(false);
                        }
                    }
                }
                // A version purged while it streamed is not exported whole.
                let current = reader
                    .get_dataset_version(&dataset_id, &version_id, 0)
                    .map_err(map_dataset_version_error)?;
                if current.purged {
                    return Err(Status::failed_precondition(
                        crate::sekai::dataset_version::DATASET_VERSION_PAST_RETENTION,
                    ));
                }
                Ok(true)
            }),
        })
    }
}

/// Definition ids: 1 to 128 letters, digits, '.', '_', '-' or ':'.
fn check_definition_id(id: &str) -> Result<(), Status> {
    let valid = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'));
    if valid {
        Ok(())
    } else {
        Err(Status::invalid_argument(
            "definition_id must be 1 to 128 letters, digits, '.', '_', '-' or ':'",
        ))
    }
}

fn decode_definition(record_json: &str) -> Result<ExportDefinition, Status> {
    serde_json::from_str(record_json).map_err(|_| Status::internal("export definition unreadable"))
}

impl SekaiServiceImpl {
    /// The export a saved definition names, checked for `caller` exactly as
    /// a live export of that source is.
    fn prepare_definition_export(
        &self,
        caller: ExportCaller,
        definition: &ExportDefinition,
    ) -> Result<PreparedExport, Status> {
        let outside =
            || Status::invalid_argument("the export source must be in the definition's namespace");
        match (&definition.object_set, &definition.dataset_version) {
            (Some(set), None) => {
                let Some(descriptor) = set
                    .descriptor
                    .as_ref()
                    .filter(|descriptor| descriptor.namespace == definition.namespace)
                else {
                    return Err(outside());
                };
                // A saved export carries no purpose. A read would silently
                // skip every row a purpose gates, so refuse it outright.
                if !purpose_allows_kind(
                    self.db.runtime(),
                    &descriptor.namespace,
                    &descriptor.kind,
                    None,
                    &mut std::collections::HashSet::new(),
                )? {
                    return Err(Status::permission_denied(
                        "the source requires a purpose, which a saved export does not carry",
                    ));
                }
                self.prepare_object_set_export(
                    caller,
                    set.descriptor.clone(),
                    set.properties.clone(),
                    &set.format,
                )
            }
            (None, Some(version)) => {
                let prepared = self.prepare_dataset_version_export(caller, version.clone())?;
                if prepared.source.namespace != definition.namespace {
                    return Err(outside());
                }
                Ok(prepared)
            }
            _ => Err(Status::invalid_argument(
                "set exactly one of object_set and dataset_version",
            )),
        }
    }

    /// The caller of a saved-export RPC. Saved exports are for principals
    /// outside a tenant assertion: a run cannot carry one, so a scoped
    /// request is refused rather than reduced to its subject. The caller
    /// also needs the namespace (write to change or run a definition).
    fn saved_export_caller<T>(
        &self,
        req: &Request<T>,
        namespace: &str,
        write: bool,
    ) -> Result<Vec<String>, Status>
    where
        T: std::any::Any,
    {
        let principals = caller_principals(req);
        require_authenticated(&principals)?;
        if request_tenant_context(self.db.runtime(), req)?.is_some() {
            return Err(Status::failed_precondition(
                "saved exports are for principals outside a tenant assertion",
            ));
        }
        check_team_namespace(self.db.runtime(), &principals, namespace, write)?;
        Ok(principals)
    }

    /// Loads a definition for its owner or an administrator of its
    /// namespace; anyone else learns nothing of it.
    fn visible_definition(
        &self,
        principals: &[String],
        namespace: &str,
        definition_id: &str,
    ) -> Result<ExportDefinition, Status> {
        let unavailable = || Status::not_found("export definition unavailable");
        let (owner, record_json) = self
            .db
            .runtime()
            .get_export_definition(namespace, definition_id)
            .map_err(Status::internal)?
            .ok_or_else(unavailable)?;
        if !principals.contains(&owner)
            && authorize_source_type_namespace_admin(self, principals, namespace).is_err()
        {
            return Err(unavailable());
        }
        decode_definition(&record_json)
    }

    /// Saves an export to run later for its caller alone (#1628). Saving
    /// checks everything a run would, for the caller as the owner: a
    /// definition that could not run now is not saved. One body per id: an
    /// identical retry returns the stored definition.
    pub(super) async fn put_export_definition_rpc(
        &self,
        req: Request<PutExportDefinitionRequest>,
    ) -> Result<Response<PutExportDefinitionResponse>, Status> {
        let caller = ExportCaller::from_request(self, &req)?;
        // A run has no request to carry a tenant assertion, so a
        // tenant-scoped caller's export could not be checked as it was saved.
        if caller.tenant_context.is_some() || caller.principals.len() != 1 {
            return Err(Status::failed_precondition(
                "saved exports are for one principal outside a tenant assertion",
            ));
        }
        let owner = caller.principals[0].clone();
        let mut definition = req
            .into_inner()
            .definition
            .ok_or_else(|| Status::invalid_argument("definition required"))?;
        check_definition_id(&definition.definition_id)?;
        definition.owner = owner.clone();
        definition.created_at_ms = 0;
        self.prepare_definition_export(ExportCaller::owner(&owner), &definition)?;
        let body = serde_json::to_string(&definition)
            .map_err(|_| Status::internal("export definition unencodable"))?;
        definition.created_at_ms = now_millis();
        let record = serde_json::to_string(&definition)
            .map_err(|_| Status::internal("export definition unencodable"))?;
        let (_, stored_json) = self
            .db
            .runtime()
            .put_export_definition(
                &definition.namespace,
                &definition.definition_id,
                &owner,
                &record,
            )
            .map_err(Status::internal)?;
        let mut stored = decode_definition(&stored_json)?;
        let created_at_ms = stored.created_at_ms;
        stored.created_at_ms = 0;
        if serde_json::to_string(&stored).ok().as_deref() != Some(body.as_str()) {
            return Err(Status::already_exists(
                "another export definition is saved under that id",
            ));
        }
        stored.created_at_ms = created_at_ms;
        Ok(Response::new(PutExportDefinitionResponse {
            definition: Some(stored),
        }))
    }

    pub(super) async fn get_export_definition_rpc(
        &self,
        req: Request<GetExportDefinitionRequest>,
    ) -> Result<Response<GetExportDefinitionResponse>, Status> {
        let namespace = req.get_ref().namespace.clone();
        let principals = self.saved_export_caller(&req, &namespace, false)?;
        let inner = req.into_inner();
        let definition =
            self.visible_definition(&principals, &inner.namespace, &inner.definition_id)?;
        Ok(Response::new(GetExportDefinitionResponse {
            definition: Some(definition),
        }))
    }

    pub(super) async fn delete_export_definition_rpc(
        &self,
        req: Request<DeleteExportDefinitionRequest>,
    ) -> Result<Response<DeleteExportDefinitionResponse>, Status> {
        let namespace = req.get_ref().namespace.clone();
        let principals = self.saved_export_caller(&req, &namespace, true)?;
        let inner = req.into_inner();
        let definition =
            self.visible_definition(&principals, &inner.namespace, &inner.definition_id)?;
        // Only the record the caller was authorized against is deleted: a
        // definition saved anew under the id since is not.
        let record = serde_json::to_string(&definition)
            .map_err(|_| Status::internal("export definition unencodable"))?;
        let deleted = self
            .db
            .runtime()
            .delete_export_definition(&inner.namespace, &inner.definition_id, &record)
            .map_err(Status::internal)?;
        Ok(Response::new(DeleteExportDefinitionResponse { deleted }))
    }

    /// Runs a saved export now, for its owner alone, into a stored artifact.
    /// Only the owner runs it. Every check is made again at run time; a run
    /// they now refuse writes a refused receipt and fails closed.
    pub(super) async fn run_export_definition_rpc(
        &self,
        req: Request<RunExportDefinitionRequest>,
    ) -> Result<Response<RunExportDefinitionResponse>, Status> {
        let namespace = req.get_ref().namespace.clone();
        let principals = self.saved_export_caller(&req, &namespace, true)?;
        let inner = req.into_inner();
        let definition =
            self.visible_definition(&principals, &inner.namespace, &inner.definition_id)?;
        if !principals.contains(&definition.owner) {
            return Err(Status::permission_denied(
                "only the owner of an export definition runs it",
            ));
        }
        let service = self.clone();
        tokio::task::spawn_blocking(move || {
            let db = service.db.runtime().clone();
            let prepared = match service
                .prepare_definition_export(ExportCaller::owner(&definition.owner), &definition)
            {
                Ok(prepared) => prepared,
                Err(status) => {
                    let receipt_id = crate::sekai::data_export::record_refused_run(
                        &db,
                        &definition.owner,
                        &definition.namespace,
                        &definition.definition_id,
                        status.message(),
                        now_millis(),
                    )
                    .map_err(|_| Status::internal("export refusal unrecorded"))?;
                    return Err(Status::new(
                        status.code(),
                        format!("{} (receipt {receipt_id})", status.message()),
                    ));
                }
            };
            let run = run_to_artifact(db, &definition.definition_id, prepared)?;
            Ok(Response::new(RunExportDefinitionResponse {
                receipt_id: run.receipt_id,
                row_count: i64::try_from(run.row_count).unwrap_or(i64::MAX),
                content_digest: run.content_digest,
            }))
        })
        .await
        .map_err(|_| Status::internal("export run failed"))?
    }
}
