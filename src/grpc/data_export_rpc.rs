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
    tx: tokio::sync::mpsc::Sender<ExportItem>,
    buffer: Vec<u8>,
    buffered_rows: u64,
}

impl ExportWriter {
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

    fn send(&self, chunk: ExportObjectSetChunk) -> bool {
        let deadline = self.receipt.deadline_ms();
        send_item(&self.tx, ExportItem::Data(chunk, deadline), &self.receipt)
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
}

pub(super) type ExportStream = std::pin::Pin<
    Box<dyn futures_util::Stream<Item = Result<ExportObjectSetChunk, Status>> + Send>,
>;

/// Runs an export on a blocking thread: begins its receipt, sends the
/// receipt id and `header`, lets `rows` write every row (true when it wrote
/// them all), then queues the receipt behind the last byte for the response
/// stream to complete. Anything short of that leaves the receipt aborted and
/// ends the stream in an error.
pub(super) fn run_export<F>(
    db: crate::db::runtime_db::RuntimeDb,
    actor: String,
    source: crate::sekai::data_export::ExportSource,
    header: Vec<u8>,
    rows: F,
) -> ExportStream
where
    F: FnOnce(&RefCell<ExportWriter>) -> Result<bool, Status> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let receipt = match crate::sekai::data_export::ExportReceipt::begin(
            db,
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
        let mut writer = ExportWriter {
            receipt,
            tx: tx.clone(),
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
                let ExportWriter { receipt, tx, .. } = writer;
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
        use crate::sekai::data_export::{ExportFormat, ExportSource, RowEncoder};

        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let policy_context = principal_policy_context(&req);
        let purpose = request_purpose_presentation(&req, &principals);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let inner = req.into_inner();
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
        let version = db
            .get_dataset_version(&dataset.id, &inner.version_id, 0)
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
        let source = ExportSource {
            namespace,
            source_kind: "dataset_version",
            source_id: dataset.id.clone(),
            source_version: version.version_id.clone(),
            definition_digest: String::new(),
            format,
            columns,
            granted_via,
        };
        let dataset_id = dataset.id;
        let version_id = version.version_id;
        let reader = db.clone();
        Ok(Response::new(run_export(
            db,
            principals[0].clone(),
            source,
            encoder.header(),
            move |writer| {
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
                        if !writer.write(encoder.row("", &values), 1) {
                            return Ok(false);
                        }
                    }
                    if !writer.keep_alive() {
                        return Ok(false);
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
            },
        )))
    }
}
