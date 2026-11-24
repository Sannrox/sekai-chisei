//! Compliance bundles over gRPC (#3047): the `sekai.compliance-export/v1`
//! bundle `sekaictl admin assurance compliance export` builds, served to
//! tooling that holds no database credentials.
//!
//! Only a service principal registered with the `compliance_export`
//! capability for the namespace, or credential admin, may export; namespace
//! roles never imply it. The bundle is unsigned: signing stays with the
//! caller's key custody.

use super::*;
use crate::compliance_export::{
    ComplianceExportRequest, RedactionMode, compliance_bundle_bytes, export_compliance_from_stores,
    record_compliance_export_success,
};

/// Bundle bytes per streamed chunk, well under the default 4 MiB limit.
const CHUNK_BYTES: usize = 1024 * 1024;

pub(super) type ComplianceBundleStream = tonic::codegen::BoxStream<ComplianceBundleChunk>;

impl SekaiServiceImpl {
    pub(super) fn export_compliance_bundle_rpc(
        &self,
        req: Request<ExportComplianceBundleRequest>,
    ) -> Result<Response<ComplianceBundleStream>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let db = self.db.runtime();
        let tenant_context = request_tenant_context(db, &req)?;
        let exporter = service_principal_scope(db, tenant_context.as_ref())?.is_some_and(|scope| {
            scope.has_capability(crate::sekai::service_principal::COMPLIANCE_EXPORT)
        });
        if !exporter {
            require_credential_admin(&principals)
                .map_err(|_| Status::permission_denied("compliance_export capability required"))?;
        }
        let input = req.into_inner();
        let namespace = input.namespace.trim();
        if namespace.is_empty() || namespace != input.namespace {
            return Err(Status::invalid_argument(
                "namespace must be a non-empty canonical name",
            ));
        }
        // A namespace outside the caller's tenant or registration hides like
        // a missing one; outages stay visible.
        check_team_namespace(db, &principals, namespace, false)
            .and_then(|()| {
                enforce_namespace_tenant_context(db, tenant_context.as_ref(), namespace, false)
            })
            .map_err(|status| match status.code() {
                tonic::Code::PermissionDenied | tonic::Code::NotFound => {
                    Status::not_found("namespace not found")
                }
                _ => status,
            })?;
        let request = ComplianceExportRequest {
            namespace: input.namespace,
            start_timestamp_ms: input.start_timestamp_ms,
            end_timestamp_ms: input.end_timestamp_ms,
            redaction: if input.full {
                RedactionMode::Full
            } else {
                RedactionMode::Redacted
            },
            actor: tenant_context
                .as_ref()
                .map(|context| context.principal.subject.clone())
                .or_else(|| principals.first().cloned())
                .unwrap_or_default(),
            request_id: input.request_id,
        };
        // Receipts live on the Chisei store, which only a process holding
        // both planes reaches. A Sekai-only process refuses rather than
        // serve a bundle without receipts.
        let receipts = self
            .cross_store
            .as_ref()
            .map(|clerk| clerk.chisei_runtime_arc())
            .ok_or_else(|| {
                Status::failed_precondition(
                    "compliance export needs the combined server, which holds the receipt store",
                )
            })?;
        let exported_at_ms = now_millis();
        let bundle = export_compliance_from_stores(&receipts, db, &request, exported_at_ms)
            .map_err(|error| export_status(&error))?;
        let bytes = compliance_bundle_bytes(&bundle).map_err(Status::internal)?;
        // Recorded when served: the plane cannot observe the caller storing
        // it. The decision id derives from the request, so a retry records once.
        record_compliance_export_success(db, &request, &bundle, exported_at_ms)
            .map_err(|error| export_status(&error))?;
        let content_digest = bundle.manifest.content_digest;
        let mut chunks: Vec<_> = bytes
            .chunks(CHUNK_BYTES)
            .map(|data| ComplianceBundleChunk {
                data: data.to_vec(),
                ..Default::default()
            })
            .collect();
        if chunks.is_empty() {
            chunks.push(ComplianceBundleChunk::default());
        }
        if let Some(last) = chunks.last_mut() {
            last.done = true;
            last.content_digest = content_digest;
            last.exported_at_ms = exported_at_ms;
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(
            chunks.into_iter().map(Ok),
        ))))
    }
}

/// Request and limit errors are the caller's to fix; others are internal.
fn export_status(error: &str) -> Status {
    if error.contains("narrow the time window")
        || error.contains("required")
        || error.contains("must be")
        || error.contains("already used")
    {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}

#[cfg(test)]
#[path = "compliance_export_rpc_tests.rs"]
mod tests;
