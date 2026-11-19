//! Namespace audit export (#2638): a paged, resumable read of one
//! namespace's audit decisions, verified against the hash chain.
//!
//! Only a namespace admin (or the local operator) may read a namespace's
//! audit, and each page read is itself recorded as an audit decision in that
//! namespace, after the page is read, so a later page returns it.

use super::*;
use crate::sekai::audit_export::{AuditCursor, AuditExportError};

/// Trait route for the facade's `delegate_rpcs!` list.
impl SekaiServiceImpl {
    pub(super) async fn export_namespace_audit_rpc(
        &self,
        req: Request<ExportNamespaceAuditRequest>,
    ) -> Result<Response<ExportNamespaceAuditResponse>, Status> {
        export_namespace_audit(self, req)
    }
}

fn export_namespace_audit(
    service: &SekaiServiceImpl,
    req: Request<ExportNamespaceAuditRequest>,
) -> Result<Response<ExportNamespaceAuditResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let db = service.db.runtime();
    let tenant_context = request_tenant_context(db, &req)?;
    let input = req.into_inner();
    let namespace = input.namespace.trim();
    if namespace.is_empty() || namespace != input.namespace {
        return Err(Status::invalid_argument(
            "namespace must be a non-empty canonical name",
        ));
    }
    enforce_namespace_tenant_context(db, tenant_context.as_ref(), namespace, false)?;
    require_namespace_admin(db, &principals, namespace)?;
    let cursor = AuditCursor::parse(&input.cursor).map_err(export_status)?;
    let page = db
        .export_namespace_audit(namespace, cursor.as_ref(), input.page_size as usize)
        .map_err(export_status)?;
    db.record_decision(&audit::Decision {
        id: format!("audit-export:{}", uuid::Uuid::new_v4().as_simple()),
        timestamp: now_millis(),
        actor: principals.first().cloned().unwrap_or_default(),
        action: "audit.export".into(),
        reason: "namespace audit export page".into(),
        evidence: HashMap::from([
            ("namespace".into(), namespace.to_string()),
            ("from_seq".into(), page.verified_from.seq.to_string()),
            ("through_seq".into(), page.next_cursor.seq.to_string()),
            ("records".into(), page.records.len().to_string()),
        ]),
        target_id: namespace.to_string(),
        outcome: "allow".into(),
    })
    .map_err(Status::internal)?;
    Ok(Response::new(ExportNamespaceAuditResponse {
        records: page
            .records
            .into_iter()
            .map(|entry| AuditExportRecord {
                seq: entry.seq,
                prev_hash: entry.prev_hash,
                entry_hash: entry.entry_hash,
                id: entry.decision.id,
                timestamp: entry.decision.timestamp,
                actor: entry.decision.actor,
                action: entry.decision.action,
                reason: entry.decision.reason,
                evidence_json: entry.evidence_json,
                target_id: entry.decision.target_id,
                outcome: entry.decision.outcome,
            })
            .collect(),
        next_cursor: page.next_cursor.encode(),
        archived_through_seq: page.archived_through_seq,
        verified_from_seq: page.verified_from.seq,
        verified_from_hash: page.verified_from.entry_hash,
        verified_through_seq: page.next_cursor.seq,
        verified_through_hash: page.next_cursor.entry_hash,
        caught_up: page.caught_up,
    }))
}

/// Root and the local operator pass; anyone else needs the admin role on
/// `namespace` itself.
fn require_namespace_admin(
    db: &RuntimeDb,
    principals: &[String],
    namespace: &str,
) -> Result<(), Status> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(());
    }
    let admin =
        team_namespace_memberships(db, principals)?
            .iter()
            .any(|(member_namespace, role)| {
                member_namespace == namespace && matches!(role, security::Role::Admin)
            });
    if admin {
        Ok(())
    } else {
        Err(Status::permission_denied("namespace admin required"))
    }
}

fn export_status(error: AuditExportError) -> Status {
    match error {
        AuditExportError::InvalidCursor => Status::invalid_argument(error.to_string()),
        AuditExportError::Chain { .. } => Status::data_loss(error.to_string()),
        AuditExportError::Store(error) => Status::internal(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db));
        for (namespace, principal, role) in [
            ("acme", "alice", security::Role::Admin),
            ("acme", "bob", security::Role::Editor),
        ] {
            let (_, grants) = svc
                .db
                .runtime()
                .ensure_team_namespace(namespace, principal, role, "local")
                .unwrap();
            for grant in grants {
                svc.security.add_grant(&grant);
            }
        }
        svc
    }

    fn request(
        namespace: &str,
        cursor: &str,
        principal: &str,
    ) -> Request<ExportNamespaceAuditRequest> {
        let mut req = Request::new(ExportNamespaceAuditRequest {
            namespace: namespace.into(),
            cursor: cursor.into(),
            page_size: 0,
        });
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    #[tokio::test]
    async fn only_a_namespace_admin_reads_and_each_read_is_audited() {
        let svc = service();
        for (namespace, principal) in [("acme", "bob"), ("other", "alice")] {
            let refused = svc
                .export_namespace_audit(request(namespace, "", principal))
                .await
                .unwrap_err();
            assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{principal}");
        }
        let first = svc
            .export_namespace_audit(request("acme", "", "alice"))
            .await
            .unwrap()
            .into_inner();
        assert!(first.caught_up);
        let second = svc
            .export_namespace_audit(request("acme", &first.next_cursor, "alice"))
            .await
            .unwrap()
            .into_inner();
        let read = second
            .records
            .iter()
            .find(|record| record.action == "audit.export")
            .expect("the first read is recorded in the namespace");
        assert_eq!(read.actor, "alice");
        assert!(first.records.iter().all(|record| record.seq < read.seq));
        let bad = svc
            .export_namespace_audit(request("acme", "not-a-cursor", "alice"))
            .await
            .unwrap_err();
        assert_eq!(bad.code(), tonic::Code::InvalidArgument);
    }
}
