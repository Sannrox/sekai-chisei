//! Cross-site attestation / compliance bundle verification and governed import (#290).
//!
//! Peer bundles are verified offline under explicitly configured trust roots, then
//! recorded as import evidence. Imported evidence is **never** local permit-
//! redemption authority (fail-closed by construction: no permit issuance path
//! consults peer-import records).

use crate::compliance_export::{
    ComplianceExportBundle, ComplianceVerifyReport, verify_compliance_export,
};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::audit::Decision;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const PEER_IMPORT_CONTRACT: &str = "sekai.peer-import/v1";
pub const TRUST_ROOT_ACTION: &str = "peer.trust_root";
pub const IMPORT_ACTION: &str = "peer.compliance_import";
/// Evidence flag permanently false for peer imports — permits must not treat this as authority.
pub const PERMIT_AUTHORITY_EVIDENCE_KEY: &str = "permit_authority";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerTrustRoot {
    pub namespace: String,
    pub site_identity: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub enabled: bool,
    pub created_by: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerImportRecord {
    pub contract_version: String,
    pub import_id: String,
    pub namespace: String,
    pub peer_site_identity: String,
    pub peer_key_id: String,
    pub bundle_content_digest: String,
    pub verified: bool,
    pub receipt_count: u32,
    pub decision_count: u32,
    pub permit_authority: bool,
    pub verification_errors: Vec<String>,
    pub imported_by: String,
    pub imported_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerImportResult {
    pub record: PeerImportRecord,
    pub verification: ComplianceVerifyReport,
}

pub fn put_trust_root(db: &RuntimeDb, root: &PeerTrustRoot) -> Result<(), String> {
    validate_trust_root(root)?;
    db.put_peer_trust_root(root)
}

pub fn list_trust_roots(db: &RuntimeDb, namespace: &str) -> Result<Vec<PeerTrustRoot>, String> {
    required("namespace", namespace)?;
    db.list_peer_trust_roots(namespace)
}

/// Verify a peer compliance export under enabled trust roots for `namespace`,
/// then persist an import decision + durable import record.
pub fn import_compliance_bundle(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    bundle: &ComplianceExportBundle,
    now_ms: i64,
) -> Result<PeerImportResult, String> {
    required("actor", actor)?;
    required("namespace", namespace)?;
    if now_ms < 0 {
        return Err("import timestamp must be non-negative".into());
    }
    if bundle.manifest.namespace != namespace {
        // Import targets a local namespace; peer may have exported under the same
        // logical name or a remote name — require explicit match for v1.
        return Err(format!(
            "bundle namespace {:?} does not match import namespace {namespace:?}",
            bundle.manifest.namespace
        ));
    }

    let roots = list_trust_roots(db, namespace)?
        .into_iter()
        .filter(|root| root.enabled)
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Err("no enabled peer trust roots configured for namespace".into());
    }

    let signature = bundle
        .signature
        .as_ref()
        .ok_or_else(|| "peer compliance import requires a signed bundle".to_string())?;

    let matching_root = roots.iter().find(|root| {
        root.site_identity == signature.identity
            && root.key_id == signature.key_id
            && root
                .public_key_hex
                .eq_ignore_ascii_case(&signature.public_key_hex)
    });
    let Some(root) = matching_root else {
        return Err(format!(
            "bundle signer {}:{} is not an enabled trust root for namespace",
            signature.identity, signature.key_id
        ));
    };

    let verification = verify_compliance_export(bundle, Some(&root.public_key_hex));
    if !verification.ok {
        return Err(format!(
            "peer bundle verification failed: {}",
            verification.errors.join("; ")
        ));
    }

    let import_id = import_id_for(
        namespace,
        &bundle.manifest.content_digest,
        &signature.identity,
        &signature.key_id,
    );
    let record = PeerImportRecord {
        contract_version: PEER_IMPORT_CONTRACT.into(),
        import_id: import_id.clone(),
        namespace: namespace.into(),
        peer_site_identity: root.site_identity.clone(),
        peer_key_id: root.key_id.clone(),
        bundle_content_digest: bundle.manifest.content_digest.clone(),
        verified: true,
        receipt_count: bundle.manifest.receipt_count,
        decision_count: bundle.manifest.decision_count,
        permit_authority: false,
        verification_errors: vec![],
        imported_by: actor.into(),
        imported_at_ms: now_ms,
    };

    // Idempotent: same digest + signer → same import record.
    if let Some(existing) = db.get_peer_import(&import_id)? {
        if existing.bundle_content_digest == record.bundle_content_digest
            && existing.peer_site_identity == record.peer_site_identity
        {
            return Ok(PeerImportResult {
                record: existing,
                verification,
            });
        }
        return Err("import id collision with different payload".into());
    }

    db.put_peer_import(&record)?;
    audit_import(db, actor, &record, now_ms)?;
    Ok(PeerImportResult {
        record,
        verification,
    })
}

/// Guard used by permit/redemption paths: peer import records never authorize permits.
pub fn peer_import_grants_permit_authority(record: &PeerImportRecord) -> bool {
    record.permit_authority
}

fn audit_import(
    db: &RuntimeDb,
    actor: &str,
    record: &PeerImportRecord,
    now_ms: i64,
) -> Result<(), String> {
    let record_json =
        serde_json::to_string(record).map_err(|error| format!("encode import record: {error}"))?;
    let decision = Decision {
        id: format!("peer-import:{}", record.import_id),
        timestamp: now_ms,
        actor: actor.into(),
        action: IMPORT_ACTION.into(),
        reason: "verified peer compliance bundle imported as governed evidence".into(),
        evidence: HashMap::from([
            ("namespace".into(), record.namespace.clone()),
            ("data_class".into(), "internal".into()),
            ("import_id".into(), record.import_id.clone()),
            (
                "bundle_content_digest".into(),
                record.bundle_content_digest.clone(),
            ),
            (
                "peer_site_identity".into(),
                record.peer_site_identity.clone(),
            ),
            (PERMIT_AUTHORITY_EVIDENCE_KEY.into(), "false".into()),
            ("import_record".into(), record_json),
        ]),
        target_id: record.import_id.clone(),
        outcome: "imported".into(),
    };
    db.record_decision(&decision)
}

fn import_id_for(namespace: &str, digest: &str, identity: &str, key_id: &str) -> String {
    let hex = format!(
        "{:x}",
        Sha256::digest(format!("{namespace}\0{digest}\0{identity}\0{key_id}").as_bytes())
    );
    format!("peer-import-{}", &hex[..32])
}

fn validate_trust_root(root: &PeerTrustRoot) -> Result<(), String> {
    required("namespace", &root.namespace)?;
    required("site identity", &root.site_identity)?;
    required("key id", &root.key_id)?;
    required("public key hex", &root.public_key_hex)?;
    required("created by", &root.created_by)?;
    if root.created_at_ms < 0 {
        return Err("trust root created_at_ms must be non-negative".into());
    }
    let bytes = decode_hex(&root.public_key_hex)?;
    if bytes.len() != 32 {
        return Err("public key must be 32-byte ed25519 key hex".into());
    }
    Ok(())
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err("public key hex length must be even".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|_| format!("invalid hex at offset {index}"))
        })
        .collect()
}

fn required(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    };
    use crate::compliance_export::{
        ComplianceExportRequest, RedactionMode, build_compliance_export, sign_compliance_export,
    };
    use crate::db::runtime_db::RuntimeDb;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn sample_receipt(namespace: &str) -> OperationReceipt {
        let event = |id: &str, kind: ReceiptEventKind| OperationReceiptEvent {
            event_id: id.into(),
            operation_id: "op-1".into(),
            parent_event_id: None,
            timestamp_ms: 1_500,
            kind,
            surface: kind.surface(),
            actor: "peer".into(),
            references: Vec::new(),
            attributes: BTreeMap::new(),
        };
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: namespace.into(),
            operation_class: "triage".into(),
            initiating_actor: "peer".into(),
            schema_version: "schema-v1".into(),
            policy_version: "pol-v1".into(),
            started_at_ms: 1_000,
            completed_at_ms: Some(2_000),
            events: vec![
                event("e0", ReceiptEventKind::IntentRecorded),
                event("e1", ReceiptEventKind::OutcomeRecorded),
            ],
            uncovered_surfaces: Vec::new(),
            reporter_grants: vec![],
        }
    }

    fn public_key_hex(signing: &SigningKey) -> String {
        signing
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn signed_bundle(namespace: &str, signing: &SigningKey) -> ComplianceExportBundle {
        let request = ComplianceExportRequest {
            namespace: namespace.into(),
            start_timestamp_ms: 0,
            end_timestamp_ms: 10_000,
            redaction: RedactionMode::Full,
            actor: "peer-exporter".into(),
            request_id: "export-1".into(),
        };
        let mut bundle =
            build_compliance_export(&request, vec![sample_receipt(namespace)], vec![], 5_000)
                .unwrap();
        sign_compliance_export(&mut bundle, signing, "peer-site-a", "k1", 5_100).unwrap();
        bundle
    }

    #[test]
    fn imports_valid_signed_bundle_under_trust_root() {
        let db = db();
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let public = public_key_hex(&signing);
        put_trust_root(
            &db,
            &PeerTrustRoot {
                namespace: "support".into(),
                site_identity: "peer-site-a".into(),
                key_id: "k1".into(),
                public_key_hex: public,
                enabled: true,
                created_by: "admin".into(),
                created_at_ms: 1,
            },
        )
        .unwrap();
        let bundle = signed_bundle("support", &signing);
        let result = import_compliance_bundle(&db, "admin", "support", &bundle, 6_000).unwrap();
        assert!(result.record.verified);
        assert!(!result.record.permit_authority);
        assert!(!peer_import_grants_permit_authority(&result.record));
        assert_eq!(result.record.receipt_count, 1);

        // Idempotent re-import
        let again = import_compliance_bundle(&db, "admin", "support", &bundle, 6_001).unwrap();
        assert_eq!(again.record.import_id, result.record.import_id);
    }

    #[test]
    fn rejects_unsigned_or_untrusted_signer() {
        let db = db();
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let public = public_key_hex(&signing);
        put_trust_root(
            &db,
            &PeerTrustRoot {
                namespace: "support".into(),
                site_identity: "peer-site-a".into(),
                key_id: "k1".into(),
                public_key_hex: public,
                enabled: true,
                created_by: "admin".into(),
                created_at_ms: 1,
            },
        )
        .unwrap();
        let other = SigningKey::from_bytes(&[4u8; 32]);
        let bundle = signed_bundle("support", &other);
        assert!(
            import_compliance_bundle(&db, "admin", "support", &bundle, 6_000)
                .unwrap_err()
                .contains("trust root")
        );
    }

    #[test]
    fn rejects_tampered_bundle() {
        let db = db();
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        let public = public_key_hex(&signing);
        put_trust_root(
            &db,
            &PeerTrustRoot {
                namespace: "support".into(),
                site_identity: "peer-site-a".into(),
                key_id: "k1".into(),
                public_key_hex: public,
                enabled: true,
                created_by: "admin".into(),
                created_at_ms: 1,
            },
        )
        .unwrap();
        let mut bundle = signed_bundle("support", &signing);
        bundle.manifest.receipt_count = 99;
        assert!(
            import_compliance_bundle(&db, "admin", "support", &bundle, 6_000)
                .unwrap_err()
                .contains("verification failed")
        );
    }
}
