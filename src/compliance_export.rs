//! Auditor-facing offline compliance export bundles (#297).
//!
//! Builds a versioned, integrity-digested package of operation receipts and
//! related audit decisions for a namespace and time range. Verification runs
//! offline without database access.

use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent};
use crate::sekai::audit::Decision;
use crate::shomei::{canonical_json, digest_serializable};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const COMPLIANCE_BUNDLE_VERSION: &str = "sekai.compliance-export/v1";
pub const COMPLIANCE_DIGEST_ALGORITHM: &str = "sha-256";
pub const COMPLIANCE_SIGNATURE_ALGORITHM: &str = "ed25519";

/// Maximum receipts accepted into one export to keep bundles bounded.
pub const MAX_COMPLIANCE_RECEIPTS: usize = 5_000;
/// Maximum audit decisions accepted into one export.
pub const MAX_COMPLIANCE_DECISIONS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    /// Keep receipt attributes as stored (still secret-free by admission policy).
    Full,
    /// Redact event attribute values that look sensitive; keep keys and decision metadata.
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceExportRequest {
    pub namespace: String,
    pub start_timestamp_ms: i64,
    pub end_timestamp_ms: i64,
    pub redaction: RedactionMode,
    pub actor: String,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceExportManifest {
    pub bundle_version: String,
    pub namespace: String,
    pub start_timestamp_ms: i64,
    pub end_timestamp_ms: i64,
    pub redaction: RedactionMode,
    pub exported_by: String,
    pub export_request_id: String,
    pub exported_at_ms: i64,
    pub receipt_count: u32,
    pub decision_count: u32,
    pub digest_algorithm: String,
    /// Digest of the unsigned payload (receipts + decisions + this manifest with digest cleared).
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceExportSignature {
    pub algorithm: String,
    pub identity: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signed_at_ms: i64,
    pub signature_hex: String,
}

/// Portable audit decision snapshot for offline export (serde-stable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDecisionRecord {
    pub id: String,
    pub timestamp: i64,
    pub actor: String,
    pub action: String,
    pub reason: String,
    pub evidence: BTreeMap<String, String>,
    pub target_id: String,
    pub outcome: String,
}

impl From<&Decision> for ComplianceDecisionRecord {
    fn from(decision: &Decision) -> Self {
        let mut evidence = BTreeMap::new();
        for (key, value) in &decision.evidence {
            evidence.insert(key.clone(), value.clone());
        }
        Self {
            id: decision.id.clone(),
            timestamp: decision.timestamp,
            actor: decision.actor.clone(),
            action: decision.action.clone(),
            reason: decision.reason.clone(),
            evidence,
            target_id: decision.target_id.clone(),
            outcome: decision.outcome.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceExportBundle {
    pub manifest: ComplianceExportManifest,
    pub receipts: Vec<OperationReceipt>,
    pub decisions: Vec<ComplianceDecisionRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ComplianceExportSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceVerifyReport {
    pub ok: bool,
    pub content_digest_ok: bool,
    pub signature_ok: bool,
    pub errors: Vec<String>,
}

/// Build a compliance export from already-authorized, window-filtered data.
pub fn build_compliance_export(
    request: &ComplianceExportRequest,
    mut receipts: Vec<OperationReceipt>,
    decisions: Vec<Decision>,
    exported_at_ms: i64,
) -> Result<ComplianceExportBundle, String> {
    validate_request(request)?;
    if receipts.len() > MAX_COMPLIANCE_RECEIPTS {
        return Err(format!(
            "compliance export receipt limit exceeded ({MAX_COMPLIANCE_RECEIPTS})"
        ));
    }
    if decisions.len() > MAX_COMPLIANCE_DECISIONS {
        return Err(format!(
            "compliance export decision limit exceeded ({MAX_COMPLIANCE_DECISIONS})"
        ));
    }

    receipts.retain(|receipt| {
        receipt.namespace == request.namespace
            && receipt_overlaps_window(
                receipt,
                request.start_timestamp_ms,
                request.end_timestamp_ms,
            )
    });
    receipts.sort_by(|left, right| {
        left.started_at_ms
            .cmp(&right.started_at_ms)
            .then_with(|| left.operation_id.cmp(&right.operation_id))
    });

    let mut decision_records: Vec<ComplianceDecisionRecord> = decisions
        .iter()
        .filter(|decision| {
            decision.timestamp >= request.start_timestamp_ms
                && decision.timestamp < request.end_timestamp_ms
                && decision_touches_namespace(decision, &request.namespace)
        })
        .map(ComplianceDecisionRecord::from)
        .collect();
    decision_records.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.id.cmp(&right.id))
    });

    if request.redaction == RedactionMode::Redacted {
        for receipt in &mut receipts {
            redact_receipt(receipt);
        }
        for decision in &mut decision_records {
            redact_decision_record(decision);
        }
    }

    let mut manifest = ComplianceExportManifest {
        bundle_version: COMPLIANCE_BUNDLE_VERSION.into(),
        namespace: request.namespace.clone(),
        start_timestamp_ms: request.start_timestamp_ms,
        end_timestamp_ms: request.end_timestamp_ms,
        redaction: request.redaction,
        exported_by: request.actor.clone(),
        export_request_id: request.request_id.clone(),
        exported_at_ms,
        receipt_count: receipts.len() as u32,
        decision_count: decision_records.len() as u32,
        digest_algorithm: COMPLIANCE_DIGEST_ALGORITHM.into(),
        content_digest: String::new(),
    };

    let mut bundle = ComplianceExportBundle {
        manifest: manifest.clone(),
        receipts,
        decisions: decision_records,
        signature: None,
    };
    let content_digest = content_digest_for(&bundle)?;
    manifest.content_digest = content_digest.clone();
    bundle.manifest = manifest;
    Ok(bundle)
}

pub fn sign_compliance_export(
    bundle: &mut ComplianceExportBundle,
    signing_key: &SigningKey,
    identity: &str,
    key_id: &str,
    signed_at_ms: i64,
) -> Result<(), String> {
    if bundle.signature.is_some() {
        return Err("compliance export is already signed".into());
    }
    if identity.trim().is_empty() || key_id.trim().is_empty() {
        return Err("signer identity and key_id required".into());
    }
    let mut unsigned = bundle.clone();
    unsigned.signature = Some(ComplianceExportSignature {
        algorithm: COMPLIANCE_SIGNATURE_ALGORITHM.into(),
        identity: identity.into(),
        key_id: key_id.into(),
        public_key_hex: encode_hex(signing_key.verifying_key().as_bytes()),
        signed_at_ms,
        signature_hex: String::new(),
    });
    let bytes = canonical_json(&unsigned)?;
    let signature = signing_key.sign(&bytes);
    bundle.signature = Some(ComplianceExportSignature {
        algorithm: COMPLIANCE_SIGNATURE_ALGORITHM.into(),
        identity: identity.into(),
        key_id: key_id.into(),
        public_key_hex: encode_hex(signing_key.verifying_key().as_bytes()),
        signed_at_ms,
        signature_hex: encode_hex(&signature.to_bytes()),
    });
    Ok(())
}

/// Offline verification: content digest + optional signature.
pub fn verify_compliance_export(
    bundle: &ComplianceExportBundle,
    trusted_public_key_hex: Option<&str>,
) -> ComplianceVerifyReport {
    let mut errors = Vec::new();
    if bundle.manifest.bundle_version != COMPLIANCE_BUNDLE_VERSION {
        errors.push(format!(
            "unsupported bundle version {}",
            bundle.manifest.bundle_version
        ));
    }
    if bundle.manifest.receipt_count as usize != bundle.receipts.len() {
        errors.push("manifest receipt_count does not match receipts".into());
    }
    if bundle.manifest.decision_count as usize != bundle.decisions.len() {
        errors.push("manifest decision_count does not match decisions".into());
    }

    let content_digest_ok = match content_digest_for(bundle) {
        Ok(digest) if digest == bundle.manifest.content_digest => true,
        Ok(digest) => {
            errors.push(format!(
                "content digest mismatch: manifest={} computed={digest}",
                bundle.manifest.content_digest
            ));
            false
        }
        Err(error) => {
            errors.push(format!("content digest failed: {error}"));
            false
        }
    };

    let signature_ok = match (&bundle.signature, trusted_public_key_hex) {
        (None, None) => true,
        (None, Some(_)) => {
            errors.push("trusted key provided but bundle is unsigned".into());
            false
        }
        (Some(signature), None) => {
            // Without an explicit trusted key, still cryptographically verify
            // against the embedded public key so signature_ok is not a free pass.
            // Callers that need identity trust must pass --trusted-key.
            match verify_signature(bundle, signature, &signature.public_key_hex) {
                Ok(()) => true,
                Err(error) => {
                    errors.push(format!(
                        "signature present but failed embedded-key verification: {error}"
                    ));
                    false
                }
            }
        }
        (Some(signature), Some(public_key_hex)) => {
            match verify_signature(bundle, signature, public_key_hex) {
                Ok(()) => true,
                Err(error) => {
                    errors.push(error);
                    false
                }
            }
        }
    };

    ComplianceVerifyReport {
        ok: errors.is_empty() && content_digest_ok && signature_ok,
        content_digest_ok,
        signature_ok,
        errors,
    }
}

pub fn compliance_bundle_bytes(bundle: &ComplianceExportBundle) -> Result<Vec<u8>, String> {
    canonical_json(bundle)
}

fn verify_signature(
    bundle: &ComplianceExportBundle,
    signature: &ComplianceExportSignature,
    public_key_hex: &str,
) -> Result<(), String> {
    if signature.algorithm != COMPLIANCE_SIGNATURE_ALGORITHM {
        return Err(format!(
            "unsupported signature algorithm {}",
            signature.algorithm
        ));
    }
    let key_bytes = decode_hex(public_key_hex)?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "ed25519 public key must be 32 bytes".to_string())?;
    let verifying = VerifyingKey::from_bytes(&key_array)
        .map_err(|error| format!("invalid ed25519 public key: {error}"))?;
    if signature.public_key_hex != encode_hex(verifying.as_bytes())
        && signature.public_key_hex != public_key_hex
    {
        // Allow either the embedded key or the trusted key when they match bytes.
        if decode_hex(&signature.public_key_hex).ok().as_deref() != Some(key_array.as_slice()) {
            return Err("bundle public key does not match trusted key".into());
        }
    }
    let sig_bytes = decode_hex(&signature.signature_hex)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "ed25519 signature must be 64 bytes".to_string())?;
    let ed_sig = Signature::from_bytes(&sig_array);
    let mut unsigned = bundle.clone();
    if let Some(sig) = &mut unsigned.signature {
        sig.signature_hex.clear();
    }
    let bytes = canonical_json(&unsigned)?;
    verifying
        .verify(&bytes, &ed_sig)
        .map_err(|_| "compliance export signature verification failed".into())
}

fn content_digest_for(bundle: &ComplianceExportBundle) -> Result<String, String> {
    let mut unsigned = bundle.clone();
    unsigned.manifest.content_digest.clear();
    unsigned.signature = None;
    digest_serializable(&unsigned)
}

fn validate_request(request: &ComplianceExportRequest) -> Result<(), String> {
    if request.namespace.trim().is_empty() {
        return Err("namespace required".into());
    }
    if request.actor.trim().is_empty() || request.request_id.trim().is_empty() {
        return Err("actor and request_id required".into());
    }
    if request.end_timestamp_ms <= request.start_timestamp_ms {
        return Err("end_timestamp_ms must be greater than start_timestamp_ms".into());
    }
    if request
        .end_timestamp_ms
        .saturating_sub(request.start_timestamp_ms)
        > 366 * 24 * 60 * 60 * 1000
    {
        return Err("compliance export window must be at most 366 days".into());
    }
    Ok(())
}

fn receipt_overlaps_window(
    receipt: &OperationReceipt,
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
) -> bool {
    receipt.started_at_ms < end_timestamp_ms
        && receipt
            .completed_at_ms
            .unwrap_or(receipt.started_at_ms)
            .max(receipt.started_at_ms)
            >= start_timestamp_ms
}

fn decision_touches_namespace(decision: &Decision, namespace: &str) -> bool {
    // Exact structured attribution only — never substring-match target ids
    // (exporting "team-a" must not pick up "team-alpha").
    decision.evidence.get("namespace").map(String::as_str) == Some(namespace)
}

fn redact_receipt(receipt: &mut OperationReceipt) {
    for event in &mut receipt.events {
        redact_event(event);
    }
}

fn redact_event(event: &mut OperationReceiptEvent) {
    let keys: Vec<String> = event.attributes.keys().cloned().collect();
    for key in keys {
        if let Some(value) = event.attributes.get_mut(&key)
            && looks_sensitive(&key, value)
        {
            *value = "[redacted]".into();
        }
    }
}

fn redact_decision_record(decision: &mut ComplianceDecisionRecord) {
    let keys: Vec<String> = decision.evidence.keys().cloned().collect();
    for key in keys {
        if let Some(value) = decision.evidence.get_mut(&key)
            && looks_sensitive(&key, value)
        {
            *value = "[redacted]".into();
        }
    }
}

fn looks_sensitive(key: &str, value: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    if lower.contains("prompt")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("password")
        || lower.contains("authorization")
        || lower.contains("api_key")
        || lower.contains("body")
        || lower.contains("content")
        || lower.contains("payload")
    {
        return true;
    }
    value.len() > 512
        || value.contains("sk-")
        || value.contains("ghp_")
        || value.contains("BEGIN PRIVATE KEY")
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&trimmed[index..index + 2], 16)
                .map_err(|error| format!("invalid hex: {error}"))
        })
        .collect()
}

/// Load receipts/decisions from the runtime store and build an export bundle.
///
/// Does **not** write audit success — callers must invoke
/// [`record_compliance_export_success`] only after the bundle is signed and
/// written to durable storage.
pub fn export_compliance_from_db(
    db: &crate::db::runtime_db::RuntimeDb,
    request: &ComplianceExportRequest,
    exported_at_ms: i64,
) -> Result<ComplianceExportBundle, String> {
    validate_request(request)?;
    // Fetch limit+1 so silent truncation is impossible.
    let receipts = db.list_operation_receipts_in_window(
        &request.namespace,
        request.start_timestamp_ms,
        request.end_timestamp_ms,
        MAX_COMPLIANCE_RECEIPTS.saturating_add(1),
    )?;
    if receipts.len() > MAX_COMPLIANCE_RECEIPTS {
        return Err(format!(
            "compliance export receipt limit exceeded ({MAX_COMPLIANCE_RECEIPTS}); narrow the time window"
        ));
    }
    let decisions = db.list_compliance_decisions_in_window(
        &request.namespace,
        request.start_timestamp_ms,
        request.end_timestamp_ms,
        MAX_COMPLIANCE_DECISIONS.saturating_add(1),
    )?;
    if decisions.len() > MAX_COMPLIANCE_DECISIONS {
        return Err(format!(
            "compliance export decision limit exceeded ({MAX_COMPLIANCE_DECISIONS}); narrow the time window"
        ));
    }
    build_compliance_export(request, receipts, decisions, exported_at_ms)
}

/// Record a successful compliance export after the bundle is durable.
pub fn record_compliance_export_success(
    db: &crate::db::runtime_db::RuntimeDb,
    request: &ComplianceExportRequest,
    bundle: &ComplianceExportBundle,
    recorded_at_ms: i64,
) -> Result<(), String> {
    let evidence = export_audit_evidence(request, bundle);
    let decision = Decision {
        id: format!(
            "compliance-export:{:x}",
            Sha256::digest(format!(
                "{}\0{}\0{}",
                request.namespace, request.actor, request.request_id
            ))
        ),
        timestamp: recorded_at_ms,
        actor: request.actor.clone(),
        action: "compliance.export".into(),
        reason: "authorized offline compliance export".into(),
        evidence,
        target_id: format!("compliance-export:{}", request.namespace),
        outcome: "succeeded".into(),
    };
    db.record_decision(&decision)
}

/// Hash used for export audit request digests.
pub fn export_request_digest(request: &ComplianceExportRequest) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(format!(
            "compliance_export\0{}\0{}\0{}\0{:?}\0{}",
            request.namespace,
            request.start_timestamp_ms,
            request.end_timestamp_ms,
            request.redaction,
            request.request_id
        ))
    )
}

pub fn export_audit_evidence(
    request: &ComplianceExportRequest,
    bundle: &ComplianceExportBundle,
) -> HashMap<String, String> {
    HashMap::from([
        ("namespace".into(), request.namespace.clone()),
        (
            "start_timestamp_ms".into(),
            request.start_timestamp_ms.to_string(),
        ),
        (
            "end_timestamp_ms".into(),
            request.end_timestamp_ms.to_string(),
        ),
        (
            "redaction".into(),
            match request.redaction {
                RedactionMode::Full => "full".into(),
                RedactionMode::Redacted => "redacted".into(),
            },
        ),
        ("request_id".into(), request.request_id.clone()),
        ("request_digest".into(), export_request_digest(request)),
        (
            "content_digest".into(),
            bundle.manifest.content_digest.clone(),
        ),
        (
            "receipt_count".into(),
            bundle.manifest.receipt_count.to_string(),
        ),
        (
            "decision_count".into(),
            bundle.manifest.decision_count.to_string(),
        ),
        ("bundle_version".into(), COMPLIANCE_BUNDLE_VERSION.into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptEventKind, ReceiptSurface,
    };
    use crate::sekai::audit::Decision;
    use std::collections::HashMap;

    fn sample_receipt(id: &str, started_at_ms: i64) -> OperationReceipt {
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: id.into(),
            parent_operation_id: None,
            namespace: "ns".into(),
            operation_class: "chat".into(),
            initiating_actor: "operator".into(),
            schema_version: "schema-1".into(),
            policy_version: "policy-1".into(),
            started_at_ms,
            completed_at_ms: Some(started_at_ms + 10),
            events: vec![OperationReceiptEvent {
                event_id: format!("{id}-intent"),
                operation_id: id.into(),
                parent_event_id: None,
                timestamp_ms: started_at_ms,
                kind: ReceiptEventKind::IntentRecorded,
                surface: ReceiptSurface::Intent,
                actor: "operator".into(),
                references: Vec::new(),
                attributes: BTreeMap::from([
                    ("prompt".into(), "secret user text".into()),
                    ("route".into(), "ollama/local".into()),
                ]),
            }],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
        }
    }

    fn sample_decision(id: &str, timestamp: i64) -> Decision {
        Decision {
            id: id.into(),
            timestamp,
            actor: "operator".into(),
            action: "policy.allow".into(),
            reason: "ok".into(),
            evidence: HashMap::from([
                ("namespace".into(), "ns".into()),
                ("token".into(), "sk-live-secret".into()),
                ("route".into(), "allowed".into()),
            ]),
            target_id: "operation:op-1".into(),
            outcome: "succeeded".into(),
        }
    }

    #[test]
    fn build_and_verify_unsigned_bundle() {
        let request = ComplianceExportRequest {
            namespace: "ns".into(),
            start_timestamp_ms: 100,
            end_timestamp_ms: 200,
            redaction: RedactionMode::Full,
            actor: "auditor".into(),
            request_id: "export-1".into(),
        };
        let bundle = build_compliance_export(
            &request,
            vec![sample_receipt("op-1", 150)],
            vec![sample_decision("d-1", 160)],
            1_000,
        )
        .unwrap();
        assert_eq!(bundle.manifest.receipt_count, 1);
        assert_eq!(bundle.manifest.decision_count, 1);
        let report = verify_compliance_export(&bundle, None);
        assert!(report.ok, "{report:?}");
    }

    #[test]
    fn redaction_strips_sensitive_fields() {
        let request = ComplianceExportRequest {
            namespace: "ns".into(),
            start_timestamp_ms: 100,
            end_timestamp_ms: 200,
            redaction: RedactionMode::Redacted,
            actor: "auditor".into(),
            request_id: "export-2".into(),
        };
        let bundle = build_compliance_export(
            &request,
            vec![sample_receipt("op-1", 150)],
            vec![sample_decision("d-1", 160)],
            1_000,
        )
        .unwrap();
        let prompt = bundle.receipts[0].events[0]
            .attributes
            .get("prompt")
            .unwrap();
        assert_eq!(prompt, "[redacted]");
        assert_eq!(
            bundle.receipts[0].events[0]
                .attributes
                .get("route")
                .unwrap(),
            "ollama/local"
        );
        assert_eq!(
            bundle.decisions[0].evidence.get("token").unwrap(),
            "[redacted]"
        );
        assert_eq!(
            bundle.decisions[0].evidence.get("route").unwrap(),
            "allowed"
        );
        assert!(verify_compliance_export(&bundle, None).ok);
    }

    #[test]
    fn signed_bundle_verifies_with_trusted_key() {
        let request = ComplianceExportRequest {
            namespace: "ns".into(),
            start_timestamp_ms: 100,
            end_timestamp_ms: 200,
            redaction: RedactionMode::Full,
            actor: "auditor".into(),
            request_id: "export-3".into(),
        };
        let mut bundle =
            build_compliance_export(&request, vec![sample_receipt("op-1", 150)], vec![], 1_000)
                .unwrap();
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        sign_compliance_export(&mut bundle, &signing, "auditor-key", "k1", 2_000).unwrap();
        let public = encode_hex(signing.verifying_key().as_bytes());
        let report = verify_compliance_export(&bundle, Some(&public));
        assert!(report.ok, "{report:?}");

        let mut tampered = bundle.clone();
        tampered.receipts[0].operation_class = "tampered".into();
        let bad = verify_compliance_export(&tampered, Some(&public));
        assert!(!bad.ok);
        assert!(!bad.content_digest_ok);
    }

    #[test]
    fn rejects_inverted_window() {
        let request = ComplianceExportRequest {
            namespace: "ns".into(),
            start_timestamp_ms: 200,
            end_timestamp_ms: 100,
            redaction: RedactionMode::Full,
            actor: "auditor".into(),
            request_id: "export-4".into(),
        };
        assert!(
            build_compliance_export(&request, vec![], vec![], 1)
                .unwrap_err()
                .contains("end_timestamp_ms")
        );
    }

    #[test]
    fn export_from_db_is_audited_and_offline_verifiable() {
        use crate::db::runtime_db::RuntimeDb;
        use crate::db::sekai::SekaiDb;
        use std::sync::Arc;

        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.put_operation_receipt(&sample_receipt("op-db-1", 150))
            .unwrap();
        // Use non-secret decision evidence so admission policy accepts it.
        let mut decision = sample_decision("d-db-1", 160);
        decision
            .evidence
            .insert("token".into(), "route-hint".into());
        db.record_decision(&decision).unwrap();

        let request = ComplianceExportRequest {
            namespace: "ns".into(),
            start_timestamp_ms: 100,
            end_timestamp_ms: 200,
            redaction: RedactionMode::Redacted,
            actor: "auditor".into(),
            request_id: "export-db-1".into(),
        };
        let bundle = export_compliance_from_db(&db, &request, 1_000).unwrap();
        assert_eq!(bundle.manifest.receipt_count, 1);
        assert!(verify_compliance_export(&bundle, None).ok);
        record_compliance_export_success(&db, &request, &bundle, 1_001).unwrap();

        let audits = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                actor: Some("auditor".into()),
                action: Some("compliance.export".into()),
                target_id: None,
                after: 0,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].outcome, "succeeded");
    }

    #[test]
    fn namespace_filter_does_not_substring_match() {
        let mut other = sample_decision("d-other", 160);
        other
            .evidence
            .insert("namespace".into(), "team-alpha".into());
        other.target_id = "operation:team-alpha:1".into();
        let request = ComplianceExportRequest {
            namespace: "team-a".into(),
            start_timestamp_ms: 100,
            end_timestamp_ms: 200,
            redaction: RedactionMode::Full,
            actor: "auditor".into(),
            request_id: "export-ns".into(),
        };
        let bundle = build_compliance_export(&request, vec![], vec![other], 1_000).unwrap();
        assert_eq!(bundle.manifest.decision_count, 0);
    }
}
