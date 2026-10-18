//! Versioned compliance packs that map framework controls to evidence in an
//! offline compliance export (#1468).
//!
//! Packs and the evidence-query catalog are JSON data. Status is evidence
//! presence (met / partly_met / no_evidence), not a legal or certification
//! claim.

use crate::compliance_export::{
    COMPLIANCE_DIGEST_ALGORITHM, COMPLIANCE_SIGNATURE_ALGORITHM, ComplianceExportBundle,
    ComplianceExportSignature, ComplianceVerifyReport,
};
use crate::shomei::{canonical_json, digest_serializable};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PACK_FORMAT: &str = "sekai.compliance-pack/v1";
pub const QUERY_CATALOG_VERSION: &str = "sekai.compliance-evidence-query/v1";
pub const PACK_REPORT_VERSION: &str = "sekai.compliance-pack-report/v1";
pub const FIXTURE_NAMESPACE: &str = "compliance-pack-fixture";

/// Catalog of named evidence queries. Hits are `decision.action` values in a
/// #297 export, not other tables. Retention persists `privacy.subject_erased`
/// (`deletion_proofs`). The remaining query ids are evaluated when those
/// actions appear in the export (fixture namespace and operator-supplied
/// bundles). This slice does not add new decision writers.
const QUERY_CATALOG_JSON: &str = include_str!("../compliance/queries/v1.json");
const PACK_FIXTURE_JSON: &str = include_str!("../compliance/packs/fixture.json");
const PACK_GDPR_JSON: &str = include_str!("../compliance/packs/gdpr.json");
const PACK_NIS2_JSON: &str = include_str!("../compliance/packs/nis2.json");
const PACK_ISO27001_JSON: &str = include_str!("../compliance/packs/iso27001.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQueryCatalog {
    pub catalog_version: String,
    pub queries: Vec<EvidenceQuery>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQuery {
    pub id: String,
    pub decision_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompliancePack {
    pub pack_format: String,
    pub id: String,
    pub version: String,
    pub framework: String,
    pub framework_version: String,
    pub controls: Vec<PackControl>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackControl {
    pub id: String,
    pub title: String,
    pub queries: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Met,
    PartlyMet,
    NoEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEvidence {
    pub query_id: String,
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlReport {
    pub id: String,
    pub title: String,
    pub status: ControlStatus,
    pub evidence: Vec<ControlEvidence>,
    pub missing_queries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackReportManifest {
    pub bundle_version: String,
    pub pack_id: String,
    pub pack_version: String,
    pub pack_digest: String,
    pub source_bundle_digest: String,
    pub namespace: String,
    pub start_timestamp_ms: i64,
    pub end_timestamp_ms: i64,
    pub generated_by: String,
    pub generated_at_ms: i64,
    pub digest_algorithm: String,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackReportBundle {
    pub manifest: PackReportManifest,
    pub pack: CompliancePack,
    pub controls: Vec<ControlReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ComplianceExportSignature>,
}

/// Built-in pack ids in stable order.
pub fn builtin_pack_ids() -> &'static [&'static str] {
    &["fixture", "gdpr", "nis2", "iso27001"]
}

pub fn load_query_catalog() -> Result<EvidenceQueryCatalog, String> {
    parse_query_catalog(QUERY_CATALOG_JSON)
}

pub fn load_builtin_pack(id: &str) -> Result<CompliancePack, String> {
    let json = match id {
        "fixture" => PACK_FIXTURE_JSON,
        "gdpr" => PACK_GDPR_JSON,
        "nis2" => PACK_NIS2_JSON,
        "iso27001" => PACK_ISO27001_JSON,
        other => return Err(format!("unknown built-in pack {other}")),
    };
    parse_pack(json)
}

pub fn parse_query_catalog(json: &str) -> Result<EvidenceQueryCatalog, String> {
    let catalog: EvidenceQueryCatalog =
        serde_json::from_str(json).map_err(|error| format!("query catalog: {error}"))?;
    if catalog.catalog_version != QUERY_CATALOG_VERSION {
        return Err(format!(
            "unsupported query catalog version {}",
            catalog.catalog_version
        ));
    }
    let mut seen = BTreeSet::new();
    for query in &catalog.queries {
        if query.id.trim().is_empty() {
            return Err("query id required".into());
        }
        if query.decision_actions.is_empty()
            || query
                .decision_actions
                .iter()
                .any(|action| action.trim().is_empty())
        {
            return Err(format!(
                "query {} needs at least one decision action",
                query.id
            ));
        }
        if !seen.insert(query.id.as_str()) {
            return Err(format!("duplicate query id {}", query.id));
        }
    }
    Ok(catalog)
}

pub fn parse_pack(json: &str) -> Result<CompliancePack, String> {
    let pack: CompliancePack =
        serde_json::from_str(json).map_err(|error| format!("compliance pack: {error}"))?;
    validate_pack(&pack, &load_query_catalog()?)?;
    Ok(pack)
}

fn validate_pack(pack: &CompliancePack, catalog: &EvidenceQueryCatalog) -> Result<(), String> {
    if pack.pack_format != PACK_FORMAT {
        return Err(format!("unsupported pack format {}", pack.pack_format));
    }
    if pack.id.trim().is_empty() || pack.version.trim().is_empty() {
        return Err("pack id and version required".into());
    }
    if pack.controls.is_empty() {
        return Err("pack must declare at least one control".into());
    }
    let known: BTreeSet<&str> = catalog
        .queries
        .iter()
        .map(|query| query.id.as_str())
        .collect();
    let mut seen = BTreeSet::new();
    for control in &pack.controls {
        if control.id.trim().is_empty() {
            return Err("control id required".into());
        }
        if !seen.insert(control.id.as_str()) {
            return Err(format!("duplicate control id {}", control.id));
        }
        if control.queries.is_empty() {
            return Err(format!(
                "control {} needs at least one evidence query",
                control.id
            ));
        }
        let mut query_seen = BTreeSet::new();
        for query_id in &control.queries {
            if !known.contains(query_id.as_str()) {
                return Err(format!(
                    "control {} references unknown evidence query {query_id}",
                    control.id
                ));
            }
            if !query_seen.insert(query_id.as_str()) {
                return Err(format!(
                    "control {} repeats evidence query {query_id}",
                    control.id
                ));
            }
        }
    }
    Ok(())
}

/// Evaluate `pack` against an already-built compliance export. No database.
pub fn build_pack_report(
    pack: &CompliancePack,
    source: &ComplianceExportBundle,
    generated_by: &str,
    generated_at_ms: i64,
) -> Result<PackReportBundle, String> {
    let catalog = load_query_catalog()?;
    validate_pack(pack, &catalog)?;
    if generated_by.trim().is_empty() {
        return Err("generated_by required".into());
    }
    let source_verify = crate::compliance_export::verify_compliance_export(source, None);
    if !source_verify.ok {
        return Err(format!(
            "source compliance export failed verification: {}",
            source_verify.errors.join("; ")
        ));
    }
    let queries: BTreeMap<&str, &EvidenceQuery> = catalog
        .queries
        .iter()
        .map(|query| (query.id.as_str(), query))
        .collect();
    let mut controls = Vec::with_capacity(pack.controls.len());
    for control in &pack.controls {
        controls.push(evaluate_control(control, source, &queries));
    }
    let mut manifest = PackReportManifest {
        bundle_version: PACK_REPORT_VERSION.into(),
        pack_id: pack.id.clone(),
        pack_version: pack.version.clone(),
        pack_digest: digest_serializable(pack)?,
        source_bundle_digest: source.manifest.content_digest.clone(),
        namespace: source.manifest.namespace.clone(),
        start_timestamp_ms: source.manifest.start_timestamp_ms,
        end_timestamp_ms: source.manifest.end_timestamp_ms,
        generated_by: generated_by.into(),
        generated_at_ms,
        digest_algorithm: COMPLIANCE_DIGEST_ALGORITHM.into(),
        content_digest: String::new(),
    };
    let mut report = PackReportBundle {
        manifest: manifest.clone(),
        pack: pack.clone(),
        controls,
        signature: None,
    };
    manifest.content_digest = content_digest_for(&report)?;
    report.manifest = manifest;
    Ok(report)
}

fn evaluate_control(
    control: &PackControl,
    source: &ComplianceExportBundle,
    queries: &BTreeMap<&str, &EvidenceQuery>,
) -> ControlReport {
    let mut evidence = Vec::new();
    let mut missing_queries = Vec::new();
    let mut matched = 0usize;
    for query_id in &control.queries {
        let Some(query) = queries.get(query_id.as_str()) else {
            missing_queries.push(query_id.clone());
            continue;
        };
        let hits = query_hits(query, source);
        if hits.is_empty() {
            missing_queries.push(query_id.clone());
        } else {
            matched += 1;
            evidence.extend(hits);
        }
    }
    let status = if matched == 0 {
        ControlStatus::NoEvidence
    } else if matched == control.queries.len() {
        ControlStatus::Met
    } else {
        ControlStatus::PartlyMet
    };
    ControlReport {
        id: control.id.clone(),
        title: control.title.clone(),
        status,
        evidence,
        missing_queries,
    }
}

fn query_hits(query: &EvidenceQuery, source: &ComplianceExportBundle) -> Vec<ControlEvidence> {
    let actions: BTreeSet<&str> = query.decision_actions.iter().map(String::as_str).collect();
    source
        .decisions
        .iter()
        .filter(|decision| actions.contains(decision.action.as_str()))
        .map(|decision| ControlEvidence {
            query_id: query.id.clone(),
            kind: "decision".into(),
            id: decision.id.clone(),
        })
        .collect()
}

pub fn sign_pack_report(
    report: &mut PackReportBundle,
    signing_key: &SigningKey,
    identity: &str,
    key_id: &str,
    signed_at_ms: i64,
) -> Result<(), String> {
    if report.signature.is_some() {
        return Err("compliance pack report is already signed".into());
    }
    if identity.trim().is_empty() || key_id.trim().is_empty() {
        return Err("signer identity and key_id required".into());
    }
    let mut unsigned = report.clone();
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
    report.signature = Some(ComplianceExportSignature {
        algorithm: COMPLIANCE_SIGNATURE_ALGORITHM.into(),
        identity: identity.into(),
        key_id: key_id.into(),
        public_key_hex: encode_hex(signing_key.verifying_key().as_bytes()),
        signed_at_ms,
        signature_hex: encode_hex(&signature.to_bytes()),
    });
    Ok(())
}

/// Offline verification of a pack report against the source export it cites.
pub fn verify_pack_report(
    report: &PackReportBundle,
    source: &ComplianceExportBundle,
    trusted_public_key_hex: Option<&str>,
) -> ComplianceVerifyReport {
    let mut errors = Vec::new();
    if report.manifest.bundle_version != PACK_REPORT_VERSION {
        errors.push(format!(
            "unsupported pack report version {}",
            report.manifest.bundle_version
        ));
    }
    if report.manifest.digest_algorithm != COMPLIANCE_DIGEST_ALGORITHM {
        errors.push(format!(
            "unsupported digest algorithm {}",
            report.manifest.digest_algorithm
        ));
    }
    match digest_serializable(&report.pack) {
        Ok(digest) if digest == report.manifest.pack_digest => {}
        Ok(digest) => errors.push(format!(
            "pack digest mismatch: manifest={} computed={digest}",
            report.manifest.pack_digest
        )),
        Err(error) => errors.push(format!("pack digest failed: {error}")),
    }
    if report.manifest.pack_id != report.pack.id
        || report.manifest.pack_version != report.pack.version
    {
        errors.push("manifest pack identity does not match embedded pack".into());
    }
    if report.manifest.source_bundle_digest != source.manifest.content_digest {
        errors.push(format!(
            "source bundle digest mismatch: report={} export={}",
            report.manifest.source_bundle_digest, source.manifest.content_digest
        ));
    }
    if report.manifest.namespace != source.manifest.namespace {
        errors.push("report namespace does not match source export".into());
    }
    if report.manifest.start_timestamp_ms != source.manifest.start_timestamp_ms
        || report.manifest.end_timestamp_ms != source.manifest.end_timestamp_ms
    {
        errors.push("report window does not match source export".into());
    }
    let source_verify = crate::compliance_export::verify_compliance_export(source, None);
    if !source_verify.ok {
        errors.push(format!(
            "source compliance export failed verification: {}",
            source_verify.errors.join("; ")
        ));
    }
    match build_pack_report(
        &report.pack,
        source,
        &report.manifest.generated_by,
        report.manifest.generated_at_ms,
    ) {
        Ok(expected) => {
            if expected.controls != report.controls {
                errors.push("recomputed control results do not match the report".into());
            }
        }
        Err(error) => errors.push(format!("could not recompute pack report: {error}")),
    }

    let content_digest_ok = match content_digest_for(report) {
        Ok(digest) if digest == report.manifest.content_digest => true,
        Ok(digest) => {
            errors.push(format!(
                "content digest mismatch: manifest={} computed={digest}",
                report.manifest.content_digest
            ));
            false
        }
        Err(error) => {
            errors.push(format!("content digest failed: {error}"));
            false
        }
    };

    let signature_ok = match (&report.signature, trusted_public_key_hex) {
        (None, None) => true,
        (None, Some(_)) => {
            errors.push("trusted key provided but pack report is unsigned".into());
            false
        }
        (Some(signature), None) => {
            match verify_signature(report, signature, &signature.public_key_hex) {
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
            match verify_signature(report, signature, public_key_hex) {
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

pub fn pack_report_bytes(report: &PackReportBundle) -> Result<Vec<u8>, String> {
    canonical_json(report)
}

fn content_digest_for(report: &PackReportBundle) -> Result<String, String> {
    let mut unsigned = report.clone();
    unsigned.manifest.content_digest.clear();
    unsigned.signature = None;
    digest_serializable(&unsigned)
}

fn verify_signature(
    report: &PackReportBundle,
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
        && decode_hex(&signature.public_key_hex).ok().as_deref() != Some(key_array.as_slice())
    {
        return Err("report public key does not match trusted key".into());
    }
    let sig_bytes = decode_hex(&signature.signature_hex)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "ed25519 signature must be 64 bytes".to_string())?;
    let ed_sig = Signature::from_bytes(&sig_array);
    let mut unsigned = report.clone();
    if let Some(sig) = &mut unsigned.signature {
        sig.signature_hex.clear();
    }
    let bytes = canonical_json(&unsigned)?;
    verifying
        .verify(&bytes, &ed_sig)
        .map_err(|_| "compliance pack report signature verification failed".into())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() || !trimmed.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    if !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("hex string must be ASCII hex".into());
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&trimmed[index..index + 2], 16)
                .map_err(|error| format!("invalid hex: {error}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance_export::{
        ComplianceExportRequest, RedactionMode, build_compliance_export, sign_compliance_export,
    };
    use crate::sekai::audit::Decision;
    use std::collections::HashMap;

    fn fixture_decisions() -> Vec<Decision> {
        let actions = [
            ("d-access", "access.review"),
            ("d-grant", "access.grant.expire"),
            ("d-purpose", "put_purpose_authorization"),
            ("d-deletion", "privacy.subject_erased"),
            ("d-incident", "incident.record"),
            ("d-keys", "rotate_provider_credential"),
            ("d-backup", "backup.drill"),
        ];
        actions
            .into_iter()
            .enumerate()
            .map(|(index, (id, action))| Decision {
                id: id.into(),
                timestamp: 1_000 + index as i64,
                actor: "operator".into(),
                action: action.into(),
                reason: "fixture".into(),
                evidence: HashMap::from([("namespace".into(), FIXTURE_NAMESPACE.into())]),
                target_id: format!("fixture:{id}"),
                outcome: "succeeded".into(),
            })
            .collect()
    }

    fn fixture_request() -> ComplianceExportRequest {
        ComplianceExportRequest {
            namespace: FIXTURE_NAMESPACE.into(),
            start_timestamp_ms: 0,
            end_timestamp_ms: 10_000,
            redaction: RedactionMode::Full,
            actor: "auditor".into(),
            request_id: "fixture-export".into(),
        }
    }

    fn fixture_bundle() -> ComplianceExportBundle {
        build_compliance_export(&fixture_request(), vec![], fixture_decisions(), 20_000).unwrap()
    }

    fn without_action(action: &str) -> ComplianceExportBundle {
        let decisions: Vec<Decision> = fixture_decisions()
            .into_iter()
            .filter(|decision| decision.action != action)
            .collect();
        build_compliance_export(&fixture_request(), vec![], decisions, 20_000).unwrap()
    }

    fn control<'a>(report: &'a PackReportBundle, id: &str) -> &'a ControlReport {
        report
            .controls
            .iter()
            .find(|control| control.id == id)
            .unwrap_or_else(|| panic!("missing control {id}"))
    }

    #[test]
    fn fixture_namespace_marks_mapped_controls_met() {
        let pack = load_builtin_pack("fixture").unwrap();
        let source = fixture_bundle();
        let report = build_pack_report(&pack, &source, "auditor", 30_000).unwrap();
        assert_eq!(report.manifest.namespace, FIXTURE_NAMESPACE);
        for id in [
            "FIX.access",
            "FIX.grant",
            "FIX.purpose",
            "FIX.deletion",
            "FIX.incident",
            "FIX.keys",
            "FIX.backup",
            "FIX.partial",
        ] {
            let row = control(&report, id);
            assert_eq!(row.status, ControlStatus::Met, "{id}");
            assert!(row.missing_queries.is_empty(), "{id}");
            assert!(!row.evidence.is_empty(), "{id}");
        }
        let verified = verify_pack_report(&report, &source, None);
        assert!(verified.ok, "{verified:?}");
    }

    #[test]
    fn removing_an_evidence_source_turns_affected_controls_to_no_evidence() {
        let pack = load_builtin_pack("fixture").unwrap();
        let source = without_action("privacy.subject_erased");
        let report = build_pack_report(&pack, &source, "auditor", 30_000).unwrap();
        let deletion = control(&report, "FIX.deletion");
        assert_eq!(deletion.status, ControlStatus::NoEvidence);
        assert_eq!(deletion.missing_queries, ["deletion_proofs"]);
        assert!(deletion.evidence.is_empty());
        assert_eq!(control(&report, "FIX.purpose").status, ControlStatus::Met);
        assert!(verify_pack_report(&report, &source, None).ok);
    }

    #[test]
    fn missing_one_of_two_queries_is_partly_met() {
        let pack = load_builtin_pack("fixture").unwrap();
        let source = without_action("backup.drill");
        let report = build_pack_report(&pack, &source, "auditor", 30_000).unwrap();
        assert_eq!(
            control(&report, "FIX.backup").status,
            ControlStatus::NoEvidence
        );
        let partial = control(&report, "FIX.partial");
        assert_eq!(partial.status, ControlStatus::PartlyMet);
        assert_eq!(partial.missing_queries, ["backup_drills"]);
        assert!(
            partial
                .evidence
                .iter()
                .any(|item| item.query_id == "incident_records")
        );
    }

    #[test]
    fn signed_report_verifies_offline_and_detects_tampering() {
        let pack = load_builtin_pack("fixture").unwrap();
        let mut source = fixture_bundle();
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        sign_compliance_export(&mut source, &signing, "export-key", "k1", 21_000).unwrap();
        let mut report = build_pack_report(&pack, &source, "auditor", 30_000).unwrap();
        sign_pack_report(&mut report, &signing, "report-key", "k1", 31_000).unwrap();
        let public = encode_hex(signing.verifying_key().as_bytes());
        let ok = verify_pack_report(&report, &source, Some(&public));
        assert!(ok.ok, "{ok:?}");

        let mut tampered = report.clone();
        tampered.controls[0].status = ControlStatus::NoEvidence;
        let bad = verify_pack_report(&tampered, &source, Some(&public));
        assert!(!bad.ok);
        assert!(!bad.content_digest_ok);
    }

    #[test]
    fn framework_packs_load_as_data_and_gap_unmapped_queries() {
        for id in ["gdpr", "nis2", "iso27001"] {
            let pack = load_builtin_pack(id).unwrap();
            let empty = build_compliance_export(&fixture_request(), vec![], vec![], 1).unwrap();
            let report = build_pack_report(&pack, &empty, "auditor", 2).unwrap();
            assert!(!report.controls.is_empty(), "{id}");
            assert!(
                report
                    .controls
                    .iter()
                    .all(|control| control.status == ControlStatus::NoEvidence),
                "{id}"
            );
        }
        let gdpr = load_builtin_pack("gdpr").unwrap();
        let source = fixture_bundle();
        let report = build_pack_report(&gdpr, &source, "auditor", 3).unwrap();
        assert_eq!(control(&report, "Art.17").status, ControlStatus::Met);
        assert_eq!(control(&report, "Art.5(1)(e)").status, ControlStatus::Met);
        assert_eq!(control(&report, "Art.32").status, ControlStatus::Met);
    }

    #[test]
    fn custom_pack_json_is_data_not_code() {
        let json = r#"{
            "pack_format": "sekai.compliance-pack/v1",
            "id": "custom",
            "version": "1",
            "framework": "custom",
            "framework_version": "1",
            "controls": [{"id": "C1", "title": "Purpose", "queries": ["purpose_records"]}]
        }"#;
        let pack = parse_pack(json).unwrap();
        let source = fixture_bundle();
        let report = build_pack_report(&pack, &source, "auditor", 4).unwrap();
        assert_eq!(control(&report, "C1").status, ControlStatus::Met);
    }

    #[test]
    fn unknown_query_is_rejected() {
        let json = r#"{
            "pack_format": "sekai.compliance-pack/v1",
            "id": "bad",
            "version": "1",
            "framework": "bad",
            "framework_version": "1",
            "controls": [{"id": "C1", "title": "x", "queries": ["not_a_query"]}]
        }"#;
        let error = parse_pack(json).unwrap_err();
        assert!(error.contains("unknown evidence query"), "{error}");
    }

    #[test]
    fn invalid_source_signature_cannot_build_a_report() {
        let pack = load_builtin_pack("fixture").unwrap();
        let mut source = fixture_bundle();
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        sign_compliance_export(&mut source, &signing, "export-key", "k1", 21_000).unwrap();
        source.signature.as_mut().unwrap().signature_hex = "00".repeat(64);
        let error = build_pack_report(&pack, &source, "auditor", 30_000).unwrap_err();
        assert!(
            error.contains("source compliance export failed verification"),
            "{error}"
        );
    }

    #[test]
    fn relabeled_report_window_fails_verify_after_digest_recompute() {
        let pack = load_builtin_pack("fixture").unwrap();
        let source = fixture_bundle();
        let mut report = build_pack_report(&pack, &source, "auditor", 5).unwrap();
        report.manifest.start_timestamp_ms += 1;
        report.manifest.content_digest.clear();
        report.signature = None;
        report.manifest.content_digest = content_digest_for(&report).unwrap();
        let bad = verify_pack_report(&report, &source, None);
        assert!(!bad.ok);
        assert!(
            bad.errors
                .iter()
                .any(|error| error.contains("report window does not match source export")),
            "{bad:?}"
        );
    }

    #[test]
    fn malformed_signature_hex_is_an_error_not_a_panic() {
        assert!(decode_hex("€a").unwrap_err().contains("ASCII hex"));
        let pack = load_builtin_pack("fixture").unwrap();
        let source = fixture_bundle();
        let mut report = build_pack_report(&pack, &source, "auditor", 6).unwrap();
        report.signature = Some(crate::compliance_export::ComplianceExportSignature {
            algorithm: crate::compliance_export::COMPLIANCE_SIGNATURE_ALGORITHM.into(),
            identity: "k".into(),
            key_id: "k1".into(),
            public_key_hex: "€a".into(),
            signed_at_ms: 1,
            signature_hex: "00".into(),
        });
        let bad = verify_pack_report(&report, &source, None);
        assert!(!bad.ok);
        assert!(
            bad.errors.iter().any(|error| error.contains("hex")),
            "{bad:?}"
        );
    }

    #[test]
    fn source_digest_mismatch_fails_verify() {
        let pack = load_builtin_pack("fixture").unwrap();
        let source = fixture_bundle();
        let report = build_pack_report(&pack, &source, "auditor", 5).unwrap();
        let other = without_action("backup.drill");
        let bad = verify_pack_report(&report, &other, None);
        assert!(!bad.ok);
        assert!(
            bad.errors
                .iter()
                .any(|error| error.contains("source bundle digest mismatch")),
            "{bad:?}"
        );
    }

    #[test]
    fn builtin_ids_match_shipped_json() {
        assert_eq!(builtin_pack_ids(), &["fixture", "gdpr", "nis2", "iso27001"]);
        for id in builtin_pack_ids() {
            assert_eq!(load_builtin_pack(id).unwrap().id, *id);
        }
    }
}
