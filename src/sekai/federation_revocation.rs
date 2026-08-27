//! Governed withdrawal of shared federation authority (#703).
//!
//! Peer, signer, grant, and snapshot-revision withdrawals are stored as
//! `sekai.federation-revocation/v1` objects. Local verify/import fail closed
//! immediately. History is retained. Propagation stays plane-local: a
//! disconnected peer is not claimed to have received the revocation.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::audit::Decision;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const REVOCATION_CONTRACT: &str = "sekai.federation-revocation/v1";
pub const POSTGRES_UNAVAILABLE: &str =
    "federation revocations are unavailable on the PostgreSQL community runtime";
pub const REVOKE_ACTION: &str = "federation.authority_revoke";
pub const OBSERVE_ACTION: &str = "federation.authority_observe";
pub const UNAVAILABLE: &str = "revoked federation authority is unavailable";

const STATUS_ACTIVE: &str = "active";
const ACK_UNKNOWN: &str = "unknown";
const ACK_DENIED: &str = "denied";
const ACK_RECONCILED: &str = "reconciled";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Peer,
    Signer,
    Grant,
    SnapshotRevision,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Signer => "signer",
            Self::Grant => "grant",
            Self::SnapshotRevision => "snapshot_revision",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim() {
            "peer" => Ok(Self::Peer),
            "signer" => Ok(Self::Signer),
            "grant" => Ok(Self::Grant),
            "snapshot-revision" | "snapshot_revision" => Ok(Self::SnapshotRevision),
            _ => Err("revocation kind is unavailable".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationPropagation {
    pub local_applied_at_ms: i64,
    pub acknowledgement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_peer_assertion_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconciled_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationRevocation {
    pub contract_version: String,
    pub revocation_id: String,
    pub subject_kind: SubjectKind,
    pub subject_id: String,
    pub peer_site_id: String,
    pub reason: String,
    pub status: String,
    pub write_authority: bool,
    pub permit_authority: bool,
    pub propagation: RevocationPropagation,
    pub revoked_by: String,
    pub revoked_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct RevokeAuthorityRequest {
    pub kind: SubjectKind,
    pub subject_id: String,
    pub peer_site_id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ImportSubjects {
    pub peer_site_id: String,
    pub signer_id: String,
    pub snapshot_digest: String,
    pub now_ms: i64,
}

pub fn signer_subject(site_id: &str, key_id: &str) -> String {
    format!("{site_id}:{key_id}")
}

pub fn revocation_id_for(kind: SubjectKind, subject_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(REVOCATION_CONTRACT.as_bytes());
    hasher.update(b"\n");
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(subject_id.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

pub fn revoke_authority(
    db: &RuntimeDb,
    actor: &str,
    request: &RevokeAuthorityRequest,
    now_ms: i64,
) -> Result<FederationRevocation, String> {
    required("actor", actor)?;
    required("subject", &request.subject_id)?;
    required("peer site id", &request.peer_site_id)?;
    if now_ms < 0 {
        return Err("revocation timestamp must be non-negative".into());
    }
    if request.kind == SubjectKind::Peer && request.subject_id != request.peer_site_id {
        return Err(UNAVAILABLE.into());
    }

    if request.kind == SubjectKind::Grant {
        mark_grant_revoked(db, &request.subject_id, now_ms)?;
    }

    let revocation_id = revocation_id_for(request.kind, &request.subject_id);
    if let Some(existing) = db.get_federation_revocation(&revocation_id)? {
        if existing.subject_kind != request.kind || existing.subject_id != request.subject_id {
            return Err(UNAVAILABLE.into());
        }
        return Ok(existing);
    }

    let record = FederationRevocation {
        contract_version: REVOCATION_CONTRACT.into(),
        revocation_id,
        subject_kind: request.kind,
        subject_id: request.subject_id.clone(),
        peer_site_id: request.peer_site_id.clone(),
        reason: request.reason.clone(),
        status: STATUS_ACTIVE.into(),
        write_authority: false,
        permit_authority: false,
        propagation: RevocationPropagation {
            local_applied_at_ms: now_ms,
            acknowledgement: ACK_UNKNOWN.into(),
            last_peer_assertion_at_ms: None,
            last_reconciled_at_ms: None,
        },
        revoked_by: actor.into(),
        revoked_at_ms: now_ms,
        updated_at_ms: now_ms,
    };
    db.put_federation_revocation(&record)?;
    audit(db, actor, REVOKE_ACTION, "revoked", &record, now_ms)?;
    Ok(record)
}

pub fn get_revocation(
    db: &RuntimeDb,
    kind: SubjectKind,
    subject_id: &str,
) -> Result<FederationRevocation, String> {
    required("subject", subject_id)?;
    let revocation_id = revocation_id_for(kind, subject_id);
    let record = db
        .get_federation_revocation(&revocation_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())?;
    if record.subject_kind != kind || record.subject_id != subject_id {
        return Err(UNAVAILABLE.into());
    }
    Ok(record)
}

pub fn list_revocations(
    db: &RuntimeDb,
    kind: Option<SubjectKind>,
) -> Result<Vec<FederationRevocation>, String> {
    db.list_federation_revocations(kind.map(SubjectKind::as_str))
}

pub fn deny_revoked_import(db: &RuntimeDb, subjects: &ImportSubjects) -> Result<(), String> {
    if subjects.now_ms < 0 {
        return Err("import timestamp must be non-negative".into());
    }
    let mut denied = Vec::new();
    push_if_active(db, SubjectKind::Peer, &subjects.peer_site_id, &mut denied)?;
    push_if_active(db, SubjectKind::Signer, &subjects.signer_id, &mut denied)?;
    push_if_active(
        db,
        SubjectKind::SnapshotRevision,
        &subjects.snapshot_digest,
        &mut denied,
    )?;
    if denied.is_empty() {
        return Ok(());
    }
    for record in denied {
        observe(db, record, ACK_DENIED, subjects.now_ms, true)?;
    }
    Err(UNAVAILABLE.into())
}

pub fn observe_revoked_grants(
    db: &RuntimeDb,
    peer_site_id: &str,
    now_ms: i64,
) -> Result<(), String> {
    required("peer site id", peer_site_id)?;
    if now_ms < 0 {
        return Err("import timestamp must be non-negative".into());
    }
    for record in db.list_federation_revocations(Some(SubjectKind::Grant.as_str()))? {
        if record.peer_site_id == peer_site_id && record.status == STATUS_ACTIVE {
            observe(db, record, ACK_DENIED, now_ms, true)?;
        }
    }
    Ok(())
}

pub fn reconcile_unpresented_revisions(
    db: &RuntimeDb,
    peer_site_id: &str,
    accepted_digest: &str,
    now_ms: i64,
) -> Result<(), String> {
    required("peer site id", peer_site_id)?;
    required("snapshot digest", accepted_digest)?;
    if now_ms < 0 {
        return Err("reconcile timestamp must be non-negative".into());
    }
    for record in db.list_federation_revocations(Some(SubjectKind::SnapshotRevision.as_str()))? {
        if record.peer_site_id == peer_site_id
            && record.subject_id != accepted_digest
            && record.status == STATUS_ACTIVE
            && record.propagation.acknowledgement != ACK_RECONCILED
        {
            observe(db, record, ACK_RECONCILED, now_ms, false)?;
        }
    }
    Ok(())
}

fn push_if_active(
    db: &RuntimeDb,
    kind: SubjectKind,
    subject_id: &str,
    denied: &mut Vec<FederationRevocation>,
) -> Result<(), String> {
    if subject_id.trim().is_empty() {
        return Ok(());
    }
    let revocation_id = revocation_id_for(kind, subject_id);
    if let Some(record) = db.get_federation_revocation(&revocation_id)?
        && record.status == STATUS_ACTIVE
        && record.subject_kind == kind
        && record.subject_id == subject_id
    {
        denied.push(record);
    }
    Ok(())
}

fn observe(
    db: &RuntimeDb,
    mut record: FederationRevocation,
    acknowledgement: &str,
    now_ms: i64,
    peer_asserted: bool,
) -> Result<FederationRevocation, String> {
    let mut changed = record.propagation.acknowledgement != acknowledgement;
    record.propagation.acknowledgement = acknowledgement.into();
    if peer_asserted {
        record.propagation.last_peer_assertion_at_ms = Some(now_ms);
        changed = true;
    }
    if acknowledgement == ACK_RECONCILED {
        record.propagation.last_reconciled_at_ms = Some(now_ms);
        changed = true;
    }
    if !changed {
        return Ok(record);
    }
    record.updated_at_ms = now_ms;
    db.put_federation_revocation(&record)?;
    audit(
        db,
        "system",
        OBSERVE_ACTION,
        acknowledgement,
        &record,
        now_ms,
    )?;
    Ok(record)
}

fn mark_grant_revoked(db: &RuntimeDb, grant_id: &str, now_ms: i64) -> Result<(), String> {
    let Some(mut grant) = db.get_federation_namespace_grant(grant_id)? else {
        return Err(UNAVAILABLE.into());
    };
    if grant.revoked {
        return Ok(());
    }
    grant.revoked = true;
    grant.revoked_at_ms = Some(now_ms);
    db.put_federation_namespace_grant(&grant)
}

fn audit(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    outcome: &str,
    record: &FederationRevocation,
    now_ms: i64,
) -> Result<(), String> {
    db.record_decision(&Decision {
        id: format!("{action}:{}:{now_ms}", record.revocation_id),
        timestamp: now_ms,
        actor: actor.into(),
        action: action.into(),
        reason: format!("recorded {REVOCATION_CONTRACT} {outcome}"),
        evidence: HashMap::from([
            ("contract_version".into(), REVOCATION_CONTRACT.into()),
            ("subject_kind".into(), record.subject_kind.as_str().into()),
            ("revocation_id".into(), record.revocation_id.clone()),
            ("peer_site_id".into(), record.peer_site_id.clone()),
            ("status".into(), record.status.clone()),
            (
                "acknowledgement".into(),
                record.propagation.acknowledgement.clone(),
            ),
            ("write_authority".into(), "false".into()),
            ("permit_authority".into(), "false".into()),
            ("data_class".into(), "internal".into()),
        ]),
        target_id: record.revocation_id.clone(),
        outcome: outcome.into(),
    })
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
    use crate::domain::Object;
    use crate::sekai::federation_profile::{
        self, JoinPeerRequest, LocalSiteIdentity, PeerHealth, PolicyPackPin,
    };
    use crate::sekai::namespace_snapshot::{
        ExportSnapshotRequest, GrantNamespaceRequest, export_namespace_snapshot, grant_namespace,
        import_namespace_snapshot, list_namespace_grants, list_snapshot_facts,
        revoke_namespace_grant,
    };
    use crate::sekai::peer_import::PeerTrustRoot;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public_key_hex(seed: u8) -> String {
        signing_key(seed)
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn pack_pin() -> PolicyPackPin {
        PolicyPackPin {
            pack_id: "governance-pack".into(),
            version: "1.0.0".into(),
            content_digest: "sha256:abc123".into(),
        }
    }

    fn register_site(db: &RuntimeDb, site_id: &str, seed: u8) {
        federation_profile::register_local_site(
            db,
            &LocalSiteIdentity {
                site_id: site_id.into(),
                key_id: "k1".into(),
                public_key_hex: public_key_hex(seed),
                region: Some("eu-central".into()),
                residency_data_classes: vec!["internal".into()],
                registered_by: "admin".into(),
                registered_at_ms: 1_000,
            },
        )
        .unwrap();
    }

    fn federate_importer(importer: &RuntimeDb) {
        register_site(importer, "site-b", 2);
        federation_profile::pin_trust_root(
            importer,
            &PeerTrustRoot {
                namespace: crate::sekai::federation_profile::TRUST_ROOT_NAMESPACE.into(),
                site_identity: "site-a".into(),
                key_id: "k1".into(),
                public_key_hex: public_key_hex(1),
                enabled: true,
                created_by: "admin".into(),
                created_at_ms: 1_100,
            },
        )
        .unwrap();
        federation_profile::join_peer(
            importer,
            "admin",
            &JoinPeerRequest {
                peer_site_id: "site-a".into(),
                peer_key_id: "k1".into(),
                peer_public_key_hex: public_key_hex(1),
                policy_pack: pack_pin(),
                residency_region: Some("us-east".into()),
                residency_data_classes: vec!["internal".into()],
                trust_namespace: crate::sekai::federation_profile::TRUST_ROOT_NAMESPACE.into(),
            },
            2_000,
        )
        .unwrap();
        federation_profile::set_peer_health(importer, "site-a", PeerHealth::Up).unwrap();
        crate::sekai::namespace_snapshot::grant_namespace(
            importer,
            "admin-b",
            &GrantNamespaceRequest {
                peer_site_id: "site-a".into(),
                namespace: "ops".into(),
                object_kinds: vec![],
                max_classification: Some("internal".into()),
                not_before_ms: 0,
                not_after_ms: None,
            },
            3_000,
        )
        .unwrap();
    }

    fn two_planes() -> (RuntimeDb, RuntimeDb) {
        let exporter = db();
        let importer = db();
        register_site(&exporter, "site-a", 1);
        federate_importer(&importer);
        (exporter, importer)
    }

    fn put_object(db: &RuntimeDb, id: &str) {
        db.create_object(&Object {
            id: id.into(),
            kind: "asset".into(),
            name: id.into(),
            namespace: "ops".into(),
            external_id: format!("asset:{id}"),
            properties: HashMap::new(),
            created: 10,
            updated: 10,
        })
        .unwrap();
    }

    fn export_from(
        exporter: &RuntimeDb,
        now_ms: i64,
    ) -> crate::sekai::namespace_snapshot::NamespaceSnapshotBundle {
        export_namespace_snapshot(
            exporter,
            &ExportSnapshotRequest {
                namespace: "ops".into(),
                actor: "local".into(),
                object_kinds: vec![],
                policy_pack: pack_pin(),
                not_before_ms: 0,
                not_after_ms: None,
            },
            &signing_key(1),
            now_ms,
        )
        .unwrap()
    }

    #[test]
    fn revoke_peer_denies_import_and_keeps_prior_replicas() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1");
        let bundle = export_from(&exporter, 4_000);
        let imported =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 4_100).unwrap();
        assert_eq!(imported.record.status, "accepted");

        let revoked = revoke_authority(
            &importer,
            "admin-b",
            &RevokeAuthorityRequest {
                kind: SubjectKind::Peer,
                subject_id: "site-a".into(),
                peer_site_id: "site-a".into(),
                reason: "peer withdrawn".into(),
            },
            4_200,
        )
        .unwrap();
        assert_eq!(revoked.propagation.acknowledgement, ACK_UNKNOWN);
        assert!(!revoked.write_authority);
        assert_eq!(
            federation_profile::get_peer(&importer, "site-a")
                .unwrap()
                .unwrap()
                .membership,
            crate::sekai::federation_profile::MembershipStatus::Joined
        );

        let replay = revoke_authority(
            &importer,
            "admin-b",
            &RevokeAuthorityRequest {
                kind: SubjectKind::Peer,
                subject_id: "site-a".into(),
                peer_site_id: "site-a".into(),
                reason: "peer withdrawn again".into(),
            },
            4_250,
        )
        .unwrap();
        assert_eq!(replay.revocation_id, revoked.revocation_id);
        assert_eq!(replay.revoked_at_ms, 4_200);

        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 4_300).unwrap_err();
        assert_eq!(err, UNAVAILABLE);
        let observed = get_revocation(&importer, SubjectKind::Peer, "site-a").unwrap();
        assert_eq!(observed.propagation.acknowledgement, ACK_DENIED);
        assert_eq!(observed.propagation.last_peer_assertion_at_ms, Some(4_300));
        assert_eq!(
            list_snapshot_facts(&importer, &imported.record.import_id, 4_300)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn revoke_signer_denies_import_while_trust_pin_stays_enabled() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1");
        let bundle = export_from(&exporter, 5_000);
        revoke_authority(
            &importer,
            "admin-b",
            &RevokeAuthorityRequest {
                kind: SubjectKind::Signer,
                subject_id: signer_subject("site-a", "k1"),
                peer_site_id: "site-a".into(),
                reason: "signer withdrawn".into(),
            },
            5_100,
        )
        .unwrap();
        let roots = crate::sekai::peer_import::list_trust_roots(
            &importer,
            crate::sekai::federation_profile::TRUST_ROOT_NAMESPACE,
        )
        .unwrap();
        assert!(roots.iter().any(|root| root.enabled && root.key_id == "k1"));
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 5_200).unwrap_err();
        assert_eq!(err, UNAVAILABLE);
        assert!(!err.contains("site-a"));
    }

    #[test]
    fn revoke_grant_records_object_and_denies_reconnect() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1");
        let bundle = export_from(&exporter, 6_000);
        import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 6_100).unwrap();
        let grants = list_namespace_grants(&importer, Some("ops"), Some("site-a")).unwrap();
        revoke_namespace_grant(&importer, "admin-b", &grants[0].grant_id, 6_200).unwrap();
        let record = get_revocation(&importer, SubjectKind::Grant, &grants[0].grant_id).unwrap();
        assert_eq!(record.propagation.acknowledgement, ACK_UNKNOWN);
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 6_300).unwrap_err();
        assert!(err.contains("grant"), "{err}");
        let observed = get_revocation(&importer, SubjectKind::Grant, &grants[0].grant_id).unwrap();
        assert_eq!(observed.propagation.acknowledgement, ACK_DENIED);

        grant_namespace(
            &importer,
            "admin-b",
            &GrantNamespaceRequest {
                peer_site_id: "site-a".into(),
                namespace: "ops".into(),
                object_kinds: vec![],
                max_classification: Some("internal".into()),
                not_before_ms: 0,
                not_after_ms: None,
            },
            6_400,
        )
        .unwrap();
        let replay =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 6_500).unwrap();
        assert_eq!(replay.record.status, "accepted");
    }

    #[test]
    fn revoke_snapshot_revision_denies_that_digest_and_reconciles_on_a_new_one() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1");
        let first = export_from(&exporter, 7_000);
        import_namespace_snapshot(&importer, "admin-b", "ops", &first, 7_100).unwrap();
        revoke_authority(
            &importer,
            "admin-b",
            &RevokeAuthorityRequest {
                kind: SubjectKind::SnapshotRevision,
                subject_id: first.manifest.content_digest.clone(),
                peer_site_id: "site-a".into(),
                reason: "revision withdrawn".into(),
            },
            7_200,
        )
        .unwrap();
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &first, 7_300).unwrap_err();
        assert_eq!(err, UNAVAILABLE);
        put_object(&exporter, "visible-2");
        let second = export_from(&exporter, 7_400);
        assert_ne!(
            second.manifest.content_digest,
            first.manifest.content_digest
        );
        let imported =
            import_namespace_snapshot(&importer, "admin-b", "ops", &second, 7_500).unwrap();
        assert_eq!(imported.record.status, "accepted");
        let observed = get_revocation(
            &importer,
            SubjectKind::SnapshotRevision,
            &first.manifest.content_digest,
        )
        .unwrap();
        assert_eq!(observed.propagation.acknowledgement, ACK_RECONCILED);
        assert_eq!(observed.propagation.last_reconciled_at_ms, Some(7_500));
    }

    #[test]
    fn offline_peer_keeps_acknowledgement_unknown() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1");
        let bundle = export_from(&exporter, 8_000);
        import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 8_100).unwrap();
        revoke_authority(
            &importer,
            "admin-b",
            &RevokeAuthorityRequest {
                kind: SubjectKind::Peer,
                subject_id: "site-a".into(),
                peer_site_id: "site-a".into(),
                reason: "peer withdrawn".into(),
            },
            8_200,
        )
        .unwrap();
        federation_profile::set_peer_health(&importer, "site-a", PeerHealth::Down).unwrap();
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 8_300).unwrap_err();
        assert!(err.contains("unavailable") || err.contains("down"), "{err}");
        let observed = get_revocation(&importer, SubjectKind::Peer, "site-a").unwrap();
        assert_eq!(observed.propagation.acknowledgement, ACK_UNKNOWN);
        assert_eq!(observed.propagation.last_peer_assertion_at_ms, None);
    }

    #[test]
    fn unknown_revocation_is_unavailable_without_catalog_disclosure() {
        let db = db();
        let err = get_revocation(&db, SubjectKind::Peer, "missing").unwrap_err();
        assert_eq!(err, UNAVAILABLE);
        assert!(!err.contains("missing"));
        let err = SubjectKind::parse("other").unwrap_err();
        assert_eq!(err, "revocation kind is unavailable");
    }

    #[test]
    fn postgres_surface_is_explicitly_unavailable() {
        assert!(POSTGRES_UNAVAILABLE.contains("PostgreSQL"));
    }
}
