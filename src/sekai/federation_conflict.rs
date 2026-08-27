//! Governed records for concurrent cross-site object assertions (#699).
//!
//! A collision between a local object and a verified peer snapshot fact is
//! stored as `sekai.federation-conflict/v1`. Both claims stay inspectable.
//! Resolution is explicit and reversible. Import never overwrites the local
//! object, the peer snapshot, or provenance hops.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::audit::Decision;
use crate::sekai::namespace_snapshot::SnapshotFact;
use crate::shomei;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const CONFLICT_CONTRACT: &str = "sekai.federation-conflict/v1";
pub const POSTGRES_UNAVAILABLE: &str =
    "federation conflicts are unavailable on the PostgreSQL community runtime";
pub const ADMIT_ACTION: &str = "federation.conflict_admit";
pub const RESOLVE_ACTION: &str = "federation.conflict_resolve";
pub const REOPEN_ACTION: &str = "federation.conflict_reopen";

const SIDE_LOCAL: &str = "local";
const SIDE_PEER: &str = "peer";
const STATUS_OPEN: &str = "open";
const STATUS_RESOLVED: &str = "resolved";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationConflictClaim {
    pub claim_id: String,
    pub side: String,
    pub site_id: String,
    pub object_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationConflictResolution {
    pub claim_id: String,
    pub resolved_by: String,
    pub resolved_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationConflict {
    pub contract_version: String,
    pub conflict_id: String,
    pub namespace: String,
    pub object_id: String,
    pub claims: Vec<FederationConflictClaim>,
    pub status: String,
    pub resolution: Option<FederationConflictResolution>,
    #[serde(default)]
    pub resolution_history: Vec<FederationConflictResolution>,
    pub write_authority: bool,
    pub permit_authority: bool,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
    pub updated_at_ms: i64,
}

pub fn conflict_id_for(namespace: &str, object_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CONFLICT_CONTRACT.as_bytes());
    hasher.update(b"\n");
    hasher.update(namespace.as_bytes());
    hasher.update(b"\n");
    hasher.update(object_id.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

#[derive(Debug, Clone)]
pub struct ImportCollision {
    pub actor: String,
    pub namespace: String,
    pub local: Object,
    pub peer_fact: SnapshotFact,
    pub peer_site_id: String,
    pub snapshot_digest: String,
    pub import_id: String,
    pub now_ms: i64,
}

pub fn admit_import_collision(
    db: &RuntimeDb,
    collision: &ImportCollision,
) -> Result<FederationConflict, String> {
    let (record, dirty) = prepare_import_collision(db, collision)?;
    if dirty {
        db.put_federation_conflict(&record)?;
        audit(
            db,
            &collision.actor,
            ADMIT_ACTION,
            "admitted",
            &record,
            collision.now_ms,
        )?;
    }
    Ok(record)
}

pub fn prepare_import_collision(
    db: &RuntimeDb,
    collision: &ImportCollision,
) -> Result<(FederationConflict, bool), String> {
    let ImportCollision {
        actor,
        namespace,
        local,
        peer_fact,
        peer_site_id,
        snapshot_digest,
        import_id,
        now_ms,
    } = collision;
    required("actor", actor)?;
    required("namespace", namespace)?;
    required("object id", &local.id)?;
    if local.namespace != *namespace || peer_fact.namespace != *namespace {
        return Err("conflict namespace does not match the imported fact".into());
    }
    if local.id != peer_fact.object_id {
        return Err("conflict object id does not match the imported fact".into());
    }
    if *now_ms < 0 {
        return Err("conflict timestamp must be non-negative".into());
    }

    let local_site = db
        .get_federation_local_site()?
        .ok_or_else(|| "local site identity is not registered".to_string())?;
    let local_claim = claim(
        SIDE_LOCAL,
        &local_site.site_id,
        &object_claim_digest(local)?,
        None,
        None,
    )?;
    let peer_claim = claim(
        SIDE_PEER,
        peer_site_id,
        &fact_claim_digest(peer_fact)?,
        Some(snapshot_digest.as_str()),
        Some(import_id.as_str()),
    )?;

    let conflict_id = conflict_id_for(namespace, &local.id);
    if let Some(mut existing) = db.get_federation_conflict(&conflict_id)? {
        if existing.namespace != *namespace || existing.object_id != local.id {
            return Err("conflict identity does not match stored record".into());
        }
        let added_peer = existing
            .claims
            .iter()
            .all(|claim| claim.claim_id != peer_claim.claim_id);
        let local_changed = merge_claim(&mut existing.claims, local_claim);
        let peer_changed = merge_claim(&mut existing.claims, peer_claim);
        let changed = local_changed || peer_changed;
        if added_peer && existing.status == STATUS_RESOLVED {
            if let Some(current) = existing.resolution.take() {
                existing.resolution_history.push(current);
            }
            existing.status = STATUS_OPEN.into();
        }
        if changed {
            existing.updated_at_ms = *now_ms;
        }
        return Ok((existing, changed));
    }

    let record = FederationConflict {
        contract_version: CONFLICT_CONTRACT.into(),
        conflict_id,
        namespace: namespace.into(),
        object_id: local.id.clone(),
        claims: vec![local_claim, peer_claim],
        status: STATUS_OPEN.into(),
        resolution: None,
        resolution_history: Vec::new(),
        write_authority: false,
        permit_authority: false,
        admitted_by: actor.into(),
        admitted_at_ms: *now_ms,
        updated_at_ms: *now_ms,
    };
    let _ = actor;
    Ok((record, true))
}

pub fn get_conflict(
    db: &RuntimeDb,
    namespace: &str,
    object_id: &str,
) -> Result<FederationConflict, String> {
    required("namespace", namespace)?;
    required("object id", object_id)?;
    let conflict_id = conflict_id_for(namespace, object_id);
    let record = db
        .get_federation_conflict(&conflict_id)?
        .ok_or_else(|| "federation conflict is unavailable".to_string())?;
    if record.namespace != namespace || record.object_id != object_id {
        return Err("federation conflict is unavailable".into());
    }
    Ok(record)
}

pub fn list_conflicts(
    db: &RuntimeDb,
    namespace: Option<&str>,
) -> Result<Vec<FederationConflict>, String> {
    db.list_federation_conflicts(namespace)
}

pub fn resolve_conflict(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    object_id: &str,
    claim_id: &str,
    now_ms: i64,
) -> Result<FederationConflict, String> {
    required("actor", actor)?;
    required("claim id", claim_id)?;
    if now_ms < 0 {
        return Err("resolution timestamp must be non-negative".into());
    }
    let mut record = get_conflict(db, namespace, object_id)?;
    if !record.claims.iter().any(|claim| claim.claim_id == claim_id) {
        return Err("selected conflict claim is unavailable".into());
    }
    if record.status == STATUS_RESOLVED
        && record
            .resolution
            .as_ref()
            .is_some_and(|item| item.claim_id == claim_id)
    {
        return Ok(record);
    }
    if let Some(current) = record.resolution.take() {
        record.resolution_history.push(current);
    }
    record.status = STATUS_RESOLVED.into();
    record.resolution = Some(FederationConflictResolution {
        claim_id: claim_id.into(),
        resolved_by: actor.into(),
        resolved_at_ms: now_ms,
    });
    record.updated_at_ms = now_ms;
    db.put_federation_conflict(&record)?;
    audit(db, actor, RESOLVE_ACTION, "resolved", &record, now_ms)?;
    Ok(record)
}

pub fn reopen_conflict(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    object_id: &str,
    now_ms: i64,
) -> Result<FederationConflict, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("reopen timestamp must be non-negative".into());
    }
    let mut record = get_conflict(db, namespace, object_id)?;
    if record.status == STATUS_OPEN && record.resolution.is_none() {
        return Ok(record);
    }
    if let Some(current) = record.resolution.take() {
        record.resolution_history.push(current);
    }
    record.status = STATUS_OPEN.into();
    record.updated_at_ms = now_ms;
    db.put_federation_conflict(&record)?;
    audit(db, actor, REOPEN_ACTION, "reopened", &record, now_ms)?;
    Ok(record)
}

fn claim(
    side: &str,
    site_id: &str,
    object_digest: &str,
    snapshot_digest: Option<&str>,
    import_id: Option<&str>,
) -> Result<FederationConflictClaim, String> {
    required("site id", site_id)?;
    required("object digest", object_digest)?;
    let snapshot = snapshot_digest
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let import = import_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    Ok(FederationConflictClaim {
        claim_id: claim_id_for(side, site_id, object_digest),
        side: side.into(),
        site_id: site_id.into(),
        object_digest: object_digest.into(),
        snapshot_digest: snapshot,
        import_id: import,
    })
}

fn claim_id_for(side: &str, site_id: &str, object_digest: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CONFLICT_CONTRACT.as_bytes());
    hasher.update(b"\nclaim\n");
    hasher.update(side.as_bytes());
    hasher.update(b"\n");
    hasher.update(site_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(object_digest.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn object_claim_digest(object: &Object) -> Result<String, String> {
    #[derive(Serialize)]
    struct Claim<'a> {
        object_id: &'a str,
        kind: &'a str,
        name: &'a str,
        namespace: &'a str,
        external_id: &'a str,
        properties: &'a std::collections::HashMap<String, String>,
        created: i64,
        updated: i64,
    }
    digest_json(&Claim {
        object_id: &object.id,
        kind: &object.kind,
        name: &object.name,
        namespace: &object.namespace,
        external_id: &object.external_id,
        properties: &object.properties,
        created: object.created,
        updated: object.updated,
    })
}

fn fact_claim_digest(fact: &SnapshotFact) -> Result<String, String> {
    #[derive(Serialize)]
    struct Claim<'a> {
        object_id: &'a str,
        kind: &'a str,
        name: &'a str,
        namespace: &'a str,
        external_id: &'a str,
        properties: &'a std::collections::BTreeMap<String, String>,
        created: i64,
        updated: i64,
        source_site_id: &'a str,
        write_authority: bool,
        provenance: &'a [crate::sekai::namespace_snapshot::ProvenanceHop],
    }
    digest_json(&Claim {
        object_id: &fact.object_id,
        kind: &fact.kind,
        name: &fact.name,
        namespace: &fact.namespace,
        external_id: &fact.external_id,
        properties: &fact.properties,
        created: fact.created,
        updated: fact.updated,
        source_site_id: &fact.source_site_id,
        write_authority: fact.write_authority,
        provenance: &fact.provenance,
    })
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, String> {
    let canonical = shomei::canonical_json_with_finite_numbers(value)
        .map_err(|_| "conflict claim digest is unsupported".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn merge_claim(
    claims: &mut Vec<FederationConflictClaim>,
    incoming: FederationConflictClaim,
) -> bool {
    if let Some(existing) = claims
        .iter_mut()
        .find(|existing| existing.claim_id == incoming.claim_id)
    {
        let mut changed = false;
        if existing.snapshot_digest != incoming.snapshot_digest {
            existing.snapshot_digest = incoming.snapshot_digest;
            changed = true;
        }
        if existing.import_id != incoming.import_id {
            existing.import_id = incoming.import_id;
            changed = true;
        }
        return changed;
    }
    claims.push(incoming);
    true
}

pub(crate) fn audit_admission(
    db: &RuntimeDb,
    actor: &str,
    record: &FederationConflict,
    now_ms: i64,
) -> Result<(), String> {
    audit(db, actor, ADMIT_ACTION, "admitted", record, now_ms)
}

fn audit(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    outcome: &str,
    record: &FederationConflict,
    now_ms: i64,
) -> Result<(), String> {
    db.record_decision(&Decision {
        id: format!("{action}:{}:{now_ms}", record.conflict_id),
        timestamp: now_ms,
        actor: actor.into(),
        action: action.into(),
        reason: format!("recorded {CONFLICT_CONTRACT} {outcome}"),
        evidence: HashMap::from([
            ("contract_version".into(), CONFLICT_CONTRACT.into()),
            ("namespace".into(), record.namespace.clone()),
            ("object_id".into(), record.object_id.clone()),
            ("conflict_id".into(), record.conflict_id.clone()),
            ("status".into(), record.status.clone()),
            ("write_authority".into(), "false".into()),
            ("permit_authority".into(), "false".into()),
            ("data_class".into(), "internal".into()),
        ]),
        target_id: record.conflict_id.clone(),
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
    use crate::sekai::federation_profile::{
        self, JoinPeerRequest, LocalSiteIdentity, PeerHealth, PolicyPackPin,
    };
    use crate::sekai::namespace_snapshot::{
        self, ExportSnapshotRequest, GrantNamespaceRequest, import_namespace_snapshot,
    };
    use crate::sekai::peer_import::PeerTrustRoot;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn object(name: &str) -> Object {
        Object {
            id: "ticket-1".into(),
            kind: "asset".into(),
            name: name.into(),
            namespace: "ops".into(),
            external_id: "asset:ticket-1".into(),
            properties: HashMap::from([("title".into(), name.into())]),
            created: 1,
            updated: 2,
        }
    }

    fn fact(name: &str) -> SnapshotFact {
        SnapshotFact {
            object_id: "ticket-1".into(),
            kind: "asset".into(),
            name: name.into(),
            namespace: "ops".into(),
            external_id: "asset:ticket-1".into(),
            properties: BTreeMap::from([("title".into(), name.into())]),
            created: 1,
            updated: 3,
            source_site_id: "site-a".into(),
            write_authority: false,
            provenance: Vec::new(),
        }
    }

    fn register_local(db: &RuntimeDb) {
        federation_profile::register_local_site(
            db,
            &LocalSiteIdentity {
                site_id: "site-b".into(),
                key_id: "k1".into(),
                public_key_hex: public_key_hex(2),
                region: Some("eu".into()),
                residency_data_classes: vec!["internal".into()],
                registered_by: "admin".into(),
                registered_at_ms: 1,
            },
        )
        .unwrap();
    }

    #[test]
    fn admits_both_claims_and_resolves_without_rewriting_sources() {
        let db = db();
        register_local(&db);
        let local = object("local");
        db.create_object(&local).unwrap();
        let peer = fact("peer");
        let admitted = admit_import_collision(
            &db,
            &ImportCollision {
                actor: "admin".into(),
                namespace: "ops".into(),
                local: local.clone(),
                peer_fact: peer.clone(),
                peer_site_id: "site-a".into(),
                snapshot_digest: "sha256:snap".into(),
                import_id: "import-1".into(),
                now_ms: 10,
            },
        )
        .unwrap();
        assert_eq!(admitted.status, STATUS_OPEN);
        assert_eq!(admitted.claims.len(), 2);
        assert!(admitted.claims.iter().any(|claim| claim.side == SIDE_LOCAL));
        assert!(admitted.claims.iter().any(|claim| claim.side == SIDE_PEER));
        assert!(!admitted.write_authority);
        assert!(!admitted.permit_authority);

        let replay = admit_import_collision(
            &db,
            &ImportCollision {
                actor: "admin".into(),
                namespace: "ops".into(),
                local: local.clone(),
                peer_fact: peer.clone(),
                peer_site_id: "site-a".into(),
                snapshot_digest: "sha256:snap".into(),
                import_id: "import-1".into(),
                now_ms: 11,
            },
        )
        .unwrap();
        assert_eq!(replay.claims, admitted.claims);

        let later_snapshot = admit_import_collision(
            &db,
            &ImportCollision {
                actor: "admin".into(),
                namespace: "ops".into(),
                local: local.clone(),
                peer_fact: peer.clone(),
                peer_site_id: "site-a".into(),
                snapshot_digest: "sha256:later".into(),
                import_id: "import-2".into(),
                now_ms: 11,
            },
        )
        .unwrap();
        assert_eq!(later_snapshot.claims.len(), 2);
        assert_eq!(
            later_snapshot
                .claims
                .iter()
                .find(|claim| claim.side == SIDE_PEER)
                .unwrap()
                .snapshot_digest
                .as_deref(),
            Some("sha256:later")
        );

        let peer_claim = admitted
            .claims
            .iter()
            .find(|claim| claim.side == SIDE_PEER)
            .unwrap()
            .claim_id
            .clone();
        let resolved = resolve_conflict(&db, "admin", "ops", "ticket-1", &peer_claim, 12).unwrap();
        assert_eq!(resolved.status, STATUS_RESOLVED);
        assert_eq!(resolved.resolution.as_ref().unwrap().claim_id, peer_claim);
        assert_eq!(db.get_object("ticket-1").unwrap().unwrap().name, "local");
        let same_fact_new_snapshot = admit_import_collision(
            &db,
            &ImportCollision {
                actor: "admin".into(),
                namespace: "ops".into(),
                local: local.clone(),
                peer_fact: peer.clone(),
                peer_site_id: "site-a".into(),
                snapshot_digest: "sha256:third".into(),
                import_id: "import-3".into(),
                now_ms: 13,
            },
        )
        .unwrap();
        assert_eq!(same_fact_new_snapshot.status, STATUS_RESOLVED);
        assert_eq!(same_fact_new_snapshot.claims.len(), 2);

        let reopened = reopen_conflict(&db, "admin", "ops", "ticket-1", 14).unwrap();
        assert_eq!(reopened.status, STATUS_OPEN);
        assert_eq!(reopened.resolution_history.len(), 1);
        assert_eq!(reopened.resolution_history[0].claim_id, peer_claim);
        assert_eq!(db.get_object("ticket-1").unwrap().unwrap().name, "local");

        let resolved_again =
            resolve_conflict(&db, "admin", "ops", "ticket-1", &peer_claim, 14).unwrap();
        let later_snapshot = admit_import_collision(
            &db,
            &ImportCollision {
                actor: "admin".into(),
                namespace: "ops".into(),
                local: local.clone(),
                peer_fact: peer.clone(),
                peer_site_id: "site-a".into(),
                snapshot_digest: "sha256:later-snap".into(),
                import_id: "import-2".into(),
                now_ms: 15,
            },
        )
        .unwrap();
        assert_eq!(later_snapshot.status, STATUS_RESOLVED);
        assert_eq!(
            later_snapshot.resolution.as_ref().unwrap().claim_id,
            resolved_again.resolution.as_ref().unwrap().claim_id
        );
        assert_eq!(later_snapshot.claims.len(), 2);
    }

    #[test]
    fn unknown_claim_and_missing_conflict_fail_closed() {
        let db = db();
        register_local(&db);
        assert!(get_conflict(&db, "ops", "missing").is_err());
        let local = object("local");
        admit_import_collision(
            &db,
            &ImportCollision {
                actor: "admin".into(),
                namespace: "ops".into(),
                local,
                peer_fact: fact("peer"),
                peer_site_id: "site-a".into(),
                snapshot_digest: "sha256:snap".into(),
                import_id: "import-1".into(),
                now_ms: 10,
            },
        )
        .unwrap();
        let err =
            resolve_conflict(&db, "admin", "ops", "ticket-1", "sha256:missing", 11).unwrap_err();
        assert!(err.contains("unavailable"), "{err}");
        assert!(!err.contains("site-a"));
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public_key_hex(seed: u8) -> String {
        encode_hex(signing_key(seed).verifying_key().as_bytes())
    }

    #[test]
    fn snapshot_import_admits_governed_conflict_for_local_collision() {
        let exporter = RuntimeDb::memory();
        let importer = RuntimeDb::memory();
        let pack = PolicyPackPin {
            pack_id: "governance-pack".into(),
            version: "1.0.0".into(),
            content_digest: "sha256:abc123".into(),
        };
        for (plane, site_id, seed) in [(&exporter, "site-a", 1u8), (&importer, "site-b", 2u8)] {
            federation_profile::register_local_site(
                plane,
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
        federation_profile::pin_trust_root(
            &importer,
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
            &importer,
            "admin",
            &JoinPeerRequest {
                peer_site_id: "site-a".into(),
                peer_key_id: "k1".into(),
                peer_public_key_hex: public_key_hex(1),
                policy_pack: pack.clone(),
                residency_region: Some("us-east".into()),
                residency_data_classes: vec!["internal".into()],
                trust_namespace: crate::sekai::federation_profile::TRUST_ROOT_NAMESPACE.into(),
            },
            2_000,
        )
        .unwrap();
        federation_profile::set_peer_health(&importer, "site-a", PeerHealth::Up).unwrap();
        namespace_snapshot::grant_namespace(
            &importer,
            "admin-b",
            &GrantNamespaceRequest {
                peer_site_id: "site-a".into(),
                namespace: "ops".into(),
                object_kinds: vec![],
                max_classification: None,
                not_before_ms: 0,
                not_after_ms: None,
            },
            3_000,
        )
        .unwrap();
        exporter
            .create_object(&Object {
                id: "visible-1".into(),
                kind: "asset".into(),
                name: "peer".into(),
                namespace: "ops".into(),
                external_id: "asset:visible-1".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        importer
            .create_object(&Object {
                id: "visible-1".into(),
                kind: "asset".into(),
                name: "local".into(),
                namespace: "ops".into(),
                external_id: "asset:local-visible-1".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        let bundle = namespace_snapshot::export_namespace_snapshot(
            &exporter,
            &ExportSnapshotRequest {
                namespace: "ops".into(),
                actor: "admin-a".into(),
                object_kinds: vec![],
                policy_pack: pack,
                not_before_ms: 0,
                not_after_ms: None,
            },
            &signing_key(1),
            10_000,
        )
        .unwrap();
        let imported =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 10_300).unwrap();
        assert_eq!(imported.record.status, "conflict");
        let conflict = get_conflict(&importer, "ops", "visible-1").unwrap();
        assert_eq!(conflict.claims.len(), 2);
        assert_eq!(
            importer.get_object("visible-1").unwrap().unwrap().name,
            "local"
        );
        let replay =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 10_400).unwrap();
        assert_eq!(replay.conflicts, imported.conflicts);
        assert_eq!(
            get_conflict(&importer, "ops", "visible-1")
                .unwrap()
                .claims
                .len(),
            2
        );
    }
}
