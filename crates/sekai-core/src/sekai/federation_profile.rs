//! Multi-control-plane federation profile v1 (#291).
//!
//! One plane = one write authority. Cross-site is verify/import/deny only.
//! Durable freeze: `docs/research/291-federation-profile.md`.
//!
//! Trust roots reuse `#290` peer import pins. Join/leave are audited. Peer
//! down keeps local governance available and marks cross-site import
//! unavailable. Remote promote / kill / budget debit are hard-denied.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::audit::Decision;
use crate::sekai::peer_import::{self, PeerTrustRoot};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const FEDERATION_PROFILE_CONTRACT: &str = "sekai.federation-profile/v1";
pub const JOIN_ACTION: &str = "federation.peer_join";
pub const LEAVE_ACTION: &str = "federation.peer_leave";
pub const FORBIDDEN_REMOTE_ACTION: &str = "federation.forbidden_remote";
pub const TRUST_ROOT_NAMESPACE: &str = "federation";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSiteIdentity {
    pub site_id: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub region: Option<String>,
    pub residency_data_classes: Vec<String>,
    pub registered_by: String,
    pub registered_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPackPin {
    pub pack_id: String,
    pub version: String,
    pub content_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerHealth {
    Up,
    Down,
    Unknown,
}

impl PeerHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "up" => Ok(Self::Up),
            "down" => Ok(Self::Down),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!(
                "invalid peer health {other:?}; expected up|down|unknown"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipStatus {
    Joined,
    Left,
}

impl MembershipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Joined => "joined",
            Self::Left => "left",
        }
    }
}

/// Remote control verbs. Only verify/import/deny are allowed across sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteControlOp {
    Verify,
    Import,
    Deny,
    Promote,
    Kill,
    BudgetDebit,
}

impl RemoteControlOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Import => "import",
            Self::Deny => "deny",
            Self::Promote => "promote",
            Self::Kill => "kill",
            Self::BudgetDebit => "budget_debit",
        }
    }

    pub fn is_forbidden(self) -> bool {
        matches!(self, Self::Promote | Self::Kill | Self::BudgetDebit)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationPeer {
    pub contract_version: String,
    pub local_site_id: String,
    pub peer_site_id: String,
    pub peer_key_id: String,
    pub peer_public_key_hex: String,
    pub policy_pack: PolicyPackPin,
    pub residency_region: Option<String>,
    pub residency_data_classes: Vec<String>,
    pub health: PeerHealth,
    pub membership: MembershipStatus,
    pub joined_by: String,
    pub joined_at_ms: i64,
    pub left_by: Option<String>,
    pub left_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSiteImportAvailability {
    pub peer_site_id: String,
    pub available: bool,
    pub reason: String,
    pub health: PeerHealth,
    pub membership: MembershipStatus,
    pub policy_pack: Option<PolicyPackPin>,
}

#[derive(Debug, Clone)]
pub struct JoinPeerRequest {
    pub peer_site_id: String,
    pub peer_key_id: String,
    pub peer_public_key_hex: String,
    pub policy_pack: PolicyPackPin,
    pub residency_region: Option<String>,
    pub residency_data_classes: Vec<String>,
    /// Namespace used for #290 trust root lookup. Defaults to `federation`.
    pub trust_namespace: String,
}

/// Register this plane's site identity (Ed25519 verifying key only).
pub fn register_local_site(db: &RuntimeDb, site: &LocalSiteIdentity) -> Result<(), String> {
    validate_local_site(site)?;
    if let Some(existing) = db.get_federation_local_site()?
        && existing.site_id != site.site_id
    {
        return Err(format!(
            "local site already registered as {:?}; cannot replace with {:?}",
            existing.site_id, site.site_id
        ));
    }
    db.put_federation_local_site(site)
}

pub fn get_local_site(db: &RuntimeDb) -> Result<Option<LocalSiteIdentity>, String> {
    db.get_federation_local_site()
}

/// Pin a peer trust root under the federation namespace (or a caller-chosen ns).
/// Thin wrapper over `#290` so operators can keep pack/site admin on one path.
pub fn pin_trust_root(db: &RuntimeDb, root: &PeerTrustRoot) -> Result<(), String> {
    peer_import::put_trust_root(db, root)
}

/// Join a peer after verifying an enabled trust root pin matches the peer identity.
pub fn join_peer(
    db: &RuntimeDb,
    actor: &str,
    request: &JoinPeerRequest,
    now_ms: i64,
) -> Result<FederationPeer, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("join timestamp must be non-negative".into());
    }
    validate_join_request(request)?;

    let local = db
        .get_federation_local_site()?
        .ok_or_else(|| "local site identity is not registered".to_string())?;

    require_enabled_trust_root(
        db,
        &request.trust_namespace,
        &request.peer_site_id,
        &request.peer_key_id,
        &request.peer_public_key_hex,
    )?;

    if request.peer_site_id == local.site_id {
        return Err("cannot join self as a federation peer".into());
    }

    let peer = FederationPeer {
        contract_version: FEDERATION_PROFILE_CONTRACT.into(),
        local_site_id: local.site_id,
        peer_site_id: request.peer_site_id.clone(),
        peer_key_id: request.peer_key_id.clone(),
        peer_public_key_hex: normalize_hex(&request.peer_public_key_hex),
        policy_pack: request.policy_pack.clone(),
        residency_region: request.residency_region.clone(),
        residency_data_classes: request.residency_data_classes.clone(),
        health: PeerHealth::Unknown,
        membership: MembershipStatus::Joined,
        joined_by: actor.into(),
        joined_at_ms: now_ms,
        left_by: None,
        left_at_ms: None,
    };

    db.put_federation_peer(&peer)?;
    audit_membership(db, actor, JOIN_ACTION, "joined", &peer, now_ms)?;
    Ok(peer)
}

pub fn leave_peer(
    db: &RuntimeDb,
    actor: &str,
    peer_site_id: &str,
    now_ms: i64,
) -> Result<FederationPeer, String> {
    required("actor", actor)?;
    required("peer site id", peer_site_id)?;
    if now_ms < 0 {
        return Err("leave timestamp must be non-negative".into());
    }

    let mut peer = db
        .get_federation_peer(peer_site_id)?
        .ok_or_else(|| format!("unknown federation peer {peer_site_id:?}"))?;
    if peer.membership == MembershipStatus::Left {
        return Ok(peer);
    }

    peer.membership = MembershipStatus::Left;
    peer.left_by = Some(actor.into());
    peer.left_at_ms = Some(now_ms);
    peer.health = PeerHealth::Down;

    db.put_federation_peer(&peer)?;
    audit_membership(db, actor, LEAVE_ACTION, "left", &peer, now_ms)?;
    Ok(peer)
}

pub fn set_peer_health(
    db: &RuntimeDb,
    peer_site_id: &str,
    health: PeerHealth,
) -> Result<FederationPeer, String> {
    required("peer site id", peer_site_id)?;
    let mut peer = db
        .get_federation_peer(peer_site_id)?
        .ok_or_else(|| format!("unknown federation peer {peer_site_id:?}"))?;
    if peer.membership != MembershipStatus::Joined {
        return Err(format!(
            "cannot set health on peer {peer_site_id:?} with membership {}",
            peer.membership.as_str()
        ));
    }
    peer.health = health;
    db.put_federation_peer(&peer)?;
    Ok(peer)
}

pub fn set_policy_pack_pin(
    db: &RuntimeDb,
    peer_site_id: &str,
    pin: PolicyPackPin,
) -> Result<FederationPeer, String> {
    required("peer site id", peer_site_id)?;
    validate_policy_pack(&pin)?;
    let mut peer = db
        .get_federation_peer(peer_site_id)?
        .ok_or_else(|| format!("unknown federation peer {peer_site_id:?}"))?;
    if peer.membership != MembershipStatus::Joined {
        return Err(format!(
            "cannot pin policy pack on peer {peer_site_id:?} with membership {}",
            peer.membership.as_str()
        ));
    }
    peer.policy_pack = pin;
    db.put_federation_peer(&peer)?;
    Ok(peer)
}

pub fn get_peer(db: &RuntimeDb, peer_site_id: &str) -> Result<Option<FederationPeer>, String> {
    required("peer site id", peer_site_id)?;
    db.get_federation_peer(peer_site_id)
}

pub fn list_peers(db: &RuntimeDb) -> Result<Vec<FederationPeer>, String> {
    db.list_federation_peers()
}

/// Cross-site import availability under the v1 fail-closed profile.
///
/// Local governance is independent of this result: import unavailable never
/// blocks plane-local write authority.
pub fn cross_site_import_availability(
    db: &RuntimeDb,
    peer_site_id: &str,
) -> Result<CrossSiteImportAvailability, String> {
    required("peer site id", peer_site_id)?;
    let Some(peer) = db.get_federation_peer(peer_site_id)? else {
        return Ok(CrossSiteImportAvailability {
            peer_site_id: peer_site_id.into(),
            available: false,
            reason: "peer is not a federation member".into(),
            health: PeerHealth::Unknown,
            membership: MembershipStatus::Left,
            policy_pack: None,
        });
    };

    if peer.membership != MembershipStatus::Joined {
        return Ok(CrossSiteImportAvailability {
            peer_site_id: peer.peer_site_id,
            available: false,
            reason: "peer membership is left; re-join required".into(),
            health: peer.health,
            membership: peer.membership,
            policy_pack: Some(peer.policy_pack),
        });
    }

    match peer.health {
        PeerHealth::Up => Ok(CrossSiteImportAvailability {
            peer_site_id: peer.peer_site_id,
            available: true,
            reason: "peer is joined and healthy".into(),
            health: peer.health,
            membership: peer.membership,
            policy_pack: Some(peer.policy_pack),
        }),
        PeerHealth::Down => Ok(CrossSiteImportAvailability {
            peer_site_id: peer.peer_site_id,
            available: false,
            reason: "peer is down; cross-site import unavailable (local governance continues)"
                .into(),
            health: peer.health,
            membership: peer.membership,
            policy_pack: Some(peer.policy_pack),
        }),
        PeerHealth::Unknown => Ok(CrossSiteImportAvailability {
            peer_site_id: peer.peer_site_id,
            available: false,
            reason: "peer health is unknown; cross-site import unavailable".into(),
            health: peer.health,
            membership: peer.membership,
            policy_pack: Some(peer.policy_pack),
        }),
    }
}

/// Guard for any code path that might attempt remote control across planes.
pub fn evaluate_remote_control(op: RemoteControlOp) -> Result<(), String> {
    if op.is_forbidden() {
        return Err(format!(
            "forbidden remote operation {}: federation profile allows verify/import/deny only",
            op.as_str()
        ));
    }
    Ok(())
}

/// Audit + deny a forbidden remote control attempt when an actor is known.
pub fn deny_forbidden_remote(
    db: &RuntimeDb,
    actor: &str,
    op: RemoteControlOp,
    peer_site_id: &str,
    now_ms: i64,
) -> Result<(), String> {
    required("actor", actor)?;
    required("peer site id", peer_site_id)?;
    if !op.is_forbidden() {
        return evaluate_remote_control(op);
    }
    let decision = Decision {
        id: format!(
            "federation-forbidden:{}:{}:{}",
            peer_site_id,
            op.as_str(),
            now_ms
        ),
        timestamp: now_ms,
        actor: actor.into(),
        action: FORBIDDEN_REMOTE_ACTION.into(),
        reason: format!(
            "denied remote {} against peer {} (federation profile v1)",
            op.as_str(),
            peer_site_id
        ),
        evidence: HashMap::from([
            (
                "contract_version".into(),
                FEDERATION_PROFILE_CONTRACT.into(),
            ),
            ("peer_site_id".into(), peer_site_id.into()),
            ("remote_op".into(), op.as_str().into()),
            ("outcome".into(), "denied".into()),
            ("data_class".into(), "internal".into()),
        ]),
        target_id: peer_site_id.into(),
        outcome: "denied".into(),
    };
    db.record_decision(&decision)?;
    Err(format!(
        "forbidden remote operation {}: federation profile allows verify/import/deny only",
        op.as_str()
    ))
}

fn require_enabled_trust_root(
    db: &RuntimeDb,
    namespace: &str,
    site_id: &str,
    key_id: &str,
    public_key_hex: &str,
) -> Result<PeerTrustRoot, String> {
    let roots = peer_import::list_trust_roots(db, namespace)?;
    let normalized = normalize_hex(public_key_hex);
    let matching = roots.into_iter().find(|root| {
        root.enabled
            && root.site_identity == site_id
            && root.key_id == key_id
            && normalize_hex(&root.public_key_hex) == normalized
    });
    matching.ok_or_else(|| {
        format!(
            "peer {}:{} is not an enabled trust root for namespace {namespace}",
            site_id, key_id
        )
    })
}

fn audit_membership(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    outcome: &str,
    peer: &FederationPeer,
    now_ms: i64,
) -> Result<(), String> {
    let peer_json =
        serde_json::to_string(peer).map_err(|error| format!("encode federation peer: {error}"))?;
    let decision = Decision {
        id: format!("federation-{}:{}:{}", outcome, peer.peer_site_id, now_ms),
        timestamp: now_ms,
        actor: actor.into(),
        action: action.into(),
        reason: format!(
            "federation peer {} {} under {}",
            peer.peer_site_id, outcome, FEDERATION_PROFILE_CONTRACT
        ),
        evidence: HashMap::from([
            (
                "contract_version".into(),
                FEDERATION_PROFILE_CONTRACT.into(),
            ),
            ("local_site_id".into(), peer.local_site_id.clone()),
            ("peer_site_id".into(), peer.peer_site_id.clone()),
            ("peer_key_id".into(), peer.peer_key_id.clone()),
            ("policy_pack_id".into(), peer.policy_pack.pack_id.clone()),
            (
                "policy_pack_version".into(),
                peer.policy_pack.version.clone(),
            ),
            (
                "policy_pack_digest".into(),
                peer.policy_pack.content_digest.clone(),
            ),
            ("membership".into(), peer.membership.as_str().into()),
            ("health".into(), peer.health.as_str().into()),
            ("data_class".into(), "internal".into()),
            ("peer_record".into(), peer_json),
        ]),
        target_id: peer.peer_site_id.clone(),
        outcome: outcome.into(),
    };
    db.record_decision(&decision)
}

fn validate_local_site(site: &LocalSiteIdentity) -> Result<(), String> {
    required("site id", &site.site_id)?;
    required("key id", &site.key_id)?;
    required("public key hex", &site.public_key_hex)?;
    required("registered by", &site.registered_by)?;
    if site.registered_at_ms < 0 {
        return Err("registered_at_ms must be non-negative".into());
    }
    validate_ed25519_hex(&site.public_key_hex)?;
    for class in &site.residency_data_classes {
        required("residency data class", class)?;
    }
    if let Some(region) = &site.region {
        required("region", region)?;
    }
    Ok(())
}

fn validate_join_request(request: &JoinPeerRequest) -> Result<(), String> {
    required("peer site id", &request.peer_site_id)?;
    required("peer key id", &request.peer_key_id)?;
    required("peer public key hex", &request.peer_public_key_hex)?;
    required("trust namespace", &request.trust_namespace)?;
    validate_ed25519_hex(&request.peer_public_key_hex)?;
    validate_policy_pack(&request.policy_pack)?;
    for class in &request.residency_data_classes {
        required("residency data class", class)?;
    }
    if let Some(region) = &request.residency_region {
        required("residency region", region)?;
    }
    Ok(())
}

fn validate_policy_pack(pin: &PolicyPackPin) -> Result<(), String> {
    required("policy pack id", &pin.pack_id)?;
    required("policy pack version", &pin.version)?;
    required("policy pack content digest", &pin.content_digest)?;
    Ok(())
}

fn validate_ed25519_hex(hex: &str) -> Result<(), String> {
    let bytes = decode_hex(hex)?;
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

fn normalize_hex(hex: &str) -> String {
    hex.trim().to_ascii_lowercase()
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
    use crate::sekai::audit::Decision;
    use ed25519_dalek::SigningKey;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn public_key_hex(seed: u8) -> String {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        signing
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn register_site(db: &RuntimeDb, site_id: &str, seed: u8) -> LocalSiteIdentity {
        let site = LocalSiteIdentity {
            site_id: site_id.into(),
            key_id: "k1".into(),
            public_key_hex: public_key_hex(seed),
            region: Some("eu-central".into()),
            residency_data_classes: vec!["internal".into()],
            registered_by: "admin".into(),
            registered_at_ms: 1_000,
        };
        register_local_site(db, &site).unwrap();
        site
    }

    fn pin_peer_root(db: &RuntimeDb, site_id: &str, seed: u8) {
        pin_trust_root(
            db,
            &PeerTrustRoot {
                namespace: TRUST_ROOT_NAMESPACE.into(),
                site_identity: site_id.into(),
                key_id: "k1".into(),
                public_key_hex: public_key_hex(seed),
                enabled: true,
                created_by: "admin".into(),
                created_at_ms: 1_100,
            },
        )
        .unwrap();
    }

    fn pack_pin() -> PolicyPackPin {
        PolicyPackPin {
            pack_id: "governance-pack".into(),
            version: "1.0.0".into(),
            content_digest: "sha256:abc123".into(),
        }
    }

    /// Acceptance: two local processes federate with pinned roots; pack pin visible.
    #[test]
    fn two_local_planes_federate_with_visible_pack_pin() {
        let plane_a = db();
        let plane_b = db();

        let site_a = register_site(&plane_a, "site-a", 1);
        let site_b = register_site(&plane_b, "site-b", 2);

        // Mutual trust root pins (each plane trusts the other's verifying key).
        pin_peer_root(&plane_a, "site-b", 2);
        pin_peer_root(&plane_b, "site-a", 1);

        let joined_on_a = join_peer(
            &plane_a,
            "admin-a",
            &JoinPeerRequest {
                peer_site_id: site_b.site_id.clone(),
                peer_key_id: site_b.key_id.clone(),
                peer_public_key_hex: site_b.public_key_hex.clone(),
                policy_pack: pack_pin(),
                residency_region: Some("us-east".into()),
                residency_data_classes: vec!["internal".into()],
                trust_namespace: TRUST_ROOT_NAMESPACE.into(),
            },
            2_000,
        )
        .unwrap();

        let joined_on_b = join_peer(
            &plane_b,
            "admin-b",
            &JoinPeerRequest {
                peer_site_id: site_a.site_id.clone(),
                peer_key_id: site_a.key_id.clone(),
                peer_public_key_hex: site_a.public_key_hex.clone(),
                policy_pack: pack_pin(),
                residency_region: Some("eu-central".into()),
                residency_data_classes: vec!["internal".into()],
                trust_namespace: TRUST_ROOT_NAMESPACE.into(),
            },
            2_001,
        )
        .unwrap();

        assert_eq!(joined_on_a.policy_pack.pack_id, "governance-pack");
        assert_eq!(joined_on_a.policy_pack.version, "1.0.0");
        assert_eq!(joined_on_a.policy_pack.content_digest, "sha256:abc123");
        assert_eq!(joined_on_b.policy_pack.content_digest, "sha256:abc123");

        let visible = get_peer(&plane_a, "site-b").unwrap().unwrap();
        assert_eq!(visible.policy_pack, pack_pin());
        assert_eq!(visible.membership, MembershipStatus::Joined);
        assert_eq!(visible.contract_version, FEDERATION_PROFILE_CONTRACT);

        let roots = peer_import::list_trust_roots(&plane_a, TRUST_ROOT_NAMESPACE).unwrap();
        assert!(
            roots
                .iter()
                .any(|r| r.site_identity == "site-b" && r.enabled)
        );
    }

    /// Acceptance: peer down → local governance continues; import unavailable.
    #[test]
    fn peer_down_local_continues_import_unavailable() {
        let plane = db();
        let _local = register_site(&plane, "site-a", 3);
        pin_peer_root(&plane, "site-b", 4);
        join_peer(
            &plane,
            "admin",
            &JoinPeerRequest {
                peer_site_id: "site-b".into(),
                peer_key_id: "k1".into(),
                peer_public_key_hex: public_key_hex(4),
                policy_pack: pack_pin(),
                residency_region: None,
                residency_data_classes: vec![],
                trust_namespace: TRUST_ROOT_NAMESPACE.into(),
            },
            3_000,
        )
        .unwrap();
        set_peer_health(&plane, "site-b", PeerHealth::Up).unwrap();
        assert!(
            cross_site_import_availability(&plane, "site-b")
                .unwrap()
                .available
        );

        set_peer_health(&plane, "site-b", PeerHealth::Down).unwrap();
        let availability = cross_site_import_availability(&plane, "site-b").unwrap();
        assert!(!availability.available);
        assert!(availability.reason.contains("import unavailable"));
        assert_eq!(availability.health, PeerHealth::Down);
        assert_eq!(
            availability.policy_pack.as_ref().unwrap().pack_id,
            "governance-pack"
        );

        // Local governance continues: plane-local decisions still record.
        plane
            .record_decision(&Decision {
                id: "local-gov-1".into(),
                timestamp: 3_100,
                actor: "admin".into(),
                action: "policy.evaluate".into(),
                reason: "local governance while peer down".into(),
                evidence: HashMap::from([("namespace".into(), "support".into())]),
                target_id: "local".into(),
                outcome: "allowed".into(),
            })
            .unwrap();
        assert!(plane.get_decision("local-gov-1").unwrap().is_some());

        evaluate_remote_control(RemoteControlOp::Import).unwrap();
        assert!(evaluate_remote_control(RemoteControlOp::Promote).is_err());
        assert!(evaluate_remote_control(RemoteControlOp::Kill).is_err());
        assert!(evaluate_remote_control(RemoteControlOp::BudgetDebit).is_err());
    }

    /// Acceptance: untrusted peer rejected.
    #[test]
    fn untrusted_peer_rejected() {
        let plane = db();
        register_site(&plane, "site-a", 5);

        let err = join_peer(
            &plane,
            "admin",
            &JoinPeerRequest {
                peer_site_id: "evil-site".into(),
                peer_key_id: "k1".into(),
                peer_public_key_hex: public_key_hex(9),
                policy_pack: pack_pin(),
                residency_region: None,
                residency_data_classes: vec![],
                trust_namespace: TRUST_ROOT_NAMESPACE.into(),
            },
            4_000,
        )
        .unwrap_err();
        assert!(err.contains("trust root"), "unexpected: {err}");

        // Wrong public key under a known site identity also fails.
        pin_peer_root(&plane, "site-b", 6);
        let err = join_peer(
            &plane,
            "admin",
            &JoinPeerRequest {
                peer_site_id: "site-b".into(),
                peer_key_id: "k1".into(),
                peer_public_key_hex: public_key_hex(7),
                policy_pack: pack_pin(),
                residency_region: None,
                residency_data_classes: vec![],
                trust_namespace: TRUST_ROOT_NAMESPACE.into(),
            },
            4_001,
        )
        .unwrap_err();
        assert!(err.contains("trust root"), "unexpected: {err}");
    }

    #[test]
    fn join_leave_audited_and_rejoin_allowed() {
        let plane = db();
        register_site(&plane, "site-a", 8);
        pin_peer_root(&plane, "site-b", 9);
        join_peer(
            &plane,
            "admin",
            &JoinPeerRequest {
                peer_site_id: "site-b".into(),
                peer_key_id: "k1".into(),
                peer_public_key_hex: public_key_hex(9),
                policy_pack: pack_pin(),
                residency_region: None,
                residency_data_classes: vec![],
                trust_namespace: TRUST_ROOT_NAMESPACE.into(),
            },
            5_000,
        )
        .unwrap();
        leave_peer(&plane, "admin", "site-b", 5_100).unwrap();
        let left = get_peer(&plane, "site-b").unwrap().unwrap();
        assert_eq!(left.membership, MembershipStatus::Left);
        assert_eq!(left.health, PeerHealth::Down);

        join_peer(
            &plane,
            "admin",
            &JoinPeerRequest {
                peer_site_id: "site-b".into(),
                peer_key_id: "k1".into(),
                peer_public_key_hex: public_key_hex(9),
                policy_pack: PolicyPackPin {
                    pack_id: "governance-pack".into(),
                    version: "1.1.0".into(),
                    content_digest: "sha256:def456".into(),
                },
                residency_region: None,
                residency_data_classes: vec![],
                trust_namespace: TRUST_ROOT_NAMESPACE.into(),
            },
            5_200,
        )
        .unwrap();
        let rejoined = get_peer(&plane, "site-b").unwrap().unwrap();
        assert_eq!(rejoined.membership, MembershipStatus::Joined);
        assert_eq!(rejoined.policy_pack.version, "1.1.0");
    }

    #[test]
    fn deny_forbidden_remote_is_audited() {
        let plane = db();
        let err = deny_forbidden_remote(
            &plane,
            "admin",
            RemoteControlOp::BudgetDebit,
            "site-b",
            6_000,
        )
        .unwrap_err();
        assert!(err.contains("forbidden remote"));
        assert!(
            plane
                .get_decision("federation-forbidden:site-b:budget_debit:6000")
                .unwrap()
                .is_some()
        );
    }
}
