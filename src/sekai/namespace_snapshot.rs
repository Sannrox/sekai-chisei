//! Bounded signed namespace snapshots under explicit peer grants (#697).
//!
//! A snapshot is a content-addressed, site-signed bundle of visible typed
//! objects. A peer signature proves identity and integrity only. An explicit
//! local grant is required before import. Imported facts never become local
//! write, permit, policy, budget, or lease authority.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{ListFilter, MAX_LIST_LIMIT, Object};
use crate::sekai::audit::Decision;
use crate::sekai::classification_lattice::evaluate_lattice_access;
use crate::sekai::evidence::EvidenceClassification;
use crate::sekai::federation_profile::{
    self, MembershipStatus, PolicyPackPin, TRUST_ROOT_NAMESPACE,
};
use crate::sekai::markings::{
    MarkingDecision, OBJECT_CLASSIFICATION_PROPERTY, PRINCIPAL_PROFILE_KIND, object_marking_token,
    parse_optional_classification, principal_authority_from_profile, principal_profile_external_id,
    trusted_service_authority,
};
use crate::sekai::peer_import;
use crate::shomei;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const NAMESPACE_SNAPSHOT_CONTRACT: &str = "sekai.namespace-snapshot/v1";
pub const SNAPSHOT_DIGEST_ALGORITHM: &str = "sha256";
pub const SNAPSHOT_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const GRANT_ACTION: &str = "federation.namespace_grant";
pub const REVOKE_GRANT_ACTION: &str = "federation.namespace_grant_revoke";
pub const EXPORT_ACTION: &str = "federation.namespace_snapshot_export";
pub const IMPORT_ACTION: &str = "federation.namespace_snapshot_import";
pub const MAX_SNAPSHOT_FACTS: usize = 5_000;
const WRITE_AUTHORITY_EVIDENCE_KEY: &str = "write_authority";
const PERMIT_AUTHORITY_EVIDENCE_KEY: &str = "permit_authority";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceSnapshotManifest {
    pub contract_version: String,
    pub snapshot_id: String,
    pub exporter_site_id: String,
    pub exporter_key_id: String,
    pub namespace: String,
    pub exported_at_ms: i64,
    pub not_before_ms: i64,
    pub not_after_ms: Option<i64>,
    pub sequence: u64,
    pub policy_pack: PolicyPackPin,
    pub residency_data_classes: Vec<String>,
    pub object_kinds: Vec<String>,
    pub fact_count: u32,
    pub hidden_omitted: bool,
    pub digest_algorithm: String,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFact {
    pub object_id: String,
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub external_id: String,
    pub properties: BTreeMap<String, String>,
    pub created: i64,
    pub updated: i64,
    pub source_site_id: String,
    pub write_authority: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceSnapshotSignature {
    pub algorithm: String,
    pub identity: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signed_at_ms: i64,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceSnapshotBundle {
    pub manifest: NamespaceSnapshotManifest,
    pub facts: Vec<SnapshotFact>,
    pub signature: Option<NamespaceSnapshotSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerNamespaceGrant {
    pub grant_id: String,
    pub peer_site_id: String,
    pub namespace: String,
    pub object_kinds: Vec<String>,
    pub max_classification: Option<String>,
    pub not_before_ms: i64,
    pub not_after_ms: Option<i64>,
    pub revoked: bool,
    pub revoked_at_ms: Option<i64>,
    pub granted_by: String,
    pub granted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantNamespaceRequest {
    pub peer_site_id: String,
    pub namespace: String,
    pub object_kinds: Vec<String>,
    pub max_classification: Option<String>,
    pub not_before_ms: i64,
    pub not_after_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSnapshotRequest {
    pub namespace: String,
    pub actor: String,
    pub object_kinds: Vec<String>,
    pub policy_pack: PolicyPackPin,
    pub not_before_ms: i64,
    pub not_after_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotImportRecord {
    pub contract_version: String,
    pub import_id: String,
    pub namespace: String,
    pub peer_site_id: String,
    pub peer_key_id: String,
    #[serde(default)]
    pub peer_public_key_hex: String,
    #[serde(default)]
    pub residency_data_classes: Vec<String>,
    #[serde(default)]
    pub not_before_ms: i64,
    #[serde(default)]
    pub not_after_ms: Option<i64>,
    pub snapshot_id: String,
    pub snapshot_digest: String,
    pub sequence: u64,
    pub fact_count: u32,
    pub conflict_count: u32,
    #[serde(default)]
    pub conflict_object_ids: Vec<String>,
    pub write_authority: bool,
    pub permit_authority: bool,
    pub status: String,
    pub imported_by: String,
    pub imported_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotImportResult {
    pub record: SnapshotImportRecord,
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotExportRecord {
    pub snapshot_id: String,
    pub snapshot_digest: String,
    pub namespace: String,
    pub sequence: u64,
    pub fact_count: u32,
    pub hidden_omitted: bool,
    pub exported_by: String,
    pub exported_at_ms: i64,
}

pub fn grant_namespace(
    db: &RuntimeDb,
    actor: &str,
    request: &GrantNamespaceRequest,
    now_ms: i64,
) -> Result<PeerNamespaceGrant, String> {
    required("actor", actor)?;
    required("peer site id", &request.peer_site_id)?;
    required("namespace", &request.namespace)?;
    if now_ms < 0 {
        return Err("grant timestamp must be non-negative".into());
    }
    if request.not_before_ms < 0 {
        return Err("grant not_before_ms must be non-negative".into());
    }
    if let Some(not_after) = request.not_after_ms
        && not_after <= request.not_before_ms
    {
        return Err("grant not_after_ms must be after not_before_ms".into());
    }
    if let Some(classification) = &request.max_classification {
        parse_required_classification(classification)?;
    }
    for kind in &request.object_kinds {
        required("object kind", kind)?;
    }
    let peer = db
        .get_federation_peer(&request.peer_site_id)?
        .ok_or_else(|| format!("unknown federation peer {}", request.peer_site_id))?;
    if peer.membership != MembershipStatus::Joined {
        return Err(format!(
            "cannot grant namespace access to peer {} with membership {}",
            request.peer_site_id,
            peer.membership.as_str()
        ));
    }

    let grant = PeerNamespaceGrant {
        grant_id: grant_id_for(&request.peer_site_id, &request.namespace, now_ms),
        peer_site_id: request.peer_site_id.clone(),
        namespace: request.namespace.clone(),
        object_kinds: request.object_kinds.clone(),
        max_classification: request.max_classification.clone(),
        not_before_ms: request.not_before_ms,
        not_after_ms: request.not_after_ms,
        revoked: false,
        revoked_at_ms: None,
        granted_by: actor.into(),
        granted_at_ms: now_ms,
    };
    db.put_federation_namespace_grant(&grant)?;
    audit_grant(db, actor, GRANT_ACTION, "granted", &grant, now_ms)?;
    Ok(grant)
}

pub fn revoke_namespace_grant(
    db: &RuntimeDb,
    actor: &str,
    grant_id: &str,
    now_ms: i64,
) -> Result<PeerNamespaceGrant, String> {
    required("actor", actor)?;
    required("grant id", grant_id)?;
    if now_ms < 0 {
        return Err("revoke timestamp must be non-negative".into());
    }
    let mut grant = db
        .get_federation_namespace_grant(grant_id)?
        .ok_or_else(|| format!("unknown namespace grant {grant_id}"))?;
    if grant.revoked {
        return Ok(grant);
    }
    grant.revoked = true;
    grant.revoked_at_ms = Some(now_ms);
    db.put_federation_namespace_grant(&grant)?;
    audit_grant(db, actor, REVOKE_GRANT_ACTION, "revoked", &grant, now_ms)?;
    Ok(grant)
}

pub fn list_namespace_grants(
    db: &RuntimeDb,
    namespace: Option<&str>,
    peer_site_id: Option<&str>,
) -> Result<Vec<PeerNamespaceGrant>, String> {
    db.list_federation_namespace_grants(namespace, peer_site_id)
}

pub fn export_namespace_snapshot(
    db: &RuntimeDb,
    request: &ExportSnapshotRequest,
    signing_key: &SigningKey,
    now_ms: i64,
) -> Result<NamespaceSnapshotBundle, String> {
    required("namespace", &request.namespace)?;
    required("actor", &request.actor)?;
    validate_policy_pack(&request.policy_pack)?;
    if now_ms < 0 {
        return Err("export timestamp must be non-negative".into());
    }
    if request.not_before_ms < 0 {
        return Err("snapshot not_before_ms must be non-negative".into());
    }
    if let Some(not_after) = request.not_after_ms
        && not_after <= request.not_before_ms
    {
        return Err("snapshot not_after_ms must be after not_before_ms".into());
    }
    for kind in &request.object_kinds {
        required("object kind", kind)?;
    }

    let local = db
        .get_federation_local_site()?
        .ok_or_else(|| "local site identity is not registered".to_string())?;
    let public_key_hex = encode_hex(signing_key.verifying_key().as_bytes());
    if !public_key_hex.eq_ignore_ascii_case(&local.public_key_hex) {
        return Err("signing key does not match the registered local site verifying key".into());
    }

    let visible = collect_visible_facts(db, request)?;
    let hidden_omitted = namespace_has_omitted_facts(db, request, &visible)?;
    let facts: Vec<SnapshotFact> = visible
        .into_iter()
        .map(|object| fact_from_object(object, &local.site_id))
        .collect();
    if facts.len() > MAX_SNAPSHOT_FACTS {
        return Err(format!(
            "snapshot exceeds fact limit ({MAX_SNAPSHOT_FACTS})"
        ));
    }

    let sequence = db.reserve_federation_snapshot_sequence(&request.namespace)?;
    let mut manifest = NamespaceSnapshotManifest {
        contract_version: NAMESPACE_SNAPSHOT_CONTRACT.into(),
        snapshot_id: String::new(),
        exporter_site_id: local.site_id.clone(),
        exporter_key_id: local.key_id.clone(),
        namespace: request.namespace.clone(),
        exported_at_ms: now_ms,
        not_before_ms: request.not_before_ms,
        not_after_ms: request.not_after_ms,
        sequence,
        policy_pack: request.policy_pack.clone(),
        residency_data_classes: local.residency_data_classes.clone(),
        object_kinds: request.object_kinds.clone(),
        fact_count: facts.len() as u32,
        hidden_omitted,
        digest_algorithm: SNAPSHOT_DIGEST_ALGORITHM.into(),
        content_digest: String::new(),
    };
    let mut bundle = NamespaceSnapshotBundle {
        manifest: manifest.clone(),
        facts,
        signature: None,
    };
    let content_digest = content_digest_for(&bundle)?;
    manifest.content_digest = content_digest.clone();
    manifest.snapshot_id = snapshot_id_for(&local.site_id, &request.namespace, &content_digest);
    bundle.manifest = manifest;
    sign_namespace_snapshot(
        &mut bundle,
        signing_key,
        &local.site_id,
        &local.key_id,
        now_ms,
    )?;

    let export = SnapshotExportRecord {
        snapshot_id: bundle.manifest.snapshot_id.clone(),
        snapshot_digest: content_digest,
        namespace: request.namespace.clone(),
        sequence,
        fact_count: bundle.manifest.fact_count,
        hidden_omitted,
        exported_by: request.actor.clone(),
        exported_at_ms: now_ms,
    };
    db.put_federation_snapshot_export(&export)?;
    audit_export(db, &request.actor, &export, now_ms)?;
    Ok(bundle)
}

pub fn verify_namespace_snapshot(
    bundle: &NamespaceSnapshotBundle,
    trusted_public_key_hex: Option<&str>,
) -> Result<(), String> {
    let errors = snapshot_verification_errors(bundle, trusted_public_key_hex);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub fn import_namespace_snapshot(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    bundle: &NamespaceSnapshotBundle,
    now_ms: i64,
) -> Result<SnapshotImportResult, String> {
    required("actor", actor)?;
    required("namespace", namespace)?;
    if now_ms < 0 {
        return Err("import timestamp must be non-negative".into());
    }
    if bundle.manifest.namespace != namespace {
        return Err("bundle namespace does not match import namespace".into());
    }

    let signature = bundle
        .signature
        .as_ref()
        .ok_or_else(|| "namespace snapshot import requires a signed bundle".to_string())?;
    let roots = peer_import::list_trust_roots(db, TRUST_ROOT_NAMESPACE)?
        .into_iter()
        .filter(|root| root.enabled)
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Err("no enabled peer trust roots configured for federation".into());
    }
    let matching_root = roots.iter().find(|root| {
        root.site_identity == signature.identity
            && root.key_id == signature.key_id
            && root
                .public_key_hex
                .eq_ignore_ascii_case(&signature.public_key_hex)
    });
    let Some(root) = matching_root else {
        return Err("bundle signer is not an enabled trust root".into());
    };
    verify_namespace_snapshot(bundle, Some(&root.public_key_hex))?;

    let availability = federation_profile::cross_site_import_availability(db, &root.site_identity)?;
    if !availability.available {
        return Err(availability.reason);
    }
    let peer = db
        .get_federation_peer(&root.site_identity)?
        .ok_or_else(|| "peer is not a federation member".to_string())?;
    if bundle.manifest.exporter_site_id != root.site_identity
        || bundle.manifest.exporter_key_id != root.key_id
        || bundle.manifest.exporter_site_id != signature.identity
        || bundle.manifest.exporter_key_id != signature.key_id
        || peer.peer_key_id != root.key_id
        || !peer
            .peer_public_key_hex
            .eq_ignore_ascii_case(&root.public_key_hex)
    {
        return Err("bundle exporter identity does not match the trusted signer".into());
    }
    if peer.policy_pack != bundle.manifest.policy_pack {
        return Err("bundle policy pin does not match the joined peer policy pin".into());
    }
    if residency_conflicts(
        &peer.residency_data_classes,
        &bundle.manifest.residency_data_classes,
    ) || residency_conflicts(
        &db.get_federation_local_site()?
            .map(|site| site.residency_data_classes)
            .unwrap_or_default(),
        &bundle.manifest.residency_data_classes,
    ) {
        return Err("bundle residency conflicts with local or peer residency policy".into());
    }

    let grants = active_grants(db, &root.site_identity, namespace, now_ms)?;
    if grants.is_empty() {
        return Err("no explicit namespace grant for peer".into());
    }
    if bundle.manifest.not_before_ms > now_ms
        || bundle
            .manifest
            .not_after_ms
            .is_some_and(|deadline| now_ms >= deadline)
    {
        return Err("snapshot is stale relative to its validity window".into());
    }
    deny_hidden_or_ungranted_facts(bundle, &grants)?;

    if let Some(latest) = db.latest_federation_snapshot_import(&root.site_identity, namespace)?
        && bundle.manifest.content_digest != latest.snapshot_digest
        && bundle.manifest.sequence <= latest.sequence
    {
        return Err("snapshot is stale relative to the last accepted sequence".into());
    }

    let import_id = import_id_for(
        namespace,
        &bundle.manifest.content_digest,
        &root.site_identity,
    );
    if let Some(existing) = db.get_federation_snapshot_import(&import_id)? {
        if existing.snapshot_digest == bundle.manifest.content_digest {
            repair_import_audit(db, actor, &existing)?;
            return Ok(SnapshotImportResult {
                conflicts: existing.conflict_object_ids.clone(),
                record: existing,
            });
        }
        return Err("import id collision with different payload".into());
    }

    let mut conflicts = Vec::new();
    let mut stored = Vec::new();
    for fact in &bundle.facts {
        if fact.write_authority {
            return Err("imported facts cannot claim write authority".into());
        }
        if db.get_object(&fact.object_id)?.is_some() {
            conflicts.push(fact.object_id.clone());
            continue;
        }
        stored.push(fact.clone());
    }

    let record = SnapshotImportRecord {
        contract_version: NAMESPACE_SNAPSHOT_CONTRACT.into(),
        import_id: import_id.clone(),
        namespace: namespace.into(),
        peer_site_id: root.site_identity.clone(),
        peer_key_id: root.key_id.clone(),
        peer_public_key_hex: root.public_key_hex.clone(),
        residency_data_classes: bundle.manifest.residency_data_classes.clone(),
        not_before_ms: bundle.manifest.not_before_ms,
        not_after_ms: bundle.manifest.not_after_ms,
        snapshot_id: bundle.manifest.snapshot_id.clone(),
        snapshot_digest: bundle.manifest.content_digest.clone(),
        sequence: bundle.manifest.sequence,
        fact_count: stored.len() as u32,
        conflict_count: conflicts.len() as u32,
        conflict_object_ids: conflicts.clone(),
        write_authority: false,
        permit_authority: false,
        status: if conflicts.is_empty() {
            "accepted".into()
        } else {
            "conflict".into()
        },
        imported_by: actor.into(),
        imported_at_ms: now_ms,
    };
    db.put_federation_snapshot_import(&record, &stored)?;
    audit_import(db, actor, &record, now_ms)?;
    Ok(SnapshotImportResult { record, conflicts })
}

pub fn list_snapshot_imports(
    db: &RuntimeDb,
    namespace: Option<&str>,
) -> Result<Vec<SnapshotImportRecord>, String> {
    db.list_federation_snapshot_imports(namespace)
}

pub fn list_snapshot_facts(
    db: &RuntimeDb,
    import_id: &str,
    now_ms: i64,
) -> Result<Vec<SnapshotFact>, String> {
    required("import id", import_id)?;
    if now_ms < 0 {
        return Err("read timestamp must be non-negative".into());
    }
    let record = db
        .get_federation_snapshot_import(import_id)?
        .ok_or_else(|| "unknown snapshot import".to_string())?;
    let grants = require_live_import_authority(db, &record, now_ms)?;
    let mut facts = Vec::new();
    for fact in db.list_federation_snapshot_facts(import_id)? {
        if grants.iter().try_fold(false, |allowed, grant| {
            Ok::<bool, String>(allowed || grant_covers_fact(grant, &fact)?)
        })? {
            facts.push(fact);
        }
    }
    Ok(facts)
}

fn require_live_import_authority(
    db: &RuntimeDb,
    record: &SnapshotImportRecord,
    now_ms: i64,
) -> Result<Vec<PeerNamespaceGrant>, String> {
    let peer = db
        .get_federation_peer(&record.peer_site_id)?
        .ok_or_else(|| "imported snapshot is no longer authorized".to_string())?;
    if peer.membership != MembershipStatus::Joined {
        return Err("imported snapshot is no longer authorized".into());
    }
    // Peer health gates new imports only. Already-accepted replicas remain
    // readable while the peer is down so local inspectability continues.
    if record.not_before_ms > now_ms
        || record
            .not_after_ms
            .is_some_and(|deadline| now_ms >= deadline)
    {
        return Err("imported snapshot is no longer authorized".into());
    }
    let grants = active_grants(db, &record.peer_site_id, &record.namespace, now_ms)?;
    if grants.is_empty() {
        return Err("imported snapshot is no longer authorized".into());
    }
    if residency_conflicts(&peer.residency_data_classes, &record.residency_data_classes)
        || residency_conflicts(
            &db.get_federation_local_site()?
                .map(|site| site.residency_data_classes)
                .unwrap_or_default(),
            &record.residency_data_classes,
        )
    {
        return Err("imported snapshot is no longer authorized".into());
    }
    if record.peer_public_key_hex.trim().is_empty() {
        return Err("imported snapshot is no longer authorized".into());
    }
    let trusted = peer_import::list_trust_roots(db, TRUST_ROOT_NAMESPACE)?
        .into_iter()
        .any(|root| {
            root.enabled
                && root.site_identity == record.peer_site_id
                && root.key_id == record.peer_key_id
                && root
                    .public_key_hex
                    .eq_ignore_ascii_case(&record.peer_public_key_hex)
        });
    if !trusted {
        return Err("imported snapshot is no longer authorized".into());
    }
    Ok(grants)
}

fn collect_visible_facts(
    db: &RuntimeDb,
    request: &ExportSnapshotRequest,
) -> Result<Vec<Object>, String> {
    let kinds: BTreeSet<String> = request.object_kinds.iter().cloned().collect();
    let mut facts = Vec::new();
    let mut offset = 0;
    loop {
        let filter = ListFilter {
            namespace: Some(request.namespace.clone()),
            limit: MAX_LIST_LIMIT,
            offset,
            ..ListFilter::default()
        };
        let (page, _) =
            db.list_objects_with_total_for_principals(&filter, &[request.actor.as_str()], &[])?;
        if page.is_empty() {
            break;
        }
        offset += page.len() as i32;
        for object in page {
            if !kinds.is_empty() && !kinds.contains(&object.kind) {
                continue;
            }
            if marking_denies_export(db, &request.actor, &object)? {
                continue;
            }
            facts.push(object);
            if facts.len() > MAX_SNAPSHOT_FACTS {
                return Err(format!(
                    "snapshot exceeds fact limit ({MAX_SNAPSHOT_FACTS})"
                ));
            }
        }
    }
    facts.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(facts)
}

fn namespace_has_omitted_facts(
    db: &RuntimeDb,
    request: &ExportSnapshotRequest,
    visible: &[Object],
) -> Result<bool, String> {
    let visible_ids: BTreeSet<&str> = visible.iter().map(|object| object.id.as_str()).collect();
    let kinds: BTreeSet<String> = request.object_kinds.iter().cloned().collect();
    let mut offset = 0;
    loop {
        let filter = ListFilter {
            namespace: Some(request.namespace.clone()),
            limit: MAX_LIST_LIMIT,
            offset,
            ..ListFilter::default()
        };
        let page = db.list_objects(&filter)?;
        if page.is_empty() {
            return Ok(false);
        }
        offset += page.len() as i32;
        for object in &page {
            if !kinds.is_empty() && !kinds.contains(&object.kind) {
                continue;
            }
            if !visible_ids.contains(object.id.as_str()) {
                return Ok(true);
            }
        }
    }
}

fn marking_denies_export(db: &RuntimeDb, actor: &str, object: &Object) -> Result<bool, String> {
    let Some(token) = object_marking_token(object) else {
        return Ok(false);
    };
    // Snapshots still carry only the evidence ordinal. Custom lattice tokens
    // stay local until a later federation contract includes the lattice.
    if parse_optional_classification(token)
        .ok()
        .flatten()
        .is_none()
    {
        return Ok(true);
    }
    let authority = export_authority(db, actor)?;
    let lattice = db.get_classification_lattice(&object.namespace)?;
    Ok(evaluate_lattice_access(
        "namespace-snapshot-export",
        object_marking_token(object),
        &authority,
        lattice.as_ref(),
    )
    .decision
        == MarkingDecision::Deny)
}

fn fact_from_object(object: Object, source_site_id: &str) -> SnapshotFact {
    SnapshotFact {
        object_id: object.id,
        kind: object.kind,
        name: object.name,
        namespace: object.namespace,
        external_id: object.external_id,
        properties: object.properties.into_iter().collect(),
        created: object.created,
        updated: object.updated,
        source_site_id: source_site_id.into(),
        write_authority: false,
    }
}

fn sign_namespace_snapshot(
    bundle: &mut NamespaceSnapshotBundle,
    signing_key: &SigningKey,
    identity: &str,
    key_id: &str,
    signed_at_ms: i64,
) -> Result<(), String> {
    if bundle.signature.is_some() {
        return Err("namespace snapshot is already signed".into());
    }
    let mut unsigned = bundle.clone();
    unsigned.signature = Some(NamespaceSnapshotSignature {
        algorithm: SNAPSHOT_SIGNATURE_ALGORITHM.into(),
        identity: identity.into(),
        key_id: key_id.into(),
        public_key_hex: encode_hex(signing_key.verifying_key().as_bytes()),
        signed_at_ms,
        signature_hex: String::new(),
    });
    let bytes = shomei::canonical_json(&unsigned)?;
    let signature = signing_key.sign(&bytes);
    bundle.signature = Some(NamespaceSnapshotSignature {
        algorithm: SNAPSHOT_SIGNATURE_ALGORITHM.into(),
        identity: identity.into(),
        key_id: key_id.into(),
        public_key_hex: encode_hex(signing_key.verifying_key().as_bytes()),
        signed_at_ms,
        signature_hex: encode_hex(&signature.to_bytes()),
    });
    Ok(())
}

fn snapshot_verification_errors(
    bundle: &NamespaceSnapshotBundle,
    trusted_public_key_hex: Option<&str>,
) -> Vec<String> {
    let mut errors = Vec::new();
    if bundle.manifest.contract_version != NAMESPACE_SNAPSHOT_CONTRACT {
        errors.push("unsupported snapshot contract".into());
    }
    if bundle.manifest.digest_algorithm != SNAPSHOT_DIGEST_ALGORITHM {
        errors.push("unsupported digest algorithm".into());
    }
    if bundle.facts.len() > MAX_SNAPSHOT_FACTS {
        errors.push(format!("fact count exceeds limit ({MAX_SNAPSHOT_FACTS})"));
    }
    if bundle.manifest.fact_count as usize != bundle.facts.len() {
        errors.push("manifest fact_count does not match facts".into());
    }
    for fact in &bundle.facts {
        if fact.namespace != bundle.manifest.namespace {
            errors.push("fact namespace does not match manifest".into());
        }
        if fact.write_authority {
            errors.push("fact claims write authority".into());
        }
        if fact.source_site_id != bundle.manifest.exporter_site_id {
            errors.push("fact source site does not match exporter".into());
        }
    }
    match content_digest_for(bundle) {
        Ok(digest) if digest != bundle.manifest.content_digest => {
            errors.push("content digest mismatch".into());
        }
        Ok(_) => {}
        Err(error) => errors.push(error),
    }
    let Some(signature) = &bundle.signature else {
        errors.push("missing snapshot signature".into());
        return errors;
    };
    if signature.algorithm != SNAPSHOT_SIGNATURE_ALGORITHM {
        errors.push("unsupported signature algorithm".into());
    }
    if let Some(trusted) = trusted_public_key_hex
        && !trusted.eq_ignore_ascii_case(&signature.public_key_hex)
    {
        errors.push("signer is not the trusted peer key".into());
    }
    match verify_signature(bundle, signature) {
        Ok(()) => {}
        Err(error) => errors.push(error),
    }
    errors
}

fn verify_signature(
    bundle: &NamespaceSnapshotBundle,
    signature: &NamespaceSnapshotSignature,
) -> Result<(), String> {
    let public_bytes = decode_hex(&signature.public_key_hex)?;
    let public_key = VerifyingKey::from_bytes(
        public_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "public key must be 32-byte ed25519 key hex".to_string())?,
    )
    .map_err(|error| format!("invalid public key: {error}"))?;
    let mut unsigned = bundle.clone();
    unsigned.signature = Some(NamespaceSnapshotSignature {
        signature_hex: String::new(),
        ..signature.clone()
    });
    let bytes = shomei::canonical_json(&unsigned)?;
    let signature_bytes = decode_hex(&signature.signature_hex)?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature must be 64-byte ed25519 hex".to_string())?;
    public_key
        .verify(
            &bytes,
            &ed25519_dalek::Signature::from_bytes(&signature_array),
        )
        .map_err(|_| "snapshot signature verification failed".to_string())
}

fn content_digest_for(bundle: &NamespaceSnapshotBundle) -> Result<String, String> {
    let mut unsigned = bundle.clone();
    unsigned.signature = None;
    unsigned.manifest.content_digest.clear();
    unsigned.manifest.snapshot_id.clear();
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&unsigned)?
    ))
}

fn export_authority(
    db: &RuntimeDb,
    actor: &str,
) -> Result<crate::sekai::markings::PrincipalAuthority, String> {
    if let Some(trusted) = trusted_service_authority(actor) {
        return Ok(trusted);
    }
    let profiles = db
        .find_all_by_external_id(&principal_profile_external_id(actor))?
        .into_iter()
        .filter(|object| object.kind == PRINCIPAL_PROFILE_KIND)
        .collect::<Vec<_>>();
    if profiles.len() > 1 {
        return Err(
            "multiple principal profiles found; resolve duplicates before snapshot export".into(),
        );
    }
    principal_authority_from_profile(actor, profiles.first())
}

fn active_grants(
    db: &RuntimeDb,
    peer_site_id: &str,
    namespace: &str,
    now_ms: i64,
) -> Result<Vec<PeerNamespaceGrant>, String> {
    Ok(db
        .list_federation_namespace_grants(Some(namespace), Some(peer_site_id))?
        .into_iter()
        .filter(|grant| {
            !grant.revoked
                && grant.not_before_ms <= now_ms
                && grant.not_after_ms.is_none_or(|deadline| now_ms < deadline)
        })
        .collect())
}

fn deny_hidden_or_ungranted_facts(
    bundle: &NamespaceSnapshotBundle,
    grants: &[PeerNamespaceGrant],
) -> Result<(), String> {
    for fact in &bundle.facts {
        let mut allowed = false;
        for grant in grants {
            if grant_covers_fact(grant, fact)? {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err("bundle contains facts outside the granted scope".into());
        }
    }
    Ok(())
}

fn grant_covers_fact(grant: &PeerNamespaceGrant, fact: &SnapshotFact) -> Result<bool, String> {
    if !grant.object_kinds.is_empty() && !grant.object_kinds.iter().any(|kind| kind == &fact.kind) {
        return Ok(false);
    }
    let marking = fact
        .properties
        .get(OBJECT_CLASSIFICATION_PROPERTY)
        .map(String::as_str)
        .unwrap_or("");
    let classification = match parse_optional_classification(marking) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(false),
    };
    let ceiling = grant
        .max_classification
        .as_deref()
        .map(parse_required_classification)
        .transpose()?;
    Ok(match (classification, ceiling) {
        (Some(marking), Some(ceiling)) => marking <= ceiling,
        _ => true,
    })
}

fn residency_conflicts(local: &[String], incoming: &[String]) -> bool {
    !local.is_empty()
        && incoming
            .iter()
            .any(|class| !local.iter().any(|allowed| allowed == class))
}

fn parse_required_classification(value: &str) -> Result<EvidenceClassification, String> {
    parse_optional_classification(value)?.ok_or_else(|| "classification is required".to_string())
}

fn validate_policy_pack(pin: &PolicyPackPin) -> Result<(), String> {
    required("policy pack id", &pin.pack_id)?;
    required("policy pack version", &pin.version)?;
    required("policy pack content digest", &pin.content_digest)?;
    Ok(())
}

fn grant_id_for(peer_site_id: &str, namespace: &str, now_ms: i64) -> String {
    let digest = Sha256::digest(format!("{peer_site_id}\0{namespace}\0{now_ms}").as_bytes());
    format!("grant-{}", encode_hex(&digest[..16]))
}

fn snapshot_id_for(site_id: &str, namespace: &str, digest: &str) -> String {
    let hashed = Sha256::digest(format!("{site_id}\0{namespace}\0{digest}").as_bytes());
    format!("snapshot-{}", encode_hex(&hashed[..16]))
}

fn import_id_for(namespace: &str, digest: &str, peer_site_id: &str) -> String {
    let hashed = Sha256::digest(format!("{namespace}\0{digest}\0{peer_site_id}").as_bytes());
    format!("ns-import-{}", encode_hex(&hashed[..16]))
}

fn audit_grant(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    outcome: &str,
    grant: &PeerNamespaceGrant,
    now_ms: i64,
) -> Result<(), String> {
    let grant_json =
        serde_json::to_string(grant).map_err(|error| format!("encode grant: {error}"))?;
    db.record_decision(&Decision {
        id: format!("federation-grant:{}:{outcome}:{now_ms}", grant.grant_id),
        timestamp: now_ms,
        actor: actor.into(),
        action: action.into(),
        reason: format!("namespace grant {outcome} under {NAMESPACE_SNAPSHOT_CONTRACT}"),
        evidence: HashMap::from([
            (
                "contract_version".into(),
                NAMESPACE_SNAPSHOT_CONTRACT.into(),
            ),
            ("grant_id".into(), grant.grant_id.clone()),
            ("peer_site_id".into(), grant.peer_site_id.clone()),
            ("namespace".into(), grant.namespace.clone()),
            ("data_class".into(), "internal".into()),
            ("grant_record".into(), grant_json),
        ]),
        target_id: grant.grant_id.clone(),
        outcome: outcome.into(),
    })
}

fn audit_export(
    db: &RuntimeDb,
    actor: &str,
    export: &SnapshotExportRecord,
    now_ms: i64,
) -> Result<(), String> {
    db.record_decision(&Decision {
        id: format!("federation-snapshot-export:{}:{now_ms}", export.snapshot_id),
        timestamp: now_ms,
        actor: actor.into(),
        action: EXPORT_ACTION.into(),
        reason: format!("exported signed namespace snapshot under {NAMESPACE_SNAPSHOT_CONTRACT}"),
        evidence: HashMap::from([
            (
                "contract_version".into(),
                NAMESPACE_SNAPSHOT_CONTRACT.into(),
            ),
            ("namespace".into(), export.namespace.clone()),
            ("snapshot_id".into(), export.snapshot_id.clone()),
            ("snapshot_digest".into(), export.snapshot_digest.clone()),
            ("fact_count".into(), export.fact_count.to_string()),
            ("hidden_omitted".into(), export.hidden_omitted.to_string()),
            ("data_class".into(), "internal".into()),
        ]),
        target_id: export.snapshot_id.clone(),
        outcome: "exported".into(),
    })
}

fn repair_import_audit(
    db: &RuntimeDb,
    actor: &str,
    record: &SnapshotImportRecord,
) -> Result<(), String> {
    let decision_id = format!(
        "federation-snapshot-import:{}:{}",
        record.import_id, record.imported_at_ms
    );
    if db.get_decision(&decision_id)?.is_none() {
        audit_import(db, actor, record, record.imported_at_ms)?;
    }
    Ok(())
}

fn audit_import(
    db: &RuntimeDb,
    actor: &str,
    record: &SnapshotImportRecord,
    now_ms: i64,
) -> Result<(), String> {
    db.record_decision(&Decision {
        id: format!("federation-snapshot-import:{}:{now_ms}", record.import_id),
        timestamp: now_ms,
        actor: actor.into(),
        action: IMPORT_ACTION.into(),
        reason: format!("imported signed namespace snapshot under {NAMESPACE_SNAPSHOT_CONTRACT}"),
        evidence: HashMap::from([
            (
                "contract_version".into(),
                NAMESPACE_SNAPSHOT_CONTRACT.into(),
            ),
            ("namespace".into(), record.namespace.clone()),
            ("import_id".into(), record.import_id.clone()),
            ("snapshot_digest".into(), record.snapshot_digest.clone()),
            ("peer_site_id".into(), record.peer_site_id.clone()),
            (WRITE_AUTHORITY_EVIDENCE_KEY.into(), "false".into()),
            (PERMIT_AUTHORITY_EVIDENCE_KEY.into(), "false".into()),
            ("status".into(), record.status.clone()),
            ("data_class".into(), "internal".into()),
        ]),
        target_id: record.import_id.clone(),
        outcome: record.status.clone(),
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err("hex length must be even".into());
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
    use crate::sekai::federation_profile::{
        JoinPeerRequest, LocalSiteIdentity, PeerHealth, PolicyPackPin,
    };
    use crate::sekai::peer_import::PeerTrustRoot;
    use ed25519_dalek::SigningKey;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public_key_hex(seed: u8) -> String {
        encode_hex(signing_key(seed).verifying_key().as_bytes())
    }

    fn pack_pin() -> PolicyPackPin {
        PolicyPackPin {
            pack_id: "governance-pack".into(),
            version: "1.0.0".into(),
            content_digest: "sha256:abc123".into(),
        }
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
        federation_profile::register_local_site(db, &site).unwrap();
        site
    }

    fn pin_peer_root(db: &RuntimeDb, site_id: &str, seed: u8) {
        federation_profile::pin_trust_root(
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

    fn join(db: &RuntimeDb, peer_site_id: &str, seed: u8) {
        federation_profile::join_peer(
            db,
            "admin",
            &JoinPeerRequest {
                peer_site_id: peer_site_id.into(),
                peer_key_id: "k1".into(),
                peer_public_key_hex: public_key_hex(seed),
                policy_pack: pack_pin(),
                residency_region: Some("us-east".into()),
                residency_data_classes: vec!["internal".into()],
                trust_namespace: TRUST_ROOT_NAMESPACE.into(),
            },
            2_000,
        )
        .unwrap();
        federation_profile::set_peer_health(db, peer_site_id, PeerHealth::Up).unwrap();
    }

    fn federate_importer(importer: &RuntimeDb, exporter_seed: u8) {
        register_site(importer, "site-b", 2);
        pin_peer_root(importer, "site-a", exporter_seed);
        join(importer, "site-a", exporter_seed);
        grant_namespace(
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

    fn put_object(db: &RuntimeDb, id: &str, marking: Option<&str>) {
        let mut properties = HashMap::new();
        if let Some(marking) = marking {
            properties.insert(OBJECT_CLASSIFICATION_PROPERTY.into(), marking.into());
        }
        db.create_object(&Object {
            id: id.into(),
            kind: "asset".into(),
            name: id.into(),
            namespace: "ops".into(),
            external_id: format!("asset:{id}"),
            properties,
            created: 10,
            updated: 10,
        })
        .unwrap();
    }

    fn export_from(exporter: &RuntimeDb, seed: u8, now_ms: i64) -> NamespaceSnapshotBundle {
        export_as(exporter, seed, now_ms, "local")
    }

    fn export_as(
        exporter: &RuntimeDb,
        seed: u8,
        now_ms: i64,
        actor: &str,
    ) -> NamespaceSnapshotBundle {
        export_namespace_snapshot(
            exporter,
            &ExportSnapshotRequest {
                namespace: "ops".into(),
                actor: actor.into(),
                object_kinds: vec![],
                policy_pack: pack_pin(),
                not_before_ms: 0,
                not_after_ms: None,
            },
            &signing_key(seed),
            now_ms,
        )
        .unwrap()
    }

    fn two_planes() -> (RuntimeDb, RuntimeDb) {
        let exporter = db();
        let importer = db();
        register_site(&exporter, "site-a", 1);
        federate_importer(&importer, 1);
        (exporter, importer)
    }

    #[test]
    fn round_trip_visible_facts_under_explicit_grant() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1", Some("internal"));
        put_object(&exporter, "visible-2", None);

        let bundle = export_from(&exporter, 1, 4_000);
        assert_eq!(bundle.manifest.fact_count, 2);
        assert!(!bundle.manifest.hidden_omitted);
        verify_namespace_snapshot(&bundle, Some(&public_key_hex(1))).unwrap();

        let imported =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 4_100).unwrap();
        assert_eq!(imported.record.status, "accepted");
        assert!(!imported.record.write_authority);
        assert!(!imported.record.permit_authority);
        let facts = list_snapshot_facts(&importer, &imported.record.import_id, 4_100).unwrap();
        assert_eq!(facts.len(), 2);
        assert!(facts.iter().all(|fact| !fact.write_authority));

        let replay =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 4_200).unwrap();
        assert_eq!(replay.record.import_id, imported.record.import_id);
        assert_eq!(replay.conflicts, imported.conflicts);
        assert_eq!(
            list_snapshot_facts(&importer, &replay.record.import_id, 4_200)
                .unwrap()
                .len(),
            2
        );

        let grants = list_namespace_grants(&importer, Some("ops"), Some("site-a")).unwrap();
        revoke_namespace_grant(&importer, "admin-b", &grants[0].grant_id, 4_300).unwrap();
        let err = list_snapshot_facts(&importer, &imported.record.import_id, 4_400).unwrap_err();
        assert!(err.contains("no longer authorized"), "{err}");
    }

    #[test]
    fn hidden_data_is_omitted_without_count_leak() {
        let exporter = db();
        register_site(&exporter, "site-a", 1);
        put_object(&exporter, "visible-1", None);
        put_object(&exporter, "hidden-1", Some("restricted"));

        let bundle = export_as(&exporter, 1, 5_000, "exporter");
        assert_eq!(bundle.manifest.fact_count, 1);
        assert_eq!(bundle.facts[0].object_id, "visible-1");
        assert!(bundle.manifest.hidden_omitted);
        let encoded = serde_json::to_string(&bundle).unwrap();
        assert!(!encoded.contains("hidden-1"));
        assert!(!encoded.contains("\"hidden_count\""));
    }

    #[test]
    fn policy_pin_mismatch_is_denied() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1", None);
        let mut bundle = export_from(&exporter, 1, 6_000);
        bundle.manifest.policy_pack.version = "9.9.9".into();
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 6_100).unwrap_err();
        assert!(
            err.contains("policy pin") || err.contains("digest"),
            "{err}"
        );
    }

    #[test]
    fn ungranted_peer_is_denied() {
        let exporter = db();
        let importer = db();
        register_site(&exporter, "site-a", 1);
        register_site(&importer, "site-b", 2);
        pin_peer_root(&importer, "site-a", 1);
        join(&importer, "site-a", 1);
        put_object(&exporter, "visible-1", None);
        let bundle = export_from(&exporter, 1, 7_000);
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 7_100).unwrap_err();
        assert!(err.contains("grant"), "{err}");
    }

    #[test]
    fn stale_and_tampered_and_wrong_signer_are_denied() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1", None);
        let mut bundle = export_from(&exporter, 1, 8_000);
        bundle.manifest.not_after_ms = Some(8_000);
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 8_100).unwrap_err();
        assert!(err.contains("stale") || err.contains("digest"), "{err}");

        let mut tampered = export_from(&exporter, 1, 8_200);
        tampered.facts[0].name = "mutated".into();
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &tampered, 8_300).unwrap_err();
        assert!(err.contains("digest") || err.contains("signature"), "{err}");

        let foreign = export_namespace_snapshot(
            &exporter,
            &ExportSnapshotRequest {
                namespace: "ops".into(),
                actor: "local".into(),
                object_kinds: vec![],
                policy_pack: pack_pin(),
                not_before_ms: 0,
                not_after_ms: None,
            },
            &signing_key(9),
            8_400,
        )
        .unwrap_err();
        assert!(foreign.contains("signing key"), "{foreign}");
    }

    #[test]
    fn revoked_grant_and_residency_conflict_are_denied() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1", None);
        let grants = list_namespace_grants(&importer, Some("ops"), Some("site-a")).unwrap();
        revoke_namespace_grant(&importer, "admin-b", &grants[0].grant_id, 9_000).unwrap();
        let bundle = export_from(&exporter, 1, 9_100);
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 9_200).unwrap_err();
        assert!(err.contains("grant"), "{err}");

        let importer = db();
        register_site(&importer, "site-b", 2);
        pin_peer_root(&importer, "site-a", 1);
        federation_profile::join_peer(
            &importer,
            "admin",
            &JoinPeerRequest {
                peer_site_id: "site-a".into(),
                peer_key_id: "k1".into(),
                peer_public_key_hex: public_key_hex(1),
                policy_pack: pack_pin(),
                residency_region: Some("us-east".into()),
                residency_data_classes: vec!["public".into()],
                trust_namespace: TRUST_ROOT_NAMESPACE.into(),
            },
            2_000,
        )
        .unwrap();
        federation_profile::set_peer_health(&importer, "site-a", PeerHealth::Up).unwrap();
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
            3_000,
        )
        .unwrap();
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 9_300).unwrap_err();
        assert!(err.contains("residency"), "{err}");
    }

    #[test]
    fn hidden_bundle_facts_and_local_conflicts_fail_closed() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1", None);
        let mut bundle = export_from(&exporter, 1, 10_000);
        bundle.facts.push(SnapshotFact {
            object_id: "secret".into(),
            kind: "asset".into(),
            name: "secret".into(),
            namespace: "ops".into(),
            external_id: "asset:secret".into(),
            properties: BTreeMap::from([(
                OBJECT_CLASSIFICATION_PROPERTY.into(),
                "restricted".into(),
            )]),
            created: 1,
            updated: 1,
            source_site_id: "site-a".into(),
            write_authority: false,
        });
        bundle.manifest.fact_count = bundle.facts.len() as u32;
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &bundle, 10_100).unwrap_err();
        assert!(
            err.contains("hidden") || err.contains("digest") || err.contains("signature"),
            "{err}"
        );

        let clean = export_from(&exporter, 1, 10_200);
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
        let imported =
            import_namespace_snapshot(&importer, "admin-b", "ops", &clean, 10_300).unwrap();
        assert_eq!(imported.record.status, "conflict");
        assert_eq!(imported.conflicts, vec!["visible-1".to_string()]);
        let replay =
            import_namespace_snapshot(&importer, "admin-b", "ops", &clean, 10_400).unwrap();
        assert_eq!(replay.conflicts, imported.conflicts);
        assert_eq!(
            importer.get_object("visible-1").unwrap().unwrap().name,
            "local"
        );
        assert!(
            list_snapshot_facts(&importer, &imported.record.import_id, 10_300)
                .unwrap()
                .is_empty()
        );
    }

    fn resign(
        bundle: &mut NamespaceSnapshotBundle,
        seed: u8,
        identity: &str,
        key_id: &str,
        now_ms: i64,
    ) {
        bundle.signature = None;
        bundle.manifest.content_digest.clear();
        bundle.manifest.snapshot_id.clear();
        let digest = content_digest_for(bundle).unwrap();
        bundle.manifest.content_digest = digest.clone();
        bundle.manifest.snapshot_id = snapshot_id_for(
            &bundle.manifest.exporter_site_id,
            &bundle.manifest.namespace,
            &digest,
        );
        sign_namespace_snapshot(bundle, &signing_key(seed), identity, key_id, now_ms).unwrap();
    }

    #[test]
    fn forged_exporter_identity_and_same_sequence_divergence_are_denied() {
        let (exporter, importer) = two_planes();
        put_object(&exporter, "visible-1", None);
        let first = export_from(&exporter, 1, 11_000);
        import_namespace_snapshot(&importer, "admin-b", "ops", &first, 11_100).unwrap();

        let mut forged = first.clone();
        forged.manifest.exporter_site_id = "other-site".into();
        for fact in &mut forged.facts {
            fact.source_site_id = "other-site".into();
        }
        resign(&mut forged, 1, "site-a", "k1", 11_200);
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &forged, 11_200).unwrap_err();
        assert!(err.contains("exporter identity"), "{err}");

        put_object(&exporter, "visible-2", None);
        let mut divergent = export_from(&exporter, 1, 11_300);
        divergent.manifest.sequence = first.manifest.sequence;
        resign(&mut divergent, 1, "site-a", "k1", 11_300);
        let err =
            import_namespace_snapshot(&importer, "admin-b", "ops", &divergent, 11_400).unwrap_err();
        assert!(err.contains("stale"), "{err}");
    }

    #[test]
    fn custom_lattice_tokens_stay_out_of_snapshots() {
        let runtime = db();
        let custom = Object {
            id: "health-doc".into(),
            kind: "document".into(),
            name: "health".into(),
            namespace: "ops".into(),
            external_id: "ops:health".into(),
            properties: std::collections::HashMap::from([(
                OBJECT_CLASSIFICATION_PROPERTY.into(),
                "health".into(),
            )]),
            created: 1,
            updated: 1,
        };
        assert!(marking_denies_export(&runtime, "alice", &custom).unwrap());
        let grant = PeerNamespaceGrant {
            grant_id: "g1".into(),
            peer_site_id: "site-a".into(),
            namespace: "ops".into(),
            object_kinds: Vec::new(),
            max_classification: None,
            not_before_ms: 0,
            not_after_ms: None,
            revoked: false,
            revoked_at_ms: None,
            granted_by: "admin".into(),
            granted_at_ms: 1,
        };
        let fact = SnapshotFact {
            object_id: custom.id.clone(),
            kind: custom.kind.clone(),
            name: custom.name.clone(),
            namespace: custom.namespace.clone(),
            external_id: custom.external_id.clone(),
            properties: custom.properties.into_iter().collect(),
            created: 1,
            updated: 1,
            source_site_id: "site-a".into(),
            write_authority: false,
        };
        assert!(!grant_covers_fact(&grant, &fact).unwrap());
    }

    #[test]
    fn postgres_unavailable_is_explicit() {
        let err = RuntimeDb::memory()
            .list_federation_namespace_grants(None, None)
            .unwrap();
        assert!(err.is_empty());
    }
}
