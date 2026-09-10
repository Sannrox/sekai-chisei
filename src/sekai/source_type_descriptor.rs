//! Additive source-type descriptor identity and SQLite catalog (ADR 0060, #818).
//!
//! Register, inspect, and retire persist beside the code-owned GitHub profile.
//! Live registered descriptors may authorize `ApplySourceBatch` (#819).

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::object_sync::{
    FAMILY_OBJECT_SYNC, MAX_SOURCE_IDENTIFIER_BYTES, SOURCE_GITHUB, SourceRecord, SyncDecision,
    SyncedObject, contains_secret_like_text, object_id_for,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SOURCE_TYPE_DESCRIPTOR_CONTRACT: &str = "sekai.source-type-descriptor/v1";
pub const STATUS_LIVE: &str = "live";
pub const STATUS_RETIRED: &str = "retired";
pub const DESCRIPTOR_UNAVAILABLE: &str = "source-type descriptor is unavailable";
pub const POSTGRES_UNAVAILABLE: &str =
    "source-type descriptors are unavailable on the PostgreSQL community runtime";

/// One proposed registered source kind. One descriptor admits exactly one
/// record kind and one schema revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedSourceTypeDescriptor {
    pub contract_version: String,
    pub family: String,
    pub source: String,
    pub record_kind: String,
    pub schema_revision: String,
    pub digest: String,
}

impl ProposedSourceTypeDescriptor {
    pub fn prepare(
        source: impl Into<String>,
        record_kind: impl Into<String>,
        schema_revision: impl Into<String>,
    ) -> Result<Self, String> {
        let mut descriptor = Self {
            contract_version: SOURCE_TYPE_DESCRIPTOR_CONTRACT.into(),
            family: FAMILY_OBJECT_SYNC.into(),
            source: source.into(),
            record_kind: record_kind.into(),
            schema_revision: schema_revision.into(),
            digest: String::new(),
        };
        descriptor.digest = descriptor_digest(&descriptor)?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != SOURCE_TYPE_DESCRIPTOR_CONTRACT {
            return Err("unsupported source-type descriptor contract".into());
        }
        if self.family != FAMILY_OBJECT_SYNC {
            return Err("descriptor family must remain source_control.object_sync".into());
        }
        require_registered_token("source", &self.source)?;
        require_registered_token("record_kind", &self.record_kind)?;
        require_registered_token("schema_revision", &self.schema_revision)?;
        if self.source == SOURCE_GITHUB
            || self.record_kind == "Issue"
            || self.record_kind == "PullRequest"
        {
            return Err("GitHub Issue/PullRequest stays the code-owned profile".into());
        }
        if descriptor_digest(self)? != self.digest {
            return Err("descriptor digest does not match the registered identity".into());
        }
        Ok(())
    }
}

pub fn descriptor_digest(descriptor: &ProposedSourceTypeDescriptor) -> Result<String, String> {
    require_registered_token("source", &descriptor.source)?;
    require_registered_token("record_kind", &descriptor.record_kind)?;
    require_registered_token("schema_revision", &descriptor.schema_revision)?;
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        SOURCE_TYPE_DESCRIPTOR_CONTRACT,
        FAMILY_OBJECT_SYNC,
        descriptor.source,
        descriptor.record_kind,
        descriptor.schema_revision
    );
    Ok(format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())))
}

/// Namespaced identity for a registered descriptor. Record kind is part of the
/// key so kinds do not share GitHub's repository number space.
pub fn registered_source_id(
    descriptor: &ProposedSourceTypeDescriptor,
    source_instance: &str,
    immutable_key: &str,
) -> Result<String, String> {
    descriptor.validate()?;
    require_registered_token("source_instance", source_instance)?;
    require_registered_token("immutable_key", immutable_key)?;
    Ok(format!(
        "{}:{source_instance}#{}/{}",
        descriptor.source, descriptor.record_kind, immutable_key
    ))
}

/// Free-form names are not a registration. Callers must supply the admitted
/// descriptor; the plane must not infer one from display names or record labels.
pub fn infer_descriptor_from_name(_name: &str) -> Result<ProposedSourceTypeDescriptor, String> {
    Err("source-type descriptors cannot be inferred from free-form record names".into())
}

/// Project one record through a proposed registered descriptor.
pub fn project_registered_record(
    descriptor: &ProposedSourceTypeDescriptor,
    record: SourceRecord,
) -> Result<SyncDecision, String> {
    descriptor.validate()?;
    if record.source != descriptor.source {
        return Ok(SyncDecision::Reject {
            reason: "record source is not the registered descriptor".into(),
        });
    }
    if record.type_name != descriptor.record_kind {
        return Ok(SyncDecision::Reject {
            reason: "record kind is not the registered descriptor".into(),
        });
    }
    let source = registered_source_id(descriptor, &record.source_instance, &record.external_id)?;
    let object = SyncedObject {
        object_id: object_id_for(&descriptor.digest, &source),
        type_name: record.type_name,
        source_id: source,
        source_version: record.source_version,
        payload_digest: record.payload_digest,
        properties: record.properties,
        tombstoned: record.deleted,
        type_digest: descriptor.digest.clone(),
    };
    if record.deleted {
        Ok(SyncDecision::Tombstone(object))
    } else {
        Ok(SyncDecision::Upsert(object))
    }
}

fn require_registered_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains('#')
        || value.contains(':')
    {
        return Err(format!("{label} is not a canonical registered token"));
    }
    if value.contains('/') && label != "source_instance" {
        return Err(format!("{label} is not a canonical registered token"));
    }
    Ok(())
}

/// Research fixtures: two local synthetic kinds that are not catalog-advertised.
pub fn synthetic_pager_alert_v1() -> ProposedSourceTypeDescriptor {
    ProposedSourceTypeDescriptor::prepare("synthetic.pager", "Alert", "v1").expect("pager v1")
}

pub fn synthetic_cmdb_service_v1() -> ProposedSourceTypeDescriptor {
    ProposedSourceTypeDescriptor::prepare("synthetic.cmdb", "Service", "v1").expect("cmdb v1")
}

pub fn synthetic_pager_alert_v2() -> ProposedSourceTypeDescriptor {
    ProposedSourceTypeDescriptor::prepare("synthetic.pager", "Alert", "v2").expect("pager v2")
}

/// Durable catalog row. Inspection returns [SourceTypeDescriptorIdentity], not
/// this record: owner and timestamps stay off the inspect surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSourceTypeDescriptor {
    pub contract_version: String,
    pub namespace: String,
    pub family: String,
    pub source: String,
    pub record_kind: String,
    pub schema_revision: String,
    pub digest: String,
    pub status: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
    #[serde(default)]
    pub retired_by: String,
    #[serde(default)]
    pub retired_at_ms: i64,
}

/// Bounded inspect view: identity and lifecycle only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTypeDescriptorIdentity {
    pub contract_version: String,
    pub namespace: String,
    pub family: String,
    pub source: String,
    pub record_kind: String,
    pub schema_revision: String,
    pub digest: String,
    pub status: String,
}

pub fn inspect_identity(stored: &StoredSourceTypeDescriptor) -> SourceTypeDescriptorIdentity {
    SourceTypeDescriptorIdentity {
        contract_version: stored.contract_version.clone(),
        namespace: stored.namespace.clone(),
        family: stored.family.clone(),
        source: stored.source.clone(),
        record_kind: stored.record_kind.clone(),
        schema_revision: stored.schema_revision.clone(),
        digest: stored.digest.clone(),
        status: stored.status.clone(),
    }
}

pub fn register_source_type_descriptor(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    descriptor: &ProposedSourceTypeDescriptor,
    now_ms: i64,
) -> Result<SourceTypeDescriptorIdentity, String> {
    let stored = prepare_registration(actor, namespace, descriptor, now_ms)?;
    if let Some(existing) = db.get_source_type_descriptor(&stored.namespace, &stored.digest)? {
        return replay_or_conflict(&existing, &stored);
    }
    match db.put_source_type_descriptor(&stored) {
        Ok(()) => Ok(inspect_identity(&stored)),
        Err(error) if error == POSTGRES_UNAVAILABLE => Err(error),
        Err(error) if error == DESCRIPTOR_UNAVAILABLE => {
            let existing = db
                .get_source_type_descriptor(&stored.namespace, &stored.digest)?
                .ok_or(DESCRIPTOR_UNAVAILABLE)?;
            replay_or_conflict(&existing, &stored)
        }
        Err(error) => Err(error),
    }
}

pub fn inspect_source_type_descriptor(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    digest: &str,
) -> Result<SourceTypeDescriptorIdentity, String> {
    let stored = owned_descriptor(db, actor, namespace, digest)?;
    Ok(inspect_identity(&stored))
}

pub fn retire_source_type_descriptor(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    digest: &str,
    now_ms: i64,
) -> Result<SourceTypeDescriptorIdentity, String> {
    require_positive_timestamp(now_ms)?;
    let current = owned_descriptor(db, actor, namespace, digest)?;
    if current.status != STATUS_LIVE {
        return Err(DESCRIPTOR_UNAVAILABLE.into());
    }
    let mut next = current.clone();
    next.status = STATUS_RETIRED.into();
    next.retired_by = actor.into();
    next.retired_at_ms = now_ms;
    db.cas_source_type_descriptor(&current, &next)?;
    Ok(inspect_identity(&next))
}

fn prepare_registration(
    actor: &str,
    namespace: &str,
    descriptor: &ProposedSourceTypeDescriptor,
    now_ms: i64,
) -> Result<StoredSourceTypeDescriptor, String> {
    required("actor", actor)?;
    require_registered_token("namespace", namespace)?;
    reject_secret(actor)?;
    reject_secret(namespace)?;
    require_positive_timestamp(now_ms)?;
    descriptor.validate()?;
    reject_secret(&descriptor.source)?;
    reject_secret(&descriptor.record_kind)?;
    reject_secret(&descriptor.schema_revision)?;
    reject_secret(&descriptor.digest)?;
    Ok(StoredSourceTypeDescriptor {
        contract_version: descriptor.contract_version.clone(),
        namespace: namespace.into(),
        family: descriptor.family.clone(),
        source: descriptor.source.clone(),
        record_kind: descriptor.record_kind.clone(),
        schema_revision: descriptor.schema_revision.clone(),
        digest: descriptor.digest.clone(),
        status: STATUS_LIVE.into(),
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
        retired_by: String::new(),
        retired_at_ms: 0,
    })
}

fn owned_descriptor(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    digest: &str,
) -> Result<StoredSourceTypeDescriptor, String> {
    required("actor", actor)?;
    require_registered_token("namespace", namespace)?;
    reject_secret(actor)?;
    reject_secret(namespace)?;
    reject_secret(digest)?;
    db.get_source_type_descriptor(namespace, digest)?
        .ok_or_else(|| DESCRIPTOR_UNAVAILABLE.into())
}

fn replay_or_conflict(
    existing: &StoredSourceTypeDescriptor,
    proposed: &StoredSourceTypeDescriptor,
) -> Result<SourceTypeDescriptorIdentity, String> {
    if existing.status != STATUS_LIVE
        || existing.namespace != proposed.namespace
        || existing.family != proposed.family
        || existing.source != proposed.source
        || existing.record_kind != proposed.record_kind
        || existing.schema_revision != proposed.schema_revision
        || existing.digest != proposed.digest
        || existing.admitted_by != proposed.admitted_by
        || existing.contract_version != proposed.contract_version
    {
        return Err(DESCRIPTOR_UNAVAILABLE.into());
    }
    Ok(inspect_identity(existing))
}

fn require_positive_timestamp(now_ms: i64) -> Result<(), String> {
    if now_ms <= 0 {
        Err("timestamp must be positive".into())
    } else {
        Ok(())
    }
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn reject_secret(value: &str) -> Result<(), String> {
    if contains_secret_like_text(value) {
        Err(DESCRIPTOR_UNAVAILABLE.into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::object_sync::{
        GITHUB_OBJECT_SYNC_TYPE_DIGEST, detect_identity_conflict,
        source_id as github_style_source_id, sync_github_record,
    };
    use crate::source_adapter_catalog::built_in_source_adapters;
    use std::collections::BTreeMap;

    fn record(
        source: &str,
        instance: &str,
        kind: &str,
        key: &str,
        version: &str,
        title: &str,
        deleted: bool,
    ) -> SourceRecord {
        SourceRecord {
            source: source.into(),
            source_instance: instance.into(),
            external_id: key.into(),
            source_version: version.into(),
            type_name: kind.into(),
            display_name: title.into(),
            payload_digest: format!("sha256:{:x}", Sha256::digest(title.as_bytes())),
            properties: BTreeMap::from([("title".into(), title.into())]),
            deleted,
            observed_at_ms: 10,
            source_sequence: None,
        }
    }

    fn github_issue(number: &str) -> SourceRecord {
        SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            external_id: number.into(),
            source_version: "issue-v1".into(),
            type_name: "Issue".into(),
            display_name: "Service checkout latency incident".into(),
            payload_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            properties: BTreeMap::from([("state".into(), "open".into())]),
            deleted: false,
            observed_at_ms: 10,
            source_sequence: None,
        }
    }

    fn upsert(decision: SyncDecision) -> SyncedObject {
        match decision {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        }
    }

    fn tombstone(decision: SyncDecision) -> SyncedObject {
        match decision {
            SyncDecision::Tombstone(object) => object,
            other => panic!("expected tombstone, got {other:?}"),
        }
    }

    #[test]
    fn two_synthetic_kinds_have_collision_free_keys_and_independent_lifecycle() {
        let pager = synthetic_pager_alert_v1();
        let cmdb = synthetic_cmdb_service_v1();
        assert_ne!(pager.digest, cmdb.digest);
        assert_ne!(pager.digest, GITHUB_OBJECT_SYNC_TYPE_DIGEST);

        let alert = upsert(
            project_registered_record(
                &pager,
                record(
                    "synthetic.pager",
                    "ops-local",
                    "Alert",
                    "42",
                    "alert-v1",
                    "checkout latency",
                    false,
                ),
            )
            .unwrap(),
        );
        let service = upsert(
            project_registered_record(
                &cmdb,
                record(
                    "synthetic.cmdb",
                    "ops-local",
                    "Service",
                    "42",
                    "svc-v1",
                    "checkout",
                    false,
                ),
            )
            .unwrap(),
        );
        assert_eq!(alert.source_id, "synthetic.pager:ops-local#Alert/42");
        assert_eq!(service.source_id, "synthetic.cmdb:ops-local#Service/42");
        assert_ne!(alert.source_id, service.source_id);
        assert_ne!(alert.object_id, service.object_id);

        let refreshed = upsert(
            project_registered_record(
                &pager,
                record(
                    "synthetic.pager",
                    "ops-local",
                    "Alert",
                    "42",
                    "alert-v2",
                    "checkout latency mitigated",
                    false,
                ),
            )
            .unwrap(),
        );
        assert_eq!(refreshed.object_id, alert.object_id);
        assert_eq!(refreshed.source_id, alert.source_id);
        assert_eq!(refreshed.source_version, "alert-v2");
        assert_ne!(refreshed.payload_digest, alert.payload_digest);

        let deleted = tombstone(
            project_registered_record(
                &pager,
                record(
                    "synthetic.pager",
                    "ops-local",
                    "Alert",
                    "42",
                    "alert-v3",
                    "checkout latency mitigated",
                    true,
                ),
            )
            .unwrap(),
        );
        assert_eq!(deleted.object_id, alert.object_id);
        assert!(deleted.tombstoned);
        assert_ne!(deleted.object_id, service.object_id);
    }

    #[test]
    fn github_identity_and_refresh_rules_remain_unchanged() {
        let issue = upsert(sync_github_record(
            github_issue("42"),
            GITHUB_OBJECT_SYNC_TYPE_DIGEST,
        ));
        let pull = {
            let mut record = github_issue("42");
            record.type_name = "PullRequest".into();
            upsert(sync_github_record(record, GITHUB_OBJECT_SYNC_TYPE_DIGEST))
        };
        assert_eq!(issue.source_id, "github:acme/ops#42");
        assert_eq!(issue.source_id, pull.source_id);
        assert_eq!(issue.object_id, pull.object_id);

        let pager = synthetic_pager_alert_v1();
        let alert = upsert(
            project_registered_record(
                &pager,
                record(
                    "synthetic.pager",
                    "acme/ops",
                    "Alert",
                    "42",
                    "alert-v1",
                    "not a github issue",
                    false,
                ),
            )
            .unwrap(),
        );
        assert_ne!(alert.source_id, issue.source_id);
        assert_ne!(alert.object_id, issue.object_id);
        assert_eq!(
            github_style_source_id("github", "acme/ops", "42"),
            "github:acme/ops#42"
        );

        let mut discussion = github_issue("42");
        discussion.type_name = "Discussion".into();
        match sync_github_record(discussion, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Reject { reason } => {
                assert!(reason.contains("Issue and PullRequest"));
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn schema_revision_change_is_a_new_type_identity() {
        let v1 = synthetic_pager_alert_v1();
        let v2 = synthetic_pager_alert_v2();
        assert_ne!(v1.digest, v2.digest);

        let first = upsert(
            project_registered_record(
                &v1,
                record(
                    "synthetic.pager",
                    "ops-local",
                    "Alert",
                    "7",
                    "rev-1",
                    "same key",
                    false,
                ),
            )
            .unwrap(),
        );
        let next = upsert(
            project_registered_record(
                &v2,
                record(
                    "synthetic.pager",
                    "ops-local",
                    "Alert",
                    "7",
                    "rev-2",
                    "same key",
                    false,
                ),
            )
            .unwrap(),
        );
        assert_eq!(first.source_id, next.source_id);
        assert_ne!(first.type_digest, next.type_digest);
        assert_ne!(first.object_id, next.object_id);
        assert_eq!(
            detect_identity_conflict(&first, &next).as_deref(),
            Some("source identity moved across type revisions")
        );
    }

    #[test]
    fn immutable_source_version_cannot_change_payload() {
        let pager = synthetic_pager_alert_v1();
        let first = upsert(
            project_registered_record(
                &pager,
                record(
                    "synthetic.pager",
                    "ops-local",
                    "Alert",
                    "9",
                    "rev-1",
                    "original",
                    false,
                ),
            )
            .unwrap(),
        );
        let mutated = upsert(
            project_registered_record(
                &pager,
                record(
                    "synthetic.pager",
                    "ops-local",
                    "Alert",
                    "9",
                    "rev-1",
                    "tampered",
                    false,
                ),
            )
            .unwrap(),
        );
        assert_eq!(first.source_id, mutated.source_id);
        assert_eq!(first.object_id, mutated.object_id);
        assert_eq!(first.source_version, mutated.source_version);
        assert_ne!(first.payload_digest, mutated.payload_digest);
        assert_eq!(
            crate::sekai::object_sync::classify_source_record_compatibility(Some(&first), &mutated),
            crate::sekai::definition_diff::DefinitionCompatibilityClass::Breaking
        );
    }

    #[test]
    fn free_form_names_and_github_profile_reuse_are_rejected() {
        assert!(
            infer_descriptor_from_name("Incident")
                .unwrap_err()
                .contains("cannot be inferred")
        );
        assert!(ProposedSourceTypeDescriptor::prepare("github", "Alert", "v1").is_err());
        assert!(ProposedSourceTypeDescriptor::prepare("synthetic.pager", "Issue", "v1").is_err());
        match project_registered_record(
            &synthetic_pager_alert_v1(),
            record(
                "synthetic.cmdb",
                "ops-local",
                "Alert",
                "1",
                "v1",
                "wrong source",
                false,
            ),
        )
        .unwrap()
        {
            SyncDecision::Reject { reason } => {
                assert!(reason.contains("registered descriptor"));
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn production_catalog_and_github_mapper_do_not_admit_the_spike() {
        let profiles = built_in_source_adapters();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].source, SOURCE_GITHUB);
        assert_eq!(profiles[0].record_types, ["Issue", "PullRequest"]);

        let mut foreign = github_issue("42");
        foreign.source = "synthetic.pager".into();
        match sync_github_record(foreign, GITHUB_OBJECT_SYNC_TYPE_DIGEST) {
            SyncDecision::Reject { reason } => {
                assert!(reason.contains("GitHub"));
            }
            other => panic!("expected reject, got {other:?}"),
        }
        match sync_github_record(github_issue("42"), &synthetic_pager_alert_v1().digest) {
            SyncDecision::Reject { reason } => {
                assert!(reason.contains("not bound"));
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    fn catalog_db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    #[test]
    fn register_inspect_and_retire_one_admitted_descriptor() {
        let db = catalog_db();
        let pager = synthetic_pager_alert_v1();
        let admitted = register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
        assert_eq!(admitted.source, "synthetic.pager");
        assert_eq!(admitted.record_kind, "Alert");
        assert_eq!(admitted.status, STATUS_LIVE);
        assert_eq!(admitted.digest, pager.digest);
        let inspected =
            inspect_source_type_descriptor(&db, "local", "ops", &admitted.digest).unwrap();
        assert_eq!(inspected, admitted);
        let replay = register_source_type_descriptor(&db, "local", "ops", &pager, 11).unwrap();
        assert_eq!(replay.digest, admitted.digest);
        let retired =
            retire_source_type_descriptor(&db, "local", "ops", &admitted.digest, 12).unwrap();
        assert_eq!(retired.status, STATUS_RETIRED);
        assert_eq!(
            register_source_type_descriptor(&db, "local", "ops", &pager, 13).unwrap_err(),
            DESCRIPTOR_UNAVAILABLE
        );
    }

    #[test]
    fn conflicting_reuse_and_unauthorized_inspect_fail_without_disclosure() {
        let db = catalog_db();
        let pager = synthetic_pager_alert_v1();
        let admitted = register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
        let cmdb = synthetic_cmdb_service_v1();
        let mut colliding = cmdb.clone();
        colliding.source = pager.source.clone();
        colliding.record_kind = pager.record_kind.clone();
        colliding.schema_revision = pager.schema_revision.clone();
        colliding.digest = pager.digest.clone();
        assert_eq!(
            register_source_type_descriptor(&db, "other", "ops", &colliding, 11).unwrap_err(),
            DESCRIPTOR_UNAVAILABLE
        );
        assert_eq!(
            inspect_source_type_descriptor(&db, "other", "ops", &admitted.digest).unwrap(),
            admitted
        );
        assert_eq!(
            inspect_source_type_descriptor(&db, "local", "ops", "sha256:deadbeef").unwrap_err(),
            DESCRIPTOR_UNAVAILABLE
        );
        assert_eq!(
            inspect_source_type_descriptor(&db, "local", "missing", &admitted.digest).unwrap_err(),
            DESCRIPTOR_UNAVAILABLE
        );
        assert!(
            register_source_type_descriptor(&db, "local", "ops", &pager, 10)
                .unwrap()
                .digest
                == admitted.digest
        );
    }

    #[test]
    fn inspect_returns_bounded_identity_fields_only() {
        let db = catalog_db();
        let pager = synthetic_pager_alert_v1();
        let admitted = register_source_type_descriptor(&db, "local", "ops", &pager, 10).unwrap();
        let json = serde_json::to_string(&admitted).unwrap();
        assert!(!json.contains("admitted_by"));
        assert!(!json.contains("retired_by"));
        assert!(!json.contains("cursor"));
        assert!(!json.contains("payload"));
        assert!(!json.contains("secret"));
        assert!(json.contains(&pager.digest));
        assert_eq!(admitted.family, FAMILY_OBJECT_SYNC);
        assert_eq!(built_in_source_adapters().len(), 1);
        assert_eq!(built_in_source_adapters()[0].source, SOURCE_GITHUB);
        assert_ne!(admitted.digest, GITHUB_OBJECT_SYNC_TYPE_DIGEST);
    }

    #[test]
    fn secret_like_registration_is_unavailable() {
        let db = catalog_db();
        let pager = synthetic_pager_alert_v1();
        assert_eq!(
            register_source_type_descriptor(
                &db,
                "ghp_exampletokenvalue0123456789ab",
                "ops",
                &pager,
                10
            )
            .unwrap_err(),
            DESCRIPTOR_UNAVAILABLE
        );
    }
}
