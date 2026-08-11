//! Durable handoff creation and revocation behind one lifecycle interface.
//!
//! Transport adapters authenticate callers, authorize namespace access, and
//! evaluate whether referenced data is visible. This module owns manifest
//! invariants, replay identity, timing, predecessor compatibility, persistence,
//! and revocation authority so every transport observes the same ordering.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::handoff::{HandoffManifest, HandoffReference};

const MAX_FUTURE_SKEW_MS: i64 = 60_000;

pub(crate) struct CreateHandoff<'a> {
    pub manifest: HandoffManifest,
    pub request_id: &'a str,
    pub principals: &'a [String],
    pub now_ms: i64,
}

pub(crate) struct RevokeHandoff<'a> {
    pub manifest_id: &'a str,
    pub reason: &'a str,
    pub request_id: &'a str,
    pub principals: &'a [String],
    pub now_ms: i64,
}

#[derive(Debug, PartialEq)]
pub(crate) enum HandoffLifecycleError {
    InvalidArgument(String),
    AlreadyExists(String),
    FailedPrecondition(String),
    NotFound(String),
    Storage(String),
}

pub(crate) struct HandoffLifecycle<'a> {
    db: &'a RuntimeDb,
}

impl<'a> HandoffLifecycle<'a> {
    pub(crate) fn new(db: &'a RuntimeDb) -> Self {
        Self { db }
    }

    pub(crate) fn create<Available>(
        &self,
        command: CreateHandoff<'_>,
        mut reference_available: Available,
    ) -> Result<HandoffManifest, HandoffLifecycleError>
    where
        Available: FnMut(&HandoffReference) -> Result<bool, HandoffLifecycleError>,
    {
        let manifest = command.manifest;
        if manifest.intended_scope != manifest.namespace {
            return Err(HandoffLifecycleError::InvalidArgument(
                "intended_scope must equal the manifest namespace".into(),
            ));
        }
        if !command
            .principals
            .iter()
            .any(|principal| principal == &manifest.creator_principal)
        {
            return Err(HandoffLifecycleError::InvalidArgument(
                "creator_principal must match the authenticated caller".into(),
            ));
        }
        manifest
            .validate()
            .map_err(HandoffLifecycleError::InvalidArgument)?;
        let request_digest = manifest
            .canonical_digest()
            .map_err(HandoffLifecycleError::InvalidArgument)?;
        if let Some((existing_digest, existing)) = self
            .db
            .get_handoff_by_request(&manifest.creator_principal, command.request_id)
            .map_err(HandoffLifecycleError::Storage)?
        {
            if existing_digest != request_digest {
                return Err(HandoffLifecycleError::AlreadyExists(
                    "request_id is already bound to different handoff input".into(),
                ));
            }
            return Ok(existing);
        }
        if manifest.created_at_ms > command.now_ms.saturating_add(MAX_FUTURE_SKEW_MS)
            || manifest.expires_at_ms <= command.now_ms
        {
            return Err(HandoffLifecycleError::InvalidArgument(
                "handoff timestamps are outside the accepted window".into(),
            ));
        }
        for reference in manifest
            .references
            .iter()
            .filter(|reference| !reference.omitted)
        {
            if !reference_available(reference)? {
                return Err(HandoffLifecycleError::FailedPrecondition(
                    "handoff contains an unavailable reference".into(),
                ));
            }
        }
        if !manifest.supersedes_manifest_id.is_empty() {
            let predecessor = self
                .db
                .get_handoff(&manifest.supersedes_manifest_id)
                .map_err(HandoffLifecycleError::Storage)?
                .ok_or_else(|| {
                    HandoffLifecycleError::FailedPrecondition(
                        "superseded handoff is unavailable".into(),
                    )
                })?;
            if predecessor.creator_principal != manifest.creator_principal
                || predecessor.intended_principal != manifest.intended_principal
                || predecessor.namespace != manifest.namespace
            {
                return Err(HandoffLifecycleError::FailedPrecondition(
                    "superseded handoff is unavailable".into(),
                ));
            }
        }
        self.db
            .create_handoff(&manifest, command.request_id)
            .map_err(|error| {
                if error.contains("different handoff") {
                    HandoffLifecycleError::AlreadyExists(error)
                } else {
                    HandoffLifecycleError::InvalidArgument(error)
                }
            })
    }

    pub(crate) fn revoke(
        &self,
        command: RevokeHandoff<'_>,
    ) -> Result<HandoffManifest, HandoffLifecycleError> {
        let existing = self
            .db
            .get_handoff(command.manifest_id)
            .map_err(HandoffLifecycleError::Storage)?
            .ok_or_else(|| HandoffLifecycleError::NotFound("handoff not found".into()))?;
        if !command.principals.iter().any(|principal| {
            principal == &existing.creator_principal
                || matches!(principal.as_str(), "root" | "local")
        }) {
            return Err(HandoffLifecycleError::NotFound("handoff not found".into()));
        }
        let actor = command.principals.first().cloned().unwrap_or_default();
        self.db
            .revoke_handoff(
                command.manifest_id,
                &actor,
                command.reason,
                command.request_id,
                command.now_ms,
            )
            .map_err(HandoffLifecycleError::InvalidArgument)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::handoff::{HANDOFF_VERSION, HandoffReference};

    fn manifest(id: &str, created_at_ms: i64) -> HandoffManifest {
        HandoffManifest {
            schema_version: HANDOFF_VERSION.into(),
            id: id.into(),
            namespace: "demo".into(),
            parent_operation_id: "operation-1".into(),
            parent_attempt_id: "attempt-1".into(),
            parent_work_unit_id: "work-1".into(),
            references: vec![HandoffReference {
                kind: "object".into(),
                id: "object-1".into(),
                version: "sha256:one".into(),
                omitted: false,
                omission_reason: String::new(),
            }],
            creator_principal: "alice".into(),
            intended_principal: "bob".into(),
            intended_scope: "demo".into(),
            purpose: "continue work".into(),
            created_at_ms,
            expires_at_ms: created_at_ms + 60_000,
            digest: String::new(),
            supersedes_manifest_id: String::new(),
            revoked: false,
        }
    }

    #[test]
    fn create_interface_owns_replay_timing_and_reference_ordering() {
        let db = RuntimeDb::memory();
        let lifecycle = HandoffLifecycle::new(&db);
        let principals = vec!["alice".into()];
        let mut availability_checks = 0;
        let first = lifecycle
            .create(
                CreateHandoff {
                    manifest: manifest("handoff-1", 1_000),
                    request_id: "request-1",
                    principals: &principals,
                    now_ms: 1_000,
                },
                |_| {
                    availability_checks += 1;
                    Ok(true)
                },
            )
            .unwrap();
        let replay = lifecycle
            .create(
                CreateHandoff {
                    manifest: manifest("handoff-1", 1_000),
                    request_id: "request-1",
                    principals: &principals,
                    now_ms: 2_000,
                },
                |_| panic!("replay must return before reference evaluation"),
            )
            .unwrap();

        assert_eq!(availability_checks, 1);
        assert_eq!(first, replay);
        assert!(!first.digest.is_empty());
    }

    #[test]
    fn revoke_interface_hides_handoffs_from_unrelated_callers() {
        let db = RuntimeDb::memory();
        let lifecycle = HandoffLifecycle::new(&db);
        let owner = vec!["alice".into()];
        lifecycle
            .create(
                CreateHandoff {
                    manifest: manifest("handoff-1", 1_000),
                    request_id: "request-1",
                    principals: &owner,
                    now_ms: 1_000,
                },
                |_| Ok(true),
            )
            .unwrap();

        let error = lifecycle
            .revoke(RevokeHandoff {
                manifest_id: "handoff-1",
                reason: "superseded",
                request_id: "revoke-1",
                principals: &["mallory".into()],
                now_ms: 2_000,
            })
            .unwrap_err();
        assert_eq!(
            error,
            HandoffLifecycleError::NotFound("handoff not found".into())
        );
    }
}
