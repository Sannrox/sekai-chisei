//! Governed coordination-lease workflows.
//!
//! This module owns behavior that must be identical across transports: object-bound
//! lease authorization, acquisition, and cleanup when the target disappears during
//! acquisition. Transport adapters remain responsible for authentication, tenant
//! context, and team-namespace admission before invoking this interface.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::lease::{Lease, LeaseError};
use crate::sekai::object_security::{
    ObjectAuthorizationContext, PrincipalSecurityContext, evaluate_object_policy,
};
use crate::sekai::security::SecurityChecker;
use std::collections::{BTreeMap, BTreeSet};

const OBJECT_BOUND_LEASE_KEY_PREFIX: &str = "object:";

pub(crate) struct AcquireLease<'a> {
    pub namespace: &'a str,
    pub key: &'a str,
    pub owner: &'a str,
    pub ttl_ms: i64,
    pub request_id: &'a str,
    pub actor: &'a str,
    pub principals: &'a [String],
    pub now_ms: i64,
}

pub(crate) struct GetLease<'a> {
    pub namespace: &'a str,
    pub key: &'a str,
    pub principals: &'a [String],
}

pub(crate) struct RefreshLease<'a> {
    pub namespace: &'a str,
    pub key: &'a str,
    pub fencing_token: &'a str,
    pub ttl_ms: i64,
    pub request_id: &'a str,
    pub actor: &'a str,
    pub principals: &'a [String],
    pub now_ms: i64,
}

pub(crate) struct ReleaseLease<'a> {
    pub namespace: &'a str,
    pub key: &'a str,
    pub fencing_token: &'a str,
    pub request_id: &'a str,
    pub actor: &'a str,
    pub principals: &'a [String],
    pub now_ms: i64,
}

pub(crate) struct TakeoverExpiredLease<'a> {
    pub namespace: &'a str,
    pub key: &'a str,
    pub owner: &'a str,
    pub expected_fencing_token: &'a str,
    pub expected_expires_at_ms: i64,
    pub ttl_ms: i64,
    pub request_id: &'a str,
    pub actor: &'a str,
    pub principals: &'a [String],
    pub now_ms: i64,
}

pub(crate) struct GuardedMutationPrecondition<'a> {
    pub key: &'a str,
    pub lease_namespace: &'a str,
    pub target: GuardedMutationTarget<'a>,
}

pub(crate) enum GuardedMutationTarget<'a> {
    Create,
    Object {
        id: &'a str,
        namespace: Option<&'a str>,
    },
}

#[derive(Debug, PartialEq)]
pub(crate) enum LeaseLifecycleError {
    InvalidArgument(String),
    FailedPrecondition(String),
    PermissionDenied(String),
    NotFound(String),
    Storage(String),
    Lease(LeaseError),
}

pub(crate) struct LeaseLifecycle<'a> {
    db: &'a RuntimeDb,
    security: &'a SecurityChecker,
    site_id: &'a str,
}

impl<'a> LeaseLifecycle<'a> {
    pub(crate) fn new(db: &'a RuntimeDb, security: &'a SecurityChecker, site_id: &'a str) -> Self {
        Self {
            db,
            security,
            site_id,
        }
    }

    pub(crate) fn acquire(&self, command: AcquireLease<'_>) -> Result<Lease, LeaseLifecycleError> {
        self.authorize_object_bound(
            command.principals,
            command.namespace,
            command.key,
            true,
            false,
        )?;

        let lease = self
            .db
            .acquire_lease(
                command.namespace,
                command.key,
                command.owner,
                command.ttl_ms,
                command.request_id,
                command.actor,
                self.site_id,
                command.now_ms,
            )
            .map_err(LeaseLifecycleError::Lease)?;

        // Re-validate object-bound targets after persistence so a concurrent
        // delete cannot leave a freshly returned active lease without a live
        // target. Best-effort release if the race is detected.
        if let Some(object_id) = object_bound_target(command.key)?
            && self
                .db
                .get_object(object_id)
                .map_err(LeaseLifecycleError::Storage)?
                .is_none()
        {
            let _ = self.db.release_lease(
                command.namespace,
                command.key,
                &lease.fencing_token,
                &format!("{}:race-cleanup", command.request_id),
                command.actor,
                self.site_id,
                command.now_ms,
            );
            return Err(LeaseLifecycleError::NotFound(format!(
                "object-bound lease target {object_id} not found"
            )));
        }

        Ok(lease)
    }

    pub(crate) fn get(&self, command: GetLease<'_>) -> Result<Lease, LeaseLifecycleError> {
        self.authorize_object_bound(
            command.principals,
            command.namespace,
            command.key,
            false,
            false,
        )?;
        self.db
            .get_lease(command.namespace, command.key)
            .map_err(LeaseLifecycleError::Lease)?
            .ok_or_else(|| LeaseLifecycleError::NotFound("lease not found".into()))
    }

    pub(crate) fn refresh(&self, command: RefreshLease<'_>) -> Result<Lease, LeaseLifecycleError> {
        self.authorize_object_bound(
            command.principals,
            command.namespace,
            command.key,
            true,
            false,
        )?;
        self.db
            .refresh_lease(
                command.namespace,
                command.key,
                command.fencing_token,
                command.ttl_ms,
                command.request_id,
                command.actor,
                self.site_id,
                command.now_ms,
            )
            .map_err(LeaseLifecycleError::Lease)
    }

    pub(crate) fn release(&self, command: ReleaseLease<'_>) -> Result<Lease, LeaseLifecycleError> {
        self.authorize_object_bound(
            command.principals,
            command.namespace,
            command.key,
            true,
            true,
        )?;
        self.db
            .release_lease(
                command.namespace,
                command.key,
                command.fencing_token,
                command.request_id,
                command.actor,
                self.site_id,
                command.now_ms,
            )
            .map_err(LeaseLifecycleError::Lease)
    }

    pub(crate) fn takeover_expired(
        &self,
        command: TakeoverExpiredLease<'_>,
    ) -> Result<Lease, LeaseLifecycleError> {
        self.authorize_object_bound(
            command.principals,
            command.namespace,
            command.key,
            true,
            false,
        )?;
        self.db
            .takeover_expired_lease(
                command.namespace,
                command.key,
                command.owner,
                command.expected_fencing_token,
                command.expected_expires_at_ms,
                command.ttl_ms,
                command.request_id,
                command.actor,
                self.site_id,
                command.now_ms,
            )
            .map_err(LeaseLifecycleError::Lease)
    }

    /// Validate that an object-bound lease guards exactly the object mutation
    /// named by the caller. Free-form lease keys can guard any mutation.
    pub(crate) fn validate_guarded_mutation(
        &self,
        command: GuardedMutationPrecondition<'_>,
    ) -> Result<(), LeaseLifecycleError> {
        let Some(bound_id) = object_bound_target(command.key)? else {
            return Ok(());
        };
        match command.target {
            GuardedMutationTarget::Create => Err(LeaseLifecycleError::InvalidArgument(
                "object-bound lease keys cannot guard object creation; use a free-form key".into(),
            )),
            GuardedMutationTarget::Object { id, .. } if id != bound_id => {
                Err(LeaseLifecycleError::FailedPrecondition(
                    "object-bound lease key must match the mutation target object id".into(),
                ))
            }
            GuardedMutationTarget::Object {
                namespace: Some(namespace),
                ..
            } if namespace != command.lease_namespace => {
                Err(LeaseLifecycleError::FailedPrecondition(
                    "object-bound lease namespace must match the mutation target object namespace"
                        .into(),
                ))
            }
            GuardedMutationTarget::Object { .. } => Ok(()),
        }
    }

    pub(crate) fn authorize_object_bound(
        &self,
        principals: &[String],
        lease_namespace: &str,
        key: &str,
        write: bool,
        allow_missing_target: bool,
    ) -> Result<(), LeaseLifecycleError> {
        let Some(object_id) = object_bound_target(key)? else {
            return Ok(());
        };
        let Some(object) = self
            .db
            .get_object(object_id)
            .map_err(LeaseLifecycleError::Storage)?
        else {
            return if allow_missing_target {
                Ok(())
            } else {
                Err(LeaseLifecycleError::NotFound(format!(
                    "object-bound lease target {object_id} not found"
                )))
            };
        };

        // ACL before namespace validation so inaccessible objects do not reveal
        // their home namespace through a distinct error.
        let principal_refs: Vec<&str> = principals.iter().map(String::as_str).collect();
        let authorized = if write {
            self.security.can_write(object_id, &principal_refs)
        } else {
            self.security.can_access(object_id, &principal_refs)
        };
        if !authorized {
            return Err(LeaseLifecycleError::PermissionDenied(if write {
                "write denied".into()
            } else {
                "access denied".into()
            }));
        }
        if object.namespace != lease_namespace {
            return Err(LeaseLifecycleError::PermissionDenied(
                "object-bound lease namespace must match the target object namespace".into(),
            ));
        }
        if !object_security_allows(self.db, &object, principals, write)? {
            return if allow_missing_target {
                Ok(())
            } else {
                Err(LeaseLifecycleError::NotFound(format!(
                    "object-bound lease target {object_id} not found"
                )))
            };
        }
        Ok(())
    }
}

fn community_principal(principals: &[String]) -> PrincipalSecurityContext {
    let subject = principals
        .first()
        .cloned()
        .unwrap_or_else(|| "anonymous".into());
    let mut ordered = principals.to_vec();
    ordered.sort();
    ordered.dedup();
    PrincipalSecurityContext {
        attributes: BTreeMap::from([
            ("credential_kind".into(), "machine".into()),
            ("issuer".into(), "sekai:community".into()),
            ("subject".into(), subject),
            ("tenant_id".into(), String::new()),
            ("x_acl_principals".into(), ordered.join(",")),
        ]),
        entitlements: BTreeSet::new(),
    }
}

fn object_security_allows(
    db: &RuntimeDb,
    object: &Object,
    principals: &[String],
    write: bool,
) -> Result<bool, LeaseLifecycleError> {
    if db
        .get_object_security_profile(&object.namespace)
        .map_err(LeaseLifecycleError::Storage)?
        .is_none()
    {
        return Ok(true);
    }
    let Some(record) = db
        .get_active_object_security_policy(&object.namespace, &object.kind)
        .map_err(LeaseLifecycleError::Storage)?
    else {
        return Ok(false);
    };
    if record.revocation.is_some() {
        return Ok(false);
    }
    let context = ObjectAuthorizationContext {
        principal: community_principal(principals),
        operation: if write {
            "update".into()
        } else {
            "read".into()
        },
    };
    evaluate_object_policy(&record.policy, &context, object)
        .map(|decision| decision.allowed)
        .map_err(LeaseLifecycleError::Storage)
}

fn object_bound_target(key: &str) -> Result<Option<&str>, LeaseLifecycleError> {
    let Some(rest) = key.strip_prefix(OBJECT_BOUND_LEASE_KEY_PREFIX) else {
        return Ok(None);
    };
    if rest.is_empty() || rest != rest.trim() || rest.chars().any(char::is_whitespace) {
        return Err(LeaseLifecycleError::InvalidArgument(
            "object-bound lease key must be exactly object:<object_id> with no whitespace".into(),
        ));
    }
    Ok(Some(rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::security::{Grant, Role};
    use std::collections::HashMap;

    fn object(id: &str, namespace: &str) -> Object {
        Object {
            id: id.into(),
            kind: "component".into(),
            name: id.into(),
            namespace: namespace.into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn acquisition_interface_owns_object_authorization_and_persistence() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(&object("target", "default"), "alice")
            .unwrap();
        let security = SecurityChecker::new();
        security.add_grant(&Grant {
            id: "grant".into(),
            object_id: "target".into(),
            principal: "alice".into(),
            role: Role::Editor,
            created: 1,
        });
        let lifecycle = LeaseLifecycle::new(&db, &security, "local");

        let denied = lifecycle.acquire(AcquireLease {
            namespace: "default",
            key: "object:target",
            owner: "bob",
            ttl_ms: 1_000,
            request_id: "bob-acquire",
            actor: "bob",
            principals: &["bob".into()],
            now_ms: 10,
        });
        assert_eq!(
            denied,
            Err(LeaseLifecycleError::PermissionDenied("write denied".into()))
        );

        let lease = lifecycle
            .acquire(AcquireLease {
                namespace: "default",
                key: "object:target",
                owner: "alice",
                ttl_ms: 1_000,
                request_id: "alice-acquire",
                actor: "alice",
                principals: &["alice".into()],
                now_ms: 10,
            })
            .unwrap();
        assert_eq!(lease.key, "object:target");
        assert_eq!(
            db.get_lease("default", "object:target").unwrap(),
            Some(lease)
        );
    }

    #[test]
    fn object_bound_lease_treats_policy_hidden_targets_as_missing() {
        let db = RuntimeDb::memory();
        let mut target = object("target", "default");
        target.properties.insert("owner".into(), "alice".into());
        db.create_object_with_audit(&target, "alice").unwrap();
        let created = db
            .create_object_security_policy(
                &crate::sekai::object_security::ObjectSecurityPolicyInput {
                    namespace: "default".into(),
                    object_kind: "component".into(),
                    revision: "lease-hidden-1".into(),
                    rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                        rule_id: "owner".into(),
                        conditions: vec![crate::sekai::object_security::PolicyCondition {
                            left: crate::sekai::object_security::PolicyOperand {
                                source: crate::sekai::object_security::OperandSource::ObjectProperty,
                                name: "owner".into(),
                                value: String::new(),
                            },
                            operator: crate::sekai::object_security::ConditionOperator::Equals,
                            right: crate::sekai::object_security::PolicyOperand {
                                source: crate::sekai::object_security::OperandSource::PrincipalAttribute,
                                name: "subject".into(),
                                value: String::new(),
                            },
                        }],
                    }],
                    policy_digest: String::new(),
                    idempotency_key: "lease-hidden-policy".into(),
                },
                "root",
                2,
            )
            .unwrap();
        let crate::sekai::object_security::ObjectSecurityWriteResult::CreatePolicy { record } =
            created
        else {
            panic!("expected created policy");
        };
        db.activate_object_security_profile(
            &crate::sekai::object_security::ActivateObjectSecurityProfile {
                namespace: "default".into(),
                expected_profile_digest: String::new(),
                bindings: vec![crate::sekai::object_security::ObjectSecurityPolicyBinding {
                    object_kind: "component".into(),
                    policy_digest: record.policy.policy_digest,
                }],
                idempotency_key: "lease-hidden-profile".into(),
            },
            &["component".into()],
            "root",
            3,
        )
        .unwrap();
        let security = SecurityChecker::new();
        for principal in ["alice", "bob"] {
            security.add_grant(&Grant {
                id: format!("grant-{principal}"),
                object_id: "target".into(),
                principal: principal.into(),
                role: Role::Editor,
                created: 1,
            });
        }
        let lifecycle = LeaseLifecycle::new(&db, &security, "local");
        let hidden = lifecycle.acquire(AcquireLease {
            namespace: "default",
            key: "object:target",
            owner: "bob",
            ttl_ms: 1_000,
            request_id: "bob-acquire",
            actor: "bob",
            principals: &["bob".into()],
            now_ms: 10,
        });
        assert_eq!(
            hidden,
            Err(LeaseLifecycleError::NotFound(
                "object-bound lease target target not found".into()
            ))
        );
        lifecycle
            .acquire(AcquireLease {
                namespace: "default",
                key: "object:target",
                owner: "alice",
                ttl_ms: 1_000,
                request_id: "alice-acquire",
                actor: "alice",
                principals: &["alice".into()],
                now_ms: 11,
            })
            .unwrap();
    }

    #[test]
    fn guarded_mutation_interface_owns_object_binding_rules() {
        let db = RuntimeDb::memory();
        let security = SecurityChecker::new();
        let lifecycle = LeaseLifecycle::new(&db, &security, "local");

        let validate = |key, target| {
            lifecycle.validate_guarded_mutation(GuardedMutationPrecondition {
                key,
                lease_namespace: "default",
                target,
            })
        };

        assert_eq!(validate("free-form", GuardedMutationTarget::Create), Ok(()));
        assert!(matches!(
            validate(
                "object: target",
                GuardedMutationTarget::Object {
                    id: "target",
                    namespace: Some("default")
                }
            ),
            Err(LeaseLifecycleError::InvalidArgument(_))
        ));
        assert!(matches!(
            validate("object:target", GuardedMutationTarget::Create),
            Err(LeaseLifecycleError::InvalidArgument(_))
        ));
        assert!(matches!(
            validate(
                "object:target",
                GuardedMutationTarget::Object {
                    id: "other",
                    namespace: Some("default")
                }
            ),
            Err(LeaseLifecycleError::FailedPrecondition(_))
        ));
        assert!(matches!(
            validate(
                "object:target",
                GuardedMutationTarget::Object {
                    id: "target",
                    namespace: Some("other")
                }
            ),
            Err(LeaseLifecycleError::FailedPrecondition(_))
        ));
        assert_eq!(
            validate(
                "object:target",
                GuardedMutationTarget::Object {
                    id: "target",
                    namespace: Some("default")
                }
            ),
            Ok(())
        );
    }
}
