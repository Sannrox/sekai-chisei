//! Object mutation persistence behind one guarded/direct seam.
//!
//! Transport adapters own protocol translation and request authentication. This
//! module owns the persistence choice so create, update, and delete admission
//! can use one interface regardless of whether a lease precondition is present.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::lease::LeaseError;

pub(crate) struct LeasePrecondition<'a> {
    pub namespace: &'a str,
    pub key: &'a str,
    pub fencing_token: &'a str,
    pub request_id: &'a str,
}

#[derive(Debug)]
pub(crate) enum MutationPersistenceError {
    Graph(String),
    Lease(LeaseError),
    NotFound,
    ChangedSinceAuthorization,
}

pub(crate) struct ObjectMutation<'a> {
    db: &'a RuntimeDb,
    lease: Option<LeasePrecondition<'a>>,
    expected_policy_generation: Option<&'a str>,
}

impl<'a> ObjectMutation<'a> {
    pub(crate) fn direct(db: &'a RuntimeDb) -> Self {
        Self {
            db,
            lease: None,
            expected_policy_generation: None,
        }
    }

    pub(crate) fn guarded(db: &'a RuntimeDb, lease: LeasePrecondition<'a>) -> Self {
        Self {
            db,
            lease: Some(lease),
            expected_policy_generation: None,
        }
    }

    pub(crate) fn with_policy_generation(mut self, generation: &'a str) -> Self {
        self.expected_policy_generation = Some(generation);
        self
    }

    pub(crate) fn replay(
        &self,
        operation: &str,
        request: &Object,
    ) -> Result<Option<Object>, MutationPersistenceError> {
        let Some(lease) = &self.lease else {
            return Ok(None);
        };
        self.db
            .guarded_object_replay(
                lease.namespace,
                lease.key,
                lease.fencing_token,
                lease.request_id,
                operation,
                &request.id,
                request,
            )
            .map_err(MutationPersistenceError::Lease)
    }

    pub(crate) fn create(
        &self,
        object: &Object,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, MutationPersistenceError> {
        if let Some(lease) = &self.lease {
            self.db
                .guarded_create_object_with_policy(
                    object,
                    lease.namespace,
                    lease.key,
                    lease.fencing_token,
                    lease.request_id,
                    actor,
                    now_ms,
                    self.expected_policy_generation,
                )
                .map_err(MutationPersistenceError::Lease)
        } else {
            self.db
                .create_object_with_authorized_policy(
                    object,
                    actor,
                    self.expected_policy_generation,
                )
                .map_err(MutationPersistenceError::Graph)?;
            Ok(object.clone())
        }
    }

    pub(crate) fn update(
        &self,
        object: &Object,
        request: &Object,
        expected: Option<&Object>,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, MutationPersistenceError> {
        if let Some(lease) = &self.lease {
            self.db
                .guarded_update_object_with_policy(
                    object,
                    request,
                    expected,
                    lease.namespace,
                    lease.key,
                    lease.fencing_token,
                    lease.request_id,
                    actor,
                    now_ms,
                    self.expected_policy_generation,
                )
                .map_err(MutationPersistenceError::Lease)
        } else {
            match self.db.update_object_with_authorized_snapshot(
                object,
                expected,
                actor,
                self.expected_policy_generation,
            ) {
                Ok(Some(_)) => Ok(object.clone()),
                Ok(None) => Err(MutationPersistenceError::NotFound),
                Err(error) if error == crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION => {
                    Err(MutationPersistenceError::ChangedSinceAuthorization)
                }
                Err(error) => Err(MutationPersistenceError::Graph(error)),
            }
        }
    }

    pub(crate) fn delete(
        &self,
        id: &str,
        expected: Option<&Object>,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), MutationPersistenceError> {
        if let Some(lease) = &self.lease {
            self.db
                .guarded_delete_object_with_policy(
                    id,
                    expected,
                    lease.namespace,
                    lease.key,
                    lease.fencing_token,
                    lease.request_id,
                    actor,
                    now_ms,
                    self.expected_policy_generation,
                )
                .map_err(MutationPersistenceError::Lease)
        } else {
            match self.db.delete_object_with_authorized_snapshot(
                id,
                expected,
                actor,
                self.expected_policy_generation,
            ) {
                Ok(None) if expected.is_some() => Err(MutationPersistenceError::NotFound),
                Ok(_) => Ok(()),
                Err(error) if error == crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION => {
                    Err(MutationPersistenceError::ChangedSinceAuthorization)
                }
                Err(error) => Err(MutationPersistenceError::Graph(error)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn object(id: &str) -> Object {
        Object {
            id: id.into(),
            kind: "test".into(),
            name: id.into(),
            namespace: "default".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn direct_interface_owns_create_update_delete_persistence() {
        let db = RuntimeDb::memory();
        let mutation = ObjectMutation::direct(&db);
        let mut value = object("one");

        assert_eq!(mutation.create(&value, "actor", 1).unwrap().id, value.id);
        value.name = "updated".into();
        assert_eq!(
            mutation
                .update(
                    &value,
                    &value,
                    db.get_object("one").unwrap().as_ref(),
                    "actor",
                    2
                )
                .unwrap()
                .name,
            "updated"
        );
        mutation
            .delete("one", db.get_object("one").unwrap().as_ref(), "actor", 3)
            .unwrap();
        assert!(db.get_object("one").unwrap().is_none());
    }

    #[test]
    fn direct_update_preserves_missing_object_error() {
        let db = RuntimeDb::memory();
        let value = object("missing");
        assert!(matches!(
            ObjectMutation::direct(&db).update(&value, &value, None, "actor", 1),
            Err(MutationPersistenceError::NotFound)
        ));
    }
}
