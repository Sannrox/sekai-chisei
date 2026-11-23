//! Object mutation persistence behind one guarded/direct seam.
//!
//! Transport adapters own protocol translation and request authentication. This
//! module owns the persistence choice so create, update, and delete admission
//! can use one interface regardless of whether a lease precondition is present.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::audit::ChangeAttribution;
use crate::sekai::lease::LeaseError;

pub struct LeasePrecondition<'a> {
    pub namespace: &'a str,
    pub key: &'a str,
    pub fencing_token: &'a str,
    pub request_id: &'a str,
}

#[derive(Debug)]
pub enum MutationPersistenceError {
    Graph(String),
    Lease(LeaseError),
    NotFound,
    ChangedSinceAuthorization,
}

pub struct ObjectMutation<'a> {
    db: &'a RuntimeDb,
    lease: Option<LeasePrecondition<'a>>,
    expected_policy_generation: Option<&'a str>,
}

impl<'a> ObjectMutation<'a> {
    pub fn direct(db: &'a RuntimeDb) -> Self {
        Self {
            db,
            lease: None,
            expected_policy_generation: None,
        }
    }

    pub fn guarded(db: &'a RuntimeDb, lease: LeasePrecondition<'a>) -> Self {
        Self {
            db,
            lease: Some(lease),
            expected_policy_generation: None,
        }
    }

    pub fn with_policy_generation(mut self, generation: &'a str) -> Self {
        self.expected_policy_generation = Some(generation);
        self
    }

    pub fn replay(
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

    pub fn create(
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
                .create_object_attributed(
                    object,
                    actor,
                    self.expected_policy_generation,
                    &ChangeAttribution::direct(),
                )
                .map_err(MutationPersistenceError::Graph)?;
            Ok(object.clone())
        }
    }

    /// Reverse a create made through this handle when a follow-up write that
    /// belongs to it fails. Removes the object, its audit rows, and, when
    /// guarded, the replay row so a retry of the request runs again.
    pub fn abort_create(&self, id: &str) -> Result<(), String> {
        self.db.abort_object_create(id, self.lease.as_ref())
    }

    pub fn update(
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
            match self.db.update_object_attributed(
                object,
                expected,
                actor,
                self.expected_policy_generation,
                &ChangeAttribution::direct(),
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

    pub fn delete(
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
            match self.db.delete_object_attributed(
                id,
                expected,
                actor,
                self.expected_policy_generation,
                &ChangeAttribution::direct(),
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

    /// A reversed guarded create leaves nothing behind, so the same request
    /// runs again; a create that was changed afterwards is not reversed.
    fn abort_create_reverses_a_guarded_create(db: &RuntimeDb) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let lease = db
            .acquire_lease(
                "default", "profiles", "actor", 60_000, "acquire", "actor", "local", now,
            )
            .unwrap();
        let mutation = ObjectMutation::guarded(
            db,
            LeasePrecondition {
                namespace: "default",
                key: "profiles",
                fencing_token: &lease.fencing_token,
                request_id: "create",
            },
        );
        let value = object("one");
        mutation.create(&value, "actor", now).unwrap();
        mutation.abort_create("one").unwrap();
        assert!(db.get_object("one").unwrap().is_none());
        assert!(mutation.replay("create", &value).unwrap().is_none());
        mutation.create(&value, "actor", now).unwrap();
        assert!(db.get_object("one").unwrap().is_some());

        let mut touched = db.get_object("one").unwrap().unwrap();
        touched.updated += 1;
        ObjectMutation::direct(db)
            .update(
                &touched,
                &touched,
                db.get_object("one").unwrap().as_ref(),
                "actor",
                now,
            )
            .unwrap();
        let error = mutation.abort_create("one").unwrap_err();
        assert!(error.contains("one"), "{error}");
        assert!(db.get_object("one").unwrap().is_some());
    }

    #[test]
    fn sqlite_abort_create_reverses_a_guarded_create() {
        abort_create_reverses_a_guarded_create(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_abort_create_reverses_a_guarded_create() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        abort_create_reverses_a_guarded_create(&RuntimeDb::Postgres(std::sync::Arc::new(
            scratch.connect(),
        )));
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
