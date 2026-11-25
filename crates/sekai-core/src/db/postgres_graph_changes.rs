//! PostgreSQL apply of a graph change batch (#3062).
//!
//! Lock order follows `lock_object_lifecycle`: every touched object in id
//! order, then the namespace policy generation, then the Action instance row.
//! A unique violation on the request row means a concurrent call with the same
//! `request_id` or Action instance committed first; the transaction rolls back
//! and the stored row decides replay, conflict, or already applied.

use postgres::error::SqlState;

use crate::db::postgres::PostgresDb;
use crate::db::postgres_audit::{
    OBJECT_COLUMNS, insert_created_object_in, lock_object_lifecycles,
    require_postgres_policy_generation, row_to_object, update_object_in,
};
use crate::db::postgres_objects::insert_link_within_maximum;
use crate::domain::Object;
use crate::sekai::graph_changes::{
    GraphChangeBatch, GraphChangeError, GraphChangeOutcome, InstanceRefusal, PlannedGraphChange,
    StoredGraphChangeRequest, decode_receipt, encode_receipt, instance_refusal, map_write_error,
    replay_stored, touched_object_ids,
};

fn store(error: impl ToString) -> GraphChangeError {
    GraphChangeError::Store(error.to_string())
}

impl PostgresDb {
    pub fn get_graph_change_request(
        &self,
        namespace: &str,
        request_id: &str,
    ) -> Result<Option<StoredGraphChangeRequest>, GraphChangeError> {
        let mut connection = self.connection().map_err(store)?;
        stored_request(&mut connection, namespace, request_id)
    }

    /// Commits `batch` in one transaction, or replays the stored result of
    /// the same request.
    pub fn apply_graph_changes(
        &self,
        batch: &GraphChangeBatch,
    ) -> Result<GraphChangeOutcome, GraphChangeError> {
        let mut connection = self.connection().map_err(store)?;
        if let Some(outcome) = replay_stored(
            stored_request(&mut connection, &batch.namespace, &batch.request_id)?,
            &batch.request_digest,
        )? {
            return Ok(outcome);
        }
        match apply_in_transaction(&mut connection, batch) {
            Err(Conflict::Unique) => {
                match replay_stored(
                    stored_request(&mut connection, &batch.namespace, &batch.request_id)?,
                    &batch.request_digest,
                )? {
                    Some(outcome) => Ok(outcome),
                    None => Err(GraphChangeError::Instance(InstanceRefusal::AlreadyApplied)),
                }
            }
            Err(Conflict::Refused(error)) => Err(error),
            Ok(()) => Ok(GraphChangeOutcome::Applied(batch.receipt.clone())),
        }
    }
}

enum Conflict {
    /// A request row with the same key or Action instance committed first.
    Unique,
    Refused(GraphChangeError),
}

impl From<GraphChangeError> for Conflict {
    fn from(error: GraphChangeError) -> Self {
        Self::Refused(error)
    }
}

fn stored_request(
    client: &mut postgres::Client,
    namespace: &str,
    request_id: &str,
) -> Result<Option<StoredGraphChangeRequest>, GraphChangeError> {
    client
        .query_opt(
            "SELECT request_digest, receipt_json FROM sekai_graph_change_requests
             WHERE namespace = $1 AND request_id = $2",
            &[&namespace, &request_id],
        )
        .map_err(store)?
        .map(|row| {
            Ok(StoredGraphChangeRequest {
                request_digest: row.get(0),
                receipt: decode_receipt(&row.get::<_, String>(1))?,
            })
        })
        .transpose()
}

fn apply_in_transaction(
    connection: &mut postgres::Client,
    batch: &GraphChangeBatch,
) -> Result<(), Conflict> {
    let mut transaction = connection.transaction().map_err(store)?;
    lock_object_lifecycles(&mut transaction, touched_object_ids(&batch.changes)).map_err(store)?;
    require_postgres_policy_generation(
        &mut transaction,
        &batch.namespace,
        Some(&batch.policy_generation),
    )
    .map_err(|error| {
        if error == crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION {
            GraphChangeError::PolicyChanged
        } else {
            GraphChangeError::Store(error)
        }
    })?;
    if !batch.action_instance_id.is_empty() {
        require_applicable_instance(&mut transaction, batch)?;
    }
    for change in &batch.changes {
        apply_change(&mut transaction, batch, change)?;
    }
    let receipt_json = encode_receipt(&batch.receipt)?;
    if let Err(error) = transaction.execute(
        "INSERT INTO sekai_graph_change_requests
         (namespace, request_id, request_digest, action_instance_id, actor, receipt_json, created_at_ms)
         VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7)",
        &[
            &batch.namespace,
            &batch.request_id,
            &batch.request_digest,
            &batch.action_instance_id,
            &batch.actor,
            &receipt_json,
            &batch.now_ms,
        ],
    ) {
        return Err(if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
            Conflict::Unique
        } else {
            Conflict::Refused(store(error))
        });
    }
    transaction.commit().map_err(store)?;
    Ok(())
}

fn require_applicable_instance(
    transaction: &mut postgres::Transaction<'_>,
    batch: &GraphChangeBatch,
) -> Result<(), GraphChangeError> {
    let row = transaction
        .query_opt(
            "SELECT namespace, principal, status FROM sekai_action_instances
             WHERE instance_id = $1 FOR SHARE",
            &[&batch.action_instance_id],
        )
        .map_err(store)?
        .map(|row| (row.get(0), row.get(1), row.get(2)));
    if let Some(refusal) = instance_refusal(row, &batch.namespace, &batch.actor) {
        return Err(GraphChangeError::Instance(refusal));
    }
    let applied: bool = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM sekai_graph_change_requests WHERE action_instance_id = $1)",
            &[&batch.action_instance_id],
        )
        .map_err(store)?
        .get(0);
    if applied {
        return Err(GraphChangeError::Instance(InstanceRefusal::AlreadyApplied));
    }
    Ok(())
}

/// Fails unless each endpoint still matches the state it was authorized
/// against. Its lifecycle lock is already held.
fn require_endpoints(
    transaction: &mut postgres::Transaction<'_>,
    from: &Object,
    to: &Object,
) -> Result<(), GraphChangeError> {
    for expected in [from, to] {
        let unchanged = transaction
            .query_opt(
                &format!("SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE id = $1 FOR UPDATE"),
                &[&expected.id],
            )
            .map_err(store)?
            .map(row_to_object)
            .transpose()
            .map_err(GraphChangeError::Store)?
            .is_some_and(|stored| stored.persisted_state_matches(expected));
        if !unchanged {
            return Err(GraphChangeError::ObjectChanged(expected.id.clone()));
        }
    }
    Ok(())
}

fn apply_change(
    transaction: &mut postgres::Transaction<'_>,
    batch: &GraphChangeBatch,
    change: &PlannedGraphChange,
) -> Result<(), GraphChangeError> {
    let generation = Some(batch.policy_generation.as_str());
    match change {
        PlannedGraphChange::CreateObject(object) => {
            let exists: bool = transaction
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM sekai_objects WHERE id = $1)",
                    &[&object.id],
                )
                .map_err(store)?
                .get(0);
            if exists {
                return Err(GraphChangeError::ObjectExists(object.id.clone()));
            }
            insert_created_object_in(
                transaction,
                object,
                &batch.actor,
                generation,
                &batch.attribution,
            )
            .map_err(|error| map_write_error(&object.id, error))
        }
        PlannedGraphChange::UpdateObject { object, expected } => update_object_in(
            transaction,
            object,
            Some(expected),
            &batch.actor,
            generation,
            &batch.attribution,
        )
        .map_err(|error| map_write_error(&object.id, error))?
        .map(|_| ())
        .ok_or_else(|| GraphChangeError::ObjectChanged(object.id.clone())),
        PlannedGraphChange::CreateLink { link, from, to } => {
            require_endpoints(transaction, from, to)?;
            if insert_link_within_maximum(transaction, link).map_err(GraphChangeError::Rejected)? {
                Ok(())
            } else {
                Err(GraphChangeError::LinkExists(link.id.clone()))
            }
        }
        PlannedGraphChange::DeleteLink { link, from, to } => {
            require_endpoints(transaction, from, to)?;
            let deleted = transaction
                .execute(
                    "DELETE FROM sekai_links WHERE id = $1 AND from_id = $2 AND to_id = $3",
                    &[&link.id, &link.from_id, &link.to_id],
                )
                .map_err(store)?;
            if deleted != 1 {
                return Err(GraphChangeError::LinkMissing(link.id.clone()));
            }
            Ok(())
        }
    }
}
