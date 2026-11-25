//! All-or-nothing apply of a client's graph changes (#3062).
//!
//! A caller computes object creates, property patches, link creates and link
//! deletes; the plane authorizes each one as the matching single-record RPC
//! would, then commits them in one store transaction. Every change is fenced
//! on the object state it was authorized against, so a concurrent write fails
//! the whole call. A `(namespace, request_id)` row written in the same
//! transaction makes the call replayable, and its unique `action_instance_id`
//! makes an Action instance applicable once. Which records an Action changes
//! stays with the client.

use crate::db::sekai::SekaiDb;
use crate::domain::{Link, Object};
use rusqlite::{OptionalExtension, params};
use sekai_types::object_change::ChangeAttribution;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Most changes one call may carry.
pub const MAX_GRAPH_CHANGES: usize = 256;
/// Longest accepted `request_id`.
pub const MAX_REQUEST_ID_LEN: usize = 256;

/// One change as the caller sent it, in a canonical form for the request
/// digest: maps sorted, defaults not yet filled in.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum GraphChangeInput {
    CreateObject {
        id: String,
        kind: String,
        name: String,
        namespace: String,
        external_id: String,
        properties: BTreeMap<String, String>,
        created: i64,
        updated: i64,
    },
    PatchObject {
        object_id: String,
        expected_revision: String,
        set: BTreeMap<String, String>,
        remove: Vec<String>,
    },
    CreateLink {
        id: String,
        from_id: String,
        to_id: String,
        relation: String,
        created: i64,
    },
    DeleteLink {
        id: String,
    },
}

/// Digest that binds a `request_id` to one caller and one body. A replay
/// must match it exactly; anything else under the same id is a conflict.
pub fn request_digest(
    actor: &str,
    namespace: &str,
    action_instance_id: &str,
    changes: &[GraphChangeInput],
) -> Result<String, String> {
    let body = serde_json::to_vec(&serde_json::json!({
        "actor": actor,
        "namespace": namespace,
        "action_instance_id": action_instance_id,
        "changes": changes,
    }))
    .map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(body)))
}

/// One authorized change, with the stored state it was authorized against.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PlannedGraphChange {
    CreateObject(Object),
    UpdateObject {
        object: Object,
        expected: Object,
    },
    CreateLink {
        link: Link,
        from: Object,
        to: Object,
    },
    DeleteLink {
        link: Link,
        from: Object,
        to: Object,
    },
}

/// What a call wrote: the id of each created or patched object and each
/// created link, in change order. Stored with the request for replay; the
/// plane re-reads the objects through the caller's view when it answers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphChangeReceipt {
    pub object_ids: Vec<String>,
    pub links: Vec<Link>,
}

/// A call ready to commit.
#[derive(Debug, Clone)]
pub struct GraphChangeBatch {
    pub namespace: String,
    pub request_id: String,
    pub request_digest: String,
    pub actor: String,
    /// Empty when the call is not bound to an Action instance.
    pub action_instance_id: String,
    /// The namespace's object security generation at authorization.
    pub policy_generation: String,
    pub attribution: ChangeAttribution,
    pub changes: Vec<PlannedGraphChange>,
    pub receipt: GraphChangeReceipt,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum GraphChangeOutcome {
    Applied(GraphChangeReceipt),
    /// The stored result of an earlier call with the same id and body.
    Replayed(GraphChangeReceipt),
}

/// A stored request: its digest and receipt.
#[derive(Debug, Clone)]
pub struct StoredGraphChangeRequest {
    pub request_digest: String,
    pub receipt: GraphChangeReceipt,
}

/// Why an instance-bound call may not apply. One reason covers a missing
/// instance, another namespace and another submitter, so a caller learns
/// nothing about instances it did not submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstanceRefusal {
    NotAdmittedHere,
    Denied,
    Parked,
    AlreadyApplied,
}

impl InstanceRefusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotAdmittedHere => {
                "action instance is not admitted for this caller in this namespace"
            }
            Self::Denied => "action instance was denied",
            Self::Parked => "action instance is waiting for approval",
            Self::AlreadyApplied => "action instance was already applied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GraphChangeError {
    /// The `request_id` is bound to a different body.
    RequestConflict,
    /// The object changed since it was read or authorized.
    ObjectChanged(String),
    ObjectExists(String),
    LinkExists(String),
    LinkMissing(String),
    /// The namespace's object security policy changed since authorization.
    PolicyChanged,
    Instance(InstanceRefusal),
    /// A store rule refused a change, such as a relation maximum.
    Rejected(String),
    Store(String),
}

const SQLITE_DDL: &str = "CREATE TABLE IF NOT EXISTS sekai_graph_change_requests (
    namespace TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    action_instance_id TEXT UNIQUE,
    actor TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, request_id)
)";

pub(crate) fn encode_receipt(receipt: &GraphChangeReceipt) -> Result<String, GraphChangeError> {
    serde_json::to_string(receipt).map_err(|error| GraphChangeError::Store(error.to_string()))
}

pub(crate) fn decode_receipt(raw: &str) -> Result<GraphChangeReceipt, GraphChangeError> {
    serde_json::from_str(raw)
        .map_err(|error| GraphChangeError::Store(format!("corrupt graph change receipt: {error}")))
}

/// Replay or conflict for a stored request, `None` when there is none.
pub fn replay_stored(
    stored: Option<StoredGraphChangeRequest>,
    request_digest: &str,
) -> Result<Option<GraphChangeOutcome>, GraphChangeError> {
    match stored {
        None => Ok(None),
        Some(stored) if stored.request_digest == request_digest => {
            Ok(Some(GraphChangeOutcome::Replayed(stored.receipt)))
        }
        Some(_) => Err(GraphChangeError::RequestConflict),
    }
}

/// Refusal for an instance row `(namespace, principal, status)`, if any.
pub fn instance_refusal(
    row: Option<(String, String, String)>,
    namespace: &str,
    actor: &str,
) -> Option<InstanceRefusal> {
    use crate::sekai::action_instance::{STATUS_ADMITTED, STATUS_DENIED, STATUS_PARKED};
    let Some((row_namespace, principal, status)) = row else {
        return Some(InstanceRefusal::NotAdmittedHere);
    };
    if row_namespace != namespace || principal != actor {
        return Some(InstanceRefusal::NotAdmittedHere);
    }
    match status.as_str() {
        STATUS_ADMITTED => None,
        STATUS_DENIED => Some(InstanceRefusal::Denied),
        STATUS_PARKED => Some(InstanceRefusal::Parked),
        _ => Some(InstanceRefusal::NotAdmittedHere),
    }
}

/// Maps a store error from an object or link write to the change it belongs to.
pub(crate) fn map_write_error(object_id: &str, error: String) -> GraphChangeError {
    if error == crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION {
        GraphChangeError::ObjectChanged(object_id.to_string())
    } else {
        GraphChangeError::Rejected(error)
    }
}

/// Every object id the batch writes or links, for ordered locking.
pub(crate) fn touched_object_ids(changes: &[PlannedGraphChange]) -> Vec<&str> {
    changes
        .iter()
        .flat_map(|change| match change {
            PlannedGraphChange::CreateObject(object)
            | PlannedGraphChange::UpdateObject { object, .. } => vec![object.id.as_str()],
            PlannedGraphChange::CreateLink { from, to, .. }
            | PlannedGraphChange::DeleteLink { from, to, .. } => {
                vec![from.id.as_str(), to.id.as_str()]
            }
        })
        .collect()
}

impl SekaiDb {
    fn migrate_graph_change_requests(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(SQLITE_DDL)
            .map_err(|error| error.to_string())
    }

    pub fn get_graph_change_request(
        &self,
        namespace: &str,
        request_id: &str,
    ) -> Result<Option<StoredGraphChangeRequest>, GraphChangeError> {
        self.migrate_graph_change_requests()
            .map_err(GraphChangeError::Store)?;
        sqlite_stored_request(&self.conn(), namespace, request_id)
    }

    /// Commits `batch` in one IMMEDIATE transaction, or replays the stored
    /// result of the same request.
    pub fn apply_graph_changes(
        &self,
        batch: &GraphChangeBatch,
    ) -> Result<GraphChangeOutcome, GraphChangeError> {
        self.migrate_graph_change_requests()
            .map_err(GraphChangeError::Store)?;
        self.migrate_action_instances()
            .map_err(GraphChangeError::Store)?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| GraphChangeError::Store(error.to_string()))?;
        if let Some(outcome) = replay_stored(
            sqlite_stored_request(&tx, &batch.namespace, &batch.request_id)?,
            &batch.request_digest,
        )? {
            return Ok(outcome);
        }
        if !batch.action_instance_id.is_empty() {
            sqlite_require_applicable_instance(&tx, batch)?;
        }
        crate::sekai::audit::require_sqlite_policy_generation(
            &tx,
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
        for change in &batch.changes {
            sqlite_apply_change(&tx, batch, change)?;
        }
        tx.execute(
            "INSERT INTO sekai_graph_change_requests
             (namespace, request_id, request_digest, action_instance_id, actor, receipt_json, created_at_ms)
             VALUES (?1, ?2, ?3, NULLIF(?4, ''), ?5, ?6, ?7)",
            params![
                batch.namespace,
                batch.request_id,
                batch.request_digest,
                batch.action_instance_id,
                batch.actor,
                encode_receipt(&batch.receipt)?,
                batch.now_ms
            ],
        )
        .map_err(|error| GraphChangeError::Store(error.to_string()))?;
        tx.commit()
            .map_err(|error| GraphChangeError::Store(error.to_string()))?;
        Ok(GraphChangeOutcome::Applied(batch.receipt.clone()))
    }
}

fn sqlite_stored_request(
    conn: &rusqlite::Connection,
    namespace: &str,
    request_id: &str,
) -> Result<Option<StoredGraphChangeRequest>, GraphChangeError> {
    let row = conn
        .query_row(
            "SELECT request_digest, receipt_json FROM sekai_graph_change_requests
             WHERE namespace = ?1 AND request_id = ?2",
            params![namespace, request_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| GraphChangeError::Store(error.to_string()))?;
    row.map(|(request_digest, raw)| {
        Ok(StoredGraphChangeRequest {
            request_digest,
            receipt: decode_receipt(&raw)?,
        })
    })
    .transpose()
}

fn sqlite_require_applicable_instance(
    tx: &rusqlite::Transaction<'_>,
    batch: &GraphChangeBatch,
) -> Result<(), GraphChangeError> {
    let row = tx
        .query_row(
            "SELECT namespace, principal, status FROM sekai_action_instances WHERE instance_id = ?1",
            params![batch.action_instance_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| GraphChangeError::Store(error.to_string()))?;
    if let Some(refusal) = instance_refusal(row, &batch.namespace, &batch.actor) {
        return Err(GraphChangeError::Instance(refusal));
    }
    let applied = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sekai_graph_change_requests WHERE action_instance_id = ?1)",
            params![batch.action_instance_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| GraphChangeError::Store(error.to_string()))?;
    if applied {
        return Err(GraphChangeError::Instance(InstanceRefusal::AlreadyApplied));
    }
    Ok(())
}

fn sqlite_object(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
) -> Result<Option<Object>, GraphChangeError> {
    tx.query_row(
        "SELECT id, kind, name, namespace, external_id, properties, created, updated
         FROM sekai_objects WHERE id = ?1",
        params![id],
        crate::db::sekai::row_to_object,
    )
    .optional()
    .map_err(|error| GraphChangeError::Store(error.to_string()))
}

fn sqlite_require_endpoints(
    tx: &rusqlite::Transaction<'_>,
    from: &Object,
    to: &Object,
) -> Result<(), GraphChangeError> {
    for expected in [from, to] {
        let unchanged = sqlite_object(tx, &expected.id)?
            .is_some_and(|stored| stored.persisted_state_matches(expected));
        if !unchanged {
            return Err(GraphChangeError::ObjectChanged(expected.id.clone()));
        }
    }
    Ok(())
}

fn sqlite_apply_change(
    tx: &rusqlite::Transaction<'_>,
    batch: &GraphChangeBatch,
    change: &PlannedGraphChange,
) -> Result<(), GraphChangeError> {
    let generation = Some(batch.policy_generation.as_str());
    match change {
        PlannedGraphChange::CreateObject(object) => {
            if sqlite_object(tx, &object.id)?.is_some() {
                return Err(GraphChangeError::ObjectExists(object.id.clone()));
            }
            crate::sekai::audit::insert_created_object_in(
                tx,
                object,
                &batch.actor,
                generation,
                &batch.attribution,
            )
            .map_err(|error| map_write_error(&object.id, error))
        }
        PlannedGraphChange::UpdateObject { object, expected } => {
            crate::sekai::audit::update_object_in(
                tx,
                object,
                Some(expected),
                &batch.actor,
                generation,
                &batch.attribution,
            )
            .map_err(|error| map_write_error(&object.id, error))?
            .map(|_| ())
            .ok_or_else(|| GraphChangeError::ObjectChanged(object.id.clone()))
        }
        PlannedGraphChange::CreateLink { link, from, to } => {
            sqlite_require_endpoints(tx, from, to)?;
            let exists = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sekai_links WHERE id = ?1)",
                    params![link.id],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|error| GraphChangeError::Store(error.to_string()))?;
            if exists {
                return Err(GraphChangeError::LinkExists(link.id.clone()));
            }
            crate::sekai::ontology::validate_link_constraint(
                tx,
                &link.from_id,
                &link.to_id,
                &link.relation,
            )
            .map_err(GraphChangeError::Rejected)?;
            tx.execute(
                "INSERT INTO sekai_links (id, from_id, to_id, relation, created) VALUES (?1,?2,?3,?4,?5)",
                params![link.id, link.from_id, link.to_id, link.relation, link.created],
            )
            .map(|_| ())
            .map_err(|error| GraphChangeError::Store(error.to_string()))
        }
        PlannedGraphChange::DeleteLink { link, from, to } => {
            sqlite_require_endpoints(tx, from, to)?;
            let deleted = tx
                .execute(
                    "DELETE FROM sekai_links WHERE id = ?1 AND from_id = ?2 AND to_id = ?3",
                    params![link.id, link.from_id, link.to_id],
                )
                .map_err(|error| GraphChangeError::Store(error.to_string()))?;
            if deleted != 1 {
                return Err(GraphChangeError::LinkMissing(link.id.clone()));
            }
            Ok(())
        }
    }
}
