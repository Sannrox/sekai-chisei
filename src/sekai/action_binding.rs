//! Plane-owned automation bindings from object changes to governed Actions
//! (#1092, ADR 0090).
//!
//! A binding maps authorized object-change events for one namespace and kind
//! onto one pinned `GovernedActionType` through a closed parameter mapping.
//! It runs as an explicit service principal whose grants, policy, budget, and
//! schema are checked on every submit. The subscription itself never carries
//! authority. Idempotency comes from the binding revision and the delivered
//! event, so a redelivered page admits nothing new.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::sekai::SekaiDb;
use crate::domain::{Object, PropertyFilter};
use crate::sekai::object_change_subscription::{
    MAX_PROPERTY_FILTERS, OP_CREATE, OP_DELETE, OP_UPDATE, ObjectChangeEvent,
};

pub const ACTION_BINDING_CONTRACT: &str = "sekai.action-binding/v1";
pub const MAX_BINDING_PARAMETERS: usize = 16;
/// A mapped source the service principal cannot read, or an event that
/// carries no object for it, skips the event instead of submitting.
pub const SKIP_SOURCE_UNAVAILABLE: &str = "parameter_source_unavailable";

/// Where one Action parameter comes from. Closed: no expressions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", content = "value", rename_all = "snake_case")]
pub enum ParameterSource {
    /// The changed object's id.
    ObjectId,
    /// The event operation: `create`, `update`, or `delete`.
    EventOp,
    /// The changed field named by the event, or empty.
    EventField,
    /// A property of the changed object, read as the service principal.
    Property(String),
    /// A fixed string.
    Constant(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionBinding {
    pub contract_version: String,
    pub binding_id: String,
    pub namespace: String,
    /// Object kind whose changes trigger the binding.
    pub kind: String,
    #[serde(default)]
    pub property_filters: Vec<PropertyFilter>,
    /// Event operations that submit: a subset of create, update, delete.
    pub ops: Vec<String>,
    pub type_id: String,
    /// Pinned `GovernedActionType` version.
    pub version: String,
    /// Service principal the binding submits as.
    pub run_as: String,
    pub parameters: BTreeMap<String, ParameterSource>,
    pub enabled: bool,
    /// Increments on every install; part of the idempotency key.
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub updated_at_ms: i64,
}

impl ActionBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != ACTION_BINDING_CONTRACT {
            return Err(format!(
                "contract_version must be {ACTION_BINDING_CONTRACT}"
            ));
        }
        for (field, value) in [
            ("binding_id", &self.binding_id),
            ("namespace", &self.namespace),
            ("kind", &self.kind),
            ("type_id", &self.type_id),
            ("version", &self.version),
            ("run_as", &self.run_as),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
                return Err(format!("{field} must be non-empty without whitespace"));
            }
        }
        if self.property_filters.len() > MAX_PROPERTY_FILTERS {
            return Err(format!(
                "at most {MAX_PROPERTY_FILTERS} property filters are allowed"
            ));
        }
        if self.ops.is_empty() {
            return Err("ops must name at least one of create, update, delete".into());
        }
        for op in &self.ops {
            if ![OP_CREATE, OP_UPDATE, OP_DELETE].contains(&op.as_str()) {
                return Err(format!("unsupported op {op:?}"));
            }
        }
        if self.parameters.len() > MAX_BINDING_PARAMETERS {
            return Err(format!(
                "at most {MAX_BINDING_PARAMETERS} mapped parameters are allowed"
            ));
        }
        for (name, source) in &self.parameters {
            if name.trim().is_empty() || name.chars().any(char::is_whitespace) {
                return Err("parameter names must be non-empty without whitespace".into());
            }
            if let ParameterSource::Property(property) = source {
                if !crate::domain::is_valid_property_key(property) {
                    return Err(format!("invalid property source {property:?}"));
                }
                if self.ops.iter().any(|op| op == OP_DELETE) {
                    return Err(
                        "a binding that fires on delete cannot map object properties".into(),
                    );
                }
            }
        }
        Ok(())
    }

    /// Stable per binding revision and delivered event, so a redelivered or
    /// replayed page never admits a second instance.
    pub fn idempotency_key(&self, event: &ObjectChangeEvent) -> Result<String, String> {
        Ok(format!(
            "binding-{}",
            crate::shomei::digest_serializable(&(
                &self.binding_id,
                self.revision,
                &event.event_id,
                event.offset,
            ))?
        ))
    }

    /// Builds parameters for one event. `object` is the changed object as the
    /// service principal sees it: hidden properties are already absent, so a
    /// mapping that needs one skips the event instead of submitting.
    pub fn parameters_for(
        &self,
        event: &ObjectChangeEvent,
        object: Option<&Object>,
    ) -> Result<String, &'static str> {
        let mut parameters = serde_json::Map::new();
        for (name, source) in &self.parameters {
            let value = match source {
                ParameterSource::ObjectId => event.object_id.clone(),
                ParameterSource::EventOp => event.op.clone(),
                ParameterSource::EventField => event.field.clone(),
                ParameterSource::Constant(value) => value.clone(),
                ParameterSource::Property(property) => object
                    .and_then(|object| object.properties.get(property))
                    .cloned()
                    .ok_or(SKIP_SOURCE_UNAVAILABLE)?,
            };
            parameters.insert(name.clone(), serde_json::Value::String(value));
        }
        Ok(serde_json::Value::Object(parameters).to_string())
    }
}

/// Delivery state the plane keeps per binding between runs.
///
/// Reading a subscription page commits its cursor, so the events of a page
/// are persisted here before any is submitted and cleared after. A run that
/// finds pending events finishes them first; idempotency keys make those
/// resubmits replays, so a crash mid-page neither loses nor repeats work.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionBindingCursor {
    pub snapshot_revision: String,
    pub last_page_digest: String,
    pub pending_events: Vec<ObjectChangeEvent>,
    /// The subscription as it stood before an in-flight read. Present only
    /// between reading a page and persisting its events: a run that finds it
    /// restores the subscription to it, so the page is delivered again
    /// instead of lost.
    pub read_marker: Option<crate::sekai::event_subscription::EventSubscription>,
}

impl SekaiDb {
    fn migrate_action_bindings(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_action_bindings (
                    namespace TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    body_json TEXT NOT NULL,
                    snapshot_revision TEXT NOT NULL DEFAULT '',
                    last_page_digest TEXT NOT NULL DEFAULT '',
                    pending_events_json TEXT NOT NULL DEFAULT '[]',
                    read_marker_json TEXT NOT NULL DEFAULT '',
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (namespace, binding_id)
                );",
            )
            .map_err(|error| error.to_string())
    }

    /// Installs or replaces a binding. A new revision restarts delivery from
    /// a fresh snapshot, so events are never admitted under a stale mapping.
    pub fn put_action_binding(
        &self,
        binding: &ActionBinding,
        actor: &str,
        now_ms: i64,
    ) -> Result<ActionBinding, String> {
        binding.validate()?;
        self.migrate_action_bindings()?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let previous: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM sekai_action_bindings WHERE namespace = ?1 AND binding_id = ?2",
                params![binding.namespace, binding.binding_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let mut stored = binding.clone();
        stored.revision = previous.map_or(1, |revision| revision as u64 + 1);
        stored.created_by = actor.to_string();
        stored.updated_at_ms = now_ms;
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO sekai_action_bindings
                    (namespace, binding_id, revision, body_json, snapshot_revision,
                     last_page_digest, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, '', '', ?5)
                 ON CONFLICT(namespace, binding_id) DO UPDATE SET
                    revision = excluded.revision,
                    body_json = excluded.body_json,
                    snapshot_revision = '',
                    last_page_digest = '',
                    pending_events_json = '[]',
                    read_marker_json = '',
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    stored.namespace,
                    stored.binding_id,
                    stored.revision as i64,
                    body,
                    now_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }

    pub fn get_action_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Option<(ActionBinding, ActionBindingCursor)>, String> {
        self.migrate_action_bindings()?;
        self.conn()
            .query_row(
                "SELECT body_json, snapshot_revision, last_page_digest, pending_events_json,
                        read_marker_json
                 FROM sekai_action_bindings WHERE namespace = ?1 AND binding_id = ?2",
                params![namespace, binding_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(
                |(body, snapshot_revision, last_page_digest, pending, marker)| {
                    let binding: ActionBinding = serde_json::from_str(&body)
                        .map_err(|error| format!("corrupt action binding: {error}"))?;
                    let pending_events = serde_json::from_str(&pending)
                        .map_err(|error| format!("corrupt action binding cursor: {error}"))?;
                    let read_marker =
                        if marker.is_empty() {
                            None
                        } else {
                            Some(serde_json::from_str(&marker).map_err(|error| {
                                format!("corrupt action binding cursor: {error}")
                            })?)
                        };
                    Ok((
                        binding,
                        ActionBindingCursor {
                            snapshot_revision,
                            last_page_digest,
                            pending_events,
                            read_marker,
                        },
                    ))
                },
            )
            .transpose()
    }

    /// Advances delivery state only for the revision that read the page, so a
    /// reinstall during a run cannot inherit the old cursor.
    pub fn advance_action_binding_cursor(
        &self,
        binding: &ActionBinding,
        cursor: &ActionBindingCursor,
        now_ms: i64,
    ) -> Result<(), String> {
        self.migrate_action_bindings()?;
        let pending =
            serde_json::to_string(&cursor.pending_events).map_err(|error| error.to_string())?;
        let marker = cursor
            .read_marker
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or_default();
        self.conn()
            .execute(
                "UPDATE sekai_action_bindings
                 SET snapshot_revision = ?4, last_page_digest = ?5, pending_events_json = ?6,
                     read_marker_json = ?8, updated_at_ms = ?7
                 WHERE namespace = ?1 AND binding_id = ?2 AND revision = ?3",
                params![
                    binding.namespace,
                    binding.binding_id,
                    binding.revision as i64,
                    cursor.snapshot_revision,
                    cursor.last_page_digest,
                    pending,
                    now_ms,
                    marker
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn binding() -> ActionBinding {
        ActionBinding {
            contract_version: ACTION_BINDING_CONTRACT.into(),
            binding_id: "escalate-on-update".into(),
            namespace: "acme".into(),
            kind: "incident".into(),
            property_filters: Vec::new(),
            ops: vec![OP_UPDATE.into()],
            type_id: "incident.escalate".into(),
            version: "1".into(),
            run_as: "svc-escalator".into(),
            parameters: BTreeMap::from([
                ("object_id".into(), ParameterSource::ObjectId),
                (
                    "severity".into(),
                    ParameterSource::Property("severity".into()),
                ),
                ("channel".into(), ParameterSource::Constant("pager".into())),
            ]),
            enabled: true,
            revision: 0,
            created_by: String::new(),
            updated_at_ms: 0,
        }
    }

    fn event(event_id: &str) -> ObjectChangeEvent {
        ObjectChangeEvent {
            offset: 7,
            event_id: event_id.into(),
            object_id: "inc-1".into(),
            kind: "incident".into(),
            op: OP_UPDATE.into(),
            field: "severity".into(),
            committed_at_ms: 1,
            operation_id: "op".into(),
        }
    }

    #[test]
    fn a_binding_rejects_open_ended_or_delete_property_mappings() {
        assert!(binding().validate().is_ok());
        let mut delete = binding();
        delete.ops.push(OP_DELETE.into());
        assert!(delete.validate().unwrap_err().contains("delete"));
        let mut unknown_op = binding();
        unknown_op.ops = vec!["invalidate".into()];
        assert!(unknown_op.validate().is_err());
        let mut spaced = binding();
        spaced.run_as = "svc escalator".into();
        assert!(spaced.validate().is_err());
    }

    #[test]
    fn parameters_come_only_from_the_closed_mapping_and_visible_properties() {
        let visible = Object {
            id: "inc-1".into(),
            kind: "incident".into(),
            name: "inc-1".into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([
                ("severity".into(), "high".into()),
                ("secret_note".into(), "never mapped".into()),
            ]),
            created: 1,
            updated: 1,
        };
        let parameters = binding()
            .parameters_for(&event("e1"), Some(&visible))
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&parameters).unwrap();
        assert_eq!(
            parsed,
            serde_json::json!({"object_id": "inc-1", "severity": "high", "channel": "pager"})
        );

        // A property hidden from the service principal is absent from what it
        // reads, so the event is skipped rather than submitted without it.
        let mut hidden = visible.clone();
        hidden.properties.remove("severity");
        assert_eq!(
            binding().parameters_for(&event("e1"), Some(&hidden)),
            Err(SKIP_SOURCE_UNAVAILABLE)
        );
    }

    #[test]
    fn the_idempotency_key_is_stable_per_event_and_changes_with_the_revision() {
        let first = binding().idempotency_key(&event("e1")).unwrap();
        assert_eq!(first, binding().idempotency_key(&event("e1")).unwrap());
        assert_ne!(first, binding().idempotency_key(&event("e2")).unwrap());
        let mut reinstalled = binding();
        reinstalled.revision = 2;
        assert_ne!(first, reinstalled.idempotency_key(&event("e1")).unwrap());
        assert!(!first.chars().any(char::is_whitespace));
    }

    #[test]
    fn reinstalling_a_binding_bumps_the_revision_and_resets_delivery() {
        let db = SekaiDb::new(":memory:").unwrap();
        let first = db.put_action_binding(&binding(), "admin", 1).unwrap();
        assert_eq!(first.revision, 1);
        db.advance_action_binding_cursor(
            &first,
            &ActionBindingCursor {
                snapshot_revision: "v1:3:sha256:x".into(),
                last_page_digest: "sha256:page".into(),
                pending_events: vec![event("e1")],
                read_marker: None,
            },
            2,
        )
        .unwrap();
        let second = db.put_action_binding(&binding(), "admin", 3).unwrap();
        assert_eq!(second.revision, 2);
        let (stored, cursor) = db
            .get_action_binding("acme", "escalate-on-update")
            .unwrap()
            .unwrap();
        assert_eq!(stored.revision, 2);
        assert_eq!(cursor, ActionBindingCursor::default());
        // A run that read under revision 1 cannot move revision 2's cursor.
        db.advance_action_binding_cursor(
            &first,
            &ActionBindingCursor {
                snapshot_revision: "stale".into(),
                last_page_digest: "stale".into(),
                pending_events: Vec::new(),
                read_marker: None,
            },
            4,
        )
        .unwrap();
        assert_eq!(
            db.get_action_binding("acme", "escalate-on-update")
                .unwrap()
                .unwrap()
                .1,
            ActionBindingCursor::default()
        );
    }
}
