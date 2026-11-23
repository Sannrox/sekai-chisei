//! Plane-owned automation bindings from object changes, or from a fixed
//! schedule, to governed Actions (#1092, ADR 0090; #3033).
//!
//! A binding maps authorized object-change events for one namespace and kind
//! onto one pinned `GovernedActionType` through a closed parameter mapping.
//! A scheduled binding instead submits one Action per interval bucket from
//! constant parameters; the plane's schedule tick runs it.
//! It runs as an explicit service principal whose grants, policy, budget, and
//! schema are checked on every submit. The subscription itself never carries
//! authority. Idempotency comes from the binding revision and the delivered
//! event, or the schedule bucket, so a redelivered page or a second tick of
//! one bucket admits nothing new.

use std::collections::{BTreeMap, HashMap};

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
/// The schedule tick runs once a minute, so a shorter interval cannot fire.
pub const MIN_SCHEDULE_EVERY_MS: i64 = 60_000;
pub const MAX_SCHEDULE_EVERY_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// A fixed-interval trigger. Buckets are phased per binding, so bindings with
/// one interval do not all fire on the same tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionBindingSchedule {
    pub every_ms: i64,
}

/// A trigger on new dataset versions (#3034): an append snapshot, a rollback,
/// or a branch merge. Branch working copies write no version, so they do not
/// fire. Scoped to the datasets whose binding object is in the namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionBindingDatasetCommit {
    /// One dataset, or every dataset in the namespace when empty.
    #[serde(default)]
    pub dataset_id: String,
}

/// Recorded as the pin of a dataset-commit binding once its first run has
/// recorded every scoped dataset's latest version.
pub const DATASET_COMMIT_PINNED: &str = "dataset-versions";
/// The `op` a dataset-commit submission reports.
pub const OP_DATASET_COMMIT: &str = "dataset_commit";

/// Stored in place of `enabled` for an enabled binding that requires
/// approval (#3035). The stored body then says `enabled: false`, so a plane
/// that predates `require_approval` refuses the run instead of submitting
/// without a park; this plane reads the binding back as enabled.
const STORED_APPROVAL_GATED_ENABLED: &str = "approval_gated_enabled";

/// The stored form of a binding. See [`STORED_APPROVAL_GATED_ENABLED`].
pub fn encode_binding_body(binding: &ActionBinding) -> Result<String, String> {
    let mut body = serde_json::to_value(binding).map_err(|error| error.to_string())?;
    if binding.require_approval && binding.enabled {
        let fields = body
            .as_object_mut()
            .ok_or("action binding must encode as an object")?;
        fields.insert("enabled".into(), serde_json::Value::Bool(false));
        fields.insert(
            STORED_APPROVAL_GATED_ENABLED.into(),
            serde_json::Value::Bool(true),
        );
    }
    Ok(body.to_string())
}

/// Reads a stored binding body, written by [`encode_binding_body`] or by a
/// plane that predates it.
pub fn decode_binding_body(body: &str) -> Result<ActionBinding, String> {
    let corrupt = |error: serde_json::Error| format!("corrupt action binding: {error}");
    let mut value: serde_json::Value = serde_json::from_str(body).map_err(corrupt)?;
    let gated = value
        .as_object_mut()
        .and_then(|fields| fields.remove(STORED_APPROVAL_GATED_ENABLED))
        .is_some_and(|gated| gated == serde_json::Value::Bool(true));
    let mut binding: ActionBinding = serde_json::from_value(value).map_err(corrupt)?;
    if gated && binding.require_approval {
        binding.enabled = true;
    }
    Ok(binding)
}

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
    /// The committed dataset's id (dataset-commit bindings only).
    DatasetId,
    /// The new version's id (dataset-commit bindings only).
    VersionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionBinding {
    pub contract_version: String,
    pub binding_id: String,
    pub namespace: String,
    /// Object kind whose changes trigger the binding; empty when scheduled.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub property_filters: Vec<PropertyFilter>,
    /// Event operations that submit: a subset of create, update, delete.
    /// Empty when scheduled.
    #[serde(default)]
    pub ops: Vec<String>,
    /// Fires on this interval instead of on object changes (#3033).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<ActionBindingSchedule>,
    /// Fires on new dataset versions instead of on object changes (#3034).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_commit: Option<ActionBindingDatasetCommit>,
    /// Parks every submit for a human decision, whatever the policy allows
    /// (#3035). It only adds a park: a denial or a policy park stands.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_approval: bool,
    pub type_id: String,
    /// Pinned `GovernedActionType` version.
    pub version: String,
    /// Service principal the binding submits as.
    pub run_as: String,
    pub parameters: BTreeMap<String, ParameterSource>,
    /// Markings every Action the binding submits carries, joined with the
    /// changed object's (#1706).
    #[serde(default)]
    pub markings: Vec<String>,
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
            ("type_id", &self.type_id),
            ("version", &self.version),
            ("run_as", &self.run_as),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
                return Err(format!("{field} must be non-empty without whitespace"));
            }
        }
        if self.parameters.len() > MAX_BINDING_PARAMETERS {
            return Err(format!(
                "at most {MAX_BINDING_PARAMETERS} mapped parameters are allowed"
            ));
        }
        if self
            .parameters
            .keys()
            .any(|name| name.trim().is_empty() || name.chars().any(char::is_whitespace))
        {
            return Err("parameter names must be non-empty without whitespace".into());
        }
        if self.schedule.is_some() && self.dataset_commit.is_some() {
            return Err("a binding names at most one of schedule and dataset_commit".into());
        }
        if let Some(schedule) = self.schedule {
            return self.validate_scheduled(schedule);
        }
        if let Some(trigger) = &self.dataset_commit {
            return self.validate_dataset_commit(trigger);
        }
        if self.kind.trim().is_empty() || self.kind.chars().any(char::is_whitespace) {
            return Err("kind must be non-empty without whitespace".into());
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
        for (name, source) in &self.parameters {
            if matches!(
                source,
                ParameterSource::DatasetId | ParameterSource::VersionId
            ) {
                return Err(format!(
                    "parameter {name:?} maps a dataset source, which only dataset_commit bindings have"
                ));
            }
            if let ParameterSource::Property(property) = source {
                if property == crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY {
                    return Err("the marking property cannot be mapped into parameters".into());
                }
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

    /// A scheduled binding has no object or event, so it names no kind, ops
    /// or filters and maps constants only.
    fn validate_scheduled(&self, schedule: ActionBindingSchedule) -> Result<(), String> {
        if !(MIN_SCHEDULE_EVERY_MS..=MAX_SCHEDULE_EVERY_MS).contains(&schedule.every_ms) {
            return Err(format!(
                "schedule.every_ms must be between {MIN_SCHEDULE_EVERY_MS} and {MAX_SCHEDULE_EVERY_MS}"
            ));
        }
        if !self.kind.is_empty() || !self.ops.is_empty() || !self.property_filters.is_empty() {
            return Err("a scheduled binding must not name kind, ops or property filters".into());
        }
        for (name, source) in &self.parameters {
            if !matches!(source, ParameterSource::Constant(_)) {
                return Err(format!(
                    "a scheduled binding must map parameter {name:?} from a constant"
                ));
            }
        }
        Ok(())
    }

    /// The approval rule a submit carries: `action_binding:<id>@<revision>`
    /// when the binding requires approval, so a parked instance names the
    /// automation that requested it; empty otherwise.
    pub fn approval_rule(&self) -> String {
        if self.require_approval {
            format!("action_binding:{}@{}", self.binding_id, self.revision)
        } else {
            String::new()
        }
    }

    /// A dataset-commit binding has no object event, so it names no kind, ops
    /// or filters and maps constants, the dataset id and the version id.
    fn validate_dataset_commit(&self, trigger: &ActionBindingDatasetCommit) -> Result<(), String> {
        if trigger.dataset_id.chars().any(char::is_whitespace) {
            return Err("dataset_commit.dataset_id must not contain whitespace".into());
        }
        if !self.kind.is_empty() || !self.ops.is_empty() || !self.property_filters.is_empty() {
            return Err(
                "a dataset_commit binding must not name kind, ops or property filters".into(),
            );
        }
        for (name, source) in &self.parameters {
            if !matches!(
                source,
                ParameterSource::Constant(_)
                    | ParameterSource::DatasetId
                    | ParameterSource::VersionId
            ) {
                return Err(format!(
                    "a dataset_commit binding must map parameter {name:?} from a constant, dataset_id or version_id"
                ));
            }
        }
        Ok(())
    }

    /// Stable per binding revision and committed version, so a rerun, or a
    /// rerun after a crash before the cursor moved, replays one instance.
    pub fn dataset_idempotency_key(
        &self,
        dataset_id: &str,
        version_id: &str,
    ) -> Result<String, String> {
        Ok(format!(
            "binding-{}",
            crate::shomei::digest_serializable(&(
                &self.namespace,
                &self.binding_id,
                self.revision,
                OP_DATASET_COMMIT,
                dataset_id,
                version_id,
            ))?
        ))
    }

    /// Parameters for one dataset version: validation allows constants and
    /// the dataset and version ids only.
    pub fn dataset_parameters(&self, dataset_id: &str, version_id: &str) -> String {
        let parameters = self
            .parameters
            .iter()
            .filter_map(|(name, source)| {
                let value = match source {
                    ParameterSource::Constant(value) => value.clone(),
                    ParameterSource::DatasetId => dataset_id.to_string(),
                    ParameterSource::VersionId => version_id.to_string(),
                    _ => return None,
                };
                Some((name.clone(), serde_json::Value::String(value)))
            })
            .collect::<serde_json::Map<_, _>>();
        serde_json::Value::Object(parameters).to_string()
    }

    /// The latest bucket start at or before `now_ms` of a scheduled binding,
    /// phased per binding as site agent schedule wakes are (ADR 0137). Ticks
    /// missed while no plane ran collapse into this one bucket.
    pub fn due_at_ms(&self, schedule: ActionBindingSchedule, now_ms: i64) -> i64 {
        crate::sekai::agent_wake::due_at(
            &format!("{}/{}", self.namespace, self.binding_id),
            schedule.every_ms,
            now_ms,
        )
    }

    /// Stable per binding revision and bucket, so two planes ticking the same
    /// bucket, or a rerun after a crash, replay one instance.
    pub fn tick_idempotency_key(&self, due_at_ms: i64) -> Result<String, String> {
        Ok(format!(
            "binding-{}",
            crate::shomei::digest_serializable(&(
                &self.namespace,
                &self.binding_id,
                self.revision,
                "schedule",
                due_at_ms,
            ))?
        ))
    }

    /// Parameters for one scheduled submit: validation allows constants only.
    pub fn tick_parameters(&self) -> String {
        let parameters = self
            .parameters
            .iter()
            .filter_map(|(name, source)| match source {
                ParameterSource::Constant(value) => {
                    Some((name.clone(), serde_json::Value::String(value.clone())))
                }
                _ => None,
            })
            .collect::<serde_json::Map<_, _>>();
        serde_json::Value::Object(parameters).to_string()
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
                // Validation keeps dataset sources off object-change bindings.
                ParameterSource::DatasetId | ParameterSource::VersionId => {
                    return Err(SKIP_SOURCE_UNAVAILABLE);
                }
            };
            parameters.insert(name.clone(), serde_json::Value::String(value));
        }
        Ok(serde_json::Value::Object(parameters).to_string())
    }
}

/// Decodes stored binding bodies and keeps the enabled scheduled ones.
pub fn scheduled_bindings(
    bodies: impl IntoIterator<Item = String>,
) -> Result<Vec<ActionBinding>, String> {
    let mut scheduled = Vec::new();
    for body in bodies {
        let binding = decode_binding_body(&body)?;
        if binding.enabled && binding.schedule.is_some() {
            scheduled.push(binding);
        }
    }
    Ok(scheduled)
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
    pub read_marker: Option<ReadMarker>,
}

/// Subscription state recorded before a page read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadMarker {
    /// No subscription existed yet (the first pin): recovery rewinds
    /// the one the read created to its pin, so the page is delivered again.
    Absent,
    Subscription(Box<crate::sekai::event_subscription::EventSubscription>),
}

const READ_MARKER_ABSENT: &str = "absent";

/// A cursor's pending events and read marker as both backends store them.
pub fn encode_cursor(cursor: &ActionBindingCursor) -> Result<(String, String), String> {
    let pending =
        serde_json::to_string(&cursor.pending_events).map_err(|error| error.to_string())?;
    let marker = match &cursor.read_marker {
        None => String::new(),
        Some(ReadMarker::Absent) => READ_MARKER_ABSENT.into(),
        Some(ReadMarker::Subscription(subscription)) => {
            serde_json::to_string(subscription).map_err(|error| error.to_string())?
        }
    };
    Ok((pending, marker))
}

/// A stored binding row, as both backends read it back.
pub fn decode_stored(
    body: &str,
    snapshot_revision: String,
    last_page_digest: String,
    pending: &str,
    marker: &str,
) -> Result<(ActionBinding, ActionBindingCursor), String> {
    let binding = decode_binding_body(body)?;
    let pending_events = serde_json::from_str(pending)
        .map_err(|error| format!("corrupt action binding cursor: {error}"))?;
    let read_marker = match marker {
        "" => None,
        READ_MARKER_ABSENT => Some(ReadMarker::Absent),
        json => Some(ReadMarker::Subscription(Box::new(
            serde_json::from_str(json)
                .map_err(|error| format!("corrupt action binding cursor: {error}"))?,
        ))),
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
                );
                CREATE TABLE IF NOT EXISTS sekai_action_binding_dataset_cursors (
                    namespace TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    dataset_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    seq INTEGER NOT NULL,
                    PRIMARY KEY (namespace, binding_id, dataset_id)
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
        let body = encode_binding_body(&stored)?;
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

    pub fn list_action_bindings(&self, namespace: &str) -> Result<Vec<ActionBinding>, String> {
        self.migrate_action_bindings()?;
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT body_json FROM sekai_action_bindings
                 WHERE namespace = ?1
                 ORDER BY binding_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut bindings = Vec::new();
        for body in rows {
            let body = body.map_err(|error| error.to_string())?;
            let binding = decode_binding_body(&body)?;
            bindings.push(binding);
        }
        Ok(bindings)
    }

    /// Enabled scheduled bindings in every namespace, for the schedule tick.
    pub fn list_scheduled_action_bindings(&self) -> Result<Vec<ActionBinding>, String> {
        self.migrate_action_bindings()?;
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT body_json FROM sekai_action_bindings ORDER BY namespace, binding_id")
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let bodies = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        scheduled_bindings(bodies)
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
                    decode_stored(
                        &body,
                        snapshot_revision,
                        last_page_digest,
                        &pending,
                        &marker,
                    )
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
        let (pending, marker) = encode_cursor(cursor)?;
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

    /// The last delivered dataset version `seq` per dataset for this binding
    /// revision. Rows of an older revision are not returned.
    pub fn action_binding_dataset_cursors(
        &self,
        binding: &ActionBinding,
    ) -> Result<HashMap<String, i64>, String> {
        self.migrate_action_bindings()?;
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT dataset_id, seq FROM sekai_action_binding_dataset_cursors
                 WHERE namespace = ?1 AND binding_id = ?2 AND revision = ?3",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(
                params![
                    binding.namespace,
                    binding.binding_id,
                    binding.revision as i64
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<_, _>>()
            .map_err(|error| error.to_string())
    }

    /// Moves one dataset's cursor forward, only while `binding.revision` is
    /// still installed. A row of an older revision is replaced.
    pub fn advance_action_binding_dataset_cursor(
        &self,
        binding: &ActionBinding,
        dataset_id: &str,
        seq: i64,
    ) -> Result<(), String> {
        self.migrate_action_bindings()?;
        self.conn()
            .execute(
                "INSERT INTO sekai_action_binding_dataset_cursors
                    (namespace, binding_id, dataset_id, revision, seq)
                 SELECT ?1, ?2, ?3, ?4, ?5
                 WHERE EXISTS (SELECT 1 FROM sekai_action_bindings
                               WHERE namespace = ?1 AND binding_id = ?2 AND revision = ?4)
                 ON CONFLICT(namespace, binding_id, dataset_id) DO UPDATE SET
                    seq = CASE WHEN revision = excluded.revision
                               THEN max(seq, excluded.seq) ELSE excluded.seq END,
                    revision = excluded.revision",
                params![
                    binding.namespace,
                    binding.binding_id,
                    dataset_id,
                    binding.revision as i64,
                    seq
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_markers_round_trip_through_storage() {
        // #1141: an absent marker, a recorded subscription, and no marker
        // each read back as written.
        let db = SekaiDb::new(":memory:").unwrap();
        let stored = db.put_action_binding(&binding(), "admin", 1).unwrap();
        let subscription = crate::sekai::event_subscription::EventSubscription {
            contract_version: "sekai.event-subscription/v1".into(),
            subscription_id: "action-binding.escalate-on-update".into(),
            namespace: "acme".into(),
            owner: "svc".into(),
            stream_id: "stream-1".into(),
            schema_revision: "1".into(),
            type_digest: "sha256:type".into(),
            definition_digest: "sha256:definition".into(),
            columns: Vec::new(),
            retention_ms: 0,
            status: "active".into(),
            cursor: crate::sekai::event_subscription::EventSubscriptionCursor {
                generation: 1,
                feed_epoch: "epoch".into(),
                committed_offset: 7,
                last_page_digest: "sha256:page".into(),
                admitted_at_ms: 1,
            },
            registered_by: "svc".into(),
            registered_at_ms: 1,
        };
        for marker in [
            None,
            Some(ReadMarker::Absent),
            Some(ReadMarker::Subscription(Box::new(subscription))),
        ] {
            let cursor = ActionBindingCursor {
                snapshot_revision: "pin".into(),
                read_marker: marker.clone(),
                ..Default::default()
            };
            db.advance_action_binding_cursor(&stored, &cursor, 2)
                .unwrap();
            let (_, loaded) = db
                .get_action_binding("acme", "escalate-on-update")
                .unwrap()
                .unwrap();
            assert_eq!(loaded.read_marker, marker);
        }
    }

    pub fn binding() -> ActionBinding {
        ActionBinding {
            contract_version: ACTION_BINDING_CONTRACT.into(),
            binding_id: "escalate-on-update".into(),
            namespace: "acme".into(),
            kind: "incident".into(),
            property_filters: Vec::new(),
            ops: vec![OP_UPDATE.into()],
            schedule: None,
            dataset_commit: None,
            require_approval: false,
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
            markings: Vec::new(),
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

    fn scheduled(every_ms: i64) -> ActionBinding {
        ActionBinding {
            kind: String::new(),
            ops: Vec::new(),
            schedule: Some(ActionBindingSchedule { every_ms }),
            parameters: BTreeMap::from([(
                "channel".into(),
                ParameterSource::Constant("pager".into()),
            )]),
            ..binding()
        }
    }

    #[test]
    fn a_scheduled_binding_maps_constants_only_within_the_interval_range() {
        assert_eq!(scheduled(MIN_SCHEDULE_EVERY_MS).validate(), Ok(()));
        assert_eq!(scheduled(MAX_SCHEDULE_EVERY_MS).validate(), Ok(()));
        assert!(scheduled(MIN_SCHEDULE_EVERY_MS - 1).validate().is_err());
        assert!(scheduled(MAX_SCHEDULE_EVERY_MS + 1).validate().is_err());
        let with_kind = ActionBinding {
            kind: "incident".into(),
            ..scheduled(MIN_SCHEDULE_EVERY_MS)
        };
        assert!(with_kind.validate().is_err());
        let mut from_object = scheduled(MIN_SCHEDULE_EVERY_MS);
        from_object
            .parameters
            .insert("object_id".into(), ParameterSource::ObjectId);
        assert!(from_object.validate().is_err());
        assert_eq!(
            scheduled(MIN_SCHEDULE_EVERY_MS).tick_parameters(),
            r#"{"channel":"pager"}"#
        );
    }

    fn on_commit() -> ActionBinding {
        ActionBinding {
            kind: String::new(),
            ops: Vec::new(),
            dataset_commit: Some(ActionBindingDatasetCommit::default()),
            parameters: BTreeMap::from([
                ("dataset".into(), ParameterSource::DatasetId),
                ("version".into(), ParameterSource::VersionId),
                ("channel".into(), ParameterSource::Constant("pager".into())),
            ]),
            ..binding()
        }
    }

    #[test]
    fn dataset_sources_belong_to_dataset_commit_bindings_only() {
        assert_eq!(on_commit().validate(), Ok(()));
        assert_eq!(
            on_commit().dataset_parameters("orders", "v-2"),
            r#"{"channel":"pager","dataset":"orders","version":"v-2"}"#
        );
        let mut object_change = binding();
        object_change
            .parameters
            .insert("dataset".into(), ParameterSource::DatasetId);
        assert!(object_change.validate().is_err());
        let mut scheduled = scheduled(MIN_SCHEDULE_EVERY_MS);
        scheduled
            .parameters
            .insert("version".into(), ParameterSource::VersionId);
        assert!(scheduled.validate().is_err());
        let both = ActionBinding {
            schedule: Some(ActionBindingSchedule {
                every_ms: MIN_SCHEDULE_EVERY_MS,
            }),
            parameters: BTreeMap::new(),
            ..on_commit()
        };
        assert!(both.validate().is_err());
        let with_kind = ActionBinding {
            kind: "incident".into(),
            ..on_commit()
        };
        assert!(with_kind.validate().is_err());
        let mut from_object = on_commit();
        from_object
            .parameters
            .insert("object_id".into(), ParameterSource::ObjectId);
        assert!(from_object.validate().is_err());
    }

    #[test]
    fn a_dataset_key_is_stable_per_version_and_changes_with_version_or_revision() {
        let binding = on_commit();
        let key = binding.dataset_idempotency_key("orders", "v-1").unwrap();
        assert_eq!(
            key,
            binding.dataset_idempotency_key("orders", "v-1").unwrap()
        );
        assert_ne!(
            key,
            binding.dataset_idempotency_key("orders", "v-2").unwrap()
        );
        let reinstalled = ActionBinding {
            revision: binding.revision + 1,
            ..binding.clone()
        };
        assert_ne!(
            key,
            reinstalled
                .dataset_idempotency_key("orders", "v-1")
                .unwrap()
        );
    }

    #[test]
    fn a_binding_stored_before_dataset_triggers_decodes_as_object_change() {
        let mut legacy = serde_json::to_value(binding()).unwrap();
        let fields = legacy.as_object_mut().unwrap();
        fields.remove("dataset_commit");
        fields.remove("schedule");
        let decoded: ActionBinding = serde_json::from_value(legacy).unwrap();
        assert!(decoded.dataset_commit.is_none() && decoded.schedule.is_none());
        assert_eq!(decoded.validate(), Ok(()));
        // The field is omitted when unset, so an object-change body an older
        // replica reads is byte-for-byte what it wrote.
        assert!(
            !serde_json::to_string(&binding())
                .unwrap()
                .contains("dataset_commit")
        );
    }

    #[test]
    fn a_plane_without_require_approval_reads_an_approval_binding_as_disabled() {
        let gated = ActionBinding {
            require_approval: true,
            revision: 4,
            ..binding()
        };
        let body = encode_binding_body(&gated).unwrap();
        // An older plane decodes the body with plain serde and ignores the
        // fields it does not know: it sees a disabled binding and refuses
        // the run instead of submitting without a park.
        let older: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(older["enabled"], serde_json::Value::Bool(false));
        let decoded = decode_binding_body(&body).unwrap();
        assert!(decoded.enabled && decoded.require_approval);
        assert_eq!(
            decoded.approval_rule(),
            "action_binding:escalate-on-update@4"
        );

        let paused = ActionBinding {
            enabled: false,
            ..gated
        };
        assert!(
            !decode_binding_body(&encode_binding_body(&paused).unwrap())
                .unwrap()
                .enabled
        );
        // A binding without the flag is stored exactly as before.
        let plain = encode_binding_body(&binding()).unwrap();
        assert_eq!(plain, serde_json::to_value(binding()).unwrap().to_string());
        assert!(binding().approval_rule().is_empty());
    }

    #[test]
    fn a_scheduled_key_is_stable_per_bucket_and_changes_with_bucket_or_revision() {
        let binding = scheduled(MIN_SCHEDULE_EVERY_MS);
        let schedule = binding.schedule.unwrap();
        let due = binding.due_at_ms(schedule, 10 * MIN_SCHEDULE_EVERY_MS);
        // Any time within one bucket names that bucket; a later bucket does not.
        assert_eq!(
            binding.due_at_ms(schedule, due + MIN_SCHEDULE_EVERY_MS - 1),
            due
        );
        assert_eq!(
            binding.tick_idempotency_key(due),
            binding.tick_idempotency_key(due)
        );
        assert_ne!(
            binding.tick_idempotency_key(due),
            binding.tick_idempotency_key(due + MIN_SCHEDULE_EVERY_MS)
        );
        let reinstalled = ActionBinding {
            revision: binding.revision + 1,
            ..binding.clone()
        };
        assert_ne!(
            binding.tick_idempotency_key(due),
            reinstalled.tick_idempotency_key(due)
        );
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
        let listed = db.list_action_bindings("acme").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].binding_id, "escalate-on-update");
        assert!(db.list_action_bindings("other").unwrap().is_empty());
        assert_eq!(
            db.get_action_binding("acme", "escalate-on-update")
                .unwrap()
                .unwrap()
                .1,
            ActionBindingCursor::default()
        );
    }
}
