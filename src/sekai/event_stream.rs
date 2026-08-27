//! Checkpointed event-stream projections (#684).
//!
//! A registered stream is local ordered-batch evidence, not a broker
//! consumer. Projection is the `stream_projection` class of
//! `sekai.governed-transform-execution/v1`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::evidence::EvidenceClassification;
use crate::sekai::markings::{
    PRINCIPAL_PROFILE_KIND, PRINCIPAL_PROFILE_SEALED_PROPERTY, PrincipalAuthority,
    parse_classification, principal_authority_from_profile, principal_profile_external_id,
    trusted_service_authority,
};
use crate::sekai::security::Role;
use crate::shomei;

pub const EVENT_STREAM_CONTRACT: &str = "sekai.event-stream-projection/v1";
pub const TRANSFORM_PROFILE: &str = "sekai.governed-transform-execution/v1";
pub const TRANSFORM_CLASS: &str = "stream_projection";
pub const SCHEMA_REVISION_V1: &str = "v1";
pub const MAX_COLUMNS: usize = 64;
pub const MAX_EVENTS: usize = 500;
pub const PROJECT_UNAVAILABLE: &str = "event stream projection is not admitted";
pub const BATCH_MALFORMED: &str = "event stream batch is malformed";
pub const BATCH_GAP: &str = "event stream batch has a gap";
pub const BATCH_LATE: &str = "event stream batch is late";
pub const REVISION_UNSUPPORTED: &str = "event stream revision is unsupported";
pub const CHECKPOINT_CONFLICT: &str = "event stream checkpoint conflict";
pub const POSTGRES_UNAVAILABLE: &str =
    "event stream projections are unavailable on the PostgreSQL community runtime";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventStreamColumn {
    pub name: String,
    pub col_type: String,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventStreamBinding {
    pub contract_version: String,
    pub stream_id: String,
    pub namespace: String,
    pub owner: String,
    pub source: String,
    pub source_instance: String,
    pub schema_revision: String,
    pub type_digest: String,
    pub definition_digest: String,
    pub columns: Vec<EventStreamColumn>,
    pub registered_by: String,
    pub registered_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamEvent {
    pub offset: u64,
    pub event_id: String,
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventStreamBatch {
    pub stream_id: String,
    pub generation: u64,
    pub feed_epoch: String,
    pub offset_start: u64,
    pub offset_end: u64,
    pub events: Vec<StreamEvent>,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventStreamCheckpoint {
    pub stream_id: String,
    pub generation: u64,
    pub feed_epoch: String,
    pub committed_offset: u64,
    pub last_batch_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventStreamProjection {
    pub profile_version: String,
    pub class: String,
    pub namespace: String,
    pub stream_id: String,
    pub generation: u64,
    pub feed_epoch: String,
    pub definition_digest: String,
    pub input_digest: String,
    pub outcome: String,
    pub columns: Vec<String>,
    pub event_count: u32,
    pub projection_digest: String,
    pub checkpoint: EventStreamCheckpoint,
    pub events: Vec<ProjectedStreamEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedStreamEvent {
    pub offset: u64,
    pub event_id: String,
    pub properties: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct DefinitionPin<'a> {
    profile_version: &'a str,
    class: &'a str,
    namespace: &'a str,
    stream_id: &'a str,
    owner: &'a str,
    source: &'a str,
    source_instance: &'a str,
    schema_revision: &'a str,
    type_digest: &'a str,
    columns: &'a [EventStreamColumn],
}

#[derive(Serialize)]
struct BatchPin<'a> {
    stream_id: &'a str,
    generation: u64,
    feed_epoch: &'a str,
    offset_start: u64,
    offset_end: u64,
    events: &'a [StreamEvent],
}

#[derive(Serialize)]
struct ProjectionPin<'a> {
    columns: &'a [String],
    events: &'a [ProjectedStreamEvent],
}

#[derive(Serialize)]
struct AdmittedEventPin<'a> {
    offset: u64,
    event_id: &'a str,
    properties: &'a BTreeMap<String, String>,
}

pub fn admitted_event_digest(event: &StreamEvent) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&AdmittedEventPin {
            offset: event.offset,
            event_id: &event.event_id,
            properties: &event.properties,
        })?
    ))
}

pub fn batch_digest_for(batch: &EventStreamBatch) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&BatchPin {
            stream_id: &batch.stream_id,
            generation: batch.generation,
            feed_epoch: &batch.feed_epoch,
            offset_start: batch.offset_start,
            offset_end: batch.offset_end,
            events: &batch.events,
        })?
    ))
}

pub fn register_event_stream(
    db: &RuntimeDb,
    actor: &str,
    binding: &EventStreamBinding,
    now_ms: i64,
) -> Result<EventStreamBinding, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("register timestamp must be non-negative".into());
    }
    let validated = validate_binding(binding, actor, now_ms)?;
    if let Some(existing) = db.get_event_stream_binding(&validated.stream_id)?
        && existing.owner != actor
    {
        return Err(PROJECT_UNAVAILABLE.into());
    }
    db.put_event_stream_binding(&validated)?;
    Ok(validated)
}

pub fn project_event_batch(
    db: &RuntimeDb,
    actor: &str,
    batch: &EventStreamBatch,
    now_ms: i64,
) -> Result<EventStreamProjection, String> {
    required("actor", actor)?;
    required("stream id", &batch.stream_id)?;
    if now_ms < 0 {
        return Err("project timestamp must be non-negative".into());
    }
    let binding = db
        .get_event_stream_binding(&batch.stream_id)?
        .ok_or(PROJECT_UNAVAILABLE)?;
    if binding.owner != actor {
        return Err(PROJECT_UNAVAILABLE.into());
    }
    if binding.contract_version != EVENT_STREAM_CONTRACT
        || binding.schema_revision != SCHEMA_REVISION_V1
    {
        return Err(REVISION_UNSUPPORTED.into());
    }
    let authority = stream_authority(db, actor)?;
    let authorized = authorized_columns(&binding, &authority);
    validate_batch(&binding, batch)?;
    let digest = batch_digest_for(batch)?;
    if digest != batch.content_digest {
        return Err(BATCH_MALFORMED.into());
    }

    let expected = current_checkpoint(db, &batch.stream_id, batch)?;
    if let Some(projection) =
        decided_without_advance(&binding, batch, &authorized, &digest, &expected)?
    {
        db.ensure_event_stream_admitted_events(batch)?;
        return Ok(projection);
    }

    let events = project_events(batch, &authorized)?;
    let next = EventStreamCheckpoint {
        stream_id: batch.stream_id.clone(),
        generation: batch.generation,
        feed_epoch: batch.feed_epoch.clone(),
        committed_offset: batch.offset_end,
        last_batch_digest: digest.clone(),
    };
    match db.advance_event_stream_checkpoint(
        &next,
        &expected,
        &binding.definition_digest,
        Some(&batch.events),
    ) {
        Ok(()) => projection_result(&binding, batch, &authorized, events, next, "accepted"),
        Err(error) if error == CHECKPOINT_CONFLICT => {
            let latest = current_checkpoint(db, &batch.stream_id, batch)?;
            decided_without_advance(&binding, batch, &authorized, &digest, &latest)?
                .ok_or_else(|| BATCH_GAP.to_string())
        }
        Err(error) => Err(error),
    }
}

fn current_checkpoint(
    db: &RuntimeDb,
    stream_id: &str,
    batch: &EventStreamBatch,
) -> Result<EventStreamCheckpoint, String> {
    Ok(db
        .get_event_stream_checkpoint(stream_id)?
        .unwrap_or(EventStreamCheckpoint {
            stream_id: stream_id.into(),
            generation: batch.generation,
            feed_epoch: batch.feed_epoch.clone(),
            committed_offset: 0,
            last_batch_digest: String::new(),
        }))
}

fn decided_without_advance(
    binding: &EventStreamBinding,
    batch: &EventStreamBatch,
    authorized: &[String],
    digest: &str,
    checkpoint: &EventStreamCheckpoint,
) -> Result<Option<EventStreamProjection>, String> {
    if checkpoint.committed_offset > 0 {
        if checkpoint.generation != batch.generation || checkpoint.feed_epoch != batch.feed_epoch {
            return Err(BATCH_GAP.into());
        }
        if batch.offset_end <= checkpoint.committed_offset {
            if digest == checkpoint.last_batch_digest
                && batch.offset_start <= checkpoint.committed_offset
            {
                return Ok(Some(replayed_projection(
                    binding,
                    batch,
                    authorized,
                    checkpoint.clone(),
                )?));
            }
            return Err(BATCH_LATE.into());
        }
        if batch.offset_start != checkpoint.committed_offset.saturating_add(1) {
            return Err(BATCH_GAP.into());
        }
        return Ok(None);
    }
    if batch.offset_start != 1 {
        return Err(BATCH_GAP.into());
    }
    Ok(None)
}

fn replayed_projection(
    binding: &EventStreamBinding,
    batch: &EventStreamBatch,
    authorized: &[String],
    checkpoint: EventStreamCheckpoint,
) -> Result<EventStreamProjection, String> {
    let events = project_events(batch, authorized)?;
    projection_result(binding, batch, authorized, events, checkpoint, "replayed")
}

fn projection_result(
    binding: &EventStreamBinding,
    batch: &EventStreamBatch,
    authorized: &[String],
    events: Vec<ProjectedStreamEvent>,
    checkpoint: EventStreamCheckpoint,
    outcome: &str,
) -> Result<EventStreamProjection, String> {
    let projection_digest = format!(
        "sha256:{}",
        shomei::digest_serializable(&ProjectionPin {
            columns: authorized,
            events: &events,
        })?
    );
    Ok(EventStreamProjection {
        profile_version: TRANSFORM_PROFILE.into(),
        class: TRANSFORM_CLASS.into(),
        namespace: binding.namespace.clone(),
        stream_id: binding.stream_id.clone(),
        generation: batch.generation,
        feed_epoch: batch.feed_epoch.clone(),
        definition_digest: definition_digest(binding)?,
        input_digest: batch.content_digest.clone(),
        outcome: outcome.into(),
        columns: authorized.to_vec(),
        event_count: u32::try_from(events.len()).map_err(|error| error.to_string())?,
        projection_digest,
        checkpoint,
        events,
    })
}

fn validate_binding(
    binding: &EventStreamBinding,
    actor: &str,
    now_ms: i64,
) -> Result<EventStreamBinding, String> {
    if binding.contract_version != EVENT_STREAM_CONTRACT
        || binding.schema_revision != SCHEMA_REVISION_V1
    {
        return Err(REVISION_UNSUPPORTED.into());
    }
    required("stream id", &binding.stream_id)?;
    required("namespace", &binding.namespace)?;
    required("owner", &binding.owner)?;
    required("source", &binding.source)?;
    required("source instance", &binding.source_instance)?;
    required("type digest", &binding.type_digest)?;
    if binding.owner != actor {
        return Err(PROJECT_UNAVAILABLE.into());
    }
    if binding.columns.is_empty() || binding.columns.len() > MAX_COLUMNS {
        return Err("event stream must declare between 1 and 64 columns".into());
    }
    let mut seen = BTreeSet::new();
    for column in &binding.columns {
        required("column name", &column.name)?;
        if !seen.insert(column.name.clone()) {
            return Err(BATCH_MALFORMED.into());
        }
        if !matches!(column.col_type.as_str(), "string" | "int" | "bool") {
            return Err(REVISION_UNSUPPORTED.into());
        }
        parse_classification(&column.classification)?;
    }
    let mut validated = binding.clone();
    validated.registered_by = actor.into();
    validated.registered_at_ms = now_ms;
    validated.definition_digest = definition_digest(&validated)?;
    Ok(validated)
}

pub(crate) fn validate_batch(
    binding: &EventStreamBinding,
    batch: &EventStreamBatch,
) -> Result<(), String> {
    if batch.stream_id != binding.stream_id {
        return Err(PROJECT_UNAVAILABLE.into());
    }
    required("feed epoch", &batch.feed_epoch)?;
    if batch.generation == 0
        || batch.offset_start == 0
        || batch.offset_end < batch.offset_start
        || batch.generation > i64::MAX as u64
        || batch.offset_start > i64::MAX as u64
        || batch.offset_end > i64::MAX as u64
    {
        return Err(BATCH_MALFORMED.into());
    }
    if batch.events.is_empty() || batch.events.len() > MAX_EVENTS {
        return Err(BATCH_MALFORMED.into());
    }
    let expected_len = batch
        .offset_end
        .saturating_sub(batch.offset_start)
        .saturating_add(1);
    if u64::try_from(batch.events.len()).ok() != Some(expected_len) {
        return Err(BATCH_MALFORMED.into());
    }
    let expected: BTreeSet<&str> = binding
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    for (index, event) in batch.events.iter().enumerate() {
        required("event id", &event.event_id)?;
        let offset = batch.offset_start.saturating_add(index as u64);
        if event.offset != offset {
            return Err(BATCH_MALFORMED.into());
        }
        let keys: BTreeSet<&str> = event.properties.keys().map(String::as_str).collect();
        if keys != expected {
            return Err(BATCH_MALFORMED.into());
        }
        for column in &binding.columns {
            let value = event.properties.get(&column.name).ok_or(BATCH_MALFORMED)?;
            if !typed_value(&column.col_type, value) {
                return Err(BATCH_MALFORMED.into());
            }
        }
    }
    Ok(())
}

fn typed_value(col_type: &str, value: &str) -> bool {
    match col_type {
        "string" => true,
        "int" => value.parse::<i64>().is_ok(),
        "bool" => matches!(value, "true" | "false"),
        _ => false,
    }
}

pub(crate) fn stream_authority(db: &RuntimeDb, actor: &str) -> Result<PrincipalAuthority, String> {
    if let Some(trusted) = trusted_service_authority(actor) {
        return Ok(trusted);
    }
    let candidates = db.find_all_by_external_id(&principal_profile_external_id(actor))?;
    let mut sealed = Vec::new();
    for object in &candidates {
        if object.kind != PRINCIPAL_PROFILE_KIND {
            continue;
        }
        if object
            .properties
            .get(PRINCIPAL_PROFILE_SEALED_PROPERTY)
            .is_none_or(|value| value != "true")
        {
            continue;
        }
        if db
            .list_grants(&object.id)?
            .iter()
            .any(|grant| matches!(grant.role, Role::Admin))
        {
            sealed.push(object);
        }
    }
    if sealed.len() > 1 {
        return Err(PROJECT_UNAVAILABLE.into());
    }
    principal_authority_from_profile(actor, sealed.first().copied())
}

pub(crate) fn authorized_columns(
    binding: &EventStreamBinding,
    authority: &PrincipalAuthority,
) -> Vec<String> {
    binding
        .columns
        .iter()
        .filter(|column| column_visible(column, authority))
        .map(|column| column.name.clone())
        .collect()
}

fn column_visible(column: &EventStreamColumn, authority: &PrincipalAuthority) -> bool {
    let Ok(marking) = parse_classification(&column.classification) else {
        return false;
    };
    marking == EvidenceClassification::Public
        || authority
            .classification_ceiling
            .is_some_and(|ceiling| ceiling >= marking)
}

pub(crate) fn project_events(
    batch: &EventStreamBatch,
    authorized: &[String],
) -> Result<Vec<ProjectedStreamEvent>, String> {
    let mut events = Vec::new();
    for event in &batch.events {
        let mut properties = BTreeMap::new();
        for name in authorized {
            let value = event.properties.get(name).ok_or(BATCH_MALFORMED)?;
            properties.insert(name.clone(), value.clone());
        }
        events.push(ProjectedStreamEvent {
            offset: event.offset,
            event_id: event.event_id.clone(),
            properties,
        });
    }
    Ok(events)
}

fn definition_digest(binding: &EventStreamBinding) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&DefinitionPin {
            profile_version: TRANSFORM_PROFILE,
            class: TRANSFORM_CLASS,
            namespace: &binding.namespace,
            stream_id: &binding.stream_id,
            owner: &binding.owner,
            source: &binding.source,
            source_instance: &binding.source_instance,
            schema_revision: &binding.schema_revision,
            type_digest: &binding.type_digest,
            columns: &binding.columns,
        })?
    ))
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY;
    use crate::sekai::security::Grant;
    use std::collections::HashMap;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn pin_ceiling(runtime: &RuntimeDb, principal: &str, ceiling: &str) {
        let profile_id = format!("profile:{principal}");
        runtime
            .create_object(&Object {
                id: profile_id.clone(),
                kind: PRINCIPAL_PROFILE_KIND.into(),
                name: principal.into(),
                namespace: "ops".into(),
                external_id: principal_profile_external_id(principal),
                properties: HashMap::from([
                    (
                        PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        ceiling.into(),
                    ),
                    (PRINCIPAL_PROFILE_SEALED_PROPERTY.into(), "true".into()),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        runtime
            .create_grant(&Grant {
                id: format!("grant:{principal}"),
                object_id: profile_id,
                principal: "root".into(),
                role: Role::Admin,
                created: 1,
            })
            .unwrap();
    }

    fn binding() -> EventStreamBinding {
        EventStreamBinding {
            contract_version: EVENT_STREAM_CONTRACT.into(),
            stream_id: "github:ops".into(),
            namespace: "ops".into(),
            owner: "analyst".into(),
            source: "github".into(),
            source_instance: "sekai/chisei".into(),
            schema_revision: SCHEMA_REVISION_V1.into(),
            type_digest: "sha256:typedef".into(),
            definition_digest: String::new(),
            columns: vec![
                EventStreamColumn {
                    name: "id".into(),
                    col_type: "int".into(),
                    classification: "public".into(),
                },
                EventStreamColumn {
                    name: "kind".into(),
                    col_type: "string".into(),
                    classification: "internal".into(),
                },
                EventStreamColumn {
                    name: "secret".into(),
                    col_type: "string".into(),
                    classification: "restricted".into(),
                },
            ],
            registered_by: String::new(),
            registered_at_ms: 0,
        }
    }

    fn event(offset: u64) -> StreamEvent {
        StreamEvent {
            offset,
            event_id: format!("e{offset}"),
            properties: BTreeMap::from([
                ("id".into(), offset.to_string()),
                ("kind".into(), "issue".into()),
                ("secret".into(), "hidden".into()),
            ]),
        }
    }

    fn batch(start: u64, end: u64) -> EventStreamBatch {
        let events: Vec<_> = (start..=end).map(event).collect();
        let mut batch = EventStreamBatch {
            stream_id: "github:ops".into(),
            generation: 1,
            feed_epoch: "epoch-1".into(),
            offset_start: start,
            offset_end: end,
            events,
            content_digest: String::new(),
        };
        batch.content_digest = batch_digest_for(&batch).unwrap();
        batch
    }

    fn setup() -> RuntimeDb {
        let runtime = db();
        pin_ceiling(&runtime, "analyst", "internal");
        register_event_stream(&runtime, "analyst", &binding(), 1_000).unwrap();
        runtime
    }

    #[test]
    fn accepted_batch_replays_without_moving_the_checkpoint_twice() {
        let runtime = setup();
        let first = project_event_batch(&runtime, "analyst", &batch(1, 2), 2_000).unwrap();
        assert_eq!(first.outcome, "accepted");
        assert_eq!(first.checkpoint.committed_offset, 2);
        assert_eq!(first.event_count, 2);
        assert_eq!(first.events[0].event_id, "e1");
        assert_eq!(first.events[0].offset, 1);
        assert!(
            first
                .events
                .iter()
                .all(|event| !event.properties.contains_key("secret"))
        );
        let replay = project_event_batch(&runtime, "analyst", &batch(1, 2), 3_000).unwrap();
        assert_eq!(replay.outcome, "replayed");
        assert_eq!(replay.checkpoint.committed_offset, 2);
        assert_eq!(replay.projection_digest, first.projection_digest);
        assert_eq!(
            replay.checkpoint.last_batch_digest,
            first.checkpoint.last_batch_digest
        );
    }

    #[test]
    fn gap_late_malformed_and_hidden_fields_do_not_advance() {
        let runtime = setup();
        project_event_batch(&runtime, "analyst", &batch(1, 1), 2_000).unwrap();
        assert_eq!(
            project_event_batch(&runtime, "analyst", &batch(3, 3), 2_100).unwrap_err(),
            BATCH_GAP
        );
        let mut late = batch(1, 1);
        late.events[0].event_id = "other".into();
        late.content_digest = batch_digest_for(&late).unwrap();
        assert_eq!(
            project_event_batch(&runtime, "analyst", &late, 2_200).unwrap_err(),
            BATCH_LATE
        );
        let mut malformed = batch(2, 2);
        malformed.events[0].offset = 9;
        malformed.content_digest = batch_digest_for(&malformed).unwrap();
        assert_eq!(
            project_event_batch(&runtime, "analyst", &malformed, 2_300).unwrap_err(),
            BATCH_MALFORMED
        );
        assert_eq!(
            db().get_event_stream_checkpoint("github:ops").unwrap(),
            None
        );
        assert_eq!(
            runtime
                .get_event_stream_checkpoint("github:ops")
                .unwrap()
                .unwrap()
                .committed_offset,
            1
        );
    }

    #[test]
    fn foreign_owner_and_unsupported_revision_fail_closed() {
        let runtime = setup();
        assert_eq!(
            project_event_batch(&runtime, "intruder", &batch(1, 1), 2_000).unwrap_err(),
            PROJECT_UNAVAILABLE
        );
        let mut bad = binding();
        bad.stream_id = "github:v2".into();
        bad.schema_revision = "v2".into();
        assert_eq!(
            register_event_stream(&runtime, "analyst", &bad, 2_000).unwrap_err(),
            REVISION_UNSUPPORTED
        );
    }

    #[test]
    fn definition_change_resets_checkpoint_and_stale_cas_fails() {
        let runtime = setup();
        project_event_batch(&runtime, "analyst", &batch(1, 1), 2_000).unwrap();
        let mut next = binding();
        next.type_digest = "sha256:other".into();
        register_event_stream(&runtime, "analyst", &next, 3_000).unwrap();
        assert_eq!(
            runtime.get_event_stream_checkpoint("github:ops").unwrap(),
            None
        );
        let restart = project_event_batch(&runtime, "analyst", &batch(1, 1), 4_000).unwrap();
        assert_eq!(restart.outcome, "accepted");
        assert_eq!(restart.checkpoint.committed_offset, 1);

        let stale = EventStreamCheckpoint {
            stream_id: "github:ops".into(),
            generation: 1,
            feed_epoch: "epoch-1".into(),
            committed_offset: 0,
            last_batch_digest: String::new(),
        };
        let attempted = EventStreamCheckpoint {
            stream_id: "github:ops".into(),
            generation: 1,
            feed_epoch: "epoch-1".into(),
            committed_offset: 2,
            last_batch_digest: "sha256:stale".into(),
        };
        assert_eq!(
            runtime
                .advance_event_stream_checkpoint(
                    &attempted,
                    &stale,
                    &runtime
                        .get_event_stream_binding("github:ops")
                        .unwrap()
                        .unwrap()
                        .definition_digest,
                    None,
                )
                .unwrap_err(),
            CHECKPOINT_CONFLICT
        );
        assert_eq!(
            runtime
                .get_event_stream_checkpoint("github:ops")
                .unwrap()
                .unwrap()
                .committed_offset,
            1
        );

        let mut oversized = batch(2, 2);
        oversized.generation = u64::MAX;
        oversized.content_digest = batch_digest_for(&oversized).unwrap();
        assert_eq!(
            project_event_batch(&runtime, "analyst", &oversized, 5_000).unwrap_err(),
            BATCH_MALFORMED
        );
        assert_eq!(
            runtime
                .advance_event_stream_checkpoint(
                    &attempted,
                    &runtime
                        .get_event_stream_checkpoint("github:ops")
                        .unwrap()
                        .unwrap(),
                    "sha256:stale-definition",
                    None,
                )
                .unwrap_err(),
            CHECKPOINT_CONFLICT
        );
    }
}
