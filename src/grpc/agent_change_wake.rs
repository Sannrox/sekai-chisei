//! Change wakes of site agent instances (ADR 0137, #1952).
//!
//! For each instance with a `change:<debounce_ms>` token, a tick reads the
//! committed object mutations after the token's cursor, keeps those on
//! objects in the instance's responsibility, and reads them as the
//! instance's principal: an object the principal cannot read wakes nothing,
//! and the subscription projection rules (ADR 0068) decide the events. An
//! update wakes only when the principal may read the changed field, so a
//! change to a property hidden by a property grant or a restricted
//! classification wakes nothing. A delete wakes nothing, since the principal
//! can no longer be shown to read the object. Changes in one debounce window
//! share a turn. The cursor advances after the turns are admitted, so a
//! crash replays the page and admission dedupes it. The cursor keeps the
//! change id at its sequence; when purged history has reused or removed that
//! sequence, the cursor restarts from the beginning, and the replayed changes
//! dedupe against the turns already admitted.

use super::*;
use crate::sekai::agent_wake::{self, WakePolicy};
use crate::sekai::object_change_subscription::{
    CommittedObjectMutation, OP_CREATE, OP_UPDATE, ObjectChangeScope, project_events,
};
use crate::sekai::object_security::PropertyGrantAccess;
use crate::sekai::schema::{SchemaRegistry, is_restricted_property_classification};

/// Mutations read per instance and token per tick.
const PAGE: i32 = 256;

impl SekaiServiceImpl {
    /// Admits the change turns of every instance with a change token, as
    /// `actor`.
    pub(super) fn tick_change_wakes(&self, now_ms: i64, actor: &str) -> Result<(), String> {
        let db = self.db.runtime();
        // Refreshed, so a classification another plane changed applies.
        let schema = self
            .schema_definitions
            .refresh_snapshot()
            .map_err(|error| {
                map_schema_definition_lifecycle_error(error)
                    .message()
                    .to_string()
            })?;
        for instance in agent_wake::instances(db)? {
            for (token, policy) in agent_wake::policies(&instance) {
                if let WakePolicy::Change { debounce_ms } = policy {
                    self.tick_change_wake(&schema, &instance, &token, debounce_ms, actor, now_ms)?;
                }
            }
        }
        Ok(())
    }

    fn tick_change_wake(
        &self,
        schema: &SchemaRegistry,
        instance: &domain::Object,
        token: &str,
        debounce_ms: i64,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        let db = self.db.runtime();
        let Some(after) = agent_wake::change_cursor(db, &instance.id, token)? else {
            // A new token starts at the present; earlier history wakes nothing.
            let watermark = db.object_change_watermark(&instance.namespace)?;
            let start = mutation_at(db, &instance.namespace, watermark)?.unwrap_or_default();
            agent_wake::advance_change_cursor(db, &instance.id, token, None, &start)?;
            return Ok(());
        };
        if after.seq > 0
            && mutation_at(db, &instance.namespace, after.seq)?.as_ref() != Some(&after)
        {
            // Purged history can reuse sequences; reread from the start.
            // Replayed changes map to windows already admitted, which dedupe.
            let start = agent_wake::ChangeCursor::default();
            agent_wake::advance_change_cursor(db, &instance.id, token, Some(&after), &start)?;
            return Ok(());
        }
        let mutations =
            db.list_committed_object_mutations_after(&instance.namespace, after.seq, PAGE)?;
        let Some(last) = mutations.last().map(cursor_of) else {
            return Ok(());
        };
        let responsibility: std::collections::BTreeSet<&str> = instance
            .properties
            .get("responsibility")
            .map(String::as_str)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        let mut by_kind = BTreeMap::<String, Vec<CommittedObjectMutation>>::new();
        for mutation in mutations {
            if responsibility.contains(mutation.change.object_id.as_str()) {
                by_kind
                    .entry(mutation.object_kind.clone())
                    .or_default()
                    .push(mutation);
            }
        }
        let principals = instance
            .properties
            .get("principal_id")
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();
        for (kind, changes) in by_kind {
            let mut object_ids = changes
                .iter()
                .map(|mutation| mutation.change.object_id.clone())
                .collect::<Vec<_>>();
            object_ids.sort();
            object_ids.dedup();
            let mut visible = Vec::new();
            for id in &object_ids {
                if let Some(object) = self.readable_by(id, &principals)? {
                    visible.push(object);
                }
            }
            let scope = ObjectChangeScope {
                namespace: instance.namespace.clone(),
                kind,
                object_ids,
                property_filters: Vec::new(),
            };
            for event in project_events(&scope, &visible, &changes, 0, &HashMap::new())? {
                let Some(object) = visible.iter().find(|object| object.id == event.object_id)
                else {
                    continue;
                };
                let wakes = event.op == OP_CREATE
                    || (event.op == OP_UPDATE
                        && self.field_readable(schema, object, &event.field, &principals)?);
                if wakes {
                    agent_wake::admit_change(
                        db,
                        instance,
                        token,
                        debounce_ms,
                        event.committed_at_ms,
                        actor,
                        now_ms,
                    )?;
                }
            }
        }
        agent_wake::advance_change_cursor(db, &instance.id, token, Some(&after), &last)?;
        Ok(())
    }

    /// `id` as `principals` may read it now, or `None` when they may not.
    fn readable_by(
        &self,
        id: &str,
        principals: &[String],
    ) -> Result<Option<domain::Object>, String> {
        if principals.is_empty() {
            return Ok(None);
        }
        let db = self.db.runtime();
        let context = principal_policy_context_from(principals, None);
        let Some(object) = db.get_object_with_policy_context(id, &context)? else {
            return Ok(None);
        };
        match require_visible_object_contents(
            db,
            &self.security,
            object,
            principals,
            None,
            &format!("agent_change_wake:{id}"),
            None,
        ) {
            Ok((object, _)) => Ok(Some(object)),
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::NotFound | tonic::Code::PermissionDenied
                ) =>
            {
                Ok(None)
            }
            Err(status) => Err(status.message().to_string()),
        }
    }

    /// Whether `principals` may read the changed `field` of `object`. The
    /// change log names a property `properties.<name>`: a property grant
    /// must allow it, and a restricted property needs object admin. Other
    /// fields, such as the name, are read with the object.
    fn field_readable(
        &self,
        schema: &SchemaRegistry,
        object: &domain::Object,
        field: &str,
        principals: &[String],
    ) -> Result<bool, String> {
        let Some(field) = field.strip_prefix("properties.") else {
            return Ok(true);
        };
        match self
            .db
            .runtime()
            .active_object_policy(&object.namespace, &object.kind)
        {
            Ok(Some(policy))
                if !policy.allows_property_access(field, PropertyGrantAccess::Read) =>
            {
                return Ok(false);
            }
            Ok(_) => {}
            Err(error) if error.starts_with("object_security_denied") => return Ok(false),
            Err(error) => return Err(error),
        }
        let restricted = schema.get(&object.kind).is_some_and(|object_type| {
            object_type.properties.iter().any(|property| {
                property.name == field
                    && is_restricted_property_classification(&property.classification)
            })
        });
        Ok(!restricted || can_read_restricted_properties(&self.security, object, principals))
    }
}

fn cursor_of(mutation: &CommittedObjectMutation) -> agent_wake::ChangeCursor {
    agent_wake::ChangeCursor {
        seq: mutation.seq,
        change_id: mutation.change.id.clone(),
    }
}

/// The cursor naming the mutation at `seq`, if one is there.
fn mutation_at(
    db: &RuntimeDb,
    namespace: &str,
    seq: u64,
) -> Result<Option<agent_wake::ChangeCursor>, String> {
    if seq == 0 {
        return Ok(None);
    }
    Ok(db
        .list_committed_object_mutations_after(namespace, seq - 1, 1)?
        .first()
        .filter(|mutation| mutation.seq == seq)
        .map(cursor_of))
}
