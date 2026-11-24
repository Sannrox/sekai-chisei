//! ObjectSet membership over object-change subscription cursors (#3038).
//!
//! A subscription names a set descriptor instead of a scope. After a
//! resnapshot the client starts empty: the first pages deliver the set as
//! `enter` events. Later pages re-evaluate, as the reader, the objects the
//! scanned history touched and report `enter` and `leave` against the member
//! ids stored with the cursor.
//! The member ids are one reader's delivery state, not a stored set: they are
//! written in the cursor's transaction and dropped on revoke.

use std::collections::{BTreeMap, BTreeSet};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::event_subscription::{
    EventSubscription, EventSubscriptionCursor, SUBSCRIBE_UNAVAILABLE,
};
use crate::sekai::object_change_subscription::{
    Admission, Admitted, MAX_BACKLOG, OP_ENTER, OP_LEAVE, OUTCOME_PAGE, OUTCOME_RESNAPSHOT,
    ObjectChangeEvent, ObjectChangePage, ObjectChangeReadRequest, admit, empty_page, mutation_kind,
    page_digest, page_limit, restart_for_resnapshot,
};

/// The most members a subscribed set may hold; a larger set is refused.
pub const MAX_MEMBERS: usize = 1_000;
pub const MEMBERSHIP_TOO_LARGE: &str = "object-set membership exceeds 1000 members";

/// The member ids a subscription has delivered, pinned to the snapshot
/// revision and reader (`epoch`) they were evaluated for, plus the snapshot
/// ids still to deliver as enters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSetMembership {
    pub epoch: String,
    pub member_ids: Vec<String>,
    pub pending_ids: Vec<String>,
}

/// Reads one membership page. `request.scope` names the namespace and member
/// kind with no ids or filters; the descriptor lives in `authorization_pin`,
/// so a changed descriptor restarts the subscription.
///
/// `evaluate(None)` returns every member id visible to the reader;
/// `evaluate(Some(ids))` returns which of `ids` are members now. Both must
/// be evaluated as the reader, so an object they may not read is never one.
pub fn read_object_set_membership<F>(
    db: &RuntimeDb,
    actor: &str,
    request: &ObjectChangeReadRequest,
    now_ms: i64,
    authorization_pin: &str,
    mut evaluate: F,
) -> Result<ObjectChangePage, String>
where
    F: FnMut(Option<&[String]>) -> Result<Vec<String>, String>,
{
    let Admitted {
        scope,
        subscription,
        admitted_watermark,
        live_revision,
    } = match admit(db, actor, request, now_ms, authorization_pin)? {
        Admission::Page(page) => {
            if page.outcome == OUTCOME_RESNAPSHOT {
                store_baseline(
                    db,
                    actor,
                    request,
                    &epoch(&page.snapshot_revision, authorization_pin),
                    &mut evaluate,
                )?;
            }
            return Ok(page);
        }
        Admission::Ready(admitted) => admitted,
    };
    let Some(membership) = db
        .get_object_set_membership(&scope.namespace, &request.subscription_id)?
        .filter(|membership| {
            membership.epoch == epoch(&request.snapshot_revision, authorization_pin)
        })
    else {
        // No baseline for this revision: lost, or another reader's. Restart
        // rather than guess what the client already holds.
        let page = restart_for_resnapshot(db, &subscription, now_ms, live_revision)?;
        store_baseline(
            db,
            actor,
            request,
            &epoch(&page.snapshot_revision, authorization_pin),
            &mut evaluate,
        )?;
        return Ok(page);
    };

    let after_seq = if subscription.cursor.committed_offset > 0 {
        subscription.cursor.committed_offset
    } else {
        admitted_watermark
    };
    let limit = page_limit(request.limit);
    let mut pending = membership.pending_ids;
    let mut members: BTreeSet<String> = membership.member_ids.into_iter().collect();
    let mut events = Vec::new();
    let mut scanned_to = after_seq;
    // The snapshot is delivered first, as enters re-checked as the reader,
    // so what the client holds is exactly the stored member ids.
    while events.is_empty() && !pending.is_empty() {
        let chunk = pending
            .drain(..limit.min(pending.len()))
            .collect::<Vec<_>>();
        for object_id in evaluate(Some(&chunk))? {
            if members.insert(object_id.clone()) {
                events.push(ObjectChangeEvent {
                    offset: after_seq,
                    event_id: format!("snapshot:{object_id}"),
                    object_id,
                    kind: scope.kind.clone(),
                    op: OP_ENTER.into(),
                    ..ObjectChangeEvent::default()
                });
            }
        }
    }
    if events.is_empty() && pending.is_empty() {
        let raw = db.list_committed_object_mutations_after(
            &scope.namespace,
            after_seq,
            i32::try_from(MAX_BACKLOG).map_err(|error| error.to_string())?,
        )?;
        // Scan a prefix touching at most `limit` member-kind objects. Events
        // re-evaluate current state, so any prefix is a consistent page.
        let mut last_touch: BTreeMap<String, (u64, String, i64)> = BTreeMap::new();
        for mutation in &raw {
            if mutation_kind(mutation) == scope.kind {
                let object_id = &mutation.change.object_id;
                if !last_touch.contains_key(object_id) && last_touch.len() == limit {
                    break;
                }
                last_touch.insert(
                    object_id.clone(),
                    (
                        mutation.seq,
                        mutation.change.id.clone(),
                        mutation.change.timestamp,
                    ),
                );
            }
            scanned_to = mutation.seq;
        }
        if !last_touch.is_empty() {
            let candidates = last_touch.keys().cloned().collect::<Vec<_>>();
            let now: BTreeSet<String> = evaluate(Some(&candidates))?.into_iter().collect();
            let operation_ids = crate::sekai::operation_correlation::operation_ids_for_objects(
                db,
                &last_touch.keys().cloned().collect(),
            )?;
            for (object_id, (seq, change_id, committed_at_ms)) in last_touch {
                let is_member = now.contains(&object_id);
                let op = match (members.contains(&object_id), is_member) {
                    (false, true) => OP_ENTER,
                    (true, false) => OP_LEAVE,
                    _ => continue,
                };
                if is_member {
                    members.insert(object_id.clone());
                } else {
                    members.remove(&object_id);
                }
                events.push(ObjectChangeEvent {
                    offset: seq,
                    event_id: change_id,
                    // A leave names only the object: the reader may no
                    // longer see it.
                    operation_id: if is_member {
                        operation_ids.get(&object_id).cloned().unwrap_or_default()
                    } else {
                        String::new()
                    },
                    object_id,
                    kind: scope.kind.clone(),
                    op: op.into(),
                    committed_at_ms,
                    ..ObjectChangeEvent::default()
                });
            }
        }
    }
    if members.len() > MAX_MEMBERS {
        return Err(MEMBERSHIP_TOO_LARGE.into());
    }
    events.sort_by_key(|event| event.offset);

    let next_membership = ObjectSetMembership {
        epoch: membership.epoch,
        member_ids: members.into_iter().collect(),
        pending_ids: pending,
    };
    let generation = subscription.cursor.generation.max(1);
    let digest = if events.is_empty() {
        subscription.cursor.last_page_digest.clone()
    } else {
        page_digest(
            &subscription.subscription_id,
            &subscription.stream_id,
            generation,
            &request.snapshot_revision,
            events.first().map(|event| event.offset).unwrap_or(1),
            events.last().map(|event| event.offset).unwrap_or(1),
            &events,
        )?
    };
    let next = EventSubscription {
        cursor: EventSubscriptionCursor {
            generation,
            feed_epoch: request.snapshot_revision.clone(),
            committed_offset: scanned_to,
            last_page_digest: digest.clone(),
            admitted_at_ms: now_ms,
        },
        ..subscription.clone()
    };
    db.advance_event_subscription_cursor_with_membership(&next, &subscription, &next_membership)?;
    if events.is_empty() {
        return Ok(empty_page(&next, &request.snapshot_revision));
    }
    Ok(ObjectChangePage {
        outcome: OUTCOME_PAGE.into(),
        generation,
        committed_offset: scanned_to,
        page_digest: digest,
        events,
        ..empty_page(&next, &request.snapshot_revision)
    })
}

/// A baseline's epoch: the snapshot revision plus the reader's
/// authorization pin, so one reader's members never seed another's page.
fn epoch(revision: &str, authorization_pin: &str) -> String {
    format!("{revision}#{authorization_pin}")
}

/// Evaluates the whole set as the reader and stores it as the snapshot the
/// next pages deliver as enters, the client starting from an empty set.
/// Evaluated after the revision's watermark was read, so a change in between
/// is re-evaluated when the history scan reaches it. A subscription id
/// another principal owns is left untouched.
fn store_baseline<F>(
    db: &RuntimeDb,
    actor: &str,
    request: &ObjectChangeReadRequest,
    epoch: &str,
    evaluate: &mut F,
) -> Result<(), String>
where
    F: FnMut(Option<&[String]>) -> Result<Vec<String>, String>,
{
    if db
        .get_event_subscription(&request.scope.namespace, &request.subscription_id)?
        .is_some_and(|existing| existing.owner != actor)
    {
        return Err(SUBSCRIBE_UNAVAILABLE.into());
    }
    let mut member_ids = evaluate(None)?;
    member_ids.sort_unstable();
    member_ids.dedup();
    if member_ids.len() > MAX_MEMBERS {
        return Err(MEMBERSHIP_TOO_LARGE.into());
    }
    db.put_object_set_membership(
        &request.scope.namespace,
        &request.subscription_id,
        &ObjectSetMembership {
            epoch: epoch.into(),
            member_ids: Vec::new(),
            pending_ids: member_ids,
        },
    )
}
