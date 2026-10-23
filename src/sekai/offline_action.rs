//! Governed Actions prepared on a disconnected device (#1580, ADR 0127).
//!
//! A device prepares an Action offline and submits it later, perhaps hours
//! later, through the ordinary submit path. The submission names what the
//! device saw: the bound object's update time (its base version) and the
//! values of the properties the Action writes. Policy is decided when the
//! Action arrives, never on the device. If the object changed since the
//! base, the Action type's conflict rule decides:
//!
//! - `reject_any` (the default): any change is a conflict.
//! - `reject_touched`: a conflict only if a property the Action writes
//!   changed.
//! - `last_writer_wins`: like `reject_touched`, except that the declared
//!   properties may be overwritten.
//!
//! A conflict is stored on the instance, which is denied with
//! [`CONFLICT_REASON`], so a retry with the same idempotency key returns the
//! same outcome.

use crate::domain::Object;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CONFLICT_REJECT_ANY: &str = "reject_any";
pub const CONFLICT_REJECT_TOUCHED: &str = "reject_touched";
pub const CONFLICT_LAST_WRITER_WINS: &str = "last_writer_wins";
/// `deny_reason` of an instance refused because its base is stale.
pub const CONFLICT_REASON: &str = "offline_conflict";
/// How far a prepare time may lie ahead of the plane's clock.
const PREPARED_SKEW_MS: i64 = 5 * 60 * 1000;

/// What a device saw when it prepared the Action, and how it submits it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineSubmission {
    pub prepared_at_ms: i64,
    /// The bound object's update time when the device read it.
    pub base_updated_ms: i64,
    /// What the device saw for each field the Action writes (its
    /// properties, and `name` when it renames); `None` when absent.
    #[serde(default)]
    pub base_properties: BTreeMap<String, Option<String>>,
    /// The offline lease the device prepared under (#102), if any.
    #[serde(default)]
    pub lease_id: String,
    /// The device that submitted, from its device-bound assertion. Set by
    /// the plane, never by the device.
    #[serde(default)]
    pub device_id: String,
}

/// Why an offline Action was not applied: the object moved past its base.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionConflict {
    pub object_id: String,
    pub base_updated_ms: i64,
    pub current_updated_ms: i64,
    /// The written properties whose current values differ from the base.
    /// Empty under `reject_any`, which compares versions only.
    pub properties: Vec<String>,
}

/// Check an Action type's conflict rule and its last-writer-wins
/// properties.
pub fn validate_rule(rule: &str, last_writer_wins: &[String]) -> Result<(), String> {
    match rule {
        "" | CONFLICT_REJECT_ANY | CONFLICT_REJECT_TOUCHED => {
            if !last_writer_wins.is_empty() {
                return Err(
                    "last_writer_wins_properties need offline_conflict last_writer_wins".into(),
                );
            }
        }
        CONFLICT_LAST_WRITER_WINS => {
            if last_writer_wins.is_empty() {
                return Err(
                    "offline_conflict last_writer_wins needs last_writer_wins_properties".into(),
                );
            }
            if let Some(key) = last_writer_wins
                .iter()
                .find(|key| !crate::domain::is_valid_property_key(key))
            {
                return Err(format!("invalid last_writer_wins property {key}"));
            }
        }
        other => {
            return Err(format!(
                "unknown offline_conflict {other:?}: expected reject_any, reject_touched or last_writer_wins"
            ));
        }
    }
    Ok(())
}

/// The field an Action writes as `current` holds it now. `name` is the
/// object's name; an Action cannot write a property of that name.
fn current_value<'a>(current: &'a Object, key: &str) -> Option<&'a str> {
    if key == NAME_FIELD {
        Some(current.name.as_str())
    } else {
        current.properties.get(key).map(String::as_str)
    }
}

/// The written field that is the object's name, not a property.
pub const NAME_FIELD: &str = "name";

impl OfflineSubmission {
    /// Check the submission before anything is decided: a prepare time no
    /// later than now, a base, and a base value for every field the Action
    /// writes.
    pub fn validate(&self, touched: &BTreeSet<String>, now_ms: i64) -> Result<(), String> {
        if self.prepared_at_ms <= 0 || self.prepared_at_ms > now_ms + PREPARED_SKEW_MS {
            return Err("offline prepared_at_ms must be a time before now".into());
        }
        if self.base_updated_ms <= 0 {
            return Err("offline base_updated_ms required".into());
        }
        if self.lease_id.len() > 256 || self.lease_id.chars().any(char::is_whitespace) {
            return Err(
                "offline lease_id must be at most 256 characters with no whitespace".into(),
            );
        }
        // Every rule compares the written fields, so each needs its base.
        if let Some(missing) = touched
            .iter()
            .find(|key| !self.base_properties.contains_key(*key))
        {
            return Err(format!(
                "offline base_properties must include every property the Action writes; missing {missing}"
            ));
        }
        Ok(())
    }

    /// The conflict, if any, between this base and `current` under `rule`.
    pub fn conflict(
        &self,
        rule: &str,
        last_writer_wins: &[String],
        current: &Object,
        touched: &BTreeSet<String>,
    ) -> Option<ActionConflict> {
        // Versions are update times in milliseconds, so two writes within
        // one millisecond share one. The written fields the device sent are
        // therefore compared even when the version matches.
        let changed = || -> Vec<String> {
            touched
                .iter()
                .filter(|key| {
                    current_value(current, key)
                        != self.base_properties.get(*key).and_then(Option::as_deref)
                })
                .filter(|key| rule != CONFLICT_LAST_WRITER_WINS || !last_writer_wins.contains(*key))
                .cloned()
                .collect()
        };
        let properties = match rule {
            CONFLICT_REJECT_TOUCHED | CONFLICT_LAST_WRITER_WINS => {
                let properties = changed();
                if properties.is_empty() {
                    return None;
                }
                properties
            }
            _ => {
                // `reject_any`: a moved version conflicts, and so does any
                // written field the device saw differently.
                let properties: Vec<String> = touched
                    .iter()
                    .filter(|key| self.base_properties.contains_key(*key))
                    .filter(|key| {
                        current_value(current, key)
                            != self.base_properties.get(*key).and_then(Option::as_deref)
                    })
                    .cloned()
                    .collect();
                if current.updated == self.base_updated_ms && properties.is_empty() {
                    return None;
                }
                properties
            }
        };
        Some(ActionConflict {
            object_id: current.id.clone(),
            base_updated_ms: self.base_updated_ms,
            current_updated_ms: current.updated,
            properties,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(updated: i64, status: &str, note: &str) -> Object {
        Object {
            id: "ticket-1".into(),
            kind: "ticket".into(),
            name: "ticket-1".into(),
            namespace: "field".into(),
            external_id: String::new(),
            properties: [
                ("status".into(), status.into()),
                ("note".into(), note.into()),
            ]
            .into(),
            created: 1,
            updated,
        }
    }

    fn base() -> OfflineSubmission {
        OfflineSubmission {
            prepared_at_ms: 10,
            base_updated_ms: 100,
            base_properties: [("status".into(), Some("open".into()))].into(),
            ..Default::default()
        }
    }

    #[test]
    fn each_rule_decides_a_stale_base() {
        let touched = BTreeSet::from(["status".to_string()]);
        let base = base();
        // Unchanged since the base: no rule conflicts.
        for rule in ["", CONFLICT_REJECT_TOUCHED] {
            assert_eq!(
                base.conflict(rule, &[], &object(100, "open", "a"), &touched),
                None
            );
        }
        // Another property changed.
        let other = object(200, "open", "b");
        let strict = base
            .conflict(CONFLICT_REJECT_ANY, &[], &other, &touched)
            .unwrap();
        assert_eq!(
            (strict.base_updated_ms, strict.current_updated_ms),
            (100, 200)
        );
        assert_eq!(
            base.conflict(CONFLICT_REJECT_TOUCHED, &[], &other, &touched),
            None
        );
        // The written property changed.
        let touched_change = object(200, "closed", "a");
        assert_eq!(
            base.conflict(CONFLICT_REJECT_TOUCHED, &[], &touched_change, &touched)
                .unwrap()
                .properties,
            ["status"]
        );
        let lww = ["status".to_string()];
        assert_eq!(
            base.conflict(CONFLICT_LAST_WRITER_WINS, &lww, &touched_change, &touched),
            None
        );
    }

    #[test]
    fn a_written_field_changed_within_the_base_millisecond_conflicts() {
        let touched = BTreeSet::from(["status".to_string()]);
        // Same update time as the base, but the written field differs.
        let same_ms = object(100, "closed", "a");
        for rule in [CONFLICT_REJECT_ANY, CONFLICT_REJECT_TOUCHED] {
            assert_eq!(
                base()
                    .conflict(rule, &[], &same_ms, &touched)
                    .unwrap()
                    .properties,
                ["status"],
                "{rule}"
            );
        }
    }

    #[test]
    fn absent_fields_and_renames_are_compared() {
        let touched = BTreeSet::from(["flag".to_string(), NAME_FIELD.to_string()]);
        let base = OfflineSubmission {
            base_properties: [
                ("flag".to_string(), None),
                (NAME_FIELD.to_string(), Some("ticket-1".into())),
            ]
            .into(),
            ..base()
        };
        // Still absent and not renamed: another change does not conflict.
        assert_eq!(
            base.conflict(
                CONFLICT_REJECT_TOUCHED,
                &[],
                &object(200, "x", "y"),
                &touched
            ),
            None
        );
        let mut renamed = object(200, "open", "a");
        renamed.name = "renamed".into();
        assert_eq!(
            base.conflict(CONFLICT_REJECT_TOUCHED, &[], &renamed, &touched)
                .unwrap()
                .properties,
            [NAME_FIELD]
        );
        let mut flagged = object(200, "open", "a");
        flagged.properties.insert("flag".into(), String::new());
        assert_eq!(
            base.conflict(CONFLICT_REJECT_TOUCHED, &[], &flagged, &touched)
                .unwrap()
                .properties,
            ["flag"]
        );
    }

    #[test]
    fn submissions_and_rules_are_validated() {
        let touched = BTreeSet::from(["status".to_string(), "note".to_string()]);
        // A written field without its base is refused under every rule.
        let refused = base().validate(&touched, 1_000).unwrap_err();
        assert!(refused.contains("missing note"), "{refused}");
        let future = OfflineSubmission {
            prepared_at_ms: 1_000_000_000,
            ..base()
        };
        assert!(future.validate(&BTreeSet::new(), 1_000).is_err());
        assert!(
            base()
                .validate(&BTreeSet::from(["status".to_string()]), 1_000)
                .is_ok()
        );
        assert!(validate_rule(CONFLICT_LAST_WRITER_WINS, &[]).is_err());
        assert!(validate_rule(CONFLICT_REJECT_ANY, &["status".into()]).is_err());
        assert!(validate_rule("merge", &[]).is_err());
        assert!(validate_rule(CONFLICT_LAST_WRITER_WINS, &["status".into()]).is_ok());
    }
}
