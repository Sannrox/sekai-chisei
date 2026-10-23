//! Offline sync scopes (#1632, ADR 0124).
//!
//! A principal defines a scope: one object kind with property filters, and
//! optionally the objects linked to those by one relation, up to two hops.
//! A client takes a snapshot of the scope, then reads deltas from the cursor
//! the snapshot ends with.
//!
//! The server keeps a position per cursor: the authorization it was computed
//! under, and the scope's visible members at that point, each with a
//! fingerprint of the object as the caller read it. A delta read diffs the
//! stored members against the current ones: objects that join the scope or
//! read differently (a property, a computed value, a property grant) are
//! sent whole, and objects that leave it, become hidden or are deleted are
//! removed. Snapshot pages read the stored members in object id order, so a
//! resumed snapshot has no duplicates or gaps. A position records the
//! successor its first delta read produced, so a retried read returns the
//! same cursor until the client reads from that one.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SYNC_CONTRACT: &str = "sekai.sync/v1";
/// A delivered fingerprint that matches nothing, so the next delta resends
/// the object (or removes it).
pub const AMBIGUOUS: &str = "?";
/// Most objects a scope may hold, whatever its own quota says.
pub const MAX_SCOPE_OBJECTS: u32 = 5_000;
pub const MAX_PAGE: u32 = 100;
pub const DEFAULT_PAGE: u32 = 50;
pub const MAX_LINK_HOPS: u32 = 2;
const MAX_PROPERTY_FILTERS: usize = 4;
const FILTER_OPS: &[&str] = &["eq", "gt", "gte", "lt", "lte"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeFilter {
    pub key: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkDirection {
    Outgoing,
    Incoming,
}

/// Objects linked to the scope's roots by `relation`, up to `max_hops`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeLink {
    pub relation: String,
    pub direction: LinkDirection,
    pub max_hops: u32,
}

/// What a scope selects. Stored as JSON; the version is in the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeDefinition {
    pub kind: String,
    pub property_filters: Vec<ScopeFilter>,
    pub link: Option<ScopeLink>,
    /// The scope's own quota: snapshots and deltas refuse a scope with more
    /// visible members than this.
    pub max_objects: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncScope {
    pub namespace: String,
    pub owner: String,
    pub scope_id: String,
    pub definition: ScopeDefinition,
    pub updated_at_ms: i64,
}

/// A member as the client holds it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Member {
    pub object_id: String,
    /// Digest of the object as the caller read it.
    pub fingerprint: String,
}

/// A stored point a cursor names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPosition {
    pub position_id: String,
    pub namespace: String,
    pub owner: String,
    pub scope_id: String,
    pub authorization_pin: String,
    /// Visible members, sorted by id.
    pub members: Vec<Member>,
    /// The position the first delta read from here produced: the stable
    /// transition every retry of this cursor answers with.
    pub successor: Option<String>,
    /// The cursor whose delta read produced this one.
    pub origin: Option<String>,
    /// What responses ending at this position delivered, by object id,
    /// where it differs from `members`: the delivered fingerprint, empty
    /// when the object could not be sent, or [`AMBIGUOUS`] when two answers
    /// disagreed and the server cannot know which the client kept.
    pub delivered: BTreeMap<String, String>,
}

impl SyncPosition {
    /// The members as the client holds them after the last response that
    /// ended here.
    pub fn baseline(&self) -> Vec<Member> {
        self.members
            .iter()
            .filter_map(|member| match self.delivered.get(&member.object_id) {
                None => Some(member.clone()),
                Some(fingerprint) if fingerprint.is_empty() => None,
                Some(fingerprint) => Some(Member {
                    object_id: member.object_id.clone(),
                    fingerprint: fingerprint.clone(),
                }),
            })
            .chain(
                self.delivered
                    .iter()
                    .filter(|(id, fingerprint)| {
                        !fingerprint.is_empty()
                            && !self.members.iter().any(|member| &member.object_id == *id)
                    })
                    .map(|(id, fingerprint)| Member {
                        object_id: id.clone(),
                        fingerprint: fingerprint.clone(),
                    }),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    Invalid(String),
    NotFound,
    Storage(String),
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
}

impl ScopeDefinition {
    pub fn validate(&self) -> Result<(), String> {
        if !token(&self.kind) {
            return Err("kind must be 1 to 128 letters, digits, `_`, `-`, `.` or `:`".into());
        }
        if self.property_filters.len() > MAX_PROPERTY_FILTERS {
            return Err(format!(
                "a scope has at most {MAX_PROPERTY_FILTERS} property filters"
            ));
        }
        for filter in &self.property_filters {
            if !token(&filter.key) || !FILTER_OPS.contains(&filter.op.as_str()) {
                return Err(format!(
                    "property filter `{}` needs a key and one of {}",
                    filter.key,
                    FILTER_OPS.join(", ")
                ));
            }
        }
        if let Some(link) = &self.link
            && (!token(&link.relation) || !(1..=MAX_LINK_HOPS).contains(&link.max_hops))
        {
            return Err(format!(
                "a link needs a relation and 1 to {MAX_LINK_HOPS} hops"
            ));
        }
        if !(1..=MAX_SCOPE_OBJECTS).contains(&self.max_objects) {
            return Err(format!(
                "max_objects must be between 1 and {MAX_SCOPE_OBJECTS}"
            ));
        }
        Ok(())
    }
}

pub fn validate_scope_id(scope_id: &str) -> Result<(), String> {
    if token(scope_id) {
        Ok(())
    } else {
        Err("scope_id must be 1 to 128 letters, digits, `_`, `-`, `.` or `:`".into())
    }
}

/// What a delta read sends: members to send whole and members to drop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemberDiff {
    pub upserts: Vec<String>,
    pub removes: Vec<String>,
}

/// The diff from `before` to `after`: members that are new or read
/// differently, and members that are gone. Output is sorted by id.
pub fn diff_members(before: &[Member], after: &[Member]) -> MemberDiff {
    let before: BTreeMap<&str, &str> = before
        .iter()
        .map(|member| (member.object_id.as_str(), member.fingerprint.as_str()))
        .collect();
    let after_ids: BTreeSet<&str> = after
        .iter()
        .map(|member| member.object_id.as_str())
        .collect();
    MemberDiff {
        upserts: after
            .iter()
            .filter(|member| {
                before.get(member.object_id.as_str()) != Some(&member.fingerprint.as_str())
            })
            .map(|member| member.object_id.clone())
            .collect(),
        removes: before
            .keys()
            .filter(|id| !after_ids.contains(*id))
            .map(|id| id.to_string())
            .collect(),
    }
}

/// At most `limit` changes of `diff`: upserts first, then removals.
pub fn page(diff: &MemberDiff, limit: usize) -> MemberDiff {
    let upserts: Vec<String> = diff.upserts.iter().take(limit).cloned().collect();
    let removes = diff
        .removes
        .iter()
        .take(limit - upserts.len())
        .cloned()
        .collect();
    MemberDiff { upserts, removes }
}

/// The members a client holds after applying `sent`: what was not sent yet
/// stays as it was, so the next read sends it.
pub fn advance(before: &[Member], after: &[Member], sent: &MemberDiff) -> Vec<Member> {
    let removed: BTreeSet<&str> = sent.removes.iter().map(String::as_str).collect();
    let sent: BTreeSet<&String> = sent.upserts.iter().collect();
    let mut held: BTreeMap<String, String> = before
        .iter()
        .filter(|member| !removed.contains(member.object_id.as_str()))
        .map(|member| (member.object_id.clone(), member.fingerprint.clone()))
        .collect();
    for member in after
        .iter()
        .filter(|member| sent.contains(&member.object_id))
    {
        held.insert(member.object_id.clone(), member.fingerprint.clone());
    }
    held.into_iter()
        .map(|(object_id, fingerprint)| Member {
            object_id,
            fingerprint,
        })
        .collect()
}

/// Snapshot page token: the position and the last member sent.
pub fn snapshot_token(position_id: &str, after: &str) -> String {
    format!("{position_id}/{after}")
}

pub fn parse_snapshot_token(token: &str) -> Result<(&str, &str), SyncError> {
    token
        .split_once('/')
        .ok_or_else(|| SyncError::Invalid("malformed snapshot page token".into()))
}

fn hex16(digest: &[u8]) -> String {
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A fingerprint of `parts`, length-prefixed so no two inputs collide.
pub fn fingerprint<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex16(&hasher.finalize())
}

/// The position id a cursor names: a digest of everything it holds, plus a
/// distinguisher so two reads that land on the same state still get distinct
/// cursors.
pub fn position_id(
    namespace: &str,
    owner: &str,
    scope_id: &str,
    pin: &str,
    members: &[Member],
    distinguisher: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let parts = [namespace, owner, scope_id, pin, distinguisher]
        .into_iter()
        .chain(
            members
                .iter()
                .flat_map(|member| [member.object_id.as_str(), member.fingerprint.as_str()]),
        );
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("pos-{}", hex16(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition() -> ScopeDefinition {
        ScopeDefinition {
            kind: "WorkOrder".into(),
            property_filters: vec![ScopeFilter {
                key: "site".into(),
                op: "eq".into(),
                value: "north".into(),
            }],
            link: Some(ScopeLink {
                relation: "located_at".into(),
                direction: LinkDirection::Outgoing,
                max_hops: 1,
            }),
            max_objects: 100,
        }
    }

    #[test]
    fn definitions_are_bounded() {
        assert!(definition().validate().is_ok());
        let cases = [
            ScopeDefinition {
                kind: String::new(),
                ..definition()
            },
            ScopeDefinition {
                max_objects: 0,
                ..definition()
            },
            ScopeDefinition {
                max_objects: MAX_SCOPE_OBJECTS + 1,
                ..definition()
            },
            ScopeDefinition {
                link: Some(ScopeLink {
                    relation: "located_at".into(),
                    direction: LinkDirection::Incoming,
                    max_hops: 3,
                }),
                ..definition()
            },
            ScopeDefinition {
                property_filters: vec![ScopeFilter {
                    key: "site".into(),
                    op: "like".into(),
                    value: "n%".into(),
                }],
                ..definition()
            },
        ];
        for case in cases {
            assert!(case.validate().is_err(), "{case:?}");
        }
    }

    fn members(values: &[(&str, &str)]) -> Vec<Member> {
        values
            .iter()
            .map(|(object_id, fingerprint)| Member {
                object_id: object_id.to_string(),
                fingerprint: fingerprint.to_string(),
            })
            .collect()
    }

    #[test]
    fn diffs_send_joiners_and_changes_and_drop_leavers() {
        let before = members(&[("a", "1"), ("b", "1"), ("c", "1")]);
        let after = members(&[("b", "2"), ("c", "1"), ("d", "1")]);
        let diff = diff_members(&before, &after);
        assert_eq!(diff.upserts, ["b", "d"]);
        assert_eq!(diff.removes, ["a"]);
        assert_eq!(diff_members(&after, &after), MemberDiff::default());
        // A page of one sends `b` only; `d` and the removal of `a` wait.
        let first = page(&diff, 1);
        assert_eq!(
            (first.upserts.as_slice(), first.removes.len()),
            (&["b".to_string()][..], 0)
        );
        let held = advance(&before, &after, &first);
        assert_eq!(held, members(&[("a", "1"), ("b", "2"), ("c", "1")]));
        let rest = diff_members(&held, &after);
        assert_eq!(
            (rest.upserts, rest.removes),
            (vec!["d".to_string()], vec!["a".to_string()])
        );
        assert_eq!(page(&diff, 2).removes, Vec::<String>::new());
        assert_eq!(page(&diff, 3).removes, ["a"]);
    }

    #[test]
    fn positions_name_their_whole_state() {
        let held = members(&[("a", "1")]);
        let base = position_id("ns", "alice", "s", "pin", &held, "n");
        assert_eq!(base, position_id("ns", "alice", "s", "pin", &held, "n"));
        assert_ne!(base, position_id("ns", "alice", "s", "pin", &held, "m"));
        assert_ne!(base, position_id("ns", "bob", "s", "pin", &held, "n"));
        assert_ne!(base, position_id("ns", "alice", "s", "pin2", &held, "n"));
        assert_ne!(
            base,
            position_id("ns", "alice", "s", "pin", &members(&[("a", "2")]), "n")
        );
        assert_ne!(fingerprint(["ab", "c"]), fingerprint(["a", "bc"]));
        let token = snapshot_token(&base, "obj-1");
        assert_eq!(
            parse_snapshot_token(&token).unwrap(),
            (base.as_str(), "obj-1")
        );
    }
}
