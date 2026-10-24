//! Comment threads on objects (#1442).
//!
//! A comment is a reserved governance object (`object_comment`). It lives
//! outside every namespace, as action policies do, so it never counts as an
//! instantiated kind for policy activation; `target_namespace` records where
//! its target lives. Generic object reads never return it; the comment RPCs show it
//! only to callers who can read the target, and the anchored property when
//! there is one. Every write goes through the audited object path: the change
//! log records the creation and each later change with old and new values,
//! so with the current values it is the whole history, and its entries are
//! the receipts.
//!
//! When a comment is written, the properties whose values its body quotes
//! are recorded with a digest of each value, judged only against what the
//! writer can see: a guess at a hidden value is never matched, so a comment
//! is no oracle for hidden values. A reader gets the body only if they can
//! see every quoted property with the same value now; otherwise it is
//! redacted, so a later value change never reveals an old quote.

use std::collections::BTreeSet;

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{ListFilter, MAX_LIST_LIMIT, Object, PropertyFilter, is_valid_property_key};

pub const OBJECT_COMMENT_KIND: &str = "object_comment";
pub const MAX_COMMENT_BODY_BYTES: usize = 8 * 1024;
pub const MAX_COMMENT_MENTIONS: usize = 32;
/// Comments read for one target or one mention listing. More fail closed.
pub const MAX_COMMENTS_READ: usize = 10_000;
pub const REDACTED_BODY: &str = "[redacted: quotes a property you cannot read]";
/// Property values shorter than this are not treated as quoted: matching them
/// would flag ordinary words.
const MIN_QUOTED_VALUE_CHARS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectComment {
    pub id: String,
    pub namespace: String,
    pub target_object_id: String,
    /// Empty when the comment is on the whole object.
    pub target_property: String,
    pub body: String,
    pub author: String,
    pub mentions: Vec<String>,
    /// `key:digest` of each target property value the body quoted when it
    /// was written, sorted.
    pub quoted_properties: Vec<String>,
    pub resolved: bool,
    pub resolved_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentError {
    Invalid(String),
    /// Another writer changed the comment since it was read.
    Conflict,
    Storage(String),
}

/// Validate a body and mention list, returning mentions sorted and deduplicated.
pub fn validate_content(body: &str, mentions: &[String]) -> Result<Vec<String>, CommentError> {
    if body.trim().is_empty() {
        return Err(CommentError::Invalid("comment body is required".into()));
    }
    if body.len() > MAX_COMMENT_BODY_BYTES {
        return Err(CommentError::Invalid(format!(
            "comment body must be at most {MAX_COMMENT_BODY_BYTES} bytes"
        )));
    }
    let mentions: BTreeSet<String> = mentions.iter().map(|m| m.trim().to_string()).collect();
    if mentions.len() > MAX_COMMENT_MENTIONS {
        return Err(CommentError::Invalid(format!(
            "a comment mentions at most {MAX_COMMENT_MENTIONS} principals"
        )));
    }
    if let Some(bad) = mentions.iter().find(|mention| {
        mention.is_empty()
            || !mention
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.:@".contains(c))
    }) {
        return Err(CommentError::Invalid(format!(
            "invalid mentioned principal {bad:?}"
        )));
    }
    Ok(mentions.into_iter().collect())
}

pub fn validate_target_property(property: &str) -> Result<(), CommentError> {
    if property.is_empty() || is_valid_property_key(property) {
        Ok(())
    } else {
        Err(CommentError::Invalid(
            "comment property is not a valid key".into(),
        ))
    }
}

/// Lists stored as `,a,b,` so `contains ",a,"` finds an entry on both backends.
fn list_index(items: &[String]) -> String {
    format!(",{},", items.join(","))
}

fn parse_list(index: &str) -> Vec<String> {
    index
        .split(',')
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn value_digest(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `key:digest` for each of `visible` (the writer's view of the target)
/// whose value `body` quotes, sorted.
pub fn quoted_properties(
    body: &str,
    visible: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let mut quoted: Vec<String> = visible
        .iter()
        .filter(|(_, value)| {
            value.chars().count() >= MIN_QUOTED_VALUE_CHARS && body.contains(value.as_str())
        })
        .map(|(key, value)| format!("{key}:{}", value_digest(value)))
        .collect();
    quoted.sort();
    quoted
}

/// The body as a reader with `visible` (their view of the target) may read
/// it: whole for the author, otherwise redacted unless every quoted property
/// is visible with the value it had when quoted.
pub fn body_for(
    comment: &ObjectComment,
    viewer: &str,
    visible: &std::collections::HashMap<String, String>,
) -> String {
    let still_visible = |quote: &String| {
        quote.split_once(':').is_some_and(|(key, digest)| {
            visible
                .get(key)
                .is_some_and(|value| value_digest(value) == digest)
        })
    };
    if comment.author == viewer || comment.quoted_properties.iter().all(still_visible) {
        comment.body.clone()
    } else {
        REDACTED_BODY.into()
    }
}

impl ObjectComment {
    fn to_object(&self) -> Object {
        let properties = [
            ("target_namespace", self.namespace.clone()),
            ("target_object_id", self.target_object_id.clone()),
            ("target_property", self.target_property.clone()),
            ("body", self.body.clone()),
            ("author", self.author.clone()),
            ("mentions", list_index(&self.mentions)),
            ("quoted_properties", list_index(&self.quoted_properties)),
            ("resolved", self.resolved.to_string()),
            ("resolved_by", self.resolved_by.clone()),
        ];
        Object {
            id: self.id.clone(),
            kind: OBJECT_COMMENT_KIND.into(),
            name: String::new(),
            namespace: String::new(),
            external_id: self.id.clone(),
            properties: properties
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
            created: self.created_at_ms,
            updated: self.updated_at_ms,
        }
    }

    fn from_object(object: &Object) -> Option<Self> {
        if object.kind != OBJECT_COMMENT_KIND {
            return None;
        }
        let property = |key: &str| object.properties.get(key).cloned().unwrap_or_default();
        Some(Self {
            id: object.id.clone(),
            namespace: property("target_namespace"),
            target_object_id: property("target_object_id"),
            target_property: property("target_property"),
            body: property("body"),
            author: property("author"),
            mentions: parse_list(&property("mentions")),
            quoted_properties: parse_list(&property("quoted_properties")),
            resolved: property("resolved") == "true",
            resolved_by: property("resolved_by"),
            created_at_ms: object.created,
            updated_at_ms: object.updated,
        })
    }
}

pub fn get(db: &RuntimeDb, comment_id: &str) -> Result<Option<ObjectComment>, String> {
    Ok(db
        .get_object(comment_id)?
        .as_ref()
        .and_then(ObjectComment::from_object))
}

pub fn create(db: &RuntimeDb, comment: &ObjectComment) -> Result<(), CommentError> {
    db.create_object_with_audit(&comment.to_object(), &comment.author)
        .map_err(CommentError::Storage)
}

/// Replace `previous` with `next`, failing with `Conflict` if the stored
/// comment is no longer `previous`.
pub fn update(
    db: &RuntimeDb,
    previous: &ObjectComment,
    next: &ObjectComment,
    actor: &str,
) -> Result<(), CommentError> {
    db.update_object_with_authorized_snapshot(
        &next.to_object(),
        Some(&previous.to_object()),
        actor,
        None,
    )
    .map_err(|error| {
        if error.contains(crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION) {
            CommentError::Conflict
        } else {
            CommentError::Storage(error)
        }
    })?
    .ok_or(CommentError::Conflict)
    .map(|_| ())
}

fn list(
    db: &RuntimeDb,
    namespace: &str,
    filter: PropertyFilter,
) -> Result<Vec<ObjectComment>, String> {
    let in_namespace = PropertyFilter {
        key: "target_namespace".into(),
        op: "eq".into(),
        value: namespace.into(),
    };
    let mut comments = Vec::new();
    loop {
        let page = db.list_objects(&ListFilter {
            kind: Some(OBJECT_COMMENT_KIND.into()),
            namespace: Some(String::new()),
            property_filters: vec![in_namespace.clone(), filter.clone()],
            limit: MAX_LIST_LIMIT,
            offset: comments.len() as i32,
            order_by: "created".into(),
            ..ListFilter::default()
        })?;
        let full = page.len() == MAX_LIST_LIMIT as usize;
        comments.extend(page.iter().filter_map(ObjectComment::from_object));
        if comments.len() > MAX_COMMENTS_READ {
            return Err("too many comments to read in one request".into());
        }
        if !full {
            return Ok(comments);
        }
    }
}

/// Every comment on `target_object_id`, oldest first.
pub fn list_for_target(
    db: &RuntimeDb,
    namespace: &str,
    target_object_id: &str,
) -> Result<Vec<ObjectComment>, String> {
    list(
        db,
        namespace,
        PropertyFilter {
            key: "target_object_id".into(),
            op: "eq".into(),
            value: target_object_id.into(),
        },
    )
}

/// Every comment in `namespace` that mentions `principal`, oldest first.
pub fn list_mentioning(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
) -> Result<Vec<ObjectComment>, String> {
    Ok(list(
        db,
        namespace,
        PropertyFilter {
            key: "mentions".into(),
            op: "contains".into(),
            value: format!(",{principal},"),
        },
    )?
    .into_iter()
    .filter(|comment| comment.mentions.iter().any(|m| m == principal))
    .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn comment(id: &str, target: &str, mentions: &[&str]) -> ObjectComment {
        ObjectComment {
            id: id.into(),
            namespace: "acme".into(),
            target_object_id: target.into(),
            target_property: String::new(),
            body: "looks wrong".into(),
            author: "alice".into(),
            mentions: mentions.iter().map(|m| m.to_string()).collect(),
            quoted_properties: Vec::new(),
            resolved: false,
            resolved_by: String::new(),
            created_at_ms: 10,
            updated_at_ms: 10,
        }
    }

    #[test]
    fn content_is_bounded_and_mentions_are_normalized() {
        assert_eq!(
            validate_content("hi", &["bob".into(), "alice".into(), "bob".into()]).unwrap(),
            ["alice", "bob"]
        );
        assert!(validate_content("  ", &[]).is_err());
        assert!(validate_content(&"x".repeat(MAX_COMMENT_BODY_BYTES + 1), &[]).is_err());
        assert!(validate_content("hi", &["a,b".into()]).is_err());
        assert!(validate_target_property("salary").is_ok());
        assert!(validate_target_property("bad key").is_err());
    }

    #[test]
    fn quotes_bind_to_the_value_the_writer_saw() {
        let writer_view = std::collections::HashMap::from([
            ("salary".to_string(), "120000".to_string()),
            ("team".to_string(), "ops".to_string()),
        ]);
        let quoted = quoted_properties("salary 120000 for ops, maybe 99999", &writer_view);
        assert_eq!(quoted.len(), 1, "short values are not quotes: {quoted:?}");
        assert!(quoted[0].starts_with("salary:"));
        let comment = ObjectComment {
            body: "salary 120000 for ops".into(),
            quoted_properties: quoted,
            ..comment("c1", "doc", &[])
        };
        let without_salary =
            std::collections::HashMap::from([("team".to_string(), "ops".to_string())]);
        let changed =
            std::collections::HashMap::from([("salary".to_string(), "130000".to_string())]);
        assert_eq!(body_for(&comment, "bob", &without_salary), REDACTED_BODY);
        assert_eq!(body_for(&comment, "bob", &changed), REDACTED_BODY);
        assert_eq!(body_for(&comment, "bob", &writer_view), comment.body);
        assert_eq!(body_for(&comment, "alice", &without_salary), comment.body);
        // A guess at a value the writer cannot see is never matched.
        assert!(quoted_properties("is it 120000?", &without_salary).is_empty());
    }

    #[test]
    fn comments_round_trip_list_by_target_and_mention_and_detect_conflicts() {
        let db = RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new(":memory:").unwrap(),
        ));
        create(&db, &comment("c1", "doc", &["bob"])).unwrap();
        create(&db, &comment("c2", "doc", &["bobby"])).unwrap();
        create(&db, &comment("c3", "other", &["bob"])).unwrap();
        let on_doc = list_for_target(&db, "acme", "doc").unwrap();
        assert_eq!(on_doc.len(), 2);
        assert_eq!(on_doc[0], comment("c1", "doc", &["bob"]));
        let bob: Vec<String> = list_mentioning(&db, "acme", "bob")
            .unwrap()
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(bob, ["c1", "c3"]);

        let before = get(&db, "c1").unwrap().unwrap();
        let resolved = ObjectComment {
            resolved: true,
            resolved_by: "bob".into(),
            updated_at_ms: 20,
            ..before.clone()
        };
        update(&db, &before, &resolved, "bob").unwrap();
        assert_eq!(get(&db, "c1").unwrap(), Some(resolved.clone()));
        // A writer holding the old version loses.
        assert_eq!(
            update(&db, &before, &resolved, "carol"),
            Err(CommentError::Conflict)
        );
        let history = db.list_object_changes("c1", 10, 0).unwrap();
        assert!(
            history
                .iter()
                .any(|change| change.field == "properties.resolved" && change.changed_by == "bob")
        );
    }
}
