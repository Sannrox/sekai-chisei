//! Governed catalog entries for datasets, object types and pipelines (#1559).
//!
//! An entry is an object of kind `catalog_entry` in the namespace it
//! describes, so reads, search, facets, markings and ACLs follow the ordinary
//! object read policy and every write is in the audited object change log.
//! Generic object writes refuse the kind; entries change only through
//! registration, which is idempotent by the source's stable id (ADR 0122).

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;

pub const CATALOG_ENTRY_KIND: &str = "catalog_entry";
pub const CATALOG_ENTRY_CONTRACT: &str = "sekai.catalog-entry/v1";
/// Source system of entries derived from the published ontology.
pub const ONTOLOGY_SOURCE: &str = "sekai.ontology";
pub const MAX_CATALOG_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_CATALOG_LIST_ITEMS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Dataset,
    ObjectType,
    Pipeline,
}

impl EntryKind {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "dataset" => Ok(Self::Dataset),
            "object_type" => Ok(Self::ObjectType),
            "pipeline" => Ok(Self::Pipeline),
            other => Err(format!("unknown catalog entry kind {other:?}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dataset => "dataset",
            Self::ObjectType => "object_type",
            Self::Pipeline => "pipeline",
        }
    }
}

/// One registration, as a source system reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogRegistration {
    pub namespace: String,
    pub entry_kind: EntryKind,
    pub source_system: String,
    pub source_id: String,
    pub display_name: String,
    pub description: String,
    pub owners: Vec<String>,
    pub steward: String,
    pub tags: Vec<String>,
    /// Classification marking; registration may raise it, never lower it.
    pub marking: String,
    pub schema_summary: String,
    pub freshness_ms: i64,
    pub deprecated: bool,
    /// Monotonic generation of the source's view; a registration older than
    /// the stored one is superseded. Zero when the source has none.
    pub source_generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    Invalid(String),
    /// The caller may not write this entry.
    Denied(String),
    /// Another writer changed the entry since it was read.
    Conflict,
    /// The stored entry comes from a newer source generation.
    Superseded,
    Storage(String),
}

fn token_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.:@/".contains(c))
}

fn normalized_list(label: &str, items: &[String]) -> Result<Vec<String>, CatalogError> {
    let mut list: Vec<String> = items.iter().map(|item| item.trim().to_string()).collect();
    list.sort();
    list.dedup();
    if list.len() > MAX_CATALOG_LIST_ITEMS {
        return Err(CatalogError::Invalid(format!(
            "at most {MAX_CATALOG_LIST_ITEMS} {label}"
        )));
    }
    if let Some(bad) = list.iter().find(|item| !token_ok(item)) {
        return Err(CatalogError::Invalid(format!(
            "invalid {label} entry {bad:?}"
        )));
    }
    Ok(list)
}

impl CatalogRegistration {
    /// Validate and normalize: trimmed, sorted and deduplicated lists.
    pub fn normalized(mut self) -> Result<Self, CatalogError> {
        let invalid = |message: &str| Err(CatalogError::Invalid(message.into()));
        if self.namespace.trim().is_empty() || self.namespace.trim() != self.namespace {
            return invalid("namespace is required");
        }
        // The entry id hashes the source id, so any canonical identifier works,
        // including definition ids such as `Sales Order`.
        if !token_ok(&self.source_system)
            || self.source_id.trim().is_empty()
            || self.source_id.trim() != self.source_id
            || self.source_id.len() > 256
            || self.source_id.chars().any(char::is_control)
        {
            return invalid("source_system and source_id must be stable identifiers");
        }
        if self.display_name.trim().is_empty() {
            return invalid("display_name is required");
        }
        for (label, text) in [
            ("display_name", &self.display_name),
            ("description", &self.description),
            ("schema_summary", &self.schema_summary),
        ] {
            if text.len() > MAX_CATALOG_TEXT_BYTES {
                return Err(CatalogError::Invalid(format!(
                    "{label} must be at most {MAX_CATALOG_TEXT_BYTES} bytes"
                )));
            }
        }
        if !self.steward.is_empty() && !token_ok(&self.steward) {
            return invalid("steward is not a principal");
        }
        if self.freshness_ms < 0 {
            return invalid("freshness_ms must not be negative");
        }
        self.owners = normalized_list("owners", &self.owners)?;
        self.tags = normalized_list("tags", &self.tags)?;
        Ok(self)
    }

    /// Stable object id: one entry per (namespace, kind, source, source id).
    pub fn entry_id(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [
            self.namespace.as_str(),
            self.entry_kind.as_str(),
            self.source_system.as_str(),
            self.source_id.as_str(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        let digest = format!("{:x}", hasher.finalize());
        format!("catalog:{}", &digest[..32])
    }

    fn properties(&self) -> BTreeMap<String, String> {
        let list = |items: &[String]| items.join(",");
        let mut properties = BTreeMap::from([
            ("contract_version".into(), CATALOG_ENTRY_CONTRACT.into()),
            ("entry_kind".into(), self.entry_kind.as_str().into()),
            ("source_system".into(), self.source_system.clone()),
            ("source_id".into(), self.source_id.clone()),
            ("description".into(), self.description.clone()),
            ("owners".into(), list(&self.owners)),
            ("steward".into(), self.steward.clone()),
            ("tags".into(), list(&self.tags)),
            ("schema_summary".into(), self.schema_summary.clone()),
            ("freshness_ms".into(), self.freshness_ms.to_string()),
            (
                "status".into(),
                if self.deprecated {
                    "deprecated"
                } else {
                    "active"
                }
                .into(),
            ),
        ]);
        if self.source_generation > 0 {
            properties.insert(
                "source_generation".into(),
                self.source_generation.to_string(),
            );
        }
        if !self.marking.is_empty() {
            properties.insert(OBJECT_CLASSIFICATION_PROPERTY.into(), self.marking.clone());
        }
        properties.retain(|_, value| !value.is_empty());
        properties
    }
}

/// The marking to store: the least marking that dominates both the stored
/// and the requested one, under the namespace's lattice when it has one.
/// Lowering a marking goes through the audited declassify path, not here;
/// markings with no common bound fail closed.
pub fn raised_marking(
    stored: &str,
    requested: &str,
    lattice: Option<&crate::sekai::classification_lattice::ClassificationLattice>,
) -> Result<String, CatalogError> {
    let invalid = |message: String| CatalogError::Invalid(message);
    if !requested.is_empty() {
        crate::sekai::classification_lattice::validate_written_marking_token(
            Some(requested),
            lattice,
        )
        .map_err(invalid)?;
    }
    if stored.is_empty() {
        return Ok(requested.into());
    }
    if requested.is_empty() || requested == stored {
        return Ok(stored.into());
    }
    match lattice {
        Some(lattice) => lattice
            .join(stored, requested)
            .map_err(invalid)?
            .ok_or_else(|| invalid("markings have no common bound".into())),
        None => {
            use crate::sekai::markings::parse_classification;
            let stored_class = parse_classification(stored).map_err(invalid)?;
            let requested_class = parse_classification(requested).map_err(invalid)?;
            Ok(if stored_class >= requested_class {
                stored.into()
            } else {
                requested.into()
            })
        }
    }
}

/// What registration did.
#[derive(Debug, Clone)]
pub struct Registered {
    pub entry: Object,
    /// False when the stored entry already said exactly this.
    pub changed: bool,
}

/// Create or update the entry for `registration` through the audited object
/// path. `authorize` sees the stored entry (if any) and the proposed one,
/// which it may adjust as property grants require, before anything is
/// returned or written; the write is then fenced on that
/// same stored snapshot and on `policy_generation`. Identical content is a
/// no-op, so a retried registration succeeds and writes nothing.
pub fn register(
    db: &RuntimeDb,
    registration: CatalogRegistration,
    actor: &str,
    now_ms: i64,
    policy_generation: Option<&str>,
    authorize: impl FnOnce(Option<&Object>, &mut Object) -> Result<(), CatalogError>,
) -> Result<Registered, CatalogError> {
    let mut registration = registration.normalized()?;
    let id = registration.entry_id();
    let existing = db.get_object(&id).map_err(CatalogError::Storage)?;
    if let Some(existing) = &existing {
        if existing.kind != CATALOG_ENTRY_KIND || existing.namespace != registration.namespace {
            return Err(CatalogError::Invalid(
                "catalog entry id is held by another object".into(),
            ));
        }
        let stored_generation: i64 = existing
            .properties
            .get("source_generation")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        if registration.source_generation < stored_generation {
            return Err(CatalogError::Superseded);
        }
    }
    let stored = existing
        .as_ref()
        .and_then(|object| {
            object
                .properties
                .get(OBJECT_CLASSIFICATION_PROPERTY)
                .cloned()
        })
        .unwrap_or_default();
    let lattice = db
        .get_classification_lattice(&registration.namespace)
        .map_err(CatalogError::Storage)?;
    registration.marking = raised_marking(&stored, &registration.marking, lattice.as_ref())?;
    let mut entry = Object {
        id: id.clone(),
        kind: CATALOG_ENTRY_KIND.into(),
        name: registration.display_name.clone(),
        namespace: registration.namespace.clone(),
        // Opaque, so the source identity is only in governed properties.
        external_id: id.clone(),
        properties: registration.properties().into_iter().collect(),
        created: existing.as_ref().map_or(now_ms, |object| object.created),
        // Strictly after the stored revision, whatever the clock says.
        updated: existing
            .as_ref()
            .map_or(now_ms, |object| now_ms.max(object.updated + 1)),
    };
    authorize(existing.as_ref(), &mut entry)?;
    // Grant checks may keep a stored value; the result must still carry at
    // least the marking the source asked for.
    let kept = entry
        .properties
        .get(OBJECT_CLASSIFICATION_PROPERTY)
        .cloned()
        .unwrap_or_default();
    if raised_marking(&kept, &registration.marking, lattice.as_ref())? != kept {
        return Err(CatalogError::Denied(
            "the requested marking cannot be written".into(),
        ));
    }
    if let Some(existing) = &existing
        && existing.name == entry.name
        && existing.properties == entry.properties
    {
        return Ok(Registered {
            entry: existing.clone(),
            changed: false,
        });
    }
    let written = match &existing {
        None => db.create_object_with_authorized_policy(&entry, actor, policy_generation),
        Some(existing) => db
            .update_object_with_authorized_snapshot(
                &entry,
                Some(existing),
                actor,
                policy_generation,
            )
            .and_then(|updated| {
                updated
                    .map(|_| ())
                    .ok_or_else(|| crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION.into())
            }),
    };
    written.map_err(|error| {
        if error.contains(crate::sekai::lease::OBJECT_CHANGED_SINCE_AUTHORIZATION)
            || error.contains("UNIQUE constraint failed")
            || error.contains("duplicate key value")
            || error.contains("policy generation")
        {
            CatalogError::Conflict
        } else {
            CatalogError::Storage(error)
        }
    })?;
    Ok(Registered {
        entry,
        changed: true,
    })
}

/// Bring the object-type entries of `namespace` in line with its published
/// ontology: one active entry per published object type, and deprecated
/// entries for object types no longer published. Entries carry the number
/// of publishes in the namespace's history as their source generation, so a
/// sync for an older revision never overwrites a newer one's entries.
/// Idempotent, so running it again after any failure repairs the catalog.
pub fn sync_ontology_entries(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<(), CatalogError> {
    let storage = CatalogError::Storage;
    let Some(revision) = db
        .get_published_definition_revision(namespace)
        .map_err(storage)?
    else {
        return Ok(());
    };
    // A frozen namespace is left as it is, and so is every namespace while
    // any tenant is frozen: the plane cannot tell which tenant a namespace
    // belongs to here. The reconciler catches up after the freeze lifts.
    use crate::sekai::write_freeze::{MODE_BLOCK_WRITES, SCOPE_TENANT, freeze_reason, write_check};
    let tenant_frozen = db
        .list_write_freezes()
        .map_err(storage)?
        .iter()
        .any(|freeze| {
            freeze.enabled && freeze.scope_kind == SCOPE_TENANT && freeze.mode == MODE_BLOCK_WRITES
        });
    if tenant_frozen
        || freeze_reason(db, write_check(namespace, "", actor, ""))
            .map_err(storage)?
            .is_some()
    {
        return Ok(());
    }
    let generation = published_generation(db, namespace, &revision.revision_digest)?;
    // One failing entry does not stop the others; the first failure is
    // returned once every entry has been tried.
    let mut failures = Vec::new();
    let members = db
        .get_definition_members(namespace, &revision.revision_digest)
        .map_err(storage)?;
    let mut published = std::collections::BTreeSet::new();
    for member in members.iter().filter(|m| m.member_kind == "object_type") {
        published.insert(member.member_id.clone());
        register(
            db,
            CatalogRegistration {
                namespace: namespace.into(),
                entry_kind: EntryKind::ObjectType,
                source_system: ONTOLOGY_SOURCE.into(),
                source_id: member.member_id.clone(),
                display_name: member.member_id.clone(),
                description: String::new(),
                owners: Vec::new(),
                steward: String::new(),
                tags: Vec::new(),
                marking: definition_marking(&member.definition_json),
                schema_summary: schema_summary(&member.definition_json),
                freshness_ms: revision.created_at_ms,
                deprecated: false,
                source_generation: generation,
            },
            actor,
            now_ms,
            None,
            |_, _| Ok(()),
        )
        .or_else(skip_superseded)
        .err()
        .into_iter()
        .for_each(|error| failures.push(error));
    }
    // Every ontology entry, page by page; entries for object types no
    // longer published are retired.
    let mut listed = Vec::new();
    loop {
        let page = db
            .list_objects(&crate::domain::ListFilter {
                kind: Some(CATALOG_ENTRY_KIND.into()),
                namespace: Some(namespace.into()),
                property_filters: vec![crate::domain::PropertyFilter {
                    key: "source_system".into(),
                    op: "eq".into(),
                    value: ONTOLOGY_SOURCE.into(),
                }],
                limit: crate::domain::MAX_LIST_LIMIT,
                offset: listed.len() as i32,
                ..crate::domain::ListFilter::default()
            })
            .map_err(storage)?;
        let full = page.len() == crate::domain::MAX_LIST_LIMIT as usize;
        listed.extend(page);
        if !full {
            break;
        }
    }
    for entry in listed {
        let source_id = entry
            .properties
            .get("source_id")
            .cloned()
            .unwrap_or_default();
        let active = entry.properties.get("status").map(String::as_str) == Some("active");
        if active && !published.contains(&source_id) {
            let property = |key: &str| entry.properties.get(key).cloned().unwrap_or_default();
            register(
                db,
                CatalogRegistration {
                    namespace: namespace.into(),
                    entry_kind: EntryKind::ObjectType,
                    source_system: ONTOLOGY_SOURCE.into(),
                    source_id,
                    display_name: entry.name.clone(),
                    description: property("description"),
                    owners: split_list(&property("owners")),
                    steward: property("steward"),
                    tags: split_list(&property("tags")),
                    marking: property(OBJECT_CLASSIFICATION_PROPERTY),
                    schema_summary: property("schema_summary"),
                    freshness_ms: property("freshness_ms").parse().unwrap_or(0),
                    deprecated: true,
                    source_generation: generation,
                },
                actor,
                now_ms,
                None,
                |_, _| Ok(()),
            )
            .or_else(skip_superseded)
            .err()
            .into_iter()
            .for_each(|error| failures.push(error));
        }
    }
    failures.into_iter().next().map_or(Ok(()), Err)
}

/// The position of `head` in the namespace's publish chain: each publish
/// names the head it replaced, so walking back from `head` counts publishes
/// in order without trusting timestamps or history sort order. A head with
/// no merged history is the first, seeded revision.
fn published_generation(db: &RuntimeDb, namespace: &str, head: &str) -> Result<i64, CatalogError> {
    let mut previous = std::collections::HashMap::new();
    let mut page_token = String::new();
    loop {
        let (page, next) = db
            .list_published_definition_revisions(namespace, "", "", &page_token, 200)
            .map_err(CatalogError::Storage)?;
        for entry in page {
            previous.insert(entry.revision_digest, entry.previous_published_digest);
        }
        if next.is_empty() {
            break;
        }
        page_token = next;
    }
    let mut generation = 1i64;
    let mut cursor = head.to_string();
    while let Some(parent) = previous.remove(&cursor) {
        generation += 1;
        cursor = parent;
    }
    Ok(generation)
}

/// The `access_marking` an object-type definition declares, if any.
fn definition_marking(definition_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(definition_json)
        .ok()
        .and_then(|value| {
            value
                .get("access_marking")
                .and_then(|marking| marking.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

/// Actor the background reconciler writes as.
pub const RECONCILER_ACTOR: &str = "sekai.catalog-reconciler";

/// Re-run the ontology sync for every namespace with a published ontology.
/// Run periodically on any number of instances: the sync is idempotent and
/// generation-fenced, so a publish whose own sync was missed (a crash, a
/// failure, a race with a newer publish) converges here. Returns the
/// namespaces that failed.
pub fn reconcile_ontology_entries(db: &RuntimeDb, now_ms: i64) -> Result<Vec<String>, String> {
    let mut failed = Vec::new();
    for namespace in db.list_published_definition_namespaces()? {
        if sync_ontology_entries(db, &namespace, RECONCILER_ACTOR, now_ms).is_err() {
            failed.push(namespace);
        }
    }
    Ok(failed)
}

/// A sync that lost to a newer publish leaves that publish's entry alone.
fn skip_superseded(error: CatalogError) -> Result<Registered, CatalogError> {
    match error {
        CatalogError::Superseded => Ok(Registered {
            entry: Object {
                id: String::new(),
                kind: CATALOG_ENTRY_KIND.into(),
                name: String::new(),
                namespace: String::new(),
                external_id: String::new(),
                properties: Default::default(),
                created: 0,
                updated: 0,
            },
            changed: false,
        }),
        other => Err(other),
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// Property names of an object-type definition, comma separated, cut to
/// fit the catalog's text bound with a count of the names left out.
pub fn schema_summary(definition_json: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(definition_json) else {
        return String::new();
    };
    let mut names: Vec<String> = match value.get("properties") {
        Some(serde_json::Value::Object(map)) => map.keys().cloned().collect(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    names.sort();
    let mut summary = String::new();
    for (index, name) in names.iter().enumerate() {
        let rest = format!(",+{} more", names.len() - index);
        let separator = if summary.is_empty() { "" } else { "," };
        if summary.len() + separator.len() + name.len() + rest.len() > MAX_CATALOG_TEXT_BYTES {
            summary.push_str(&rest[usize::from(summary.is_empty())..]);
            return summary;
        }
        summary.push_str(separator);
        summary.push_str(name);
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn registration(source_id: &str) -> CatalogRegistration {
        CatalogRegistration {
            namespace: "acme".into(),
            entry_kind: EntryKind::Dataset,
            source_system: "mizuchi".into(),
            source_id: source_id.into(),
            display_name: "Orders".into(),
            description: "daily orders".into(),
            owners: vec!["team:billing".into(), "alice".into(), "alice".into()],
            steward: "bob".into(),
            tags: vec!["finance".into()],
            marking: "internal".into(),
            schema_summary: "id,total".into(),
            freshness_ms: 10,
            deprecated: false,
            source_generation: 0,
        }
    }

    fn put(
        db: &RuntimeDb,
        registration: CatalogRegistration,
        now_ms: i64,
    ) -> Result<Registered, CatalogError> {
        register(db, registration, "svc", now_ms, None, |_, _| Ok(()))
    }

    fn db() -> RuntimeDb {
        RuntimeDb::Sqlite(Arc::new(
            crate::db::sekai::SekaiDb::new(":memory:").unwrap(),
        ))
    }

    #[test]
    fn one_entry_per_source_id_and_reregistering_is_a_noop() {
        let db = db();
        let first = register(
            &db,
            registration("tbl-1"),
            "mizuchi-svc",
            100,
            None,
            |_, _| Ok(()),
        )
        .unwrap();
        assert!(first.changed);
        assert_eq!(first.entry.properties["owners"], "alice,team:billing");
        let again = register(
            &db,
            registration("tbl-1"),
            "mizuchi-svc",
            200,
            None,
            |_, _| Ok(()),
        )
        .unwrap();
        assert!(!again.changed);
        assert_eq!(again.entry.updated, 100);
        let other = register(
            &db,
            registration("tbl-2"),
            "mizuchi-svc",
            300,
            None,
            |_, _| Ok(()),
        )
        .unwrap();
        assert_ne!(other.entry.id, first.entry.id);
        let entries = db
            .list_objects(&crate::domain::ListFilter {
                kind: Some(CATALOG_ENTRY_KIND.into()),
                namespace: Some("acme".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(entries.len(), 2);
        let history = db.list_object_changes(&first.entry.id, 10, 0).unwrap();
        assert!(history.iter().any(|c| c.changed_by == "mizuchi-svc"));
    }

    #[test]
    fn markings_only_rise_and_deregistration_deprecates() {
        let db = db();
        let mut strict = registration("tbl-1");
        strict.marking = "confidential".into();
        put(&db, strict, 1).unwrap();
        let lowered = put(&db, registration("tbl-1"), 2).unwrap();
        assert_eq!(
            lowered.entry.properties[OBJECT_CLASSIFICATION_PROPERTY],
            "confidential"
        );
        let mut gone = registration("tbl-1");
        gone.deprecated = true;
        let deprecated = put(&db, gone, 3).unwrap();
        assert_eq!(deprecated.entry.properties["status"], "deprecated");
        assert_eq!(
            db.get_object(&deprecated.entry.id).unwrap().unwrap().id,
            deprecated.entry.id
        );
    }

    #[test]
    fn older_generations_and_denied_writers_change_nothing() {
        let db = db();
        let newer = CatalogRegistration {
            source_generation: 20,
            ..registration("tbl-1")
        };
        put(&db, newer, 1).unwrap();
        let older = CatalogRegistration {
            source_generation: 10,
            description: "stale".into(),
            ..registration("tbl-1")
        };
        assert_eq!(put(&db, older, 2).unwrap_err(), CatalogError::Superseded);
        let denied = register(
            &db,
            CatalogRegistration {
                source_generation: 20,
                ..registration("tbl-1")
            },
            "svc",
            3,
            None,
            |existing, _| {
                assert!(existing.is_some());
                Err(CatalogError::Denied("no".into()))
            },
        );
        assert_eq!(denied.unwrap_err(), CatalogError::Denied("no".into()));
    }

    #[test]
    fn registrations_validate() {
        assert!(registration("Sales Order").normalized().is_ok());
        assert!(registration(" padded").normalized().is_err());
        assert!(registration("tab\there").normalized().is_err());
        assert!(raised_marking("", "secret-ish", None).is_err());
        assert_eq!(
            raised_marking("confidential", "internal", None).unwrap(),
            "confidential"
        );
        assert_eq!(
            raised_marking("internal", "restricted", None).unwrap(),
            "restricted"
        );
        assert_eq!(schema_summary(r#"{"properties":{"b":{},"a":{}}}"#), "a,b");
        assert_eq!(schema_summary(r#"{"properties":["x"]}"#), "x");
        let many: Vec<String> = (0..2_000).map(|i| format!("p{i:04}")).collect();
        let long = schema_summary(&serde_json::json!({ "properties": many }).to_string());
        assert!(long.len() <= MAX_CATALOG_TEXT_BYTES, "{}", long.len());
        assert!(long.ends_with("more"), "{long}");
    }
}
