//! Ontology foundation layer (issue #141).
//!
//! Sits above the typed object graph and lets objects be understood by their
//! meaning and relationships, not only their kind. This module owns the durable
//! ontology primitives — classes (with inheritance, equivalence, disjointness),
//! properties, and relations (with domain/range and cardinality) — plus their
//! SQLite storage, definition validation, and a projection from the existing
//! `SchemaRegistry`.
//!
//! Inference/entailment (#143), endpoint enforcement (#142), and query surfaces
//! (#144/#145) are intentionally out of scope here; this layer only represents
//! and persists the ontology.

use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;
use crate::sekai::schema::{PropertyType, SchemaRegistry};
use crate::sekai::security::Grant;
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;
use uuid::Uuid;

/// Cardinality bound for the range side of a relation. `max = None` means
/// unbounded. Inference does not act on these bounds; in the 1.x contract they
/// remain advisory metadata. Declaration validation rejects malformed ranges,
/// but link writes and relation updates do not enforce cardinality.
///
/// The default (`min = 0`, `max = None`) is the least restrictive bound, so
/// projecting or importing existing relations never tightens behavior.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Cardinality {
    pub min: u32,
    pub max: Option<u32>,
}

/// A property attached to an ontology class. Reuses the schema `PropertyType`
/// vocabulary so classes and object types describe values the same way.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OntologyProperty {
    pub name: String,
    pub prop_type: PropertyType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: String,
}

/// A first-class semantic concept. `mapped_kind` records the existing sekai
/// object kind this class projects from (empty when the class is purely
/// semantic).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OntologyClass {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// `subclass_of` targets: names of parent classes.
    #[serde(default)]
    pub superclasses: Vec<String>,
    #[serde(default)]
    pub equivalent_classes: Vec<String>,
    #[serde(default)]
    pub disjoint_classes: Vec<String>,
    #[serde(default)]
    pub properties: Vec<OntologyProperty>,
    #[serde(default)]
    pub is_builtin: bool,
    #[serde(default)]
    pub mapped_kind: String,
}

/// A typed, directed relation between two classes. `inverse` names the relation
/// that holds in the opposite direction (empty when none); `transitive` is
/// durable metadata consumed by later reasoning work (#143).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OntologyRelation {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub domain: String,
    pub range: String,
    #[serde(default)]
    pub cardinality: Cardinality,
    #[serde(default)]
    pub inverse: String,
    #[serde(default)]
    pub transitive: bool,
    #[serde(default)]
    pub is_builtin: bool,
    #[serde(default)]
    pub mapped_relation: String,
}

/// In-memory view of the ontology used for validation and projection.
#[derive(Clone, Default)]
pub struct OntologyRegistry {
    classes: HashMap<String, OntologyClass>,
    relations: HashMap<String, OntologyRelation>,
}

impl OntologyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_parts(classes: Vec<OntologyClass>, relations: Vec<OntologyRelation>) -> Self {
        let mut registry = Self::new();
        for class in classes {
            registry.register_class(class);
        }
        for relation in relations {
            registry.register_relation(relation);
        }
        registry
    }

    pub fn register_class(&mut self, class: OntologyClass) {
        self.classes.insert(class.name.clone(), class);
    }

    pub fn register_relation(&mut self, relation: OntologyRelation) {
        self.relations.insert(relation.name.clone(), relation);
    }

    pub fn remove_class(&mut self, name: &str) {
        self.classes.remove(name);
    }

    pub fn remove_relation(&mut self, name: &str) {
        self.relations.remove(name);
    }

    pub fn get_class(&self, name: &str) -> Option<&OntologyClass> {
        self.classes.get(name)
    }

    pub fn get_relation(&self, name: &str) -> Option<&OntologyRelation> {
        self.relations.get(name)
    }

    pub fn classes(&self) -> Vec<OntologyClass> {
        let mut classes: Vec<_> = self.classes.values().cloned().collect();
        classes.sort_by(|a, b| a.name.cmp(&b.name));
        classes
    }

    pub fn relations(&self) -> Vec<OntologyRelation> {
        let mut relations: Vec<_> = self.relations.values().cloned().collect();
        relations.sort_by(|a, b| a.name.cmp(&b.name));
        relations
    }

    /// Stable content revision for an immutable ontology snapshot. It is a
    /// projection identifier, not a persisted database revision.
    pub fn revision(&self) -> String {
        let content = serde_json::to_vec(&(self.classes(), self.relations()))
            .expect("ontology definitions are serializable");
        format!("sha256:{:x}", Sha256::digest(content))
    }

    /// Transitive set of ancestor class names reachable via `superclasses`.
    /// Cycle-safe: a class already visited is never expanded twice, so a
    /// pre-existing cycle terminates instead of looping. The starting class is
    /// not included in the result.
    pub fn superclass_closure(&self, name: &str) -> HashSet<String> {
        let mut ancestors = HashSet::new();
        let mut stack: Vec<String> = self
            .classes
            .get(name)
            .map(|class| class.superclasses.clone())
            .unwrap_or_default();
        while let Some(current) = stack.pop() {
            if !ancestors.insert(current.clone()) {
                continue;
            }
            if let Some(class) = self.classes.get(&current) {
                for parent in &class.superclasses {
                    if !ancestors.contains(parent) {
                        stack.push(parent.clone());
                    }
                }
            }
        }
        ancestors
    }

    /// Whether an object kind is an instance of `expected`, accounting for
    /// mapped classes, transitive inheritance, and symmetric/transitive class
    /// equivalence.
    pub fn kind_satisfies_class(&self, kind: &str, expected: &str) -> bool {
        self.kind_entailment_path(kind, expected).is_some()
    }

    /// Deterministic shortest class path for an object's mapped kind. Each
    /// tuple is `(from, to, rule)` where rule is `subclass` or `equivalence`.
    pub fn kind_entailment_path(
        &self,
        kind: &str,
        expected: &str,
    ) -> Option<Vec<(String, String, &'static str)>> {
        let mut reachable = HashSet::new();
        let mut starts = self
            .classes
            .values()
            .filter(|class| class.mapped_kind == kind)
            .map(|class| class.name.clone())
            .collect::<Vec<_>>();
        starts.sort();
        let mut queue = starts
            .into_iter()
            .map(|class| (class, Vec::new()))
            .collect::<VecDeque<_>>();
        while let Some((current, path)) = queue.pop_front() {
            if !reachable.insert(current.clone()) {
                continue;
            }
            if !self.classes.contains_key(&current) {
                continue;
            }
            if current == expected {
                return Some(path);
            }
            let Some(class) = self.classes.get(&current) else {
                continue;
            };
            let mut edges = class
                .superclasses
                .iter()
                .map(|target| (target.clone(), "subclass"))
                .chain(
                    class
                        .equivalent_classes
                        .iter()
                        .map(|target| (target.clone(), "equivalence")),
                )
                .chain(
                    self.classes
                        .values()
                        .filter(|candidate| candidate.equivalent_classes.contains(&current))
                        .map(|candidate| (candidate.name.clone(), "equivalence")),
                )
                .collect::<Vec<_>>();
            edges.sort();
            edges.dedup();
            for (target, rule) in edges {
                let mut next_path = path.clone();
                next_path.push((current.clone(), target.clone(), rule));
                queue.push_back((target, next_path));
            }
        }
        None
    }

    pub fn constraints_for_mapped_relation(&self, mapped_relation: &str) -> Vec<&OntologyRelation> {
        if mapped_relation.is_empty() {
            return Vec::new();
        }
        let mut constraints = self
            .relations
            .values()
            .filter(|relation| relation.mapped_relation == mapped_relation)
            .collect::<Vec<_>>();
        constraints.sort_by(|left, right| left.name.cmp(&right.name));
        constraints
    }
}

pub(crate) fn load_ontology_registry_from_connection(
    conn: &rusqlite::Connection,
) -> Result<OntologyRegistry, String> {
    Ok(OntologyRegistry::from_parts(
        select_classes(conn)?,
        select_relations(conn)?,
    ))
}

pub(crate) fn validate_link_constraint(
    conn: &rusqlite::Connection,
    from_id: &str,
    to_id: &str,
    mapped_relation: &str,
) -> Result<(), String> {
    if mapped_relation.is_empty() {
        return Ok(());
    }
    let registry = load_ontology_registry_from_connection(conn)?;
    let constraints = registry.constraints_for_mapped_relation(mapped_relation);
    if constraints.is_empty() {
        return Ok(());
    }
    let from_kind = conn
        .query_row(
            "SELECT kind FROM sekai_objects WHERE id = ?1",
            params![from_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "link endpoint unavailable".to_string())?;
    let to_kind = conn
        .query_row(
            "SELECT kind FROM sekai_objects WHERE id = ?1",
            params![to_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "link endpoint unavailable".to_string())?;
    if constraints.into_iter().any(|constraint| {
        !registry.kind_satisfies_class(&from_kind, &constraint.domain)
            || !registry.kind_satisfies_class(&to_kind, &constraint.range)
    }) {
        return Err("link endpoints violate ontology constraint".into());
    }
    Ok(())
}

pub(crate) fn validate_object_kind_change(
    conn: &rusqlite::Connection,
    object_id: &str,
    new_kind: &str,
) -> Result<(), String> {
    let registry = load_ontology_registry_from_connection(conn)?;
    let old_kind = conn
        .query_row(
            "SELECT kind FROM sekai_objects WHERE id = ?1",
            params![object_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| error.to_string())?;
    let mut stmt = conn
        .prepare(
            "SELECT from_id, to_id, relation FROM sekai_links
             WHERE from_id = ?1 OR to_id = ?1 ORDER BY id",
        )
        .map_err(|error| error.to_string())?;
    let links = stmt
        .query_map(params![object_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    for (from_id, to_id, relation) in links {
        let constraints = registry.constraints_for_mapped_relation(&relation);
        if constraints.is_empty() {
            continue;
        }
        if constraints.into_iter().any(|constraint| {
            let introduces_domain_violation = from_id == object_id
                && registry.kind_satisfies_class(&old_kind, &constraint.domain)
                && !registry.kind_satisfies_class(new_kind, &constraint.domain);
            let introduces_range_violation = to_id == object_id
                && registry.kind_satisfies_class(&old_kind, &constraint.range)
                && !registry.kind_satisfies_class(new_kind, &constraint.range);
            introduces_domain_violation || introduces_range_violation
        }) {
            return Err("link endpoints violate ontology constraint".into());
        }
    }
    Ok(())
}

/// Validate an ontology class definition against the current registry.
///
/// `existing` is the stored definition being replaced, if any. `registry`
/// holds the classes referenced by inheritance/equivalence/disjointness and is
/// expected not to contain the candidate under its final form yet.
pub fn validate_class_definition(
    class: &OntologyClass,
    existing: Option<&OntologyClass>,
    registry: &OntologyRegistry,
) -> Result<(), String> {
    if class.name.trim().is_empty() {
        return Err("class name required".into());
    }
    if class.is_builtin {
        return Err("builtin ontology classes are code-owned".into());
    }
    if existing
        .map(|existing| existing.is_builtin)
        .unwrap_or(false)
    {
        return Err("cannot replace builtin ontology class".into());
    }

    let mut seen = HashSet::new();
    for property in &class.properties {
        if property.name.trim().is_empty() {
            return Err("property name required".into());
        }
        if !seen.insert(property.name.as_str()) {
            return Err(format!("duplicate property '{}'", property.name));
        }
    }

    validate_class_refs("superclass", &class.superclasses, class, registry)?;
    validate_class_refs(
        "equivalent class",
        &class.equivalent_classes,
        class,
        registry,
    )?;
    validate_class_refs("disjoint class", &class.disjoint_classes, class, registry)?;

    if let Some(contradiction) = class
        .equivalent_classes
        .iter()
        .find(|equivalent| class.disjoint_classes.contains(equivalent))
    {
        return Err(format!(
            "class '{}' cannot be both equivalent to and disjoint with '{}'",
            class.name, contradiction
        ));
    }
    for equivalent in &class.equivalent_classes {
        if registry
            .get_class(equivalent)
            .is_some_and(|other| other.disjoint_classes.contains(&class.name))
        {
            return Err(format!(
                "class '{}' cannot be equivalent to '{}' because it is disjoint",
                class.name, equivalent
            ));
        }
    }
    for disjoint in &class.disjoint_classes {
        if registry
            .get_class(disjoint)
            .is_some_and(|other| other.equivalent_classes.contains(&class.name))
        {
            return Err(format!(
                "class '{}' cannot be disjoint with '{}' because it is equivalent",
                class.name, disjoint
            ));
        }
    }

    // A superclass edge that leads back to this class forms an inheritance
    // cycle. Because the candidate is not yet registered, checking each
    // declared parent's ancestor closure detects the cycle deterministically.
    for parent in &class.superclasses {
        if parent == &class.name {
            return Err(format!(
                "class '{}' cannot be its own superclass",
                class.name
            ));
        }
        if registry.superclass_closure(parent).contains(&class.name) {
            return Err(format!(
                "inheritance cycle: '{}' is already an ancestor of superclass '{}'",
                class.name, parent
            ));
        }
    }

    // Disjointness with an ancestor (or self) is contradictory: no instance
    // could satisfy both.
    let mut ancestors = HashSet::new();
    for parent in &class.superclasses {
        ancestors.insert(parent.clone());
        ancestors.extend(registry.superclass_closure(parent));
    }
    for disjoint in &class.disjoint_classes {
        if disjoint == &class.name {
            return Err(format!(
                "class '{}' cannot be disjoint with itself",
                class.name
            ));
        }
        if ancestors.contains(disjoint) {
            return Err(format!(
                "class '{}' cannot be disjoint with its ancestor '{}'",
                class.name, disjoint
            ));
        }
    }

    Ok(())
}

fn validate_class_refs(
    label: &str,
    refs: &[String],
    class: &OntologyClass,
    registry: &OntologyRegistry,
) -> Result<(), String> {
    for reference in refs {
        if reference.trim().is_empty() {
            return Err(format!("{label} name required"));
        }
        if reference == &class.name {
            continue;
        }
        if registry.get_class(reference).is_none() {
            return Err(format!("unknown {label} '{reference}'"));
        }
    }
    Ok(())
}

/// Validate an ontology relation definition against the current registry.
pub fn validate_relation_definition(
    relation: &OntologyRelation,
    existing: Option<&OntologyRelation>,
    registry: &OntologyRegistry,
) -> Result<(), String> {
    if relation.name.trim().is_empty() {
        return Err("relation name required".into());
    }
    if relation.is_builtin {
        return Err("builtin ontology relations are code-owned".into());
    }
    if existing
        .map(|existing| existing.is_builtin)
        .unwrap_or(false)
    {
        return Err("cannot replace builtin ontology relation".into());
    }
    if relation.domain.trim().is_empty() {
        return Err("relation domain required".into());
    }
    if relation.range.trim().is_empty() {
        return Err("relation range required".into());
    }
    if registry.get_class(&relation.domain).is_none() {
        return Err(format!("unknown domain class '{}'", relation.domain));
    }
    if registry.get_class(&relation.range).is_none() {
        return Err(format!("unknown range class '{}'", relation.range));
    }
    if let Some(max) = relation.cardinality.max
        && max < relation.cardinality.min
    {
        return Err(format!(
            "relation '{}' cardinality max {} is below min {}",
            relation.name, max, relation.cardinality.min
        ));
    }
    if !relation.inverse.is_empty() && relation.inverse == relation.name {
        return Err(format!(
            "relation '{}' cannot be its own inverse",
            relation.name
        ));
    }
    if !relation.inverse.is_empty() {
        let inverse = registry
            .get_relation(&relation.inverse)
            .ok_or_else(|| format!("unknown inverse relation '{}'", relation.inverse))?;
        if !inverse.inverse.is_empty() && inverse.inverse != relation.name {
            return Err(format!(
                "inverse relation '{}' already points to '{}'",
                inverse.name, inverse.inverse
            ));
        }
        if inverse.domain != relation.range || inverse.range != relation.domain {
            return Err(format!(
                "inverse relation '{}' must reverse domain and range",
                inverse.name
            ));
        }
    }
    Ok(())
}

/// Project an existing `SchemaRegistry` into ontology classes.
///
/// Object types and interfaces become classes; an object type's `implements`
/// list becomes `superclasses`, and each schema `PropertyDef` becomes an
/// `OntologyProperty`. `mapped_kind` records the originating object kind so the
/// projection stays reversible.
pub fn project_schema_registry(schema: &SchemaRegistry) -> Result<OntologyRegistry, String> {
    let mut registry = OntologyRegistry::new();
    let interfaces = schema.all_interfaces();
    let interface_names: HashSet<_> = interfaces
        .iter()
        .map(|interface| interface.name.as_str())
        .collect();
    for object_type in schema.all() {
        if interface_names.contains(object_type.kind.as_str()) {
            return Err(format!(
                "schema type and interface share ontology class name '{}'",
                object_type.kind
            ));
        }
    }
    for interface in interfaces {
        registry.register_class(OntologyClass {
            name: interface.name.clone(),
            description: interface.description,
            superclasses: Vec::new(),
            equivalent_classes: Vec::new(),
            disjoint_classes: Vec::new(),
            properties: interface.properties.iter().map(project_property).collect(),
            is_builtin: interface.is_builtin,
            mapped_kind: String::new(),
        });
    }
    for object_type in schema.all() {
        registry.register_class(OntologyClass {
            name: object_type.kind.clone(),
            description: object_type.description,
            superclasses: object_type.implements.clone(),
            equivalent_classes: Vec::new(),
            disjoint_classes: Vec::new(),
            properties: object_type
                .properties
                .iter()
                .map(project_property)
                .collect(),
            is_builtin: object_type.is_builtin,
            mapped_kind: object_type.kind,
        });
    }
    Ok(registry)
}

fn project_property(property: &crate::sekai::schema::PropertyDef) -> OntologyProperty {
    OntologyProperty {
        name: property.name.clone(),
        prop_type: property.prop_type.clone(),
        required: property.required,
        description: property.description.clone(),
    }
}

impl SekaiDb {
    pub(crate) fn migrate_ontology(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_ontology_classes (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                superclasses_json TEXT NOT NULL DEFAULT '[]',
                equivalent_json TEXT NOT NULL DEFAULT '[]',
                disjoint_json TEXT NOT NULL DEFAULT '[]',
                properties_json TEXT NOT NULL DEFAULT '[]',
                mapped_kind TEXT NOT NULL DEFAULT '',
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ontology_classes_mapped_kind ON sekai_ontology_classes(mapped_kind);
            CREATE TABLE IF NOT EXISTS sekai_ontology_relations (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                range TEXT NOT NULL DEFAULT '',
                cardinality_json TEXT NOT NULL DEFAULT '{}',
                inverse TEXT NOT NULL DEFAULT '',
                transitive INTEGER NOT NULL DEFAULT 0,
                mapped_relation TEXT NOT NULL DEFAULT '',
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ontology_relations_domain ON sekai_ontology_relations(domain);
            CREATE INDEX IF NOT EXISTS idx_ontology_relations_range ON sekai_ontology_relations(range);",
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn upsert_ontology_class(&self, class: &OntologyClass) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        upsert_class_row(&self.conn(), class, now)
    }

    pub fn upsert_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
    ) -> Result<(), String> {
        self.upsert_ontology_class_with_audit_and_acl(class, actor, None)
    }

    /// Persist a projected class, its audit decision, and the source schema's
    /// ACL in one transaction. `source_grants` is `Some` even when empty so a
    /// newly-public source removes restrictions left by an earlier projection.
    pub fn upsert_projected_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
        source_grants: &[Grant],
    ) -> Result<(), String> {
        self.upsert_ontology_class_with_audit_and_acl(class, actor, Some(source_grants))
    }

    fn upsert_ontology_class_with_audit_and_acl(
        &self,
        class: &OntologyClass,
        actor: &str,
        source_grants: Option<&[Grant]>,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let existed = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sekai_ontology_classes WHERE name = ?1)",
                params![class.name],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| error.to_string())?;
        upsert_class_row(&transaction, class, now)?;
        if let Some(source_grants) = source_grants {
            let object_id = format!("ontology:class:{}", class.name);
            transaction
                .execute(
                    "DELETE FROM sekai_grants WHERE object_id = ?1",
                    params![object_id],
                )
                .map_err(|error| error.to_string())?;
            for grant in source_grants {
                transaction
                    .execute(
                        "INSERT INTO sekai_grants (id, object_id, principal, role, created)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            format!("ontology-projection-{}", Uuid::new_v4().simple()),
                            object_id,
                            grant.principal,
                            grant.role.as_str(),
                            grant.created
                        ],
                    )
                    .map_err(|error| error.to_string())?;
            }
        }
        insert_ontology_audit(
            &transaction,
            actor,
            if existed {
                "ontology.class.update"
            } else {
                "ontology.class.create"
            },
            &format!("ontology:class:{}", class.name),
            &class.name,
            now,
        )?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn delete_ontology_class(&self, name: &str) -> Result<bool, String> {
        delete_class_row(&self.conn(), name)
    }

    pub fn delete_ontology_class_with_audit(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<bool, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let class_reference = transaction
            .query_row(
                "SELECT name FROM sekai_ontology_classes
                 WHERE name != ?1 AND (
                    EXISTS (SELECT 1 FROM json_each(superclasses_json) WHERE value = ?1) OR
                    EXISTS (SELECT 1 FROM json_each(equivalent_json) WHERE value = ?1) OR
                    EXISTS (SELECT 1 FROM json_each(disjoint_json) WHERE value = ?1)
                 ) LIMIT 1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(class_name) = class_reference {
            return Err(format!("class '{class_name}' still references '{name}'"));
        }
        let relation_reference = transaction
            .query_row(
                "SELECT name FROM sekai_ontology_relations
                 WHERE domain = ?1 OR range = ?1 LIMIT 1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(relation_name) = relation_reference {
            return Err(format!(
                "relation '{relation_name}' still uses '{name}' as domain or range"
            ));
        }
        let deleted = delete_class_row(&transaction, name)?;
        if deleted {
            transaction
                .execute(
                    "DELETE FROM sekai_grants WHERE object_id = ?1",
                    params![format!("ontology:class:{name}")],
                )
                .map_err(|error| error.to_string())?;
            insert_ontology_audit(
                &transaction,
                actor,
                "ontology.class.delete",
                &format!("ontology:class:{name}"),
                name,
                now,
            )?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(deleted)
    }

    pub fn get_ontology_class(&self, name: &str) -> Result<Option<OntologyClass>, String> {
        select_class(&self.conn(), name)
    }

    pub fn list_ontology_classes(&self) -> Result<Vec<OntologyClass>, String> {
        select_classes(&self.conn())
    }

    pub fn list_readable_ontology_classes(
        &self,
        principals: &[String],
        deadline: Instant,
        limit: u32,
    ) -> Result<Vec<OntologyClass>, String> {
        select_readable_classes(&self.conn(), principals, deadline, limit)
    }

    pub fn upsert_ontology_relation(&self, relation: &OntologyRelation) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        upsert_relation_row(&self.conn(), relation, now)
    }

    pub fn upsert_ontology_relation_with_audit(
        &self,
        relation: &OntologyRelation,
        actor: &str,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let existed = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sekai_ontology_relations WHERE name = ?1)",
                params![relation.name],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| error.to_string())?;
        upsert_relation_row(&transaction, relation, now)?;
        insert_ontology_audit(
            &transaction,
            actor,
            if existed {
                "ontology.relation.update"
            } else {
                "ontology.relation.create"
            },
            &format!("ontology:relation:{}", relation.name),
            &relation.name,
            now,
        )?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn delete_ontology_relation(&self, name: &str) -> Result<bool, String> {
        delete_relation_row(&self.conn(), name)
    }

    pub fn delete_ontology_relation_with_audit(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<bool, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let inverse_reference = transaction
            .query_row(
                "SELECT name FROM sekai_ontology_relations
                 WHERE name != ?1 AND inverse = ?1 LIMIT 1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(relation_name) = inverse_reference {
            return Err(format!(
                "relation '{relation_name}' still uses '{name}' as its inverse"
            ));
        }
        let deleted = delete_relation_row(&transaction, name)?;
        if deleted {
            transaction
                .execute(
                    "DELETE FROM sekai_grants WHERE object_id = ?1",
                    params![format!("ontology:relation:{name}")],
                )
                .map_err(|error| error.to_string())?;
            insert_ontology_audit(
                &transaction,
                actor,
                "ontology.relation.delete",
                &format!("ontology:relation:{name}"),
                name,
                now,
            )?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(deleted)
    }

    pub fn get_ontology_relation(&self, name: &str) -> Result<Option<OntologyRelation>, String> {
        select_relation(&self.conn(), name)
    }

    pub fn list_ontology_relations(&self) -> Result<Vec<OntologyRelation>, String> {
        select_relations(&self.conn())
    }

    pub fn list_readable_ontology_relations(
        &self,
        principals: &[String],
        deadline: Instant,
        limit: u32,
    ) -> Result<Vec<OntologyRelation>, String> {
        select_readable_relations(&self.conn(), principals, deadline, limit)
    }

    /// Load the durable ontology into an in-memory registry for validation and
    /// discovery.
    pub fn load_ontology_registry(&self) -> Result<OntologyRegistry, String> {
        Ok(OntologyRegistry::from_parts(
            self.list_ontology_classes()?,
            self.list_ontology_relations()?,
        ))
    }
}

fn insert_ontology_audit(
    transaction: &Transaction<'_>,
    actor: &str,
    action: &str,
    target_id: &str,
    definition_name: &str,
    timestamp: i64,
) -> Result<(), String> {
    crate::sekai::ledger::insert_chained_decision(
        transaction,
        &Decision {
            id: format!("ontology-audit-{}", Uuid::new_v4().simple()),
            timestamp,
            actor: actor.to_string(),
            action: action.to_string(),
            reason: "ontology definition mutation".into(),
            evidence: HashMap::from([
                ("definition_name".into(), definition_name.to_string()),
                ("data_class".into(), "unclassified".into()),
            ]),
            target_id: target_id.to_string(),
            outcome: "applied".into(),
        },
    )
}

/// Column list for every class read, declared once so it cannot drift from the
/// positional access in [`row_to_ontology_class`].
const CLASS_COLUMNS: &str = "name, description, superclasses_json, equivalent_json, disjoint_json, properties_json, mapped_kind";

/// Column list for every relation read; see [`CLASS_COLUMNS`].
const RELATION_COLUMNS: &str =
    "name, description, domain, range, cardinality_json, inverse, transitive, mapped_relation";

/// Storage primitives shared by the plain and audited paths. Each takes a bare
/// `&Connection` so the audited callers can pass their in-flight `Transaction`
/// (which derefs to `Connection`) and get the same statement the plain path
/// runs, rather than a second copy of it.
///
/// `now` is a parameter rather than read here so an audited mutation stamps the
/// row and its decision record with one timestamp.
fn upsert_class_row(
    conn: &rusqlite::Connection,
    class: &OntologyClass,
    now: i64,
) -> Result<(), String> {
    let superclasses_json =
        serde_json::to_string(&class.superclasses).map_err(|error| error.to_string())?;
    let equivalent_json =
        serde_json::to_string(&class.equivalent_classes).map_err(|error| error.to_string())?;
    let disjoint_json =
        serde_json::to_string(&class.disjoint_classes).map_err(|error| error.to_string())?;
    let properties_json =
        serde_json::to_string(&class.properties).map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO sekai_ontology_classes
            (name, description, superclasses_json, equivalent_json, disjoint_json, properties_json, mapped_kind, created, updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
         ON CONFLICT(name) DO UPDATE SET
            description = excluded.description,
            superclasses_json = excluded.superclasses_json,
            equivalent_json = excluded.equivalent_json,
            disjoint_json = excluded.disjoint_json,
            properties_json = excluded.properties_json,
            mapped_kind = excluded.mapped_kind,
            updated = excluded.updated",
        params![
            class.name,
            class.description,
            superclasses_json,
            equivalent_json,
            disjoint_json,
            properties_json,
            class.mapped_kind,
            now
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn delete_class_row(conn: &rusqlite::Connection, name: &str) -> Result<bool, String> {
    let deleted = conn
        .execute(
            "DELETE FROM sekai_ontology_classes WHERE name = ?1",
            params![name],
        )
        .map_err(|error| error.to_string())?;
    Ok(deleted > 0)
}

fn select_class(conn: &rusqlite::Connection, name: &str) -> Result<Option<OntologyClass>, String> {
    conn.query_row(
        &format!("SELECT {CLASS_COLUMNS} FROM sekai_ontology_classes WHERE name = ?1"),
        params![name],
        row_to_ontology_class,
    )
    .optional()
    .map_err(|error| error.to_string())?
    .transpose()
}

fn select_classes(conn: &rusqlite::Connection) -> Result<Vec<OntologyClass>, String> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {CLASS_COLUMNS} FROM sekai_ontology_classes ORDER BY name"
        ))
        .map_err(|error| error.to_string())?;
    let mut rows = stmt.query([]).map_err(|error| error.to_string())?;
    let mut classes = Vec::new();
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        classes.push(row_to_ontology_class(row).map_err(|error| error.to_string())??);
    }
    Ok(classes)
}

fn select_readable_classes(
    conn: &rusqlite::Connection,
    principals: &[String],
    deadline: Instant,
    limit: u32,
) -> Result<Vec<OntologyClass>, String> {
    let principals_json = serde_json::to_string(principals).map_err(|error| error.to_string())?;
    conn.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(|error| error.to_string())?;
    let result = (|| {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {CLASS_COLUMNS} FROM sekai_ontology_classes c
             WHERE NOT EXISTS (
                 SELECT 1 FROM sekai_grants g
                 WHERE g.object_id = 'ontology:class:' || c.name
             ) OR EXISTS (
                 SELECT 1 FROM sekai_grants g
                 WHERE g.object_id = 'ontology:class:' || c.name
                   AND g.principal IN (SELECT value FROM json_each(?1))
             ) ORDER BY c.name LIMIT ?2"
            ))
            .map_err(|error| error.to_string())?;
        let mut rows = stmt
            .query(params![principals_json, limit])
            .map_err(|error| error.to_string())?;
        let mut classes = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            classes.push(row_to_ontology_class(row).map_err(|error| error.to_string())??);
        }
        Ok(classes)
    })();
    conn.progress_handler(0, None::<fn() -> bool>)
        .map_err(|error| error.to_string())?;
    result
}

fn upsert_relation_row(
    conn: &rusqlite::Connection,
    relation: &OntologyRelation,
    now: i64,
) -> Result<(), String> {
    let cardinality_json =
        serde_json::to_string(&relation.cardinality).map_err(|error| error.to_string())?;
    conn.execute(
        "INSERT INTO sekai_ontology_relations
            (name, description, domain, range, cardinality_json, inverse, transitive, mapped_relation, created, updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
         ON CONFLICT(name) DO UPDATE SET
            description = excluded.description,
            domain = excluded.domain,
            range = excluded.range,
            cardinality_json = excluded.cardinality_json,
            inverse = excluded.inverse,
            transitive = excluded.transitive,
            mapped_relation = excluded.mapped_relation,
            updated = excluded.updated",
        params![
            relation.name,
            relation.description,
            relation.domain,
            relation.range,
            cardinality_json,
            relation.inverse,
            relation.transitive as i64,
            relation.mapped_relation,
            now
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn delete_relation_row(conn: &rusqlite::Connection, name: &str) -> Result<bool, String> {
    let deleted = conn
        .execute(
            "DELETE FROM sekai_ontology_relations WHERE name = ?1",
            params![name],
        )
        .map_err(|error| error.to_string())?;
    Ok(deleted > 0)
}

fn select_relation(
    conn: &rusqlite::Connection,
    name: &str,
) -> Result<Option<OntologyRelation>, String> {
    conn.query_row(
        &format!("SELECT {RELATION_COLUMNS} FROM sekai_ontology_relations WHERE name = ?1"),
        params![name],
        row_to_ontology_relation,
    )
    .optional()
    .map_err(|error| error.to_string())?
    .transpose()
}

fn select_relations(conn: &rusqlite::Connection) -> Result<Vec<OntologyRelation>, String> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {RELATION_COLUMNS} FROM sekai_ontology_relations ORDER BY name"
        ))
        .map_err(|error| error.to_string())?;
    let mut rows = stmt.query([]).map_err(|error| error.to_string())?;
    let mut relations = Vec::new();
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        relations.push(row_to_ontology_relation(row).map_err(|error| error.to_string())??);
    }
    Ok(relations)
}

fn select_readable_relations(
    conn: &rusqlite::Connection,
    principals: &[String],
    deadline: Instant,
    limit: u32,
) -> Result<Vec<OntologyRelation>, String> {
    let principals_json = serde_json::to_string(principals).map_err(|error| error.to_string())?;
    conn.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(|error| error.to_string())?;
    let result = (|| {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {RELATION_COLUMNS} FROM sekai_ontology_relations r
             WHERE NOT EXISTS (
                 SELECT 1 FROM sekai_grants g
                 WHERE g.object_id = 'ontology:relation:' || r.name
             ) OR EXISTS (
                 SELECT 1 FROM sekai_grants g
                 WHERE g.object_id = 'ontology:relation:' || r.name
                   AND g.principal IN (SELECT value FROM json_each(?1))
             ) ORDER BY r.name LIMIT ?2"
            ))
            .map_err(|error| error.to_string())?;
        let mut rows = stmt
            .query(params![principals_json, limit])
            .map_err(|error| error.to_string())?;
        let mut relations = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            relations.push(row_to_ontology_relation(row).map_err(|error| error.to_string())??);
        }
        Ok(relations)
    })();
    conn.progress_handler(0, None::<fn() -> bool>)
        .map_err(|error| error.to_string())?;
    result
}

/// Deserialize a class row. The outer `rusqlite::Result` covers column access;
/// the inner `Result<_, String>` covers JSON decode so a corrupt row surfaces a
/// clear error instead of a panic.
fn row_to_ontology_class(
    row: &rusqlite::Row,
) -> Result<Result<OntologyClass, String>, rusqlite::Error> {
    let name: String = row.get(0)?;
    let description: String = row.get(1)?;
    let superclasses_json: String = row.get(2)?;
    let equivalent_json: String = row.get(3)?;
    let disjoint_json: String = row.get(4)?;
    let properties_json: String = row.get(5)?;
    let mapped_kind: String = row.get(6)?;
    Ok((|| {
        Ok(OntologyClass {
            name,
            description,
            superclasses: serde_json::from_str(&superclasses_json)
                .map_err(|error| error.to_string())?,
            equivalent_classes: serde_json::from_str(&equivalent_json)
                .map_err(|error| error.to_string())?,
            disjoint_classes: serde_json::from_str(&disjoint_json)
                .map_err(|error| error.to_string())?,
            properties: serde_json::from_str(&properties_json)
                .map_err(|error| error.to_string())?,
            is_builtin: false,
            mapped_kind,
        })
    })())
}

fn row_to_ontology_relation(
    row: &rusqlite::Row,
) -> Result<Result<OntologyRelation, String>, rusqlite::Error> {
    let name: String = row.get(0)?;
    let description: String = row.get(1)?;
    let domain: String = row.get(2)?;
    let range: String = row.get(3)?;
    let cardinality_json: String = row.get(4)?;
    let inverse: String = row.get(5)?;
    let transitive: i64 = row.get(6)?;
    let mapped_relation: String = row.get(7)?;
    Ok((|| {
        Ok(OntologyRelation {
            name,
            description,
            domain,
            range,
            cardinality: serde_json::from_str(&cardinality_json)
                .map_err(|error| error.to_string())?,
            inverse,
            transitive: transitive != 0,
            is_builtin: false,
            mapped_relation,
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(name: &str) -> OntologyClass {
        OntologyClass {
            name: name.into(),
            description: String::new(),
            superclasses: Vec::new(),
            equivalent_classes: Vec::new(),
            disjoint_classes: Vec::new(),
            properties: Vec::new(),
            is_builtin: false,
            mapped_kind: String::new(),
        }
    }

    fn relation(name: &str, domain: &str, range: &str) -> OntologyRelation {
        OntologyRelation {
            name: name.into(),
            description: String::new(),
            domain: domain.into(),
            range: range.into(),
            cardinality: Cardinality::default(),
            inverse: String::new(),
            transitive: false,
            is_builtin: false,
            mapped_relation: String::new(),
        }
    }

    fn registry_with(classes: &[&str]) -> OntologyRegistry {
        OntologyRegistry::from_parts(classes.iter().map(|name| class(name)).collect(), Vec::new())
    }

    #[test]
    fn class_crud_round_trip() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut person = class("Person");
        person.description = "A human".into();
        person.mapped_kind = "person".into();
        person.properties = vec![OntologyProperty {
            name: "email".into(),
            prop_type: PropertyType::String,
            required: false,
            description: String::new(),
        }];
        db.upsert_ontology_class(&person).unwrap();

        let loaded = db.get_ontology_class("Person").unwrap().unwrap();
        assert_eq!(loaded.description, "A human");
        assert_eq!(loaded.mapped_kind, "person");
        assert_eq!(loaded.properties.len(), 1);
        assert_eq!(db.list_ontology_classes().unwrap().len(), 1);

        assert!(db.delete_ontology_class("Person").unwrap());
        assert!(db.get_ontology_class("Person").unwrap().is_none());
    }

    #[test]
    fn ontology_survives_database_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ontology.db");
        {
            let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
            db.upsert_ontology_class(&class("Person")).unwrap();
            db.upsert_ontology_class(&class("Company")).unwrap();
            db.upsert_ontology_relation(&relation("works_for", "Person", "Company"))
                .unwrap();
        }

        let reopened = SekaiDb::new(path.to_str().unwrap()).unwrap();
        assert!(reopened.get_ontology_class("Person").unwrap().is_some());
        assert!(
            reopened
                .get_ontology_relation("works_for")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn kind_matching_accepts_inherited_and_equivalent_classes() {
        let mut person = class("Person");
        person.equivalent_classes = vec!["Human".into()];
        let human = class("Human");
        let mut engineer = class("Engineer");
        engineer.superclasses = vec!["Human".into()];
        engineer.mapped_kind = "engineer".into();
        let registry = OntologyRegistry::from_parts(vec![person, human, engineer], vec![]);

        assert!(registry.kind_satisfies_class("engineer", "Engineer"));
        assert!(registry.kind_satisfies_class("engineer", "Human"));
        assert!(registry.kind_satisfies_class("engineer", "Person"));
        assert!(!registry.kind_satisfies_class("engineer", "Company"));
    }

    #[test]
    fn audited_mutation_rolls_back_when_audit_insert_fails() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.conn().execute("DROP TABLE sekai_decisions", []).unwrap();

        assert!(
            db.upsert_ontology_class_with_audit(&class("Person"), "tester")
                .is_err()
        );
        assert!(db.get_ontology_class("Person").unwrap().is_none());
    }

    #[test]
    fn relation_crud_round_trip() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut works_for = relation("works_for", "Person", "Company");
        works_for.cardinality = Cardinality {
            min: 0,
            max: Some(1),
        };
        works_for.transitive = false;
        works_for.mapped_relation = "employed_by".into();
        db.upsert_ontology_relation(&works_for).unwrap();

        let loaded = db.get_ontology_relation("works_for").unwrap().unwrap();
        assert_eq!(loaded.domain, "Person");
        assert_eq!(loaded.range, "Company");
        assert_eq!(loaded.cardinality.max, Some(1));
        assert_eq!(loaded.mapped_relation, "employed_by");
        assert_eq!(db.list_ontology_relations().unwrap().len(), 1);

        assert!(db.delete_ontology_relation("works_for").unwrap());
        assert!(db.get_ontology_relation("works_for").unwrap().is_none());
    }

    #[test]
    fn valid_subclass_passes() {
        let registry = registry_with(&["Person"]);
        let mut engineer = class("Engineer");
        engineer.superclasses = vec!["Person".into()];
        assert!(validate_class_definition(&engineer, None, &registry).is_ok());
    }

    #[test]
    fn unknown_superclass_rejected() {
        let registry = registry_with(&[]);
        let mut engineer = class("Engineer");
        engineer.superclasses = vec!["Person".into()];
        let error = validate_class_definition(&engineer, None, &registry).unwrap_err();
        assert!(error.contains("unknown superclass"), "got: {error}");
    }

    #[test]
    fn empty_class_name_rejected() {
        let registry = registry_with(&[]);
        let error = validate_class_definition(&class(""), None, &registry).unwrap_err();
        assert!(error.contains("class name required"), "got: {error}");
    }

    #[test]
    fn duplicate_property_rejected() {
        let registry = registry_with(&[]);
        let mut widget = class("Widget");
        let dup = OntologyProperty {
            name: "size".into(),
            prop_type: PropertyType::Int,
            required: false,
            description: String::new(),
        };
        widget.properties = vec![dup.clone(), dup];
        let error = validate_class_definition(&widget, None, &registry).unwrap_err();
        assert!(error.contains("duplicate property"), "got: {error}");
    }

    #[test]
    fn inheritance_cycle_rejected() {
        // Person already subclasses Engineer; defining Engineer -> Person closes
        // the loop and must be rejected.
        let mut person = class("Person");
        person.superclasses = vec!["Engineer".into()];
        let registry = OntologyRegistry::from_parts(vec![person, class("Engineer")], Vec::new());
        let mut engineer = class("Engineer");
        engineer.superclasses = vec!["Person".into()];
        let error = validate_class_definition(&engineer, None, &registry).unwrap_err();
        assert!(error.contains("inheritance cycle"), "got: {error}");
    }

    #[test]
    fn disjoint_with_ancestor_rejected() {
        let registry = registry_with(&["Person"]);
        let mut engineer = class("Engineer");
        engineer.superclasses = vec!["Person".into()];
        engineer.disjoint_classes = vec!["Person".into()];
        let error = validate_class_definition(&engineer, None, &registry).unwrap_err();
        assert!(error.contains("disjoint with its ancestor"), "got: {error}");
    }

    #[test]
    fn equivalent_and_disjoint_contradiction_rejected() {
        let registry = registry_with(&["Person"]);
        let mut human = class("Human");
        human.equivalent_classes = vec!["Person".into()];
        human.disjoint_classes = vec!["Person".into()];
        let error = validate_class_definition(&human, None, &registry).unwrap_err();
        assert!(
            error.contains("both equivalent to and disjoint"),
            "got: {error}"
        );
    }

    #[test]
    fn asymmetric_equivalent_disjoint_contradiction_rejected() {
        let mut person = class("Person");
        person.disjoint_classes = vec!["Human".into()];
        let registry = OntologyRegistry::from_parts(vec![person, class("Human")], Vec::new());
        let mut human = class("Human");
        human.equivalent_classes = vec!["Person".into()];
        let error = validate_class_definition(&human, None, &registry).unwrap_err();
        assert!(error.contains("because it is disjoint"), "got: {error}");
    }

    #[test]
    fn builtin_replacement_rejected() {
        let registry = registry_with(&[]);
        let mut existing = class("Person");
        existing.is_builtin = true;
        let error =
            validate_class_definition(&class("Person"), Some(&existing), &registry).unwrap_err();
        assert!(error.contains("cannot replace builtin"), "got: {error}");
    }

    #[test]
    fn relation_unknown_endpoint_rejected() {
        let registry = registry_with(&["Person"]);
        let error = validate_relation_definition(
            &relation("works_for", "Person", "Company"),
            None,
            &registry,
        )
        .unwrap_err();
        assert!(error.contains("unknown range class"), "got: {error}");
    }

    #[test]
    fn relation_valid_endpoints_pass() {
        let registry = registry_with(&["Person", "Company"]);
        assert!(
            validate_relation_definition(
                &relation("works_for", "Person", "Company"),
                None,
                &registry
            )
            .is_ok()
        );
    }

    #[test]
    fn relation_bad_cardinality_rejected() {
        let registry = registry_with(&["Person", "Company"]);
        let mut works_for = relation("works_for", "Person", "Company");
        works_for.cardinality = Cardinality {
            min: 3,
            max: Some(1),
        };
        let error = validate_relation_definition(&works_for, None, &registry).unwrap_err();
        assert!(error.contains("cardinality max"), "got: {error}");
    }

    #[test]
    fn relation_unknown_inverse_rejected() {
        let registry = registry_with(&["Person", "Company"]);
        let mut works_for = relation("works_for", "Person", "Company");
        works_for.inverse = "employs".into();
        let error = validate_relation_definition(&works_for, None, &registry).unwrap_err();
        assert!(error.contains("unknown inverse relation"), "got: {error}");
    }

    #[test]
    fn relation_inverse_must_reverse_endpoints() {
        let mut registry = registry_with(&["Person", "Company"]);
        registry.register_relation(relation("employs", "Person", "Company"));
        let mut works_for = relation("works_for", "Person", "Company");
        works_for.inverse = "employs".into();
        let error = validate_relation_definition(&works_for, None, &registry).unwrap_err();
        assert!(error.contains("reverse domain and range"), "got: {error}");
    }

    #[test]
    fn projection_maps_object_types_and_inheritance() {
        use crate::sekai::schema::{ObjectType, PropertyDef, SchemaRegistry};

        let mut schema = SchemaRegistry::new();
        schema.register(ObjectType {
            kind: "invoice".into(),
            description: "An invoice".into(),
            is_builtin: false,
            implements: vec![],
            properties: vec![PropertyDef {
                name: "total".into(),
                prop_type: PropertyType::Float,
                required: true,
                description: String::new(),
                enum_values: vec![],
                link_kind: String::new(),
                compute_expr: String::new(),
                classification: crate::sekai::schema::default_property_classification(),
                struct_fields: vec![],
            }],
        });

        let ontology = project_schema_registry(&schema).unwrap();
        let invoice = ontology
            .get_class("invoice")
            .expect("invoice projected to a class");
        assert_eq!(invoice.mapped_kind, "invoice");
        assert_eq!(invoice.properties.len(), 1);
        assert_eq!(invoice.properties[0].name, "total");

        // The projection round-trips through storage.
        let db = SekaiDb::new(":memory:").unwrap();
        for class in ontology.classes() {
            if !class.is_builtin {
                db.upsert_ontology_class(&class).unwrap();
            }
        }
        assert!(db.get_ontology_class("invoice").unwrap().is_some());
    }
}
