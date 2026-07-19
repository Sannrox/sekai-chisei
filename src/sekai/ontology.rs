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
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Cardinality bound for the range side of a relation. `max = None` means
/// unbounded. Inference does not act on these bounds yet; they are durable
/// metadata that #142 will enforce.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    }
    Ok(())
}

/// Project an existing `SchemaRegistry` into ontology classes.
///
/// Object types and interfaces become classes; an object type's `implements`
/// list becomes `superclasses`, and each schema `PropertyDef` becomes an
/// `OntologyProperty`. `mapped_kind` records the originating object kind so the
/// projection stays reversible.
pub fn project_schema_registry(schema: &SchemaRegistry) -> OntologyRegistry {
    let mut registry = OntologyRegistry::new();
    for interface in schema.all_interfaces() {
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
    registry
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
        let superclasses_json =
            serde_json::to_string(&class.superclasses).map_err(|error| error.to_string())?;
        let equivalent_json =
            serde_json::to_string(&class.equivalent_classes).map_err(|error| error.to_string())?;
        let disjoint_json =
            serde_json::to_string(&class.disjoint_classes).map_err(|error| error.to_string())?;
        let properties_json =
            serde_json::to_string(&class.properties).map_err(|error| error.to_string())?;
        let conn = self.conn();
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

    pub fn upsert_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let superclasses_json =
            serde_json::to_string(&class.superclasses).map_err(|error| error.to_string())?;
        let equivalent_json =
            serde_json::to_string(&class.equivalent_classes).map_err(|error| error.to_string())?;
        let disjoint_json =
            serde_json::to_string(&class.disjoint_classes).map_err(|error| error.to_string())?;
        let properties_json =
            serde_json::to_string(&class.properties).map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let existed = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sekai_ontology_classes WHERE name = ?1)",
                params![class.name],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
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
        let conn = self.conn();
        let deleted = conn
            .execute(
                "DELETE FROM sekai_ontology_classes WHERE name = ?1",
                params![name],
            )
            .map_err(|error| error.to_string())?;
        Ok(deleted > 0)
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
        let deleted = transaction
            .execute(
                "DELETE FROM sekai_ontology_classes WHERE name = ?1",
                params![name],
            )
            .map_err(|error| error.to_string())?;
        if deleted > 0 {
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
        Ok(deleted > 0)
    }

    pub fn get_ontology_class(&self, name: &str) -> Result<Option<OntologyClass>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT name, description, superclasses_json, equivalent_json, disjoint_json, properties_json, mapped_kind
             FROM sekai_ontology_classes WHERE name = ?1",
            params![name],
            row_to_ontology_class,
        )
        .optional()
        .map_err(|error| error.to_string())?
        .transpose()
    }

    pub fn list_ontology_classes(&self) -> Result<Vec<OntologyClass>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT name, description, superclasses_json, equivalent_json, disjoint_json, properties_json, mapped_kind
                 FROM sekai_ontology_classes ORDER BY name",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = stmt.query([]).map_err(|error| error.to_string())?;
        let mut classes = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            classes.push(row_to_ontology_class(row).map_err(|error| error.to_string())??);
        }
        Ok(classes)
    }

    pub fn upsert_ontology_relation(&self, relation: &OntologyRelation) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let cardinality_json =
            serde_json::to_string(&relation.cardinality).map_err(|error| error.to_string())?;
        let conn = self.conn();
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

    pub fn upsert_ontology_relation_with_audit(
        &self,
        relation: &OntologyRelation,
        actor: &str,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let cardinality_json =
            serde_json::to_string(&relation.cardinality).map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let existed = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sekai_ontology_relations WHERE name = ?1)",
                params![relation.name],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
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
        let conn = self.conn();
        let deleted = conn
            .execute(
                "DELETE FROM sekai_ontology_relations WHERE name = ?1",
                params![name],
            )
            .map_err(|error| error.to_string())?;
        Ok(deleted > 0)
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
        let deleted = transaction
            .execute(
                "DELETE FROM sekai_ontology_relations WHERE name = ?1",
                params![name],
            )
            .map_err(|error| error.to_string())?;
        if deleted > 0 {
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
        Ok(deleted > 0)
    }

    pub fn get_ontology_relation(&self, name: &str) -> Result<Option<OntologyRelation>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT name, description, domain, range, cardinality_json, inverse, transitive, mapped_relation
             FROM sekai_ontology_relations WHERE name = ?1",
            params![name],
            row_to_ontology_relation,
        )
        .optional()
        .map_err(|error| error.to_string())?
        .transpose()
    }

    pub fn list_ontology_relations(&self) -> Result<Vec<OntologyRelation>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT name, description, domain, range, cardinality_json, inverse, transitive, mapped_relation
                 FROM sekai_ontology_relations ORDER BY name",
            )
            .map_err(|error| error.to_string())?;
        let mut rows = stmt.query([]).map_err(|error| error.to_string())?;
        let mut relations = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            relations.push(row_to_ontology_relation(row).map_err(|error| error.to_string())??);
        }
        Ok(relations)
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

        let ontology = project_schema_registry(&schema);
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
