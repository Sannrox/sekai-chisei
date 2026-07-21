use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 1;
pub const EMBEDDED_SKILL: &str = include_str!("../assets/SKILL.md");

#[derive(Debug)]
pub enum Error {
    Database(String),
    Input(String),
    Validation(Vec<ValidationIssue>),
    NotFound(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(message) | Self::Input(message) | Self::NotFound(message) => {
                formatter.write_str(message)
            }
            Self::Validation(issues) => {
                write!(
                    formatter,
                    "ontology validation failed with {} issue(s)",
                    issues.len()
                )
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportDocument {
    pub schema_version: u32,
    #[serde(default)]
    pub classes: Vec<Class>,
    #[serde(default)]
    pub relations: Vec<Relation>,
    #[serde(default)]
    pub provenance: Vec<Provenance>,
}

/// The versioned, storage-independent ontology exchange document.
///
/// Export deliberately reuses the import contract so a document can be moved
/// between databases without exposing the private SQLite schema.
pub type ExportDocument = ImportDocument;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Class {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub superclasses: Vec<String>,
    #[serde(default)]
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Property {
    pub name: String,
    #[serde(rename = "type")]
    pub value_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relation {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub domain: String,
    pub range: String,
    #[serde(default)]
    pub cardinality: Cardinality,
    #[serde(default)]
    pub transitive: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cardinality {
    #[serde(default)]
    pub min: u32,
    #[serde(default)]
    pub max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub subject: String,
    pub source: String,
    #[serde(default)]
    pub locator: String,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}

fn default_confidence() -> f64 {
    1.0
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub code: String,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExplainResult {
    pub class: Class,
    pub superclass_closure: Vec<String>,
    pub outbound_relations: Vec<Relation>,
    pub inbound_relations: Vec<Relation>,
    pub provenance: Vec<Provenance>,
}

pub trait Ontology {
    fn class(&self, name: &str) -> Result<Option<Class>, Error>;
    fn relations(&self, name: &str) -> Result<Vec<Relation>, Error>;
    fn validate(&self) -> Result<Vec<ValidationIssue>, Error>;
    fn explain(&self, name: &str) -> Result<ExplainResult, Error>;
}

pub struct SqliteOntology {
    connection: Connection,
}

type OntologyParts = (
    BTreeMap<String, Class>,
    BTreeMap<String, Relation>,
    Vec<Provenance>,
);

impl SqliteOntology {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map(|connection| Self { connection })
            .map_err(database_error)
    }

    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, Error> {
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map(|connection| Self { connection })
            .map_err(database_error)
    }

    pub fn initialize(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(database_error)?;
        let has_metadata = connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_master
                   WHERE type = 'table' AND name = 'ontology_metadata'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(database_error)?;
        if has_metadata {
            let ontology = Self { connection };
            ontology.check_schema_version()?;
            return Ok(ontology);
        }
        let transaction = connection.transaction().map_err(database_error)?;
        transaction
            .execute_batch(
                "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS ontology_metadata (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
             );
             INSERT INTO ontology_metadata(key, value) VALUES ('schema_version', '1')
               ON CONFLICT(key) DO NOTHING;
             CREATE TABLE IF NOT EXISTS ontology_classes (
               name TEXT PRIMARY KEY,
               definition_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS ontology_relations (
               name TEXT PRIMARY KEY,
               definition_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS ontology_provenance (
               subject TEXT NOT NULL,
               source TEXT NOT NULL,
               locator TEXT NOT NULL,
               confidence REAL NOT NULL,
               PRIMARY KEY(subject, source, locator)
             );",
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(Self { connection })
    }

    pub fn import_json(&mut self, input: &str) -> Result<(), Error> {
        let document: ImportDocument = serde_json::from_str(input)
            .map_err(|error| Error::Input(format!("invalid import document: {error}")))?;
        self.import(document)
    }

    pub fn import(&mut self, document: ImportDocument) -> Result<(), Error> {
        self.check_schema_version()?;
        if document.schema_version != SCHEMA_VERSION {
            return Err(Error::Input(format!(
                "unsupported import schema version {}; expected {SCHEMA_VERSION}",
                document.schema_version
            )));
        }
        let transaction = self.connection.transaction().map_err(database_error)?;
        let (mut classes, mut relations, mut provenance) = load_all(&transaction)?;
        for class in document.classes {
            classes.insert(class.name.clone(), class);
        }
        for relation in document.relations {
            relations.insert(relation.name.clone(), relation);
        }
        for record in document.provenance {
            provenance.retain(|existing| {
                !(existing.subject == record.subject
                    && existing.source == record.source
                    && existing.locator == record.locator)
            });
            provenance.push(record);
        }
        let issues = validate_parts(&classes, &relations, &provenance);
        if !issues.is_empty() {
            return Err(Error::Validation(issues));
        }
        persist_all(&transaction, &classes, &relations, &provenance)?;
        transaction.commit().map_err(database_error)
    }

    pub fn export(&self) -> Result<ExportDocument, Error> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        check_schema_version(&transaction)?;
        let (classes, relations, provenance) = load_all(&transaction)?;
        Ok(ExportDocument {
            schema_version: SCHEMA_VERSION,
            classes: classes.into_values().collect(),
            relations: relations.into_values().collect(),
            provenance,
        })
    }

    fn check_schema_version(&self) -> Result<(), Error> {
        check_schema_version(&self.connection)
    }
}

fn check_schema_version(connection: &Connection) -> Result<(), Error> {
    let version = connection
        .query_row(
            "SELECT value FROM ontology_metadata WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?;
    match version.as_deref() {
        Some("1") => Ok(()),
        Some(value) => Err(Error::Database(format!(
            "unsupported database schema version {value}"
        ))),
        None => Err(Error::Database(
            "not an initialized ontology database".into(),
        )),
    }
}

impl Ontology for SqliteOntology {
    fn class(&self, name: &str) -> Result<Option<Class>, Error> {
        self.check_schema_version()?;
        self.connection
            .query_row(
                "SELECT definition_json FROM ontology_classes WHERE name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?
            .map(|json| parse_stored(&json, "class"))
            .transpose()
    }

    fn relations(&self, name: &str) -> Result<Vec<Relation>, Error> {
        self.check_schema_version()?;
        let (_, relations, _) = load_all(&self.connection)?;
        Ok(relations
            .into_values()
            .filter(|relation| relation.domain == name || relation.range == name)
            .collect())
    }

    fn validate(&self) -> Result<Vec<ValidationIssue>, Error> {
        self.check_schema_version()?;
        let (classes, relations, provenance) = load_all(&self.connection)?;
        Ok(validate_parts(&classes, &relations, &provenance))
    }

    fn explain(&self, name: &str) -> Result<ExplainResult, Error> {
        self.check_schema_version()?;
        let (classes, relations, provenance) = load_all(&self.connection)?;
        let class = classes
            .get(name)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("class '{name}' was not found")))?;
        let mut closure = BTreeSet::new();
        let mut stack = class.superclasses.clone();
        while let Some(parent) = stack.pop() {
            if closure.insert(parent.clone())
                && let Some(parent_class) = classes.get(&parent)
            {
                stack.extend(parent_class.superclasses.iter().cloned());
            }
        }
        let outbound_relations = relations
            .values()
            .filter(|relation| relation.domain == name)
            .cloned()
            .collect::<Vec<_>>();
        let inbound_relations = relations
            .values()
            .filter(|relation| relation.range == name)
            .cloned()
            .collect::<Vec<_>>();
        let mut subjects = closure.clone();
        subjects.insert(name.to_string());
        subjects.extend(
            outbound_relations
                .iter()
                .map(|relation| relation.name.clone()),
        );
        subjects.extend(
            inbound_relations
                .iter()
                .map(|relation| relation.name.clone()),
        );
        let provenance = provenance
            .into_iter()
            .filter(|record| subjects.contains(&record.subject))
            .collect();
        Ok(ExplainResult {
            class,
            superclass_closure: closure.into_iter().collect(),
            outbound_relations,
            inbound_relations,
            provenance,
        })
    }
}

fn load_all(connection: &Connection) -> Result<OntologyParts, Error> {
    let mut class_statement = connection
        .prepare("SELECT name, definition_json FROM ontology_classes ORDER BY name")
        .map_err(database_error)?;
    let class_rows = class_statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(database_error)?;
    let mut classes = BTreeMap::new();
    for row in class_rows {
        let (name, json) = row.map_err(database_error)?;
        let class: Class = parse_stored(&json, "class")?;
        if class.name != name {
            return Err(Error::Database(format!(
                "stored class key '{name}' does not match its definition"
            )));
        }
        classes.insert(name, class);
    }
    let mut relation_statement = connection
        .prepare("SELECT name, definition_json FROM ontology_relations ORDER BY name")
        .map_err(database_error)?;
    let relation_rows = relation_statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(database_error)?;
    let mut relations = BTreeMap::new();
    for row in relation_rows {
        let (name, json) = row.map_err(database_error)?;
        let relation: Relation = parse_stored(&json, "relation")?;
        if relation.name != name {
            return Err(Error::Database(format!(
                "stored relation key '{name}' does not match its definition"
            )));
        }
        relations.insert(name, relation);
    }
    let mut provenance_statement = connection
        .prepare(
            "SELECT subject, source, locator, confidence FROM ontology_provenance
         ORDER BY subject, source, locator",
        )
        .map_err(database_error)?;
    let provenance = provenance_statement
        .query_map([], |row| {
            Ok(Provenance {
                subject: row.get(0)?,
                source: row.get(1)?,
                locator: row.get(2)?,
                confidence: row.get(3)?,
            })
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    Ok((classes, relations, provenance))
}

fn persist_all(
    transaction: &Transaction<'_>,
    classes: &BTreeMap<String, Class>,
    relations: &BTreeMap<String, Relation>,
    provenance: &[Provenance],
) -> Result<(), Error> {
    for class in classes.values() {
        let json = serde_json::to_string(class).map_err(|error| Error::Input(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO ontology_classes(name, definition_json) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET definition_json = excluded.definition_json",
                params![class.name, json],
            )
            .map_err(database_error)?;
    }
    for relation in relations.values() {
        let json =
            serde_json::to_string(relation).map_err(|error| Error::Input(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO ontology_relations(name, definition_json) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET definition_json = excluded.definition_json",
                params![relation.name, json],
            )
            .map_err(database_error)?;
    }
    for record in provenance {
        transaction
            .execute(
                "INSERT INTO ontology_provenance(subject, source, locator, confidence)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(subject, source, locator) DO UPDATE SET confidence = excluded.confidence",
                params![
                    record.subject,
                    record.source,
                    record.locator,
                    record.confidence
                ],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

fn validate_parts(
    classes: &BTreeMap<String, Class>,
    relations: &BTreeMap<String, Relation>,
    provenance: &[Provenance],
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    for (name, class) in classes {
        if name.trim().is_empty() {
            issue(
                &mut issues,
                "empty_name",
                "classes[].name",
                "class name must not be empty",
            );
        }
        for (index, parent) in class.superclasses.iter().enumerate() {
            if !classes.contains_key(parent) {
                issue(
                    &mut issues,
                    "undefined_superclass",
                    &format!("classes.{name}.superclasses[{index}]"),
                    &format!("undefined superclass '{parent}'"),
                );
            }
        }
        for (index, property) in class.properties.iter().enumerate() {
            if property.name.trim().is_empty() || property.value_type.trim().is_empty() {
                issue(
                    &mut issues,
                    "invalid_property",
                    &format!("classes.{name}.properties[{index}]"),
                    "property name and type must not be empty",
                );
            }
        }
        let mut seen = BTreeSet::new();
        if inheritance_cycle(name, classes, &mut seen, &mut BTreeSet::new()) {
            issue(
                &mut issues,
                "inheritance_cycle",
                &format!("classes.{name}.superclasses"),
                "superclass graph contains a cycle",
            );
        }
    }
    for (name, relation) in relations {
        if name.trim().is_empty() {
            issue(
                &mut issues,
                "empty_name",
                "relations[].name",
                "relation name must not be empty",
            );
        }
        if classes.contains_key(name) {
            issue(
                &mut issues,
                "ambiguous_definition_name",
                &format!("relations.{name}.name"),
                "class and relation names must be distinct",
            );
        }
        if !classes.contains_key(&relation.domain) {
            issue(
                &mut issues,
                "unknown_relation_endpoint",
                &format!("relations.{name}.domain"),
                &format!("unknown class '{}'", relation.domain),
            );
        }
        if !classes.contains_key(&relation.range) {
            issue(
                &mut issues,
                "unknown_relation_endpoint",
                &format!("relations.{name}.range"),
                &format!("unknown class '{}'", relation.range),
            );
        }
        if relation
            .cardinality
            .max
            .is_some_and(|max| max < relation.cardinality.min)
        {
            issue(
                &mut issues,
                "invalid_cardinality",
                &format!("relations.{name}.cardinality"),
                "max must be greater than or equal to min",
            );
        }
    }
    for (index, record) in provenance.iter().enumerate() {
        if !classes.contains_key(&record.subject) && !relations.contains_key(&record.subject) {
            issue(
                &mut issues,
                "unknown_provenance_subject",
                &format!("provenance[{index}].subject"),
                &format!("unknown subject '{}'", record.subject),
            );
        }
        if record.source.trim().is_empty() {
            issue(
                &mut issues,
                "invalid_provenance",
                &format!("provenance[{index}].source"),
                "source must not be empty",
            );
        }
        if !record.confidence.is_finite() || !(0.0..=1.0).contains(&record.confidence) {
            issue(
                &mut issues,
                "invalid_confidence",
                &format!("provenance[{index}].confidence"),
                "confidence must be between 0 and 1",
            );
        }
    }
    issues.sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
    issues.dedup();
    issues
}

fn inheritance_cycle(
    name: &str,
    classes: &BTreeMap<String, Class>,
    visited: &mut BTreeSet<String>,
    active: &mut BTreeSet<String>,
) -> bool {
    if active.contains(name) {
        return true;
    }
    if !visited.insert(name.to_string()) {
        return false;
    }
    active.insert(name.to_string());
    let cycle = classes.get(name).is_some_and(|class| {
        class.superclasses.iter().any(|parent| {
            classes.contains_key(parent) && inheritance_cycle(parent, classes, visited, active)
        })
    });
    active.remove(name);
    cycle
}

fn issue(issues: &mut Vec<ValidationIssue>, code: &str, path: &str, message: &str) {
    issues.push(ValidationIssue {
        code: code.into(),
        path: path.into(),
        message: message.into(),
    });
}

fn parse_stored<T: serde::de::DeserializeOwned>(json: &str, kind: &str) -> Result<T, Error> {
    serde_json::from_str(json)
        .map_err(|error| Error::Database(format!("malformed stored {kind}: {error}")))
}

fn database_error(error: rusqlite::Error) -> Error {
    Error::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> ImportDocument {
        serde_json::from_str(include_str!("../tests/fixtures/codebase.json")).unwrap()
    }

    #[test]
    fn import_is_transactional_and_explain_resolves_context() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("knowledge.db");
        let mut ontology = SqliteOntology::initialize(&path).unwrap();
        ontology.import(document()).unwrap();
        let explanation = ontology.explain("Api").unwrap();
        assert_eq!(explanation.superclass_closure, ["Component", "Service"]);
        assert_eq!(explanation.outbound_relations[0].name, "depends_on");
        assert_eq!(explanation.inbound_relations[0].name, "serves");
        assert_eq!(explanation.provenance.len(), 4);

        let mut invalid = document();
        invalid.classes[1].superclasses = vec!["Missing".into()];
        assert!(matches!(
            ontology.import(invalid),
            Err(Error::Validation(_))
        ));
        assert_eq!(ontology.explain("Api").unwrap(), explanation);
    }

    #[test]
    fn export_round_trips_the_complete_logical_ontology() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.db");
        let destination_path = directory.path().join("destination.db");
        let mut source = SqliteOntology::initialize(&source_path).unwrap();
        source.import(document()).unwrap();

        let exported = source.export().unwrap();
        assert_eq!(exported.schema_version, SCHEMA_VERSION);
        assert_eq!(
            exported
                .classes
                .iter()
                .map(|class| class.name.as_str())
                .collect::<Vec<_>>(),
            ["Api", "Client", "Component", "Database", "Service"]
        );
        assert_eq!(
            exported
                .relations
                .iter()
                .map(|relation| relation.name.as_str())
                .collect::<Vec<_>>(),
            ["depends_on", "serves"]
        );
        assert_eq!(exported.provenance.len(), 4);

        let mut destination = SqliteOntology::initialize(&destination_path).unwrap();
        destination.import(exported.clone()).unwrap();
        assert_eq!(destination.export().unwrap(), exported);
        assert_eq!(destination.validate().unwrap(), source.validate().unwrap());
    }

    #[test]
    fn empty_ontology_exports_empty_collections() {
        let directory = tempfile::tempdir().unwrap();
        let ontology = SqliteOntology::initialize(directory.path().join("empty.db")).unwrap();
        assert_eq!(
            ontology.export().unwrap(),
            ExportDocument {
                schema_version: SCHEMA_VERSION,
                classes: vec![],
                relations: vec![],
                provenance: vec![],
            }
        );
    }

    #[test]
    fn validation_locates_required_definition_failures() {
        let classes = BTreeMap::from([(
            "Child".into(),
            Class {
                name: "Child".into(),
                description: String::new(),
                superclasses: vec!["Missing".into()],
                properties: vec![],
            },
        )]);
        let relations = BTreeMap::from([(
            "bad".into(),
            Relation {
                name: "bad".into(),
                description: String::new(),
                domain: "Child".into(),
                range: "Missing".into(),
                cardinality: Cardinality {
                    min: 2,
                    max: Some(1),
                },
                transitive: false,
            },
        )]);
        let issues = validate_parts(&classes, &relations, &[]);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "undefined_superclass")
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "unknown_relation_endpoint")
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "invalid_cardinality")
        );

        let colliding_relations = BTreeMap::from([(
            "Child".into(),
            Relation {
                name: "Child".into(),
                description: String::new(),
                domain: "Child".into(),
                range: "Child".into(),
                cardinality: Cardinality::default(),
                transitive: false,
            },
        )]);
        let issues = validate_parts(&classes, &colliding_relations, &[]);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "ambiguous_definition_name")
        );
    }

    #[test]
    fn initialize_does_not_modify_an_incompatible_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("future.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE ontology_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO ontology_metadata(key, value) VALUES ('schema_version', '2');",
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteOntology::initialize(&path),
            Err(Error::Database(message)) if message.contains("schema version 2")
        ));
        let connection = Connection::open(&path).unwrap();
        let ontology_tables: u32 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN (
                   'ontology_classes', 'ontology_relations', 'ontology_provenance'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ontology_tables, 0);
    }
}
