use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

mod directory;

pub use directory::{
    DEFAULT_DIRECTORY_KIND, DIRECTORY_RELATION_CONTAINS, DIRECTORY_SCHEMA_VERSION,
    DirectoryDocument, DirectoryEntity, DirectoryImportReport, DirectoryIndexReport, DirectoryLink,
    DirectoryQueryResult, DirectoryScanOptions, MAX_DIRECTORY_DEPTH, directory_ontology_document,
};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_QUERY_DEPTH: u32 = 32;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalDirection {
    Outbound,
    Inbound,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryOptions {
    pub direction: TraversalDirection,
    pub relation: Option<String>,
    pub depth: u32,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            direction: TraversalDirection::Both,
            relation: None,
            depth: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct QueryResult {
    pub start: String,
    pub options: QueryOptions,
    pub classes: Vec<Class>,
    pub relations: Vec<Relation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionKind {
    Class,
    Relation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchMatch {
    pub kind: DefinitionKind,
    pub name: String,
    pub score: u32,
    pub matched_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchResult {
    pub query: String,
    pub matches: Vec<SearchMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedDefinition {
    pub name: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct DiffSummary {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<ChangedDefinition>,
}

impl DiffSummary {
    fn is_changed(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.changed.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OntologyDiff {
    pub before_schema_version: u32,
    pub after_schema_version: u32,
    pub schema_changed: bool,
    pub classes: DiffSummary,
    pub relations: DiffSummary,
    pub provenance: DiffSummary,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AskStatus {
    Ready,
    Ambiguous,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AskOperation {
    Explain,
    Query,
    Find,
    DirectoryQuery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AskPlan {
    pub operation: AskOperation,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<QueryOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AskInterpretation {
    pub question: String,
    pub status: AskStatus,
    pub interpretation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<AskPlan>,
    pub candidates: Vec<SearchMatch>,
}

pub trait Ontology {
    fn class(&self, name: &str) -> Result<Option<Class>, Error>;
    fn relations(&self, name: &str) -> Result<Vec<Relation>, Error>;
    fn validate(&self) -> Result<Vec<ValidationIssue>, Error>;
    fn explain(&self, name: &str) -> Result<ExplainResult, Error>;
    fn query(&self, _start: &str, _options: QueryOptions) -> Result<QueryResult, Error> {
        Err(Error::Input(
            "bounded traversal is not supported by this ontology implementation".into(),
        ))
    }
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
            directory::ensure_schema(&ontology.connection)?;
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
        let ontology = Self { connection };
        directory::ensure_schema(&ontology.connection)?;
        Ok(ontology)
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

    pub fn find(&self, query: &str) -> Result<SearchResult, Error> {
        self.check_schema_version()?;
        search_document(&self.export()?, query)
    }

    fn check_schema_version(&self) -> Result<(), Error> {
        check_schema_version(&self.connection)
    }
}

pub fn search_document(document: &ExportDocument, query: &str) -> Result<SearchResult, Error> {
    if normalize_text(query).is_empty() {
        return Err(Error::Input("find query must not be empty".into()));
    }

    let mut matches = Vec::new();
    for class in &document.classes {
        let mut fields = vec![
            ("name".to_string(), class.name.clone()),
            ("description".to_string(), class.description.clone()),
            ("superclasses".to_string(), class.superclasses.join(" ")),
        ];
        for property in &class.properties {
            fields.push(("properties".to_string(), property.name.clone()));
            fields.push(("property_types".to_string(), property.value_type.clone()));
            fields.push((
                "property_descriptions".to_string(),
                property.description.clone(),
            ));
        }
        let field_refs = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        if let Some((score, matched_fields)) = score_fields(query, &field_refs) {
            matches.push(SearchMatch {
                kind: DefinitionKind::Class,
                name: class.name.clone(),
                score,
                matched_fields,
            });
        }
    }
    for relation in &document.relations {
        let fields = [
            ("name", relation.name.as_str()),
            ("description", relation.description.as_str()),
            ("domain", relation.domain.as_str()),
            ("range", relation.range.as_str()),
        ];
        if let Some((score, matched_fields)) = score_fields(query, &fields) {
            matches.push(SearchMatch {
                kind: DefinitionKind::Relation,
                name: relation.name.clone(),
                score,
                matched_fields,
            });
        }
    }
    matches.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    Ok(SearchResult {
        query: query.to_string(),
        matches,
    })
}

pub fn diff_documents(before: &ExportDocument, after: &ExportDocument) -> OntologyDiff {
    let classes = diff_classes(before, after);
    let relations = diff_relations(before, after);
    let provenance = diff_provenance(before, after);
    let schema_changed = before.schema_version != after.schema_version;
    let changed =
        schema_changed || classes.is_changed() || relations.is_changed() || provenance.is_changed();
    OntologyDiff {
        before_schema_version: before.schema_version,
        after_schema_version: after.schema_version,
        schema_changed,
        classes,
        relations,
        provenance,
        changed,
    }
}

pub fn interpret_question(
    document: &ExportDocument,
    question: &str,
) -> Result<AskInterpretation, Error> {
    let normalized = normalize_text(question);
    if normalized.is_empty() {
        return Err(Error::Input("ask question must not be empty".into()));
    }
    if has_signed_depth(question) {
        return Ok(unsupported_interpretation(
            question,
            "the question names an invalid depth",
            Vec::new(),
        ));
    }

    if let Some(query) = extract_find_operand(question) {
        let depth = match strip_depth(&normalized)? {
            DepthStrip::Conflict => {
                return Ok(unsupported_interpretation(
                    question,
                    "the question names more than one depth",
                    Vec::new(),
                ));
            }
            DepthStrip::Parsed { depth, .. } => depth,
        };
        if depth.is_some() {
            return Ok(unsupported_interpretation(
                question,
                "find questions do not accept a depth",
                Vec::new(),
            ));
        }
        return find_interpretation(question, &query);
    }

    let path_resolution = resolve_path(question);
    let working_text = match &path_resolution {
        PathResolution::Unique(path) => remove_once(question, path),
        PathResolution::None | PathResolution::Ambiguous(_) => question.to_string(),
    };
    let (normalized, depth) = match strip_depth(&normalize_text(&working_text))? {
        DepthStrip::Conflict => {
            return Ok(unsupported_interpretation(
                question,
                "the question names more than one depth",
                Vec::new(),
            ));
        }
        DepthStrip::Parsed { remainder, depth } => (remainder, depth),
    };
    if normalized.is_empty() {
        return Ok(unsupported_interpretation(
            question,
            "supported forms are explain/describe, what is related to, what does, which classes, find/search, and directory path queries",
            search_document(document, question)?.matches,
        ));
    }

    match path_resolution {
        PathResolution::Ambiguous(paths) => {
            return Ok(ambiguous_interpretation(
                question,
                &format!(
                    "more than one filesystem path matches the question: {}",
                    paths.join(", ")
                ),
                Vec::new(),
            ));
        }
        PathResolution::Unique(path) => {
            return directory_interpretation(question, &normalized, path, depth);
        }
        PathResolution::None => {}
    }

    let class_resolution = resolve_class(document, &normalized);
    let relation_resolution = resolve_relation(document, &normalized);
    let depth = depth.unwrap_or(1);
    if depth > MAX_QUERY_DEPTH {
        return Ok(unsupported_interpretation(
            question,
            &format!("query depth {depth} exceeds maximum {MAX_QUERY_DEPTH}"),
            Vec::new(),
        ));
    }

    for prefix in [
        "what is related to ",
        "what is connected to ",
        "what is linked to ",
        "what is associated with ",
        "which classes are related to ",
    ] {
        if normalized.starts_with(prefix) {
            return query_interpretation(
                question,
                class_resolution,
                None,
                TraversalDirection::Both,
                depth,
                "a bounded bidirectional relation query",
            );
        }
    }

    for prefix in ["explain ", "describe ", "what is ", "tell me about "] {
        if normalized.starts_with(prefix) {
            if depth != 1 {
                return query_interpretation(
                    question,
                    class_resolution,
                    None,
                    TraversalDirection::Both,
                    depth,
                    "a bounded bidirectional relation query",
                );
            }
            return explain_interpretation(question, class_resolution);
        }
    }

    if normalized.starts_with("what does ")
        || normalized.starts_with("which relations does ")
        || normalized.starts_with("what relations does ")
    {
        let relation = match relation_resolution {
            RelationResolution::Unique(relation) => Some(relation),
            RelationResolution::Missing => None,
            RelationResolution::Ambiguous(candidates) => {
                return Ok(ambiguous_interpretation(
                    question,
                    "more than one relation matches the question",
                    candidates,
                ));
            }
        };
        if relation.is_none()
            && !contains_any_phrase(
                &normalized,
                &[
                    "connect to",
                    "relate to",
                    "link to",
                    "associate with",
                    "have",
                ],
            )
        {
            return Ok(unsupported_interpretation(
                question,
                "the question does not name a known relation or supported generic relation phrase",
                search_document(document, question)?.matches,
            ));
        }
        return query_interpretation(
            question,
            class_resolution,
            relation,
            TraversalDirection::Outbound,
            depth,
            "a bounded outbound relation query",
        );
    }

    if normalized.starts_with("what ") || normalized.starts_with("which classes ") {
        let relation = match relation_resolution {
            RelationResolution::Unique(relation) => Some(relation),
            RelationResolution::Missing => None,
            RelationResolution::Ambiguous(candidates) => {
                return Ok(ambiguous_interpretation(
                    question,
                    "more than one relation matches the question",
                    candidates,
                ));
            }
        };
        if relation.is_none() {
            return Ok(unsupported_interpretation(
                question,
                "the question does not name a known relation",
                search_document(document, question)?.matches,
            ));
        }
        return query_interpretation(
            question,
            class_resolution,
            relation,
            TraversalDirection::Inbound,
            depth,
            "a bounded inbound relation query",
        );
    }

    Ok(unsupported_interpretation(
        question,
        "supported forms are explain/describe, what is related to, what does, which classes, find/search, and directory path queries",
        search_document(document, question)?.matches,
    ))
}

#[derive(Debug)]
enum NameResolution {
    Unique(String),
    Missing(Vec<SearchMatch>),
    Ambiguous(Vec<SearchMatch>),
}

#[derive(Debug)]
enum PathResolution {
    None,
    Unique(String),
    Ambiguous(Vec<String>),
}

#[derive(Debug)]
enum DepthStrip {
    Conflict,
    Parsed {
        remainder: String,
        depth: Option<u32>,
    },
}

#[derive(Debug)]
enum RelationResolution {
    Unique(String),
    Missing,
    Ambiguous(Vec<SearchMatch>),
}

fn score_fields(query: &str, fields: &[(&str, &str)]) -> Option<(u32, Vec<String>)> {
    let normalized_query = normalize_text(query);
    let query_tokens = normalized_query.split_whitespace().collect::<Vec<_>>();
    if query_tokens.is_empty() {
        return None;
    }

    let mut score = 0;
    let mut matched_fields = BTreeSet::new();
    for (field_name, value) in fields {
        let normalized_value = normalize_text(value);
        let field_score = field_match_score(&normalized_query, &query_tokens, &normalized_value);
        if field_score > 0 {
            score = score.max(field_score);
            matched_fields.insert((*field_name).to_string());
        }
    }
    (score > 0).then(|| (score, matched_fields.into_iter().collect()))
}

fn field_match_score(query: &str, query_tokens: &[&str], value: &str) -> u32 {
    if value.is_empty() {
        return 0;
    }
    if value == query {
        return 1000;
    }
    if value.starts_with(query) {
        return 850;
    }
    if value.contains(query) {
        return 700;
    }

    let value_tokens = value.split_whitespace().collect::<Vec<_>>();
    let hits = query_tokens
        .iter()
        .filter(|token| value_tokens.iter().any(|value| value == *token))
        .count();
    if hits == query_tokens.len() {
        500 + hits as u32 * 10
    } else if hits > 0 {
        100 + hits as u32 * 10
    } else {
        0
    }
}

fn normalize_text(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_alphanumeric() {
            for lowercase in character.to_lowercase() {
                normalized.push(lowercase);
            }
        } else {
            normalized.push(' ');
        }
    }
    normalized.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn contains_phrase(text: &str, phrase: &str) -> bool {
    let text_tokens = text.split_whitespace().collect::<Vec<_>>();
    let phrase_tokens = phrase.split_whitespace().collect::<Vec<_>>();
    !phrase_tokens.is_empty()
        && text_tokens
            .windows(phrase_tokens.len())
            .any(|window| window == phrase_tokens.as_slice())
}

fn contains_any_phrase(text: &str, phrases: &[&str]) -> bool {
    phrases
        .iter()
        .map(|phrase| normalize_text(phrase))
        .any(|phrase| contains_phrase(text, &phrase))
}

fn singularize(token: &str) -> String {
    if token.len() > 3 && token.ends_with('s') && !token.ends_with("ss") {
        token[..token.len() - 1].to_string()
    } else {
        token.to_string()
    }
}

fn relation_variants(name: &str) -> Vec<String> {
    let base = normalize_text(name);
    let singular = base
        .split_whitespace()
        .map(singularize)
        .collect::<Vec<_>>()
        .join(" ");
    if base == singular {
        vec![base]
    } else {
        vec![base, singular]
    }
}

fn resolve_class(document: &ExportDocument, question: &str) -> NameResolution {
    let mut matches = document
        .classes
        .iter()
        .filter_map(|class| {
            let name = normalize_text(&class.name);
            contains_phrase(question, &name).then(|| (name.len(), class.name.clone()))
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    if matches.is_empty() {
        let suggestions = document
            .classes
            .iter()
            .filter_map(|class| {
                let fields = [
                    ("name", class.name.as_str()),
                    ("description", class.description.as_str()),
                ];
                score_fields(question, &fields).map(|(score, matched_fields)| SearchMatch {
                    kind: DefinitionKind::Class,
                    name: class.name.clone(),
                    score,
                    matched_fields,
                })
            })
            .collect::<Vec<_>>();
        return NameResolution::Missing(limit_search_matches(suggestions));
    }
    let longest = matches[0].0;
    let candidates = matches
        .into_iter()
        .filter(|(length, _)| *length == longest)
        .map(|(_, name)| SearchMatch {
            kind: DefinitionKind::Class,
            name,
            score: 1000,
            matched_fields: vec!["name".into()],
        })
        .collect::<Vec<_>>();
    if candidates.len() == 1 {
        NameResolution::Unique(candidates[0].name.clone())
    } else {
        NameResolution::Ambiguous(candidates)
    }
}

fn resolve_relation(document: &ExportDocument, question: &str) -> RelationResolution {
    let mut matches = document
        .relations
        .iter()
        .filter_map(|relation| {
            let variants = relation_variants(&relation.name);
            variants
                .iter()
                .find(|variant| contains_phrase(question, variant))
                .map(|variant| {
                    (
                        if variant == &variants[0] { 1000 } else { 900 },
                        relation.name.clone(),
                    )
                })
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    if matches.is_empty() {
        return RelationResolution::Missing;
    }
    let best_score = matches[0].0;
    let candidates = matches
        .into_iter()
        .filter(|(score, _)| *score == best_score)
        .map(|(score, name)| SearchMatch {
            kind: DefinitionKind::Relation,
            name,
            score,
            matched_fields: vec!["name".into()],
        })
        .collect::<Vec<_>>();
    if candidates.len() == 1 {
        RelationResolution::Unique(candidates[0].name.clone())
    } else {
        RelationResolution::Ambiguous(candidates)
    }
}

fn limit_search_matches(mut matches: Vec<SearchMatch>) -> Vec<SearchMatch> {
    matches.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    matches.truncate(5);
    matches
}

fn extract_find_operand(question: &str) -> Option<String> {
    let trimmed = question.trim();
    for prefix in [
        "search for ",
        "which classes mention ",
        "which definitions mention ",
        "which relations mention ",
        "look up ",
        "lookup ",
        "search ",
        "find ",
    ] {
        if let Some(rest) = strip_prefix_ignore_ascii_case(trimmed, prefix) {
            let operand = rest.trim().trim_end_matches(['?', '!', '.', ',']).trim();
            return (!operand.is_empty()).then(|| operand.to_string());
        }
    }
    None
}

fn strip_prefix_ignore_ascii_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let candidate = input.get(..prefix.len())?;
    candidate
        .eq_ignore_ascii_case(prefix)
        .then_some(&input[prefix.len()..])
}

fn directory_plan_shape(
    remainder: &str,
) -> Option<(TraversalDirection, Option<String>, &'static str)> {
    if remainder.starts_with("what contains")
        || remainder.starts_with("which directories contain")
        || contains_phrase(remainder, "parent of")
    {
        return Some((
            TraversalDirection::Inbound,
            Some(DIRECTORY_RELATION_CONTAINS.to_string()),
            "a bounded inbound directory query",
        ));
    }
    if contains_any_phrase(
        remainder,
        &["contain", "contains", "inside", "under", "what is in"],
    ) {
        return Some((
            TraversalDirection::Outbound,
            Some(DIRECTORY_RELATION_CONTAINS.to_string()),
            "a bounded outbound directory query",
        ));
    }
    if remainder.starts_with("what is related to")
        || remainder.starts_with("what is connected to")
        || remainder.starts_with("what is linked to")
        || remainder.starts_with("what is associated with")
        || remainder.starts_with("which directories are related to")
    {
        return Some((
            TraversalDirection::Both,
            None,
            "a bounded bidirectional directory query",
        ));
    }
    None
}

fn find_interpretation(question: &str, query: &str) -> Result<AskInterpretation, Error> {
    if normalize_text(query).is_empty() {
        return Ok(unsupported_interpretation(
            question,
            "the find question does not include search text",
            Vec::new(),
        ));
    }
    Ok(AskInterpretation {
        question: question.to_string(),
        status: AskStatus::Ready,
        interpretation: format!("a deterministic definition search for '{query}'"),
        plan: Some(AskPlan {
            operation: AskOperation::Find,
            name: query.to_string(),
            options: None,
        }),
        candidates: Vec::new(),
    })
}

fn directory_interpretation(
    question: &str,
    remainder: &str,
    path: String,
    depth: Option<u32>,
) -> Result<AskInterpretation, Error> {
    let path = match expand_user_path(&path) {
        Ok(path) => path,
        Err(message) => {
            return Ok(unsupported_interpretation(question, &message, Vec::new()));
        }
    };
    let depth = depth.unwrap_or(1);
    if depth > MAX_DIRECTORY_DEPTH {
        return Ok(unsupported_interpretation(
            question,
            &format!("directory query depth {depth} exceeds maximum {MAX_DIRECTORY_DEPTH}"),
            Vec::new(),
        ));
    }
    let Some((direction, relation, description)) = directory_plan_shape(remainder) else {
        return Ok(unsupported_interpretation(
            question,
            "the question names a filesystem path but is not a supported directory query form",
            Vec::new(),
        ));
    };
    let relation_description = relation
        .as_deref()
        .map(|relation| format!(" via relation '{relation}'"))
        .unwrap_or_default();
    let depth_description = if depth == 1 {
        String::new()
    } else {
        format!(" at depth {depth}")
    };
    Ok(AskInterpretation {
        question: question.to_string(),
        status: AskStatus::Ready,
        interpretation: format!(
            "{description}{relation_description}{depth_description} from path '{path}'"
        ),
        plan: Some(AskPlan {
            operation: AskOperation::DirectoryQuery,
            name: path,
            options: Some(QueryOptions {
                direction,
                relation,
                depth,
            }),
        }),
        candidates: Vec::new(),
    })
}

fn resolve_path(question: &str) -> PathResolution {
    let (quoted, remainder) = extract_quoted_spans(question);
    let mut matches = quoted
        .into_iter()
        .filter(|value| looks_like_path(value))
        .collect::<Vec<_>>();
    matches.extend(
        remainder
            .split_whitespace()
            .map(|token| trim_path_token(token).to_string())
            .filter(|token| looks_like_path(token)),
    );
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [] => PathResolution::None,
        [path] => PathResolution::Unique(path.clone()),
        _ => PathResolution::Ambiguous(matches),
    }
}

fn extract_quoted_spans(question: &str) -> (Vec<String>, String) {
    let chars = question.chars().collect::<Vec<_>>();
    let mut quoted = Vec::new();
    let mut remainder = String::new();
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        // Quotes starting a token delimit one path operand. Quote characters
        // inside an unquoted path token stay part of that token.
        if matches!(character, '"' | '\'')
            && (index == 0 || chars[index - 1].is_whitespace())
            && let Some(end) = chars[index + 1..]
                .iter()
                .position(|candidate| *candidate == character)
        {
            let value = chars[index + 1..index + 1 + end]
                .iter()
                .collect::<String>()
                .trim()
                .to_string();
            if !value.is_empty() {
                quoted.push(value);
            }
            remainder.push(' ');
            index += end + 2;
            continue;
        }
        remainder.push(character);
        index += 1;
    }
    (quoted, remainder)
}

fn trim_path_token(token: &str) -> &str {
    let token = token.trim_end_matches(['?', '!', ',', ';', ':']);
    if token.len() > 1
        && token.ends_with('.')
        && token != "."
        && token != ".."
        && !token.ends_with("/.")
        && !token.ends_with("/..")
    {
        token.trim_end_matches('.')
    } else {
        token
    }
}

fn expand_user_path(path: &str) -> Result<String, String> {
    if path == "~" || path.starts_with("~/") {
        let home = std::env::var("HOME").map_err(|_| {
            "home-relative ask paths require the HOME environment variable".to_string()
        })?;
        if path == "~" {
            return Ok(home);
        }
        return Ok(format!("{home}{}", &path[1..]));
    }
    Ok(path.to_string())
}

fn looks_like_path(value: &str) -> bool {
    if value.is_empty() || value.contains("://") {
        return false;
    }
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value == "~"
        || value.starts_with("~/")
}

fn remove_once(haystack: &str, needle: &str) -> String {
    match haystack.find(needle) {
        Some(index) => {
            let mut result = String::with_capacity(haystack.len().saturating_sub(needle.len()));
            result.push_str(&haystack[..index]);
            result.push_str(&haystack[index + needle.len()..]);
            result
        }
        None => haystack.to_string(),
    }
}

fn has_signed_depth(question: &str) -> bool {
    let lower = question.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(index) = rest.find("depth") {
        let after = rest[index + 5..].trim_start();
        if after.starts_with('-') {
            return true;
        }
        rest = &rest[index + 5..];
    }
    false
}

fn strip_depth(normalized: &str) -> Result<DepthStrip, Error> {
    let tokens = normalized.split_whitespace().collect::<Vec<_>>();
    let mut skip = vec![false; tokens.len()];
    let mut depth = None;
    let mut index = 0;
    while index < tokens.len() {
        let digit_token = |offset: usize| {
            tokens
                .get(index + offset)
                .filter(|token| {
                    !token.is_empty() && token.chars().all(|character| character.is_ascii_digit())
                })
                .copied()
        };
        let parsed = if matches!(tokens.get(index).copied(), Some("to" | "at"))
            && tokens.get(index + 1).copied() == Some("depth")
        {
            digit_token(2).map(|raw| (3, raw))
        } else if tokens.get(index).copied() == Some("depth") {
            digit_token(1).map(|raw| (2, raw))
        } else {
            None
        };
        if let Some((consumed, raw)) = parsed {
            let parsed = raw
                .parse::<u32>()
                .map_err(|_| Error::Input(format!("invalid ask depth '{raw}'")))?;
            if depth.is_some_and(|existing| existing != parsed) {
                return Ok(DepthStrip::Conflict);
            }
            depth = Some(parsed);
            for slot in &mut skip[index..index + consumed] {
                *slot = true;
            }
            index += consumed;
        } else {
            index += 1;
        }
    }
    Ok(DepthStrip::Parsed {
        remainder: tokens
            .iter()
            .enumerate()
            .filter(|(index, _)| !skip[*index])
            .map(|(_, token)| *token)
            .collect::<Vec<_>>()
            .join(" "),
        depth,
    })
}

fn query_interpretation(
    question: &str,
    class_resolution: NameResolution,
    relation: Option<String>,
    direction: TraversalDirection,
    depth: u32,
    description: &str,
) -> Result<AskInterpretation, Error> {
    let name = match class_resolution {
        NameResolution::Unique(name) => name,
        NameResolution::Missing(candidates) => {
            return Ok(unsupported_interpretation(
                question,
                "could not identify one class in the question",
                candidates,
            ));
        }
        NameResolution::Ambiguous(candidates) => {
            return Ok(ambiguous_interpretation(
                question,
                "more than one class matches the question",
                candidates,
            ));
        }
    };
    let relation_description = relation
        .as_deref()
        .map(|relation| format!(" via relation '{relation}'"))
        .unwrap_or_default();
    let depth_description = if depth == 1 {
        String::new()
    } else {
        format!(" at depth {depth}")
    };
    Ok(AskInterpretation {
        question: question.to_string(),
        status: AskStatus::Ready,
        interpretation: format!(
            "{description}{relation_description}{depth_description} from class '{name}'"
        ),
        plan: Some(AskPlan {
            operation: AskOperation::Query,
            name,
            options: Some(QueryOptions {
                direction,
                relation,
                depth,
            }),
        }),
        candidates: Vec::new(),
    })
}

fn explain_interpretation(
    question: &str,
    class_resolution: NameResolution,
) -> Result<AskInterpretation, Error> {
    match class_resolution {
        NameResolution::Unique(name) => Ok(AskInterpretation {
            question: question.to_string(),
            status: AskStatus::Ready,
            interpretation: format!("an explanation of class '{name}'"),
            plan: Some(AskPlan {
                operation: AskOperation::Explain,
                name,
                options: None,
            }),
            candidates: Vec::new(),
        }),
        NameResolution::Missing(candidates) => Ok(unsupported_interpretation(
            question,
            "could not identify one class to explain",
            candidates,
        )),
        NameResolution::Ambiguous(candidates) => Ok(ambiguous_interpretation(
            question,
            "more than one class matches the question",
            candidates,
        )),
    }
}

fn ambiguous_interpretation(
    question: &str,
    message: &str,
    candidates: Vec<SearchMatch>,
) -> AskInterpretation {
    AskInterpretation {
        question: question.to_string(),
        status: AskStatus::Ambiguous,
        interpretation: message.into(),
        plan: None,
        candidates,
    }
}

fn unsupported_interpretation(
    question: &str,
    message: &str,
    candidates: Vec<SearchMatch>,
) -> AskInterpretation {
    AskInterpretation {
        question: question.to_string(),
        status: AskStatus::Unsupported,
        interpretation: message.into(),
        plan: None,
        candidates: limit_search_matches(candidates),
    }
}

fn diff_classes(before: &ExportDocument, after: &ExportDocument) -> DiffSummary {
    let before = before
        .classes
        .iter()
        .map(|class| (class.name.clone(), class))
        .collect::<BTreeMap<_, _>>();
    let after = after
        .classes
        .iter()
        .map(|class| (class.name.clone(), class))
        .collect::<BTreeMap<_, _>>();
    let names = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut summary = DiffSummary::default();
    for name in names {
        match (before.get(&name), after.get(&name)) {
            (None, Some(_)) => summary.added.push(name),
            (Some(_), None) => summary.removed.push(name),
            (Some(before), Some(after)) => {
                let mut fields = Vec::new();
                if before.description != after.description {
                    fields.push("description".into());
                }
                if before.superclasses.iter().collect::<BTreeSet<_>>()
                    != after.superclasses.iter().collect::<BTreeSet<_>>()
                {
                    fields.push("superclasses".into());
                }
                let before_properties = before
                    .properties
                    .iter()
                    .map(|property| (property.name.clone(), property))
                    .collect::<BTreeMap<_, _>>();
                let after_properties = after
                    .properties
                    .iter()
                    .map(|property| (property.name.clone(), property))
                    .collect::<BTreeMap<_, _>>();
                for property_name in before_properties
                    .keys()
                    .chain(after_properties.keys())
                    .cloned()
                    .collect::<BTreeSet<_>>()
                {
                    if before_properties.get(&property_name) != after_properties.get(&property_name)
                    {
                        fields.push(format!("property:{property_name}"));
                    }
                }
                if !fields.is_empty() {
                    summary.changed.push(ChangedDefinition { name, fields });
                }
            }
            (None, None) => unreachable!(),
        }
    }
    summary
}

fn diff_relations(before: &ExportDocument, after: &ExportDocument) -> DiffSummary {
    let before = before
        .relations
        .iter()
        .map(|relation| (relation.name.clone(), relation))
        .collect::<BTreeMap<_, _>>();
    let after = after
        .relations
        .iter()
        .map(|relation| (relation.name.clone(), relation))
        .collect::<BTreeMap<_, _>>();
    let names = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut summary = DiffSummary::default();
    for name in names {
        match (before.get(&name), after.get(&name)) {
            (None, Some(_)) => summary.added.push(name),
            (Some(_), None) => summary.removed.push(name),
            (Some(before), Some(after)) => {
                let mut fields = Vec::new();
                if before.description != after.description {
                    fields.push("description".into());
                }
                if before.domain != after.domain {
                    fields.push("domain".into());
                }
                if before.range != after.range {
                    fields.push("range".into());
                }
                if before.cardinality != after.cardinality {
                    fields.push("cardinality".into());
                }
                if before.transitive != after.transitive {
                    fields.push("transitive".into());
                }
                if !fields.is_empty() {
                    summary.changed.push(ChangedDefinition { name, fields });
                }
            }
            (None, None) => unreachable!(),
        }
    }
    summary
}

fn diff_provenance(before: &ExportDocument, after: &ExportDocument) -> DiffSummary {
    let before = before
        .provenance
        .iter()
        .map(|record| {
            (
                (
                    record.subject.clone(),
                    record.source.clone(),
                    record.locator.clone(),
                ),
                record,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let after = after
        .provenance
        .iter()
        .map(|record| {
            (
                (
                    record.subject.clone(),
                    record.source.clone(),
                    record.locator.clone(),
                ),
                record,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let keys = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut summary = DiffSummary::default();
    for key in keys {
        let label = provenance_label(&key.0, &key.1, &key.2);
        match (before.get(&key), after.get(&key)) {
            (None, Some(_)) => summary.added.push(label),
            (Some(_), None) => summary.removed.push(label),
            (Some(before), Some(after)) => {
                if before.confidence != after.confidence {
                    summary.changed.push(ChangedDefinition {
                        name: label,
                        fields: vec!["confidence".into()],
                    });
                }
            }
            (None, None) => unreachable!(),
        }
    }
    summary
}

fn provenance_label(subject: &str, source: &str, locator: &str) -> String {
    if locator.is_empty() {
        format!("{subject} @ {source}")
    } else {
        format!("{subject} @ {source}#{locator}")
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
        let mut issues = validate_parts(&classes, &relations, &provenance);
        issues.extend(directory::validate_database(&self.connection)?);
        issues.sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
        issues.dedup();
        Ok(issues)
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

    fn query(&self, start: &str, options: QueryOptions) -> Result<QueryResult, Error> {
        self.check_schema_version()?;
        if options.depth > MAX_QUERY_DEPTH {
            return Err(Error::Input(format!(
                "query depth {} exceeds maximum {MAX_QUERY_DEPTH}",
                options.depth
            )));
        }
        let (classes, relations, _) = load_all(&self.connection)?;
        if !classes.contains_key(start) {
            return Err(Error::NotFound(format!("class '{start}' was not found")));
        }

        let mut visited = BTreeSet::from([start.to_string()]);
        let mut frontier = BTreeSet::from([start.to_string()]);
        let mut reached = BTreeSet::new();
        let mut traversed = BTreeSet::new();
        for _ in 0..options.depth {
            let mut next = BTreeSet::new();
            for class_name in &frontier {
                for relation in relations.values() {
                    if options
                        .relation
                        .as_ref()
                        .is_some_and(|name| name != &relation.name)
                    {
                        continue;
                    }
                    let endpoint = match options.direction {
                        TraversalDirection::Outbound if relation.domain == *class_name => {
                            Some(&relation.range)
                        }
                        TraversalDirection::Inbound if relation.range == *class_name => {
                            Some(&relation.domain)
                        }
                        TraversalDirection::Both if relation.domain == *class_name => {
                            Some(&relation.range)
                        }
                        TraversalDirection::Both if relation.range == *class_name => {
                            Some(&relation.domain)
                        }
                        _ => None,
                    };
                    if let Some(endpoint) = endpoint {
                        traversed.insert(relation.name.clone());
                        if visited.insert(endpoint.clone()) {
                            reached.insert(endpoint.clone());
                            next.insert(endpoint.clone());
                        }
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }

        Ok(QueryResult {
            start: start.to_string(),
            options,
            classes: reached
                .into_iter()
                .filter_map(|name| classes.get(&name).cloned())
                .collect(),
            relations: traversed
                .into_iter()
                .filter_map(|name| relations.get(&name).cloned())
                .collect(),
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
    fn bounded_query_handles_directions_filters_depth_and_cycles() {
        let directory = tempfile::tempdir().unwrap();
        let mut ontology = SqliteOntology::initialize(directory.path().join("query.db")).unwrap();
        ontology
            .import(ImportDocument {
                schema_version: SCHEMA_VERSION,
                classes: ["A", "B", "C", "D"]
                    .into_iter()
                    .map(|name| Class {
                        name: name.into(),
                        description: String::new(),
                        superclasses: vec![],
                        properties: vec![],
                    })
                    .collect(),
                relations: [
                    ("a_to_b", "A", "B"),
                    ("b_to_c", "B", "C"),
                    ("c_to_a", "C", "A"),
                    ("d_to_a", "D", "A"),
                ]
                .into_iter()
                .map(|(name, domain, range)| Relation {
                    name: name.into(),
                    description: String::new(),
                    domain: domain.into(),
                    range: range.into(),
                    cardinality: Cardinality::default(),
                    transitive: false,
                })
                .collect(),
                provenance: vec![],
            })
            .unwrap();

        let outbound = ontology
            .query(
                "A",
                QueryOptions {
                    direction: TraversalDirection::Outbound,
                    relation: None,
                    depth: 3,
                },
            )
            .unwrap();
        assert_eq!(
            outbound
                .classes
                .iter()
                .map(|class| class.name.as_str())
                .collect::<Vec<_>>(),
            ["B", "C"]
        );
        assert_eq!(
            outbound
                .relations
                .iter()
                .map(|relation| relation.name.as_str())
                .collect::<Vec<_>>(),
            ["a_to_b", "b_to_c", "c_to_a"]
        );

        let inbound = ontology
            .query(
                "A",
                QueryOptions {
                    direction: TraversalDirection::Inbound,
                    relation: None,
                    depth: 1,
                },
            )
            .unwrap();
        assert_eq!(
            inbound
                .classes
                .iter()
                .map(|class| class.name.as_str())
                .collect::<Vec<_>>(),
            ["C", "D"]
        );

        let both = ontology.query("A", QueryOptions::default()).unwrap();
        assert_eq!(
            both.classes
                .iter()
                .map(|class| class.name.as_str())
                .collect::<Vec<_>>(),
            ["B", "C", "D"]
        );
        let filtered = ontology
            .query(
                "A",
                QueryOptions {
                    relation: Some("a_to_b".into()),
                    ..QueryOptions::default()
                },
            )
            .unwrap();
        assert_eq!(filtered.classes[0].name, "B");
        assert_eq!(filtered.relations[0].name, "a_to_b");

        let empty = ontology
            .query(
                "A",
                QueryOptions {
                    depth: 0,
                    ..QueryOptions::default()
                },
            )
            .unwrap();
        assert!(empty.classes.is_empty());
        assert!(empty.relations.is_empty());
        assert!(matches!(
            ontology.query(
                "A",
                QueryOptions {
                    depth: MAX_QUERY_DEPTH + 1,
                    ..QueryOptions::default()
                }
            ),
            Err(Error::Input(_))
        ));
        assert!(matches!(
            ontology.query("Missing", QueryOptions::default()),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn search_matches_names_and_definition_fields_deterministically() {
        let document = document();
        let exact = search_document(&document, "Api").unwrap();
        assert_eq!(exact.matches[0].kind, DefinitionKind::Class);
        assert_eq!(exact.matches[0].name, "Api");
        assert_eq!(exact.matches[0].score, 1000);
        assert!(
            exact.matches[0]
                .matched_fields
                .contains(&"name".to_string())
        );

        let field = search_document(&document, "language").unwrap();
        assert_eq!(field.matches[0].name, "Api");
        assert_eq!(field.matches[0].matched_fields, ["properties"]);
    }

    #[test]
    fn semantic_diff_reports_changes_but_ignores_order_only_changes() {
        let mut before = document();
        before.classes[2].superclasses = vec!["Service".into(), "Component".into()];
        let mut after = before.clone();
        after.classes[2].superclasses.reverse();
        assert!(!diff_documents(&before, &after).changed);

        after.classes[2].description = "A changed interface".into();
        after.relations[0].transitive = true;
        after.provenance[0].confidence = 0.5;
        let diff = diff_documents(&before, &after);
        assert!(diff.changed);
        assert_eq!(diff.classes.changed[0].name, "Api");
        assert_eq!(diff.classes.changed[0].fields, ["description"]);
        assert_eq!(diff.relations.changed[0].fields, ["transitive"]);
        assert_eq!(diff.provenance.changed[0].fields, ["confidence"]);
    }

    #[test]
    fn ask_interpreter_only_emits_bounded_typed_plans() {
        let document = document();

        let outbound = interpret_question(&document, "What does Api depend on?").unwrap();
        assert_eq!(outbound.status, AskStatus::Ready);
        let plan = outbound.plan.unwrap();
        assert_eq!(plan.operation, AskOperation::Query);
        assert_eq!(plan.name, "Api");
        assert_eq!(
            plan.options,
            Some(QueryOptions {
                direction: TraversalDirection::Outbound,
                relation: Some("depends_on".into()),
                depth: 1,
            })
        );

        let inbound = interpret_question(&document, "What depends on Database?").unwrap();
        assert_eq!(inbound.status, AskStatus::Ready);
        assert_eq!(
            inbound.plan.unwrap().options.unwrap().direction,
            TraversalDirection::Inbound
        );

        let explanation = interpret_question(&document, "What is Api?").unwrap();
        assert_eq!(explanation.status, AskStatus::Ready);
        assert_eq!(explanation.plan.unwrap().operation, AskOperation::Explain);

        let unsupported = interpret_question(&document, "Summarize the whole system").unwrap();
        assert_eq!(unsupported.status, AskStatus::Unsupported);
        assert!(unsupported.plan.is_none());
    }

    #[test]
    fn ask_interpreter_compiles_find_directory_and_explicit_depth() {
        let document = document();

        let find = interpret_question(&document, "Find C++").unwrap();
        assert_eq!(find.status, AskStatus::Ready);
        let plan = find.plan.unwrap();
        assert_eq!(plan.operation, AskOperation::Find);
        assert_eq!(plan.name, "C++");
        assert!(plan.options.is_none());

        let slash_class = {
            let mut slash_document = document.clone();
            slash_document.classes.push(Class {
                name: "Client/Server".into(),
                description: String::new(),
                superclasses: vec!["Component".into()],
                properties: Vec::new(),
            });
            interpret_question(&slash_document, "What does Client/Server depend on?").unwrap()
        };
        assert_eq!(slash_class.status, AskStatus::Ready);
        let plan = slash_class.plan.unwrap();
        assert_eq!(plan.operation, AskOperation::Query);
        assert_eq!(plan.name, "Client/Server");

        let slash_find = interpret_question(&document, "find foo/bar").unwrap();
        assert_eq!(slash_find.status, AskStatus::Ready);
        assert_eq!(slash_find.plan.unwrap().name, "foo/bar");

        let deep = interpret_question(&document, "What does Api depend on to depth 2?").unwrap();
        assert_eq!(deep.status, AskStatus::Ready);
        assert_eq!(
            deep.plan.unwrap().options,
            Some(QueryOptions {
                direction: TraversalDirection::Outbound,
                relation: Some("depends_on".into()),
                depth: 2,
            })
        );

        let directory =
            interpret_question(&document, "What does /tmp/Projects contain to depth 2?").unwrap();
        assert_eq!(directory.status, AskStatus::Ready);
        let plan = directory.plan.unwrap();
        assert_eq!(plan.operation, AskOperation::DirectoryQuery);
        assert_eq!(plan.name, "/tmp/Projects");
        assert_eq!(
            plan.options,
            Some(QueryOptions {
                direction: TraversalDirection::Outbound,
                relation: Some(DIRECTORY_RELATION_CONTAINS.into()),
                depth: 2,
            })
        );

        let find_with_depth = interpret_question(&document, "find language to depth 2").unwrap();
        assert_eq!(find_with_depth.status, AskStatus::Unsupported);
        assert!(find_with_depth.plan.is_none());

        let ambiguous_paths =
            interpret_question(&document, "What is related to /tmp/a and /var/projects?").unwrap();
        assert_eq!(ambiguous_paths.status, AskStatus::Ambiguous);
        assert!(ambiguous_paths.plan.is_none());

        let quoted_and_unquoted =
            interpret_question(&document, r#"What is related to "/tmp/a" and /var/b?"#).unwrap();
        assert_eq!(quoted_and_unquoted.status, AskStatus::Ambiguous);
        assert!(quoted_and_unquoted.plan.is_none());

        let spaced = interpret_question(
            &document,
            r#"What does "/tmp/My Project" contain to depth 2?"#,
        )
        .unwrap();
        assert_eq!(spaced.status, AskStatus::Ready);
        assert_eq!(spaced.plan.unwrap().name, "/tmp/My Project");

        let embedded_quotes =
            interpret_question(&document, "What does /tmp/a'b'c contain?").unwrap();
        assert_eq!(embedded_quotes.status, AskStatus::Ready);
        assert_eq!(embedded_quotes.plan.unwrap().name, "/tmp/a'b'c");

        let relative = interpret_question(&document, "What does ./src contain?").unwrap();
        assert_eq!(relative.status, AskStatus::Ready);
        assert_eq!(relative.plan.unwrap().name, "./src");

        let trailing_period =
            interpret_question(&document, "What is related to /tmp/project.").unwrap();
        assert_eq!(trailing_period.status, AskStatus::Ready);
        assert_eq!(trailing_period.plan.unwrap().name, "/tmp/project");

        let negative_depth =
            interpret_question(&document, "What does Api depend on to depth -2?").unwrap();
        assert_eq!(negative_depth.status, AskStatus::Unsupported);
        assert!(negative_depth.plan.is_none());

        if let Ok(home) = std::env::var("HOME") {
            let tilde =
                interpret_question(&document, "What does ~/Projects contain to depth 2?").unwrap();
            assert_eq!(tilde.status, AskStatus::Ready);
            assert_eq!(tilde.plan.unwrap().name, format!("{home}/Projects"));
        }

        let unsupported_path = interpret_question(&document, "frobnicate /tmp/project").unwrap();
        assert_eq!(unsupported_path.status, AskStatus::Unsupported);
        assert!(unsupported_path.plan.is_none());
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
