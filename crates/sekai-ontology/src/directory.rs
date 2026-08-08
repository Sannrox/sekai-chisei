use super::{
    Cardinality, Class, Error, ImportDocument, Property, QueryOptions, Relation, SqliteOntology,
    TraversalDirection, ValidationIssue, check_schema_version, database_error,
};
use rusqlite::{Connection, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const DIRECTORY_SCHEMA_VERSION: u32 = 1;
pub const DIRECTORY_RELATION_CONTAINS: &str = "contains";
pub const DEFAULT_DIRECTORY_KIND: &str = "Directory";
pub const MAX_DIRECTORY_DEPTH: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntity {
    pub id: String,
    pub path: String,
    pub name: String,
    #[serde(default = "default_directory_kind")]
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryLink {
    pub id: String,
    pub from_id: String,
    pub to_id: String,
    pub relation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryDocument {
    pub schema_version: u32,
    pub root: String,
    #[serde(default)]
    pub entities: Vec<DirectoryEntity>,
    #[serde(default)]
    pub links: Vec<DirectoryLink>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectoryQueryResult {
    pub start: String,
    pub options: QueryOptions,
    pub entities: Vec<DirectoryEntity>,
    pub links: Vec<DirectoryLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryScanOptions {
    pub max_depth: u32,
    pub include_hidden: bool,
    pub root_kind: String,
}

impl Default for DirectoryScanOptions {
    fn default() -> Self {
        Self {
            max_depth: MAX_DIRECTORY_DEPTH,
            include_hidden: false,
            root_kind: DEFAULT_DIRECTORY_KIND.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectoryIndexReport {
    pub root: String,
    pub scanned_entities: usize,
    pub scanned_links: usize,
    pub removed_entities: usize,
    pub removed_links: usize,
    pub pruned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectoryImportReport {
    pub root: String,
    pub imported_entities: usize,
    pub imported_links: usize,
}

type DirectoryParts = (
    BTreeMap<String, DirectoryEntity>,
    BTreeMap<String, DirectoryLink>,
);

fn default_directory_kind() -> String {
    DEFAULT_DIRECTORY_KIND.into()
}

pub(crate) fn ensure_schema(connection: &Connection) -> Result<(), Error> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS ontology_directory_entities (
               id TEXT PRIMARY KEY,
               path TEXT NOT NULL UNIQUE,
               name TEXT NOT NULL,
               kind TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS ontology_directory_links (
               id TEXT PRIMARY KEY,
               from_id TEXT NOT NULL,
               to_id TEXT NOT NULL,
               relation TEXT NOT NULL,
               UNIQUE(from_id, to_id, relation),
               FOREIGN KEY(from_id) REFERENCES ontology_directory_entities(id)
                 ON DELETE CASCADE,
               FOREIGN KEY(to_id) REFERENCES ontology_directory_entities(id)
                 ON DELETE CASCADE
             );
             CREATE INDEX IF NOT EXISTS idx_ontology_directory_entities_path
               ON ontology_directory_entities(path);
             CREATE INDEX IF NOT EXISTS idx_ontology_directory_links_from
               ON ontology_directory_links(from_id, relation);
             CREATE INDEX IF NOT EXISTS idx_ontology_directory_links_to
               ON ontology_directory_links(to_id, relation);",
        )
        .map_err(database_error)
}

fn directory_schema_state(connection: &Connection) -> Result<u8, Error> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name IN
               ('ontology_directory_entities', 'ontology_directory_links')",
            [],
            |row| row.get::<_, u8>(0),
        )
        .map_err(database_error)?;
    Ok(count)
}

fn load_all(connection: &Connection) -> Result<DirectoryParts, Error> {
    match directory_schema_state(connection)? {
        0 => return Ok((BTreeMap::new(), BTreeMap::new())),
        2 => {}
        count => {
            return Err(Error::Database(format!(
                "incomplete directory schema: found {count} of 2 tables"
            )));
        }
    }

    let mut entity_statement = connection
        .prepare("SELECT id, path, name, kind FROM ontology_directory_entities ORDER BY id")
        .map_err(database_error)?;
    let entity_rows = entity_statement
        .query_map([], |row| {
            Ok(DirectoryEntity {
                id: row.get(0)?,
                path: row.get(1)?,
                name: row.get(2)?,
                kind: row.get(3)?,
            })
        })
        .map_err(database_error)?;
    let mut entities = BTreeMap::new();
    for row in entity_rows {
        let entity = row.map_err(database_error)?;
        if entities.insert(entity.id.clone(), entity).is_some() {
            return Err(Error::Database(
                "duplicate directory entity id in storage".into(),
            ));
        }
    }

    let mut link_statement = connection
        .prepare("SELECT id, from_id, to_id, relation FROM ontology_directory_links ORDER BY id")
        .map_err(database_error)?;
    let link_rows = link_statement
        .query_map([], |row| {
            Ok(DirectoryLink {
                id: row.get(0)?,
                from_id: row.get(1)?,
                to_id: row.get(2)?,
                relation: row.get(3)?,
            })
        })
        .map_err(database_error)?;
    let mut links = BTreeMap::new();
    for row in link_rows {
        let link = row.map_err(database_error)?;
        if links.insert(link.id.clone(), link).is_some() {
            return Err(Error::Database(
                "duplicate directory link id in storage".into(),
            ));
        }
    }

    Ok((entities, links))
}

fn persist_all(
    transaction: &Transaction<'_>,
    entities: impl IntoIterator<Item = DirectoryEntity>,
    links: impl IntoIterator<Item = DirectoryLink>,
) -> Result<(), Error> {
    for entity in entities {
        transaction
            .execute(
                "INSERT INTO ontology_directory_entities(id, path, name, kind)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                   path = excluded.path,
                   name = excluded.name,
                   kind = excluded.kind",
                params![entity.id, entity.path, entity.name, entity.kind],
            )
            .map_err(database_error)?;
    }
    for link in links {
        transaction
            .execute(
                "INSERT INTO ontology_directory_links(id, from_id, to_id, relation)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                   from_id = excluded.from_id,
                   to_id = excluded.to_id,
                   relation = excluded.relation",
                params![link.id, link.from_id, link.to_id, link.relation],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

pub(crate) fn validate_database(connection: &Connection) -> Result<Vec<ValidationIssue>, Error> {
    let (entities, links) = load_all(connection)?;
    Ok(validate_parts(&entities, &links))
}

fn validate_parts(
    entities: &BTreeMap<String, DirectoryEntity>,
    links: &BTreeMap<String, DirectoryLink>,
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let mut paths = BTreeMap::<String, String>::new();

    for (id, entity) in entities {
        if id.trim().is_empty() {
            directory_issue(
                &mut issues,
                "empty_id",
                &format!("entities.{id}.id"),
                "directory entity id must not be empty",
            );
        }
        if entity.path.trim().is_empty() || !Path::new(&entity.path).is_absolute() {
            directory_issue(
                &mut issues,
                "invalid_path",
                &format!("entities.{id}.path"),
                "directory path must be an absolute, non-empty path",
            );
        }
        if entity.name.trim().is_empty() {
            directory_issue(
                &mut issues,
                "empty_name",
                &format!("entities.{id}.name"),
                "directory name must not be empty",
            );
        }
        if entity.kind.trim().is_empty() {
            directory_issue(
                &mut issues,
                "empty_kind",
                &format!("entities.{id}.kind"),
                "directory kind must not be empty",
            );
        }
        let normalized_path = normalize_absolute_path(Path::new(&entity.path));
        if directory_id(&normalized_path) != entity.id {
            directory_issue(
                &mut issues,
                "unstable_id",
                &format!("entities.{id}.id"),
                "directory entity id must be derived from its normalized absolute path",
            );
        }
        let normalized_path = normalize_absolute_path(Path::new(&entity.path))
            .to_string_lossy()
            .into_owned();
        if let Some(previous) = paths.insert(normalized_path, id.clone()) {
            directory_issue(
                &mut issues,
                "duplicate_path",
                &format!("entities.{id}.path"),
                &format!("path is already used by directory entity '{previous}'"),
            );
        }
    }

    let mut contains_parent = BTreeMap::<String, String>::new();
    for (id, link) in links {
        if id.trim().is_empty() {
            directory_issue(
                &mut issues,
                "empty_id",
                &format!("links.{id}.id"),
                "directory link id must not be empty",
            );
        }
        if link.relation.trim().is_empty() {
            directory_issue(
                &mut issues,
                "empty_relation",
                &format!("links.{id}.relation"),
                "directory link relation must not be empty",
            );
        }
        let Some(from) = entities.get(&link.from_id) else {
            directory_issue(
                &mut issues,
                "unknown_endpoint",
                &format!("links.{id}.from_id"),
                &format!("unknown directory entity '{}'", link.from_id),
            );
            continue;
        };
        let Some(to) = entities.get(&link.to_id) else {
            directory_issue(
                &mut issues,
                "unknown_endpoint",
                &format!("links.{id}.to_id"),
                &format!("unknown directory entity '{}'", link.to_id),
            );
            continue;
        };
        if link.from_id == link.to_id {
            directory_issue(
                &mut issues,
                "self_link",
                &format!("links.{id}"),
                "directory links must not point from an entity to itself",
            );
        }
        if link.relation == DIRECTORY_RELATION_CONTAINS {
            if let Some(previous) = contains_parent.insert(link.to_id.clone(), link.from_id.clone())
                && previous != link.from_id
            {
                directory_issue(
                    &mut issues,
                    "multiple_parents",
                    &format!("links.{id}.to_id"),
                    &format!(
                        "directory has multiple contains parents: '{previous}' and '{}'",
                        link.from_id
                    ),
                );
            }
            let expected_parent = normalize_absolute_path(Path::new(&to.path))
                .parent()
                .map(Path::to_path_buf);
            let actual_parent = normalize_absolute_path(Path::new(&from.path));
            if expected_parent.as_deref() != Some(actual_parent.as_path()) {
                directory_issue(
                    &mut issues,
                    "invalid_contains_path",
                    &format!("links.{id}"),
                    &format!(
                        "contains link does not join adjacent directories '{}' and '{}'",
                        from.path, to.path
                    ),
                );
            }
        }
    }

    for entity_id in contains_parent.keys() {
        let mut visited = BTreeSet::new();
        let mut current = entity_id.as_str();
        while let Some(parent) = contains_parent.get(current) {
            if !visited.insert(current.to_string()) {
                directory_issue(
                    &mut issues,
                    "contains_cycle",
                    &format!("entities.{entity_id}"),
                    "contains links must form an acyclic directory tree",
                );
                break;
            }
            current = parent;
        }
    }

    issues.sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
    issues.dedup();
    issues
}

fn validate_document(document: &DirectoryDocument) -> Result<(), Error> {
    if document.schema_version != DIRECTORY_SCHEMA_VERSION {
        return Err(Error::Input(format!(
            "unsupported directory document schema version {}; expected {DIRECTORY_SCHEMA_VERSION}",
            document.schema_version
        )));
    }
    let mut entities = BTreeMap::new();
    let mut links = BTreeMap::new();
    let mut issues = Vec::new();
    let mut entity_paths = BTreeMap::<String, usize>::new();
    for (index, entity) in document.entities.iter().enumerate() {
        if entities.insert(entity.id.clone(), entity.clone()).is_some() {
            directory_issue(
                &mut issues,
                "duplicate_id",
                &format!("entities[{index}].id"),
                &format!("directory entity id '{}' occurs more than once", entity.id),
            );
        }
        let normalized_path = normalize_absolute_path(Path::new(&entity.path))
            .to_string_lossy()
            .into_owned();
        if let Some(previous) = entity_paths.insert(normalized_path.clone(), index) {
            directory_issue(
                &mut issues,
                "duplicate_path",
                &format!("entities[{index}].path"),
                &format!("directory path is already declared at entities[{previous}].path"),
            );
        }
    }
    let mut link_keys = BTreeMap::<(String, String, String), usize>::new();
    for (index, link) in document.links.iter().enumerate() {
        if links.insert(link.id.clone(), link.clone()).is_some() {
            directory_issue(
                &mut issues,
                "duplicate_id",
                &format!("links[{index}].id"),
                &format!("directory link id '{}' occurs more than once", link.id),
            );
        }
        let key = (
            link.from_id.clone(),
            link.to_id.clone(),
            link.relation.clone(),
        );
        if let Some(previous) = link_keys.insert(key, index) {
            directory_issue(
                &mut issues,
                "duplicate_link",
                &format!("links[{index}]"),
                &format!("directory link duplicates links[{previous}]"),
            );
        }
    }
    issues.extend(validate_parts(&entities, &links));
    if document.root.trim().is_empty() || !Path::new(&document.root).is_absolute() {
        directory_issue(
            &mut issues,
            "invalid_root",
            "root",
            "directory document root must be an absolute, non-empty path",
        );
    } else {
        let root_path = normalize_absolute_path(Path::new(&document.root));
        let root_id = directory_id(&root_path);
        match entities.get(&root_id) {
            Some(entity) if normalize_absolute_path(Path::new(&entity.path)) == root_path => {}
            Some(_) => directory_issue(
                &mut issues,
                "root_mismatch",
                "root",
                "directory document root does not match its entity path",
            ),
            None => directory_issue(
                &mut issues,
                "missing_root",
                "root",
                "directory document root is not present in entities",
            ),
        }
    }
    if !issues.is_empty() {
        return Err(Error::Validation(issues));
    }
    Ok(())
}

fn directory_issue(issues: &mut Vec<ValidationIssue>, code: &str, path: &str, message: &str) {
    issues.push(ValidationIssue {
        code: code.into(),
        path: path.into(),
        message: message.into(),
    });
}

fn directory_id(path: &Path) -> String {
    format!("directory:{}", path.to_string_lossy())
}

fn contains_link_id(from_id: &str, to_id: &str) -> String {
    format!("contains:{from_id}->{to_id}")
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

fn normalize_existing_directory(path: &Path) -> Result<PathBuf, Error> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Error::Input(format!(
            "cannot resolve directory '{}': {error}",
            path.display()
        ))
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        Error::Input(format!(
            "cannot inspect directory '{}': {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(Error::Input(format!(
            "directory root '{}' is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn normalize_query_path(path: &Path) -> Result<PathBuf, Error> {
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(canonical);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| Error::Input(format!("cannot resolve current directory: {error}")))?
            .join(path)
    };
    Ok(normalize_absolute_path(&absolute))
}

fn entity_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().starts_with('.'))
        .unwrap_or(false)
}

fn collect_directory(
    path: &Path,
    depth: u32,
    options: &DirectoryScanOptions,
    entities: &mut BTreeMap<String, DirectoryEntity>,
    links: &mut BTreeMap<String, DirectoryLink>,
    kind: &str,
) -> Result<(), Error> {
    let path = normalize_existing_directory(path)?;
    let id = directory_id(&path);
    entities.insert(
        id.clone(),
        DirectoryEntity {
            id: id.clone(),
            path: path.to_string_lossy().into_owned(),
            name: entity_name(&path),
            kind: kind.into(),
        },
    );
    if depth >= options.max_depth {
        return Ok(());
    }

    let mut children = fs::read_dir(&path)
        .map_err(|error| {
            Error::Input(format!(
                "cannot read directory '{}': {error}",
                path.display()
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            Error::Input(format!(
                "cannot inspect directory '{}': {error}",
                path.display()
            ))
        })?;
    children.sort_by_key(|entry| entry.path().to_string_lossy().into_owned());
    for entry in children {
        let child_path = entry.path();
        if !options.include_hidden && is_hidden(&child_path) {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            Error::Input(format!(
                "cannot inspect '{}': {error}",
                child_path.display()
            ))
        })?;
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        let child_path = normalize_existing_directory(&child_path)?;
        let child_id = directory_id(&child_path);
        collect_directory(
            &child_path,
            depth + 1,
            options,
            entities,
            links,
            DEFAULT_DIRECTORY_KIND,
        )?;
        let link_id = contains_link_id(&id, &child_id);
        links.insert(
            link_id.clone(),
            DirectoryLink {
                id: link_id,
                from_id: id.clone(),
                to_id: child_id,
                relation: DIRECTORY_RELATION_CONTAINS.into(),
            },
        );
    }
    Ok(())
}

fn scan(root: &Path, options: &DirectoryScanOptions) -> Result<DirectoryDocument, Error> {
    if options.max_depth > MAX_DIRECTORY_DEPTH {
        return Err(Error::Input(format!(
            "directory depth {} exceeds maximum {MAX_DIRECTORY_DEPTH}",
            options.max_depth
        )));
    }
    if options.root_kind.trim().is_empty() {
        return Err(Error::Input("directory root kind must not be empty".into()));
    }
    let root = normalize_existing_directory(root)?;
    let mut entities = BTreeMap::new();
    let mut links = BTreeMap::new();
    collect_directory(
        &root,
        0,
        options,
        &mut entities,
        &mut links,
        &options.root_kind,
    )?;
    let document = DirectoryDocument {
        schema_version: DIRECTORY_SCHEMA_VERSION,
        root: root.to_string_lossy().into_owned(),
        entities: entities.into_values().collect(),
        links: links.into_values().collect(),
    };
    validate_document(&document)?;
    Ok(document)
}

fn path_is_within(root: &Path, candidate: &Path) -> bool {
    normalize_absolute_path(candidate).starts_with(normalize_absolute_path(root))
}

fn resolve_entity_id(
    entities: &BTreeMap<String, DirectoryEntity>,
    start: &str,
) -> Result<String, Error> {
    if start.starts_with("directory:") && entities.contains_key(start) {
        return Ok(start.into());
    }
    let path = normalize_query_path(Path::new(start))?;
    let id = directory_id(&path);
    if entities.contains_key(&id) {
        Ok(id)
    } else {
        Err(Error::NotFound(format!(
            "directory '{}' was not found",
            path.display()
        )))
    }
}

fn traverse(
    entities: &BTreeMap<String, DirectoryEntity>,
    links: &BTreeMap<String, DirectoryLink>,
    start_id: &str,
    options: &QueryOptions,
) -> Result<DirectoryQueryResult, Error> {
    if options.depth > MAX_DIRECTORY_DEPTH {
        return Err(Error::Input(format!(
            "directory query depth {} exceeds maximum {MAX_DIRECTORY_DEPTH}",
            options.depth
        )));
    }
    let start_entity = entities
        .get(start_id)
        .ok_or_else(|| Error::NotFound(format!("directory '{start_id}' was not found")))?;
    let mut visited = BTreeSet::from([start_id.to_string()]);
    let mut frontier = BTreeSet::from([start_id.to_string()]);
    let mut reached = BTreeSet::new();
    let mut traversed = BTreeSet::new();
    for _ in 0..options.depth {
        let mut next = BTreeSet::new();
        for entity_id in &frontier {
            for link in links.values() {
                if options
                    .relation
                    .as_ref()
                    .is_some_and(|relation| relation != &link.relation)
                {
                    continue;
                }
                let endpoint = match options.direction {
                    TraversalDirection::Outbound if link.from_id == *entity_id => Some(&link.to_id),
                    TraversalDirection::Inbound if link.to_id == *entity_id => Some(&link.from_id),
                    TraversalDirection::Both if link.from_id == *entity_id => Some(&link.to_id),
                    TraversalDirection::Both if link.to_id == *entity_id => Some(&link.from_id),
                    _ => None,
                };
                if let Some(endpoint) = endpoint {
                    traversed.insert(link.id.clone());
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
    Ok(DirectoryQueryResult {
        start: start_entity.path.clone(),
        options: options.clone(),
        entities: reached
            .into_iter()
            .filter_map(|id| entities.get(&id).cloned())
            .collect(),
        links: traversed
            .into_iter()
            .filter_map(|id| links.get(&id).cloned())
            .collect(),
    })
}

fn subtree_document(
    entities: &BTreeMap<String, DirectoryEntity>,
    links: &BTreeMap<String, DirectoryLink>,
    root_id: &str,
    max_depth: u32,
) -> Result<DirectoryDocument, Error> {
    let query = traverse(
        entities,
        links,
        root_id,
        &QueryOptions {
            direction: TraversalDirection::Outbound,
            relation: Some(DIRECTORY_RELATION_CONTAINS.into()),
            depth: max_depth,
        },
    )?;
    let root = entities
        .get(root_id)
        .ok_or_else(|| Error::NotFound(format!("directory '{root_id}' was not found")))?;
    let mut subgraph_entities = vec![root.clone()];
    subgraph_entities.extend(query.entities);
    let document = DirectoryDocument {
        schema_version: DIRECTORY_SCHEMA_VERSION,
        root: root.path.clone(),
        entities: subgraph_entities,
        links: query.links,
    };
    validate_document(&document)?;
    Ok(document)
}

impl SqliteOntology {
    pub fn initialize_directory_ontology(&mut self) -> Result<(), Error> {
        check_schema_version(&self.connection)?;
        ensure_schema(&self.connection)?;
        let existing = self.export()?;
        let standard = directory_ontology_document();
        let classes = standard
            .classes
            .into_iter()
            .filter(|class| !existing.classes.iter().any(|item| item.name == class.name))
            .collect::<Vec<_>>();
        let relations = standard
            .relations
            .into_iter()
            .filter(|relation| {
                !existing
                    .relations
                    .iter()
                    .any(|item| item.name == relation.name)
            })
            .collect::<Vec<_>>();
        let provenance = standard
            .provenance
            .into_iter()
            .filter(|record| {
                !existing.provenance.iter().any(|item| {
                    item.subject == record.subject
                        && item.source == record.source
                        && item.locator == record.locator
                })
            })
            .collect::<Vec<_>>();
        self.import(ImportDocument {
            schema_version: super::SCHEMA_VERSION,
            classes,
            relations,
            provenance,
        })
    }

    pub fn index_directory(
        &mut self,
        root: impl AsRef<Path>,
        options: DirectoryScanOptions,
        prune: bool,
    ) -> Result<DirectoryIndexReport, Error> {
        check_schema_version(&self.connection)?;
        let document = scan(root.as_ref(), &options)?;
        ensure_schema(&self.connection)?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        let (existing_entities, existing_links) = load_all(&transaction)?;
        let root_path = Path::new(&document.root);
        let scoped_ids = existing_entities
            .values()
            .filter(|entity| path_is_within(root_path, Path::new(&entity.path)))
            .map(|entity| entity.id.clone())
            .collect::<BTreeSet<_>>();
        let scanned_ids = document
            .entities
            .iter()
            .map(|entity| entity.id.clone())
            .collect::<BTreeSet<_>>();
        let scanned_link_ids = document
            .links
            .iter()
            .map(|link| link.id.clone())
            .collect::<BTreeSet<_>>();
        let stale_entities = if prune {
            scoped_ids
                .difference(&scanned_ids)
                .cloned()
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        let stale_links = if prune {
            existing_links
                .values()
                .filter(|link| {
                    stale_entities.contains(&link.from_id)
                        || stale_entities.contains(&link.to_id)
                        || (scoped_ids.contains(&link.from_id)
                            && scoped_ids.contains(&link.to_id)
                            && link.relation == DIRECTORY_RELATION_CONTAINS
                            && !scanned_link_ids.contains(&link.id))
                })
                .map(|link| link.id.clone())
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        for link_id in &stale_links {
            transaction
                .execute(
                    "DELETE FROM ontology_directory_links WHERE id = ?1",
                    params![link_id],
                )
                .map_err(database_error)?;
        }
        for entity_id in &stale_entities {
            transaction
                .execute(
                    "DELETE FROM ontology_directory_entities WHERE id = ?1",
                    params![entity_id],
                )
                .map_err(database_error)?;
        }
        persist_all(
            &transaction,
            document.entities.clone(),
            document.links.clone(),
        )?;
        transaction.commit().map_err(database_error)?;
        Ok(DirectoryIndexReport {
            root: document.root,
            scanned_entities: document.entities.len(),
            scanned_links: document.links.len(),
            removed_entities: stale_entities.len(),
            removed_links: stale_links.len(),
            pruned: prune,
        })
    }

    pub fn import_directory_document(
        &mut self,
        document: DirectoryDocument,
    ) -> Result<DirectoryImportReport, Error> {
        check_schema_version(&self.connection)?;
        validate_document(&document)?;
        ensure_schema(&self.connection)?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        let (mut entities, mut links) = load_all(&transaction)?;
        for entity in &document.entities {
            entities.insert(entity.id.clone(), entity.clone());
        }
        for link in &document.links {
            links.insert(link.id.clone(), link.clone());
        }
        let merged = DirectoryDocument {
            schema_version: DIRECTORY_SCHEMA_VERSION,
            root: document.root.clone(),
            entities: entities.into_values().collect(),
            links: links.into_values().collect(),
        };
        validate_document(&merged)?;
        persist_all(
            &transaction,
            document.entities.clone(),
            document.links.clone(),
        )?;
        transaction.commit().map_err(database_error)?;
        Ok(DirectoryImportReport {
            root: document.root,
            imported_entities: document.entities.len(),
            imported_links: document.links.len(),
        })
    }

    pub fn export_directory(&self, root: impl AsRef<Path>) -> Result<DirectoryDocument, Error> {
        self.export_directory_with_depth(root, MAX_DIRECTORY_DEPTH)
    }

    pub fn export_directory_with_depth(
        &self,
        root: impl AsRef<Path>,
        max_depth: u32,
    ) -> Result<DirectoryDocument, Error> {
        check_schema_version(&self.connection)?;
        let (entities, links) = load_all(&self.connection)?;
        let root_id = resolve_entity_id(&entities, &root.as_ref().to_string_lossy())?;
        subtree_document(&entities, &links, &root_id, max_depth)
    }

    pub fn query_directories(
        &self,
        start: impl AsRef<Path>,
        options: QueryOptions,
    ) -> Result<DirectoryQueryResult, Error> {
        check_schema_version(&self.connection)?;
        let (entities, links) = load_all(&self.connection)?;
        let start_id = resolve_entity_id(&entities, &start.as_ref().to_string_lossy())?;
        traverse(&entities, &links, &start_id, &options)
    }
}

pub fn directory_ontology_document() -> ImportDocument {
    let directory_properties = vec![
        Property {
            name: "path".into(),
            value_type: "string".into(),
            required: true,
            description: "Absolute filesystem path for the directory entity.".into(),
        },
        Property {
            name: "name".into(),
            value_type: "string".into(),
            required: true,
            description: "Filesystem basename or root display name.".into(),
        },
    ];
    ImportDocument {
        schema_version: super::SCHEMA_VERSION,
        classes: vec![
            Class {
                name: "Directory".into(),
                description: "A filesystem directory represented as a durable local fact.".into(),
                superclasses: vec![],
                properties: directory_properties.clone(),
            },
            Class {
                name: "WorkspaceDirectory".into(),
                description:
                    "A directory that scopes multiple projects and their local ontologies.".into(),
                superclasses: vec!["Directory".into()],
                properties: directory_properties.clone(),
            },
            Class {
                name: "ProjectDirectory".into(),
                description: "A project root directory with its own local ontology scope.".into(),
                superclasses: vec!["Directory".into()],
                properties: directory_properties,
            },
        ],
        relations: vec![Relation {
            name: DIRECTORY_RELATION_CONTAINS.into(),
            description: "Direct filesystem parent-child containment between directories.".into(),
            domain: "Directory".into(),
            range: "Directory".into(),
            cardinality: Cardinality::default(),
            transitive: true,
        }],
        provenance: vec![
            super::Provenance {
                subject: "Directory".into(),
                source: "sekai-directory".into(),
                locator: "directory_ontology_document".into(),
                confidence: 1.0,
            },
            super::Provenance {
                subject: "WorkspaceDirectory".into(),
                source: "sekai-directory".into(),
                locator: "directory_ontology_document".into(),
                confidence: 1.0,
            },
            super::Provenance {
                subject: "ProjectDirectory".into(),
                source: "sekai-directory".into(),
                locator: "directory_ontology_document".into(),
                confidence: 1.0,
            },
            super::Provenance {
                subject: DIRECTORY_RELATION_CONTAINS.into(),
                source: "sekai-directory".into(),
                locator: "directory_ontology_document".into(),
                confidence: 1.0,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ontology;
    use std::fs;

    #[test]
    fn indexing_querying_exporting_and_pruning_directory_facts_is_deterministic() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("Projects");
        let project = root.join("alpha");
        let source = project.join("src");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir(root.join(".hidden")).unwrap();

        let database = temporary.path().join("knowledge.db");
        let mut ontology = SqliteOntology::initialize(&database).unwrap();
        ontology.initialize_directory_ontology().unwrap();
        let report = ontology
            .index_directory(
                &root,
                DirectoryScanOptions {
                    max_depth: 8,
                    ..DirectoryScanOptions::default()
                },
                false,
            )
            .unwrap();
        assert_eq!(report.scanned_entities, 3);
        assert_eq!(report.scanned_links, 2);
        assert!(!report.pruned);

        let root_string = fs::canonicalize(&root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let query = ontology
            .query_directories(
                &root_string,
                QueryOptions {
                    direction: TraversalDirection::Outbound,
                    relation: Some(DIRECTORY_RELATION_CONTAINS.into()),
                    depth: 2,
                },
            )
            .unwrap();
        assert_eq!(query.entities.len(), 2);
        assert_eq!(query.links.len(), 2);
        assert_eq!(
            query.entities[0].path,
            fs::canonicalize(&project).unwrap().to_string_lossy()
        );

        let exported = ontology.export_directory(&root).unwrap();
        assert_eq!(exported.entities.len(), 3);
        assert_eq!(exported.links.len(), 2);
        assert!(ontology.validate().unwrap().is_empty());

        fs::remove_dir_all(&source).unwrap();
        let pruned = ontology
            .index_directory(&root, DirectoryScanOptions::default(), true)
            .unwrap();
        assert_eq!(pruned.scanned_entities, 2);
        assert_eq!(pruned.removed_entities, 1);
        assert_eq!(pruned.removed_links, 1);
        assert_eq!(ontology.export_directory(&root).unwrap().entities.len(), 2);
    }

    #[test]
    fn directory_documents_round_trip_through_a_second_database() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("workspace");
        fs::create_dir_all(root.join("project")).unwrap();
        let source_path = temporary.path().join("source.db");
        let destination_path = temporary.path().join("destination.db");
        let mut source = SqliteOntology::initialize(&source_path).unwrap();
        source
            .index_directory(&root, DirectoryScanOptions::default(), false)
            .unwrap();
        let document = source.export_directory(&root).unwrap();

        let mut destination = SqliteOntology::initialize(&destination_path).unwrap();
        let report = destination
            .import_directory_document(document.clone())
            .unwrap();
        assert_eq!(report.imported_entities, document.entities.len());
        assert_eq!(destination.export_directory(&root).unwrap(), document);
        assert!(destination.validate().unwrap().is_empty());
    }

    #[test]
    fn invalid_directory_documents_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("workspace");
        let root_string = root.to_string_lossy().into_owned();
        let root_id = directory_id(&root);
        let child = root.join("child");
        let child_id = directory_id(&child);
        let invalid = DirectoryDocument {
            schema_version: DIRECTORY_SCHEMA_VERSION,
            root: root_string.clone(),
            entities: vec![
                DirectoryEntity {
                    id: root_id.clone(),
                    path: root_string,
                    name: "workspace".into(),
                    kind: DEFAULT_DIRECTORY_KIND.into(),
                },
                DirectoryEntity {
                    id: child_id.clone(),
                    path: child.to_string_lossy().into_owned(),
                    name: "child".into(),
                    kind: DEFAULT_DIRECTORY_KIND.into(),
                },
            ],
            links: vec![DirectoryLink {
                id: "bad-link".into(),
                from_id: child_id,
                to_id: root_id,
                relation: DIRECTORY_RELATION_CONTAINS.into(),
            }],
        };
        assert!(matches!(
            validate_document(&invalid),
            Err(Error::Validation(issues)) if issues.iter().any(|issue| issue.code == "invalid_contains_path")
        ));
    }
}
