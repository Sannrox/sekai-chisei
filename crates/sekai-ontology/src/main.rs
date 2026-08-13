use sekai_ontology::{
    AskInterpretation, AskOperation, AskStatus, DEFAULT_DIRECTORY_KIND, DefinitionKind,
    DirectoryDocument, DirectoryScanOptions, EMBEDDED_SKILL, Error, ExportDocument,
    MAX_DIRECTORY_DEPTH, Ontology, QueryOptions, SCHEMA_VERSION, SqliteOntology,
    TraversalDirection, ValidationIssue, diff_documents, interpret_question,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

const EXIT_USAGE_OR_INPUT: u8 = 2;
const EXIT_NOT_FOUND: u8 = 3;
const EXIT_DATABASE: u8 = 4;
const EXIT_VALIDATION: u8 = 5;
const EXIT_ALREADY_CURRENT: u8 = 10;
const EXIT_SKILL_DRIFT: u8 = 11;
static SKILL_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
struct Envelope<T> {
    schema_version: u32,
    command: &'static str,
    data: T,
}

#[derive(Serialize)]
struct ValidationResult {
    valid: bool,
    issues: Vec<ValidationIssue>,
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "data")]
#[serde(rename_all = "snake_case")]
enum AskAnswer {
    Explain(sekai_ontology::ExplainResult),
    Query(sekai_ontology::QueryResult),
    Find(sekai_ontology::SearchResult),
    DirectoryQuery(sekai_ontology::DirectoryQueryResult),
}

#[derive(Serialize)]
struct AskResponse {
    interpretation: AskInterpretation,
    answer: Option<AskAnswer>,
}

struct Arguments {
    database: PathBuf,
    json: bool,
    command: String,
    operands: Vec<String>,
    query_options: QueryOptions,
    query_options_set: bool,
    directory_max_depth: u32,
    directory_max_depth_set: bool,
    directory_include_hidden: bool,
    directory_prune: bool,
    directory_kind: Option<String>,
    skill_path: Option<PathBuf>,
    force: bool,
    uninstall: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            if let Error::Validation(issues) = &error {
                for issue in issues {
                    eprintln!("{}: {} ({})", issue.path, issue.message, issue.code);
                }
            }
            ExitCode::from(match error {
                Error::Input(_) => EXIT_USAGE_OR_INPUT,
                Error::NotFound(_) => EXIT_NOT_FOUND,
                Error::Database(_) => EXIT_DATABASE,
                Error::Validation(_) => EXIT_VALIDATION,
            })
        }
    }
}

fn run() -> Result<ExitCode, Error> {
    let arguments = parse_arguments(env::args().skip(1))?;
    if !matches!(arguments.command.as_str(), "query" | "directory") && arguments.query_options_set {
        return Err(Error::Input(
            "--direction, --relation, and --depth are only valid with query".into(),
        ));
    }
    if arguments.command == "directory"
        && arguments.query_options_set
        && arguments.operands.first().map(String::as_str) != Some("query")
    {
        return Err(Error::Input(
            "--direction, --relation, and --depth are only valid with directory query".into(),
        ));
    }
    if arguments.command != "directory"
        && (arguments.directory_max_depth_set
            || arguments.directory_include_hidden
            || arguments.directory_prune
            || arguments.directory_kind.is_some())
    {
        return Err(Error::Input(
            "--max-depth, --include-hidden, --prune, and --kind are only valid with directory"
                .into(),
        ));
    }
    if arguments.command != "skill"
        && (arguments.skill_path.is_some() || arguments.force || arguments.uninstall)
    {
        return Err(Error::Input(
            "--path, --force, and --uninstall are only valid with skill".into(),
        ));
    }
    match arguments.command.as_str() {
        "init" => {
            expect_operands(&arguments, 0, "init")?;
            SqliteOntology::initialize(&arguments.database)?;
            println!("initialized {}", arguments.database.display());
        }
        "import" => {
            expect_operands(&arguments, 1, "import <path>")?;
            let input = fs::read_to_string(&arguments.operands[0]).map_err(|error| {
                Error::Input(format!("cannot read '{}': {error}", arguments.operands[0]))
            })?;
            let mut ontology = SqliteOntology::open(&arguments.database)?;
            ontology.import_json(&input)?;
            println!("imported {}", arguments.operands[0]);
        }
        "export" => {
            expect_operands(&arguments, 0, "export")?;
            let ontology = SqliteOntology::open_read_only(&arguments.database)?;
            let document = ontology.export()?;
            if arguments.json {
                print_json("export", document)?;
            } else {
                let output = serde_json::to_string_pretty(&document)
                    .map_err(|error| Error::Input(format!("cannot encode output: {error}")))?;
                println!("{output}");
            }
        }
        "validate" => {
            expect_operands(&arguments, 0, "validate")?;
            let ontology = SqliteOntology::open(&arguments.database)?;
            let issues = ontology.validate()?;
            if !issues.is_empty() {
                if arguments.json {
                    print_json(
                        "validate",
                        ValidationResult {
                            valid: false,
                            issues: issues.clone(),
                        },
                    )?;
                }
                return Err(Error::Validation(issues));
            }
            if arguments.json {
                print_json(
                    "validate",
                    ValidationResult {
                        valid: true,
                        issues,
                    },
                )?;
            } else {
                println!("valid");
            }
        }
        "explain" => {
            expect_operands(&arguments, 1, "explain <name>")?;
            let ontology = SqliteOntology::open(&arguments.database)?;
            let explanation = ontology.explain(&arguments.operands[0])?;
            if arguments.json {
                print_json("explain", explanation)?;
            } else {
                println!("{}", explanation.class.name);
                if !explanation.superclass_closure.is_empty() {
                    println!("  is_a: {}", explanation.superclass_closure.join(", "));
                }
                for relation in explanation.outbound_relations {
                    println!("  {} -> {}", relation.name, relation.range);
                }
                for relation in explanation.inbound_relations {
                    println!("  {} <- {}", relation.name, relation.domain);
                }
                for record in explanation.provenance {
                    println!(
                        "  derived_from: {}{}",
                        record.source,
                        if record.locator.is_empty() {
                            String::new()
                        } else {
                            format!("#{}", record.locator)
                        }
                    );
                }
            }
        }
        "query" => {
            expect_operands(
                &arguments,
                1,
                "query <name> [--direction <outbound|inbound|both>] [--relation <name>] [--depth <0..32>]",
            )?;
            let ontology = SqliteOntology::open_read_only(&arguments.database)?;
            let result = ontology.query(&arguments.operands[0], arguments.query_options)?;
            if arguments.json {
                print_json("query", result)?;
            } else {
                println!("{}", result.start);
                for relation in result.relations {
                    println!(
                        "  {}: {} -> {}",
                        relation.name, relation.domain, relation.range
                    );
                }
                for class in result.classes {
                    println!("  reached: {}", class.name);
                }
            }
        }
        "find" => run_find(&arguments)?,
        "diff" => run_diff(&arguments)?,
        "ask" => return run_ask(&arguments),
        "directory" => return run_directory(&arguments),
        "entity" => run_entity(&arguments)?,
        "relation" => run_relation(&arguments)?,
        "skill" => return run_skill(&arguments),
        "help" => print_help(),
        command => {
            return Err(Error::Input(format!(
                "unknown command '{command}'\n\n{}",
                usage()
            )));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_find(arguments: &Arguments) -> Result<(), Error> {
    expect_operands(arguments, 1, "find <text>")?;
    let result =
        SqliteOntology::open_read_only(&arguments.database)?.find(&arguments.operands[0])?;
    if arguments.json {
        print_json("find", result)?;
    } else if result.matches.is_empty() {
        println!("no definitions matched '{}'", result.query);
    } else {
        for matched in result.matches {
            println!(
                "{} {} (score {}; matched {})",
                definition_kind_name(matched.kind),
                matched.name,
                matched.score,
                matched.matched_fields.join(", ")
            );
        }
    }
    Ok(())
}

fn run_diff(arguments: &Arguments) -> Result<(), Error> {
    expect_operands(arguments, 2, "diff <before> <after>")?;
    let before = load_document(&arguments.operands[0])?;
    let after = load_document(&arguments.operands[1])?;
    let diff = diff_documents(&before, &after);
    if arguments.json {
        print_json("diff", diff)?;
    } else {
        println!("changed: {}", diff.changed);
        if diff.schema_changed {
            println!(
                "schema_version: {} -> {}",
                diff.before_schema_version, diff.after_schema_version
            );
        }
        print_diff_summary("classes", &diff.classes);
        print_diff_summary("relations", &diff.relations);
        print_diff_summary("provenance", &diff.provenance);
    }
    Ok(())
}

fn run_ask(arguments: &Arguments) -> Result<ExitCode, Error> {
    expect_operands(arguments, 1, "ask <question>")?;
    let ontology = SqliteOntology::open_read_only(&arguments.database)?;
    let document = ontology.export()?;
    let interpretation = interpret_question(&document, &arguments.operands[0])?;
    let mut answer = None;
    if let Some(plan) = &interpretation.plan {
        answer = Some(match plan.operation {
            AskOperation::Explain => AskAnswer::Explain(ontology.explain(&plan.name)?),
            AskOperation::Query => {
                let options = plan.options.clone().ok_or_else(|| {
                    Error::Input("ask query interpretation did not include options".into())
                })?;
                AskAnswer::Query(ontology.query(&plan.name, options)?)
            }
            AskOperation::Find => AskAnswer::Find(ontology.find(&plan.name)?),
            AskOperation::DirectoryQuery => {
                let options = plan.options.clone().ok_or_else(|| {
                    Error::Input(
                        "ask directory query interpretation did not include options".into(),
                    )
                })?;
                AskAnswer::DirectoryQuery(ontology.query_directories(&plan.name, options)?)
            }
        });
    }
    let status = interpretation.status;
    let response = AskResponse {
        interpretation,
        answer,
    };
    if arguments.json {
        print_json("ask", response)?;
    } else {
        print_ask_human(&response);
    }
    if status == AskStatus::Ready {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(EXIT_USAGE_OR_INPUT))
    }
}

fn run_directory(arguments: &Arguments) -> Result<ExitCode, Error> {
    let verb = arguments.operands.first().map(String::as_str).unwrap_or("");
    match verb {
        "init" => {
            if arguments.operands.len() != 1
                || arguments.directory_max_depth_set
                || arguments.directory_include_hidden
                || arguments.directory_prune
                || arguments.directory_kind.is_some()
            {
                return Err(directory_usage());
            }
            let mut ontology = SqliteOntology::open(&arguments.database)?;
            ontology.initialize_directory_ontology()?;
            println!(
                "directory vocabulary ready in {}",
                arguments.database.display()
            );
        }
        "index" => {
            if arguments.operands.len() != 2
                || arguments.query_options_set
                || arguments.directory_kind.as_deref() == Some("")
            {
                return Err(directory_usage());
            }
            let root = &arguments.operands[1];
            let options = DirectoryScanOptions {
                max_depth: arguments.directory_max_depth,
                include_hidden: arguments.directory_include_hidden,
                root_kind: arguments
                    .directory_kind
                    .clone()
                    .unwrap_or_else(|| DEFAULT_DIRECTORY_KIND.into()),
            };
            let mut ontology = SqliteOntology::open(&arguments.database)?;
            let report = ontology.index_directory(root, options, arguments.directory_prune)?;
            if arguments.json {
                print_json("directory.index", report)?;
            } else {
                println!(
                    "indexed {} directories and {} contains links under {}",
                    report.scanned_entities, report.scanned_links, report.root
                );
                if report.pruned {
                    println!(
                        "pruned {} directories and {} links",
                        report.removed_entities, report.removed_links
                    );
                }
            }
        }
        "export" | "tree" => {
            if arguments.operands.len() != 2
                || arguments.query_options_set
                || arguments.directory_include_hidden
                || arguments.directory_prune
                || arguments.directory_kind.is_some()
            {
                return Err(directory_usage());
            }
            let ontology = SqliteOntology::open_read_only(&arguments.database)?;
            let document = ontology.export_directory_with_depth(
                &arguments.operands[1],
                arguments.directory_max_depth,
            )?;
            if verb == "export" {
                print_directory_document(&document, arguments.json, "directory.export")?;
            } else if arguments.json {
                print_json("directory.tree", document)?;
            } else {
                print_directory_tree(&document);
            }
        }
        "import" => {
            if arguments.operands.len() != 2
                || arguments.query_options_set
                || arguments.directory_max_depth_set
                || arguments.directory_include_hidden
                || arguments.directory_prune
                || arguments.directory_kind.is_some()
            {
                return Err(directory_usage());
            }
            let document = load_directory_document(&arguments.operands[1])?;
            let mut ontology = SqliteOntology::open(&arguments.database)?;
            let report = ontology.import_directory_document(document)?;
            if arguments.json {
                print_json("directory.import", report)?;
            } else {
                println!(
                    "imported {} directories and {} links under {}",
                    report.imported_entities, report.imported_links, report.root
                );
            }
        }
        "query" => {
            if arguments.operands.len() != 2
                || arguments.directory_max_depth_set
                || arguments.directory_include_hidden
                || arguments.directory_prune
                || arguments.directory_kind.is_some()
            {
                return Err(directory_usage());
            }
            let ontology = SqliteOntology::open_read_only(&arguments.database)?;
            let result = ontology
                .query_directories(&arguments.operands[1], arguments.query_options.clone())?;
            if arguments.json {
                print_json("directory.query", result)?;
            } else {
                print_directory_query(&result);
            }
        }
        _ => return Err(directory_usage()),
    }
    Ok(ExitCode::SUCCESS)
}

fn directory_usage() -> Error {
    Error::Input(
        "usage: sekai [--db <path>] directory <init|index <root>|export <root>|tree <root>|import <path|->|query <path>> [--max-depth <0..64>] [--include-hidden] [--prune] [--kind <class>]".into(),
    )
}

fn load_directory_document(path: &str) -> Result<DirectoryDocument, Error> {
    let mut input = String::new();
    if path == "-" {
        io::stdin().read_to_string(&mut input).map_err(|error| {
            Error::Input(format!(
                "cannot read directory document from stdin: {error}"
            ))
        })?;
    } else {
        input = fs::read_to_string(path)
            .map_err(|error| Error::Input(format!("cannot read '{path}': {error}")))?;
    }
    let value: Value = serde_json::from_str(&input)
        .map_err(|error| Error::Input(format!("invalid directory document: {error}")))?;
    let value = if let Some(command) = value.get("command").and_then(Value::as_str) {
        if !matches!(command, "directory.export" | "directory.tree") {
            return Err(Error::Input(format!(
                "JSON input has command '{command}', expected 'directory.export' or 'directory.tree'"
            )));
        }
        value
            .get("data")
            .cloned()
            .ok_or_else(|| Error::Input("directory JSON envelope has no data field".into()))?
    } else {
        value
    };
    serde_json::from_value(value)
        .map_err(|error| Error::Input(format!("invalid directory document: {error}")))
}

fn print_directory_document(
    document: &DirectoryDocument,
    envelope: bool,
    command: &'static str,
) -> Result<(), Error> {
    if envelope {
        print_json(command, document.clone())
    } else {
        let output = serde_json::to_string_pretty(document)
            .map_err(|error| Error::Input(format!("cannot encode directory document: {error}")))?;
        println!("{output}");
        Ok(())
    }
}

fn print_directory_query(result: &sekai_ontology::DirectoryQueryResult) {
    println!("{}", result.start);
    for link in &result.links {
        println!("  {}: {} -> {}", link.relation, link.from_id, link.to_id);
    }
    for entity in &result.entities {
        println!("  reached: {} ({})", entity.path, entity.kind);
    }
}

fn print_directory_tree(document: &DirectoryDocument) {
    let entities = document
        .entities
        .iter()
        .map(|entity| (entity.id.as_str(), entity))
        .collect::<BTreeMap<_, _>>();
    let mut children = BTreeMap::<&str, Vec<&sekai_ontology::DirectoryEntity>>::new();
    for link in &document.links {
        if link.relation == sekai_ontology::DIRECTORY_RELATION_CONTAINS
            && let Some(child) = entities.get(link.to_id.as_str())
        {
            children
                .entry(link.from_id.as_str())
                .or_default()
                .push(*child);
        }
    }
    for values in children.values_mut() {
        values.sort_by(|left, right| left.path.cmp(&right.path));
    }
    let root_id = document
        .entities
        .iter()
        .find(|entity| entity.path == document.root)
        .map(|entity| entity.id.as_str())
        .unwrap_or("");
    println!("{}", document.root);
    let mut visited = BTreeSet::new();
    render_directory_children(root_id, "", &children, &mut visited);
}

fn render_directory_children(
    parent_id: &str,
    prefix: &str,
    children: &BTreeMap<&str, Vec<&sekai_ontology::DirectoryEntity>>,
    visited: &mut BTreeSet<String>,
) {
    let Some(values) = children.get(parent_id) else {
        return;
    };
    for (index, child) in values.iter().enumerate() {
        let last = index + 1 == values.len();
        let marker = if last { "└── " } else { "├── " };
        println!("{prefix}{marker}{}", child.name);
        if visited.insert(child.id.clone()) {
            let next_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
            render_directory_children(&child.id, &next_prefix, children, visited);
        }
    }
}

fn load_document(path: &str) -> Result<ExportDocument, Error> {
    let bytes =
        fs::read(path).map_err(|error| Error::Input(format!("cannot read '{path}': {error}")))?;
    let first = bytes
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .copied();
    let is_json = first == Some(b'{') || first == Some(b'[') || path.ends_with(".json");
    if is_json {
        let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
            Error::Input(format!("invalid ontology document '{path}': {error}"))
        })?;
        let value = if let Some(command) = value.get("command").and_then(Value::as_str) {
            if command != "export" {
                return Err(Error::Input(format!(
                    "JSON input '{path}' has command '{command}', expected 'export'"
                )));
            }
            value
                .get("data")
                .cloned()
                .ok_or_else(|| Error::Input(format!("JSON export '{path}' has no data field")))?
        } else {
            value
        };
        return serde_json::from_value(value)
            .map_err(|error| Error::Input(format!("invalid ontology document '{path}': {error}")));
    }
    SqliteOntology::open_read_only(path)?.export()
}

fn definition_kind_name(kind: DefinitionKind) -> &'static str {
    match kind {
        DefinitionKind::Class => "class",
        DefinitionKind::Relation => "relation",
    }
}

fn print_diff_summary(name: &str, summary: &sekai_ontology::DiffSummary) {
    for item in &summary.added {
        println!("  {name} added: {item}");
    }
    for item in &summary.removed {
        println!("  {name} removed: {item}");
    }
    for item in &summary.changed {
        println!(
            "  {name} changed: {} ({})",
            item.name,
            item.fields.join(", ")
        );
    }
}

fn print_ask_human(response: &AskResponse) {
    let interpretation = &response.interpretation;
    println!(
        "status: {}",
        match interpretation.status {
            AskStatus::Ready => "ready",
            AskStatus::Ambiguous => "ambiguous",
            AskStatus::Unsupported => "unsupported",
        }
    );
    println!("interpreted as: {}", interpretation.interpretation);
    if !interpretation.candidates.is_empty() {
        println!("candidates:");
        for candidate in &interpretation.candidates {
            println!(
                "  {} {} (score {}; matched {})",
                definition_kind_name(candidate.kind),
                candidate.name,
                candidate.score,
                candidate.matched_fields.join(", ")
            );
        }
    }
    match &response.answer {
        Some(AskAnswer::Explain(explanation)) => {
            println!("{}", explanation.class.name);
            if !explanation.superclass_closure.is_empty() {
                println!("  is_a: {}", explanation.superclass_closure.join(", "));
            }
            for relation in &explanation.outbound_relations {
                println!("  {} -> {}", relation.name, relation.range);
            }
            for relation in &explanation.inbound_relations {
                println!("  {} <- {}", relation.name, relation.domain);
            }
        }
        Some(AskAnswer::Query(query)) => {
            println!("{}", query.start);
            for relation in &query.relations {
                println!(
                    "  {}: {} -> {}",
                    relation.name, relation.domain, relation.range
                );
            }
            for class in &query.classes {
                println!("  reached: {}", class.name);
            }
        }
        Some(AskAnswer::Find(result)) => {
            if result.matches.is_empty() {
                println!("no definitions matched '{}'", result.query);
            } else {
                for matched in &result.matches {
                    println!(
                        "{} {} (score {}; matched {})",
                        definition_kind_name(matched.kind),
                        matched.name,
                        matched.score,
                        matched.matched_fields.join(", ")
                    );
                }
            }
        }
        Some(AskAnswer::DirectoryQuery(result)) => print_directory_query(result),
        None => {}
    }
}

fn run_entity(arguments: &Arguments) -> Result<(), Error> {
    match arguments.operands.as_slice() {
        [verb] if verb == "list" => {
            let document = SqliteOntology::open_read_only(&arguments.database)?.export()?;
            if arguments.json {
                print_json("entity.list", document.classes)?;
            } else {
                for class in document.classes {
                    println!("{}", class.name);
                }
            }
        }
        [verb, name] if verb == "show" => {
            let ontology = SqliteOntology::open_read_only(&arguments.database)?;
            let explanation = ontology.explain(name)?;
            if arguments.json {
                print_json("entity.show", explanation)?;
            } else {
                println!("{}", explanation.class.name);
            }
        }
        _ => {
            return Err(Error::Input(
                "usage: sekai [--db <path>] entity <list|show <name>>".into(),
            ));
        }
    }
    Ok(())
}

fn run_relation(arguments: &Arguments) -> Result<(), Error> {
    expect_operands(arguments, 1, "relation list")?;
    if arguments.operands[0] != "list" {
        return Err(Error::Input(
            "usage: sekai [--db <path>] relation list".into(),
        ));
    }
    let relations = SqliteOntology::open_read_only(&arguments.database)?
        .export()?
        .relations;
    if arguments.json {
        print_json("relation.list", relations)?;
    } else {
        for relation in relations {
            println!(
                "{}: {} -> {}",
                relation.name, relation.domain, relation.range
            );
        }
    }
    Ok(())
}

fn run_skill(arguments: &Arguments) -> Result<ExitCode, Error> {
    if arguments.force && arguments.uninstall {
        return Err(Error::Input(
            "--force and --uninstall cannot be used together".into(),
        ));
    }
    let verb = arguments.operands.first().map(String::as_str).unwrap_or("");
    let directory = arguments
        .skill_path
        .clone()
        .or_else(|| env::var_os("SEKAI_SKILL_PATH").map(PathBuf::from))
        .or_else(default_skill_path);
    match verb {
        "path" => {
            expect_operands(arguments, 1, "skill path [--path <dir>]")?;
            if arguments.force || arguments.uninstall {
                return Err(Error::Input(
                    "--force and --uninstall are only valid with skill install".into(),
                ));
            }
            println!("{}", directory.ok_or_else(|| Error::Input("cannot resolve a user skill directory; pass --path or set SEKAI_SKILL_PATH".into()))?.display());
            Ok(ExitCode::SUCCESS)
        }
        "install" => {
            expect_operands(
                arguments,
                1,
                "skill install [--path <dir>] [--force|--uninstall]",
            )?;
            let target = directory.ok_or_else(|| Error::Input("cannot resolve a user skill directory; pass --path or set SEKAI_SKILL_PATH".into()))?.join("SKILL.md");
            if arguments.uninstall {
                return uninstall_skill(&target);
            }
            install_skill(&target, arguments.force)
        }
        _ => Err(Error::Input(
            "usage: sekai skill <path|install> [--path <dir>] [--force|--uninstall]".into(),
        )),
    }
}

fn default_skill_path() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".agents/skills/sekai-ontology"))
}

fn install_skill(target: &Path, force: bool) -> Result<ExitCode, Error> {
    if target_is_symlink(target)? {
        eprintln!("refusing to follow skill symlink at {}", target.display());
        return Ok(ExitCode::from(EXIT_SKILL_DRIFT));
    }
    if target.exists() {
        let metadata = fs::symlink_metadata(target).map_err(|error| {
            Error::Input(format!("cannot inspect '{}': {error}", target.display()))
        })?;
        if !metadata.file_type().is_file() {
            eprintln!(
                "refusing to overwrite non-file skill target at {}",
                target.display()
            );
            return Ok(ExitCode::from(EXIT_SKILL_DRIFT));
        }
        let current = read_skill_file(target)?;
        if current == EMBEDDED_SKILL {
            eprintln!("skill already current at {}", target.display());
            return Ok(ExitCode::from(EXIT_ALREADY_CURRENT));
        }
        if !is_sekai_skill(&current) {
            eprintln!(
                "refusing to overwrite non-Sekai file at {}",
                target.display()
            );
            return Ok(ExitCode::from(EXIT_SKILL_DRIFT));
        }
        if !force {
            eprintln!(
                "refusing to overwrite modified or unrecognized skill at {}; rerun with --force",
                target.display()
            );
            return Ok(ExitCode::from(EXIT_SKILL_DRIFT));
        }
        replace_claimed_skill(target)?;
        println!("installed {}", target.display());
        return Ok(ExitCode::SUCCESS);
    }
    let parent = target
        .parent()
        .ok_or_else(|| Error::Input("skill target has no parent directory".into()))?;
    fs::create_dir_all(parent)
        .map_err(|error| Error::Input(format!("cannot create '{}': {error}", parent.display())))?;
    install_new_skill(target)?;
    println!("installed {}", target.display());
    Ok(ExitCode::SUCCESS)
}

fn stage_skill(target: &Path) -> Result<PathBuf, Error> {
    let parent = target
        .parent()
        .ok_or_else(|| Error::Input("skill target has no parent directory".into()))?;
    let (temporary_path, mut temporary_file) = create_skill_temp(parent)?;
    let staged = temporary_file
        .write_all(EMBEDDED_SKILL.as_bytes())
        .and_then(|()| temporary_file.sync_all());
    if let Err(error) = staged {
        let _ = fs::remove_file(&temporary_path);
        return Err(Error::Input(format!(
            "cannot stage '{}': {error}",
            target.display()
        )));
    }
    drop(temporary_file);

    Ok(temporary_path)
}

fn install_new_skill(target: &Path) -> Result<(), Error> {
    let temporary_path = stage_skill(target)?;
    if let Err(error) = fs::hard_link(&temporary_path, target) {
        let _ = fs::remove_file(&temporary_path);
        return Err(Error::Input(format!(
            "cannot install '{}': {error}",
            target.display()
        )));
    }
    fs::remove_file(&temporary_path).map_err(|error| {
        Error::Input(format!(
            "installed '{}' but cannot remove temporary file '{}': {error}",
            target.display(),
            temporary_path.display()
        ))
    })?;
    Ok(())
}

fn replace_claimed_skill(target: &Path) -> Result<(), Error> {
    let staged = stage_skill(target)?;
    let claimed = match claim_skill_target(target) {
        Ok(path) => path,
        Err(error) => {
            let _ = fs::remove_file(staged);
            return Err(error);
        }
    };
    let captured = read_skill_file(&claimed);
    if !matches!(captured.as_deref(), Ok(content) if is_sekai_skill(content)) {
        let _ = fs::remove_file(&staged);
        restore_claim(target, &claimed)?;
        return Err(Error::Input(format!(
            "skill changed before replacement at {}; refusing",
            target.display()
        )));
    }
    if let Err(error) = fs::hard_link(&staged, target) {
        let _ = fs::remove_file(&staged);
        return match restore_claim(target, &claimed) {
            Ok(()) => Err(Error::Input(format!(
                "cannot install '{}': {error}; original restored",
                target.display()
            ))),
            Err(restore_error) => Err(Error::Input(format!(
                "cannot install '{}': {error}; {restore_error}",
                target.display()
            ))),
        };
    }
    fs::remove_file(&staged).map_err(|error| {
        Error::Input(format!(
            "installed '{}' but cannot remove temporary file '{}': {error}",
            target.display(),
            staged.display()
        ))
    })?;
    fs::remove_file(&claimed).map_err(|error| {
        Error::Input(format!(
            "installed '{}' but cannot remove previous skill '{}': {error}",
            target.display(),
            claimed.display()
        ))
    })?;
    Ok(())
}

fn claim_skill_target(target: &Path) -> Result<PathBuf, Error> {
    let parent = target
        .parent()
        .ok_or_else(|| Error::Input("skill target has no parent directory".into()))?;
    for _ in 0..100 {
        let target_metadata = fs::symlink_metadata(target).map_err(|error| {
            Error::Input(format!("cannot inspect '{}': {error}", target.display()))
        })?;
        let sequence = SKILL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let claimed = parent.join(format!(
            ".SKILL.md.{}.{}.claimed",
            std::process::id(),
            sequence
        ));
        let reserved = if target_metadata.file_type().is_dir() {
            fs::create_dir(&claimed)
        } else {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&claimed)
                .map(drop)
        };
        match reserved {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Error::Input(format!(
                    "cannot reserve recovery path in '{}': {error}",
                    parent.display()
                )));
            }
        }
        if let Err(error) = fs::rename(target, &claimed) {
            if target_metadata.file_type().is_dir() {
                let _ = fs::remove_dir(&claimed);
            } else {
                let _ = fs::remove_file(&claimed);
            }
            return Err(Error::Input(format!(
                "cannot claim '{}': {error}",
                target.display()
            )));
        }
        return Ok(claimed);
    }
    Err(Error::Input(format!(
        "cannot allocate a recovery path for '{}'",
        target.display()
    )))
}

fn restore_claim(target: &Path, claimed: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(claimed).map_err(|error| {
        Error::Input(format!(
            "cannot inspect recovery file '{}': {error}",
            claimed.display()
        ))
    })?;
    if metadata.file_type().is_dir() {
        fs::create_dir(target).map_err(|error| {
            Error::Input(format!(
                "cannot reserve '{}' for restoration: {error}; original preserved at '{}'",
                target.display(),
                claimed.display()
            ))
        })?;
        if let Err(error) = fs::rename(claimed, target) {
            let _ = fs::remove_dir(target);
            return Err(Error::Input(format!(
                "cannot restore '{}': {error}; original preserved at '{}'",
                target.display(),
                claimed.display()
            )));
        }
        return Ok(());
    }
    let placeholder = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|error| {
            Error::Input(format!(
                "cannot reserve '{}' for restoration: {error}; original preserved at '{}'",
                target.display(),
                claimed.display()
            ))
        })?;
    drop(placeholder);
    if let Err(error) = fs::rename(claimed, target) {
        let _ = fs::remove_file(target);
        return Err(Error::Input(format!(
            "cannot restore '{}': {error}; original preserved at '{}'",
            target.display(),
            claimed.display()
        )));
    }
    Ok(())
}

fn create_skill_temp(parent: &Path) -> Result<(PathBuf, File), Error> {
    for _ in 0..100 {
        let sequence = SKILL_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".SKILL.md.{}.{}.tmp", std::process::id(), sequence));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Error::Input(format!(
                    "cannot create temporary skill in '{}': {error}",
                    parent.display()
                )));
            }
        }
    }
    Err(Error::Input(format!(
        "cannot allocate a temporary skill file in '{}'",
        parent.display()
    )))
}

fn read_skill_file(target: &Path) -> Result<String, Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(target)
        .map_err(|error| Error::Input(format!("cannot open '{}': {error}", target.display())))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|error| Error::Input(format!("cannot read '{}': {error}", target.display())))?;
    Ok(content)
}

fn uninstall_skill(target: &Path) -> Result<ExitCode, Error> {
    if target_is_symlink(target)? {
        eprintln!("refusing to follow skill symlink at {}", target.display());
        return Ok(ExitCode::from(EXIT_SKILL_DRIFT));
    }
    if !target.exists() {
        eprintln!("skill is not installed at {}", target.display());
        return Ok(ExitCode::from(EXIT_ALREADY_CURRENT));
    }
    let claimed = claim_skill_target(target)?;
    let current = read_skill_file(&claimed);
    if !matches!(current.as_deref(), Ok(content) if content == EMBEDDED_SKILL) {
        restore_claim(target, &claimed)?;
        eprintln!(
            "refusing to remove modified or unrecognized skill at {}",
            target.display()
        );
        return Ok(ExitCode::from(EXIT_SKILL_DRIFT));
    }
    fs::remove_file(&claimed)
        .map_err(|error| Error::Input(format!("cannot remove '{}': {error}", claimed.display())))?;
    println!("removed {}", target.display());
    Ok(ExitCode::SUCCESS)
}

fn is_sekai_skill(content: &str) -> bool {
    content
        .lines()
        .take(8)
        .any(|line| line.trim() == "name: sekai-ontology")
}

fn target_is_symlink(target: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(target) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::Input(format!(
            "cannot inspect '{}': {error}",
            target.display()
        ))),
    }
}

/// Resolve the default database path when neither `--db` nor `SEKAI_DB` is set.
///
/// Returns the nearest scoped `.sekai/knowledge.db`, then the user-level
/// default if the file already exists:
/// - macOS: `~/Library/Application Support/sekai/knowledge.db`
/// - Other (Linux, etc.): `${XDG_DATA_HOME:-~/.local/share}/sekai/knowledge.db`
///
/// Falls back to `knowledge.db` in the current working directory.
fn resolve_default_database() -> PathBuf {
    if let Some(path) = nearest_scoped_database() {
        return path;
    }
    if let Some(path) = user_default_database()
        && path.exists()
    {
        return path;
    }
    PathBuf::from("knowledge.db")
}

fn nearest_scoped_database() -> Option<PathBuf> {
    let current = env::current_dir().ok()?;
    let mut directory = current.as_path();
    loop {
        let scoped = directory.join(".sekai/knowledge.db");
        if scoped.is_file() {
            return Some(scoped);
        }
        directory = directory.parent()?;
    }
}

/// Compute the platform-specific user-level database path without checking existence.
fn user_default_database() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support/sekai/knowledge.db"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let base = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
        base.map(|b| b.join("sekai/knowledge.db"))
    }
}

fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Arguments, Error> {
    let mut database = env::var_os("SEKAI_DB").map(PathBuf::from);
    let mut json = false;
    let mut positional = Vec::new();
    let mut query_options = QueryOptions::default();
    let mut direction_set = false;
    let mut relation_set = false;
    let mut depth_set = false;
    let mut directory_max_depth = MAX_DIRECTORY_DEPTH;
    let mut directory_max_depth_set = false;
    let mut directory_include_hidden = false;
    let mut directory_prune = false;
    let mut directory_kind = None;
    let mut skill_path = None;
    let mut force = false;
    let mut uninstall = false;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--db" => {
                let path = arguments
                    .next()
                    .ok_or_else(|| Error::Input("--db requires a path".into()))?;
                database = Some(PathBuf::from(path));
            }
            "--json" => json = true,
            "--path" => {
                skill_path =
                    Some(PathBuf::from(arguments.next().ok_or_else(|| {
                        Error::Input("--path requires a directory".into())
                    })?))
            }
            "--force" => force = true,
            "--uninstall" => uninstall = true,
            "--direction" => {
                if direction_set {
                    return Err(Error::Input(
                        "--direction may only be specified once".into(),
                    ));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| Error::Input("--direction requires a value".into()))?;
                query_options.direction = match value.as_str() {
                    "outbound" => TraversalDirection::Outbound,
                    "inbound" => TraversalDirection::Inbound,
                    "both" => TraversalDirection::Both,
                    _ => {
                        return Err(Error::Input(format!(
                            "unsupported direction '{value}'; expected outbound, inbound, or both"
                        )));
                    }
                };
                direction_set = true;
            }
            "--relation" => {
                if relation_set {
                    return Err(Error::Input("--relation may only be specified once".into()));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| Error::Input("--relation requires a name".into()))?;
                if value.is_empty() {
                    return Err(Error::Input("--relation requires a non-empty name".into()));
                }
                query_options.relation = Some(value);
                relation_set = true;
            }
            "--depth" => {
                if depth_set {
                    return Err(Error::Input("--depth may only be specified once".into()));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| Error::Input("--depth requires a value".into()))?;
                query_options.depth = value.parse().map_err(|_| {
                    Error::Input(format!("invalid query depth '{value}'; expected 0..32"))
                })?;
                depth_set = true;
            }
            "--max-depth" => {
                if directory_max_depth_set {
                    return Err(Error::Input(
                        "--max-depth may only be specified once".into(),
                    ));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| Error::Input("--max-depth requires a value".into()))?;
                directory_max_depth = value.parse().map_err(|_| {
                    Error::Input(format!(
                        "invalid directory max depth '{value}'; expected 0..{MAX_DIRECTORY_DEPTH}"
                    ))
                })?;
                if directory_max_depth > MAX_DIRECTORY_DEPTH {
                    return Err(Error::Input(format!(
                        "directory max depth {directory_max_depth} exceeds maximum {MAX_DIRECTORY_DEPTH}"
                    )));
                }
                directory_max_depth_set = true;
            }
            "--include-hidden" => {
                if directory_include_hidden {
                    return Err(Error::Input(
                        "--include-hidden may only be specified once".into(),
                    ));
                }
                directory_include_hidden = true;
            }
            "--prune" => {
                if directory_prune {
                    return Err(Error::Input("--prune may only be specified once".into()));
                }
                directory_prune = true;
            }
            "--kind" => {
                if directory_kind.is_some() {
                    return Err(Error::Input("--kind may only be specified once".into()));
                }
                let value = arguments
                    .next()
                    .ok_or_else(|| Error::Input("--kind requires a value".into()))?;
                if value.trim().is_empty() {
                    return Err(Error::Input("--kind requires a non-empty value".into()));
                }
                directory_kind = Some(value);
            }
            "-h" | "--help" if positional.is_empty() => positional.push("help".into()),
            _ if argument.starts_with('-') => {
                return Err(Error::Input(format!("unknown option '{argument}'")));
            }
            _ => positional.push(argument),
        }
    }
    let command = positional.first().cloned().unwrap_or_else(|| "help".into());
    Ok(Arguments {
        database: database.unwrap_or_else(resolve_default_database),
        json,
        command,
        operands: positional.into_iter().skip(1).collect(),
        query_options,
        query_options_set: direction_set || relation_set || depth_set,
        directory_max_depth,
        directory_max_depth_set,
        directory_include_hidden,
        directory_prune,
        directory_kind,
        skill_path,
        force,
        uninstall,
    })
}

fn expect_operands(arguments: &Arguments, count: usize, usage: &str) -> Result<(), Error> {
    if arguments.operands.len() == count {
        Ok(())
    } else {
        Err(Error::Input(format!("usage: sekai [--db <path>] {usage}")))
    }
}

fn print_json<T: Serialize>(command: &'static str, data: T) -> Result<(), Error> {
    let envelope = Envelope {
        schema_version: SCHEMA_VERSION,
        command,
        data,
    };
    let output = serde_json::to_string_pretty(&envelope)
        .map_err(|error| Error::Input(format!("cannot encode output: {error}")))?;
    println!("{output}");
    Ok(())
}

fn usage() -> &'static str {
    "Usage: sekai [--db <path>] [--json] <command>\n\nCommands:\n  init\n  import <path>\n  export\n  validate\n  explain <name>\n  query <name> [--direction <outbound|inbound|both>] [--relation <name>] [--depth <0..32>]\n  find <text>\n  diff <before> <after>\n  ask <question>\n  directory init\n  directory index <root> [--max-depth <0..64>] [--include-hidden] [--prune] [--kind <class>]\n  directory export <root> [--max-depth <0..64>]\n  directory tree <root> [--max-depth <0..64>]\n  directory import <path|->\n  directory query <path> [--direction <outbound|inbound|both>] [--relation <name>] [--depth <0..64>]\n  entity list\n  entity show <name>\n  relation list\n  skill path [--path <dir>]\n  skill install [--path <dir>] [--force|--uninstall]\n\nDatabase resolution (first match wins):\n  1. --db <path>\n  2. SEKAI_DB environment variable\n  3. nearest existing .sekai/knowledge.db from the current directory upward\n  4. User-level default (if file exists):\n       macOS:  ~/Library/Application Support/sekai/knowledge.db\n       Linux:  ${XDG_DATA_HOME:-~/.local/share}/sekai/knowledge.db\n  5. knowledge.db in the current directory\n\nQuery defaults to --direction both --depth 1. `ask` is read-only and only executes bounded explain, query, find, and directory-query plans.\nDirectory indexing never follows symlinks; `--prune` removes stale indexed facts under the selected root.\n`diff` accepts raw ontology JSON, `export --json` envelopes, or SQLite databases.\nSEKAI_SKILL_PATH selects the skill directory."
}

fn print_help() {
    println!("{}", usage());
}
