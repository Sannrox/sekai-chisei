use sekai_ontology::{
    EMBEDDED_SKILL, Error, Ontology, QueryOptions, SCHEMA_VERSION, SqliteOntology,
    TraversalDirection, ValidationIssue,
};
use serde::Serialize;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
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

struct Arguments {
    database: PathBuf,
    json: bool,
    command: String,
    operands: Vec<String>,
    query_options: QueryOptions,
    query_options_set: bool,
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
    if arguments.command != "query" && arguments.query_options_set {
        return Err(Error::Input(
            "--direction, --relation, and --depth are only valid with query".into(),
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
        let (_file, current) = open_existing_skill(target)?;
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
        write_skill_atomically(target, true)?;
        println!("installed {}", target.display());
        return Ok(ExitCode::SUCCESS);
    }
    let parent = target
        .parent()
        .ok_or_else(|| Error::Input("skill target has no parent directory".into()))?;
    fs::create_dir_all(parent)
        .map_err(|error| Error::Input(format!("cannot create '{}': {error}", parent.display())))?;
    write_skill_atomically(target, false)?;
    println!("installed {}", target.display());
    Ok(ExitCode::SUCCESS)
}

fn write_skill_atomically(target: &Path, replace: bool) -> Result<(), Error> {
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

    let installed = if replace {
        fs::rename(&temporary_path, target)
    } else {
        fs::hard_link(&temporary_path, target)
    };
    if let Err(error) = installed {
        let _ = fs::remove_file(&temporary_path);
        return Err(Error::Input(format!(
            "cannot install '{}': {error}",
            target.display()
        )));
    }
    if !replace {
        fs::remove_file(&temporary_path).map_err(|error| {
            Error::Input(format!(
                "installed '{}' but cannot remove temporary file '{}': {error}",
                target.display(),
                temporary_path.display()
            ))
        })?;
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

fn open_existing_skill(target: &Path) -> Result<(File, String), Error> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
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
    Ok((file, content))
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
    let current = fs::read_to_string(target)
        .map_err(|error| Error::Input(format!("cannot read '{}': {error}", target.display())))?;
    if current != EMBEDDED_SKILL {
        eprintln!(
            "refusing to remove modified or unrecognized skill at {}",
            target.display()
        );
        return Ok(ExitCode::from(EXIT_SKILL_DRIFT));
    }
    fs::remove_file(target)
        .map_err(|error| Error::Input(format!("cannot remove '{}': {error}", target.display())))?;
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

fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Arguments, Error> {
    let mut database = env::var_os("SEKAI_DB").map(PathBuf::from);
    let mut json = false;
    let mut positional = Vec::new();
    let mut query_options = QueryOptions::default();
    let mut direction_set = false;
    let mut relation_set = false;
    let mut depth_set = false;
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
            "-h" | "--help" if positional.is_empty() => positional.push("help".into()),
            _ if argument.starts_with('-') => {
                return Err(Error::Input(format!("unknown option '{argument}'")));
            }
            _ => positional.push(argument),
        }
    }
    let command = positional.first().cloned().unwrap_or_else(|| "help".into());
    Ok(Arguments {
        database: database.unwrap_or_else(|| PathBuf::from("knowledge.db")),
        json,
        command,
        operands: positional.into_iter().skip(1).collect(),
        query_options,
        query_options_set: direction_set || relation_set || depth_set,
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
    "Usage: sekai [--db <path>] [--json] <command>\n\nCommands:\n  init\n  import <path>\n  export\n  validate\n  explain <name>\n  query <name> [--direction <outbound|inbound|both>] [--relation <name>] [--depth <0..32>]\n  entity list\n  entity show <name>\n  relation list\n  skill path [--path <dir>]\n  skill install [--path <dir>] [--force|--uninstall]\n\nQuery defaults to --direction both --depth 1. SEKAI_DB selects the database when --db is omitted. SEKAI_SKILL_PATH selects the skill directory."
}

fn print_help() {
    println!("{}", usage());
}
