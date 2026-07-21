use sekai_ontology::{
    Error, Ontology, QueryOptions, SCHEMA_VERSION, SqliteOntology, TraversalDirection,
    ValidationIssue,
};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

const EXIT_USAGE_OR_INPUT: u8 = 2;
const EXIT_NOT_FOUND: u8 = 3;
const EXIT_DATABASE: u8 = 4;
const EXIT_VALIDATION: u8 = 5;

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
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
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

fn run() -> Result<(), Error> {
    let arguments = parse_arguments(env::args().skip(1))?;
    if arguments.command != "query" && arguments.query_options_set {
        return Err(Error::Input(
            "--direction, --relation, and --depth are only valid with query".into(),
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
        "help" => print_help(),
        command => {
            return Err(Error::Input(format!(
                "unknown command '{command}'\n\n{}",
                usage()
            )));
        }
    }
    Ok(())
}

fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Arguments, Error> {
    let mut database = env::var_os("SEKAI_DB").map(PathBuf::from);
    let mut json = false;
    let mut positional = Vec::new();
    let mut query_options = QueryOptions::default();
    let mut direction_set = false;
    let mut relation_set = false;
    let mut depth_set = false;
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
    "Usage: sekai [--db <path>] [--json] <command>\n\nCommands:\n  init\n  import <path>\n  export\n  validate\n  explain <name>\n  query <name> [--direction <outbound|inbound|both>] [--relation <name>] [--depth <0..32>]\n\nQuery defaults to --direction both --depth 1. SEKAI_DB selects the database when --db is omitted."
}

fn print_help() {
    println!("{}", usage());
}
