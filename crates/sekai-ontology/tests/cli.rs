use sekai_ontology::{EMBEDDED_SKILL, ImportDocument, Ontology, SqliteOntology};
use serde_json::Value;
use std::fs;
use std::process::{Command, Output};

fn sekai(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sekai"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn fresh_file_workflow_has_stable_machine_output() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("knowledge.db");
    let database = database.to_str().unwrap();
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codebase.json");

    assert!(sekai(&["--db", database, "init"]).status.success());
    assert!(
        sekai(&["import", fixture, "--db", database])
            .status
            .success()
    );
    assert!(
        sekai(&["--json", "validate", "--db", database])
            .status
            .success()
    );
    let output = sekai(&["explain", "Api", "--json", "--db", database]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "explain");
    assert_eq!(
        json["data"]["superclass_closure"],
        serde_json::json!(["Component", "Service"])
    );
    assert_eq!(json["data"]["outbound_relations"][0]["name"], "depends_on");
    assert_eq!(json["data"]["inbound_relations"][0]["name"], "serves");
    assert_eq!(json["data"]["provenance"].as_array().unwrap().len(), 4);
}

#[test]
fn export_is_deterministic_read_only_and_round_trips() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.db");
    let destination_path = directory.path().join("destination.db");
    let source = source_path.to_str().unwrap();
    let destination = destination_path.to_str().unwrap();
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codebase.json");

    assert!(sekai(&["--db", source, "init"]).status.success());
    assert!(sekai(&["--db", source, "import", fixture]).status.success());
    let before = SqliteOntology::open_read_only(source)
        .unwrap()
        .export()
        .unwrap();

    let first = sekai(&["--db", source, "--json", "export"]);
    let second = sekai(&["export", "--json", "--db", source]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let envelope: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(envelope["schema_version"], 1);
    assert_eq!(envelope["command"], "export");
    let document: ImportDocument = serde_json::from_value(envelope["data"].clone()).unwrap();
    assert_eq!(document, before);
    let human = sekai(&["--db", source, "export"]);
    assert!(human.status.success());
    assert_eq!(
        serde_json::from_slice::<ImportDocument>(&human.stdout).unwrap(),
        before
    );

    assert!(sekai(&["--db", destination, "init"]).status.success());
    let exchange_path = directory.path().join("exchange.json");
    fs::write(
        &exchange_path,
        serde_json::to_vec_pretty(&document).unwrap(),
    )
    .unwrap();
    assert!(
        sekai(&[
            "--db",
            destination,
            "import",
            exchange_path.to_str().unwrap(),
        ])
        .status
        .success()
    );
    let destination_ontology = SqliteOntology::open_read_only(destination).unwrap();
    assert_eq!(destination_ontology.export().unwrap(), before);
    assert_eq!(destination_ontology.validate().unwrap(), Vec::new());
    assert_eq!(
        SqliteOntology::open_read_only(source)
            .unwrap()
            .export()
            .unwrap(),
        before
    );
}

#[test]
fn export_handles_empty_and_invalid_databases_without_partial_output() {
    let directory = tempfile::tempdir().unwrap();
    let empty_path = directory.path().join("empty.db");
    let empty = empty_path.to_str().unwrap();
    assert!(sekai(&["--db", empty, "init"]).status.success());
    let output = sekai(&["--db", empty, "--json", "export"]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["data"]["classes"], serde_json::json!([]));
    assert_eq!(json["data"]["relations"], serde_json::json!([]));
    assert_eq!(json["data"]["provenance"], serde_json::json!([]));

    let malformed_path = directory.path().join("malformed.db");
    fs::write(&malformed_path, b"not a sqlite database").unwrap();
    let malformed = sekai(&["--db", malformed_path.to_str().unwrap(), "--json", "export"]);
    assert_eq!(malformed.status.code(), Some(4));
    assert!(malformed.stdout.is_empty());
    assert!(!malformed.stderr.is_empty());

    let incompatible_path = directory.path().join("incompatible.db");
    let connection = rusqlite::Connection::open(&incompatible_path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE ontology_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO ontology_metadata(key, value) VALUES ('schema_version', '2');",
        )
        .unwrap();
    drop(connection);
    for invalid_path in [
        incompatible_path,
        directory.path().join("missing.db"),
        directory.path().into(),
    ] {
        let output = sekai(&["--db", invalid_path.to_str().unwrap(), "--json", "export"]);
        assert_eq!(output.status.code(), Some(4));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn embedded_skill_only_documents_shipping_commands() {
    let help = sekai(&["--help"]);
    let help = String::from_utf8(help.stdout).unwrap();
    for command in ["export", "explain", "validate", "import"] {
        assert!(help.contains(command), "help is missing {command}");
        assert!(
            EMBEDDED_SKILL.contains(command),
            "skill is missing {command}"
        );
    }
}

#[test]
fn exit_codes_distinguish_failures() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("knowledge.db");
    let database = database_path.to_str().unwrap();
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codebase.json");
    assert!(sekai(&["--db", database, "init"]).status.success());
    assert!(
        sekai(&["--db", database, "import", fixture])
            .status
            .success()
    );

    assert_eq!(sekai(&["unknown"]).status.code(), Some(2));
    assert_eq!(
        sekai(&["--db", database, "explain", "Missing"])
            .status
            .code(),
        Some(3)
    );
    let malformed = directory.path().join("malformed.db");
    std::fs::write(&malformed, b"not a sqlite database").unwrap();
    assert_eq!(
        sekai(&["--db", malformed.to_str().unwrap(), "validate"])
            .status
            .code(),
        Some(4)
    );
    let missing = directory.path().join("missing.db");
    assert_eq!(
        sekai(&["--db", missing.to_str().unwrap(), "validate"])
            .status
            .code(),
        Some(4)
    );
    assert!(!missing.exists());

    let invalid = directory.path().join("invalid.json");
    std::fs::write(
        &invalid,
        r#"{
      "schema_version": 1,
      "classes": [{"name":"Child","superclasses":["Missing"]}]
    }"#,
    )
    .unwrap();
    assert_eq!(
        sekai(&["--db", database, "import", invalid.to_str().unwrap()])
            .status
            .code(),
        Some(5)
    );
    assert_eq!(
        sekai(&["--db", database, "explain", "Child"]).status.code(),
        Some(3)
    );

    let connection = rusqlite::Connection::open(database).unwrap();
    connection
        .execute(
            "INSERT INTO ontology_classes(name, definition_json) VALUES (?1, ?2)",
            rusqlite::params!["Broken", r#"{"name":"Broken","superclasses":["Missing"]}"#],
        )
        .unwrap();
    let validation = sekai(&["--db", database, "--json", "validate"]);
    assert_eq!(validation.status.code(), Some(5));
    let json: Value = serde_json::from_slice(&validation.stdout).unwrap();
    assert_eq!(json["data"]["valid"], false);
    assert_eq!(json["data"]["issues"][0]["code"], "undefined_superclass");
    assert_eq!(
        json["data"]["issues"][0]["path"],
        "classes.Broken.superclasses[0]"
    );
}
