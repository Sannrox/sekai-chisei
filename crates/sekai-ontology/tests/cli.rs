use serde_json::Value;
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
