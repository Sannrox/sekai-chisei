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
    for command in [
        "export", "explain", "query", "validate", "import", "entity", "relation",
    ] {
        assert!(help.contains(command), "help is missing {command}");
        assert!(
            EMBEDDED_SKILL.contains(command),
            "skill is missing {command}"
        );
    }
}

#[test]
fn entity_and_relation_reads_have_stable_json() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("knowledge.db");
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codebase.json");
    let database = database.to_str().unwrap();
    assert!(sekai(&["--db", database, "init"]).status.success());
    assert!(
        sekai(&["--db", database, "import", fixture])
            .status
            .success()
    );

    let entities = sekai(&["--db", database, "--json", "entity", "list"]);
    let entities: Value = serde_json::from_slice(&entities.stdout).unwrap();
    assert_eq!(entities["command"], "entity.list");
    assert_eq!(entities["data"][0]["name"], "Api");

    let entity = sekai(&["--db", database, "--json", "entity", "show", "Api"]);
    let entity: Value = serde_json::from_slice(&entity.stdout).unwrap();
    assert_eq!(entity["command"], "entity.show");
    assert_eq!(entity["data"]["class"]["name"], "Api");

    let relations = sekai(&["--db", database, "--json", "relation", "list"]);
    let relations: Value = serde_json::from_slice(&relations.stdout).unwrap();
    assert_eq!(relations["command"], "relation.list");
    assert_eq!(relations["data"][0]["name"], "depends_on");
}

#[test]
fn skill_install_is_idempotent_and_protects_user_edits() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("nested/skill");
    let target_arg = target.to_str().unwrap();

    let path = sekai(&["skill", "path", "--path", target_arg]);
    assert!(path.status.success());
    assert_eq!(String::from_utf8(path.stdout).unwrap().trim(), target_arg);
    assert_eq!(
        sekai(&["skill", "path", "--path", target_arg, "--uninstall"])
            .status
            .code(),
        Some(2)
    );

    let installed = sekai(&["skill", "install", "--path", target_arg]);
    assert!(installed.status.success());
    let skill_file = target.join("SKILL.md");
    assert_eq!(fs::read_to_string(&skill_file).unwrap(), EMBEDDED_SKILL);
    assert_eq!(
        sekai(&["skill", "install", "--path", target_arg])
            .status
            .code(),
        Some(10)
    );

    fs::write(&skill_file, format!("{EMBEDDED_SKILL}\n# user changes\n")).unwrap();
    assert_eq!(
        sekai(&["skill", "install", "--path", target_arg])
            .status
            .code(),
        Some(11)
    );
    assert!(
        fs::read_to_string(&skill_file)
            .unwrap()
            .contains("# user changes")
    );
    assert!(
        sekai(&["skill", "install", "--path", target_arg, "--force"])
            .status
            .success()
    );
    assert_eq!(
        sekai(&["skill", "install", "--path", target_arg, "--uninstall"])
            .status
            .code(),
        Some(0)
    );
    assert!(!skill_file.exists());

    fs::write(&skill_file, "unrelated file\n").unwrap();
    assert_eq!(
        sekai(&["skill", "install", "--path", target_arg, "--force"])
            .status
            .code(),
        Some(11)
    );
    assert_eq!(fs::read_to_string(&skill_file).unwrap(), "unrelated file\n");
    assert_eq!(
        sekai(&[
            "skill",
            "install",
            "--path",
            target_arg,
            "--force",
            "--uninstall",
        ])
        .status
        .code(),
        Some(2)
    );
    assert_eq!(fs::read_to_string(&skill_file).unwrap(), "unrelated file\n");
}

#[test]
fn malformed_entity_command_fails_before_database_access() {
    let output = sekai(&[
        "--db",
        "/definitely/missing/knowledge.db",
        "entity",
        "bogus",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}

#[cfg(unix)]
#[test]
fn skill_install_refuses_symlink_targets() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("skill");
    fs::create_dir(&target).unwrap();
    let referent = directory.path().join("outside.md");
    fs::write(&referent, "outside\n").unwrap();
    symlink(&referent, target.join("SKILL.md")).unwrap();

    assert_eq!(
        sekai(&[
            "skill",
            "install",
            "--path",
            target.to_str().unwrap(),
            "--force",
        ])
        .status
        .code(),
        Some(11)
    );
    assert_eq!(fs::read_to_string(referent).unwrap(), "outside\n");
}

#[cfg(unix)]
#[test]
fn skill_install_handles_read_only_existing_files() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("skill");
    let target_arg = target.to_str().unwrap();
    assert!(
        sekai(&["skill", "install", "--path", target_arg])
            .status
            .success()
    );
    let skill_file = target.join("SKILL.md");
    fs::set_permissions(&skill_file, fs::Permissions::from_mode(0o444)).unwrap();
    assert_eq!(
        sekai(&["skill", "install", "--path", target_arg])
            .status
            .code(),
        Some(10)
    );

    fs::set_permissions(&skill_file, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&skill_file, format!("{EMBEDDED_SKILL}\n# modified\n")).unwrap();
    fs::set_permissions(&skill_file, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(
        sekai(&["skill", "install", "--path", target_arg, "--force"])
            .status
            .success()
    );
    assert_eq!(fs::read_to_string(skill_file).unwrap(), EMBEDDED_SKILL);
}

#[test]
fn skill_uninstall_preserves_unrecognized_directories() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("skill");
    let skill_path = target.join("SKILL.md");
    fs::create_dir_all(skill_path.join("nested")).unwrap();

    for extra in [None, Some("--force")] {
        let mut arguments = vec!["skill", "install", "--path", target.to_str().unwrap()];
        if let Some(extra) = extra {
            arguments.push(extra);
        }
        assert_eq!(sekai(&arguments).status.code(), Some(11));
        assert!(skill_path.join("nested").is_dir());
    }

    assert_eq!(
        sekai(&[
            "skill",
            "install",
            "--path",
            target.to_str().unwrap(),
            "--uninstall",
        ])
        .status
        .code(),
        Some(11)
    );
    assert!(skill_path.join("nested").is_dir());
}

#[test]
fn installed_skill_and_json_query_complete_agent_scenario() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("knowledge.db");
    let skill_directory = directory.path().join("agent-skill");
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codebase.json");
    assert!(
        sekai(&[
            "skill",
            "install",
            "--path",
            skill_directory.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(skill_directory.join("SKILL.md").exists());
    assert!(
        sekai(&["--db", database.to_str().unwrap(), "init"])
            .status
            .success()
    );
    assert!(
        sekai(&["--db", database.to_str().unwrap(), "import", fixture])
            .status
            .success()
    );
    let answer = sekai(&[
        "--db",
        database.to_str().unwrap(),
        "--json",
        "query",
        "Client",
        "--direction",
        "outbound",
        "--depth",
        "2",
    ]);
    let answer: Value = serde_json::from_slice(&answer.stdout).unwrap();
    assert_eq!(answer["data"]["classes"][0]["name"], "Api");
    assert_eq!(answer["data"]["classes"][1]["name"], "Database");
}

#[test]
fn query_json_answers_bounded_structural_questions() {
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

    let outbound = sekai(&[
        "--db",
        database,
        "--json",
        "query",
        "Client",
        "--direction",
        "outbound",
        "--depth",
        "2",
    ]);
    assert!(outbound.status.success());
    assert!(outbound.stderr.is_empty());
    let json: Value = serde_json::from_slice(&outbound.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "query");
    assert_eq!(json["data"]["start"], "Client");
    assert_eq!(json["data"]["options"]["direction"], "outbound");
    assert_eq!(json["data"]["options"]["relation"], Value::Null);
    assert_eq!(json["data"]["options"]["depth"], 2);
    assert_eq!(
        json["data"]["classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|class| class["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Api", "Database"]
    );
    assert_eq!(
        json["data"]["relations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|relation| relation["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["depends_on", "serves"]
    );

    let inbound = sekai(&[
        "--db",
        database,
        "--json",
        "query",
        "Api",
        "--direction",
        "inbound",
    ]);
    let inbound: Value = serde_json::from_slice(&inbound.stdout).unwrap();
    assert_eq!(inbound["data"]["classes"][0]["name"], "Client");

    let both = sekai(&["--db", database, "--json", "query", "Api"]);
    let both: Value = serde_json::from_slice(&both.stdout).unwrap();
    assert_eq!(both["data"]["options"]["direction"], "both");
    assert_eq!(both["data"]["options"]["depth"], 1);
    assert_eq!(
        both["data"]["classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|class| class["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["Client", "Database"]
    );

    let filtered = sekai(&[
        "--db",
        database,
        "--json",
        "query",
        "Api",
        "--relation",
        "serves",
    ]);
    let filtered: Value = serde_json::from_slice(&filtered.stdout).unwrap();
    assert_eq!(filtered["data"]["classes"][0]["name"], "Client");
    assert_eq!(filtered["data"]["relations"][0]["name"], "serves");

    let empty = sekai(&[
        "--db",
        database,
        "--json",
        "query",
        "Database",
        "--direction",
        "outbound",
    ]);
    assert!(empty.status.success());
    let empty: Value = serde_json::from_slice(&empty.stdout).unwrap();
    assert_eq!(empty["data"]["classes"], serde_json::json!([]));
    assert_eq!(empty["data"]["relations"], serde_json::json!([]));
}

#[test]
fn query_depth_and_usage_failures_have_stable_exit_codes() {
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

    for invalid in [
        vec!["--db", database, "query", "Api", "--depth", "33"],
        vec!["--db", database, "query", "Api", "--depth", "nope"],
        vec!["--db", database, "query", "Api", "--direction", "sideways"],
        vec!["--db", database, "query"],
        vec!["--db", database, "explain", "Api", "--depth", "1"],
    ] {
        let output = sekai(&invalid);
        assert_eq!(output.status.code(), Some(2), "arguments: {invalid:?}");
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }

    let zero = sekai(&["--db", database, "--json", "query", "Api", "--depth", "0"]);
    assert!(zero.status.success());
    let zero: Value = serde_json::from_slice(&zero.stdout).unwrap();
    assert_eq!(zero["data"]["classes"], serde_json::json!([]));
    assert_eq!(zero["data"]["relations"], serde_json::json!([]));
    assert_eq!(
        sekai(&["--db", database, "query", "Missing"]).status.code(),
        Some(3)
    );
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

#[test]
fn database_resolution_prefers_sekai_db_env_over_user_default() {
    let directory = tempfile::tempdir().unwrap();
    let env_db = directory.path().join("from_env.db");
    let fake_home = directory.path().join("home");

    // Create the user-level default with an empty ontology
    #[cfg(target_os = "macos")]
    let user_db = fake_home.join("Library/Application Support/sekai/knowledge.db");
    #[cfg(not(target_os = "macos"))]
    let user_db = fake_home.join(".local/share/sekai/knowledge.db");

    fs::create_dir_all(user_db.parent().unwrap()).unwrap();
    assert!(
        sekai(&["--db", user_db.to_str().unwrap(), "init"])
            .status
            .success()
    );

    // Initialize env db and import fixture (gives it classes)
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codebase.json");
    assert!(
        sekai(&["--db", env_db.to_str().unwrap(), "init"])
            .status
            .success()
    );
    assert!(
        sekai(&["--db", env_db.to_str().unwrap(), "import", fixture])
            .status
            .success()
    );

    // With SEKAI_DB set and a user-level default existing, SEKAI_DB should win
    let work_dir = directory.path().join("work");
    fs::create_dir(&work_dir).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sekai"));
    cmd.args(["--json", "entity", "list"])
        .env("SEKAI_DB", env_db.to_str().unwrap())
        .env("HOME", fake_home.to_str().unwrap())
        .current_dir(&work_dir);

    #[cfg(not(target_os = "macos"))]
    cmd.env_remove("XDG_DATA_HOME");

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    // The env db has classes from the fixture; user-level default is empty
    assert!(!json["data"].as_array().unwrap().is_empty());
}

#[test]
fn database_resolution_falls_back_to_cwd_knowledge_db() {
    let directory = tempfile::tempdir().unwrap();
    let cwd_db = directory.path().join("knowledge.db");

    // Initialize CWD knowledge.db
    assert!(
        sekai(&["--db", cwd_db.to_str().unwrap(), "init"])
            .status
            .success()
    );

    // Without SEKAI_DB or --db, should use knowledge.db in CWD
    // Point HOME at an empty dir so user-level default cannot interfere
    let empty_home = directory.path().join("empty_home");
    fs::create_dir(&empty_home).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sekai"));
    cmd.args(["--json", "validate"])
        .env_remove("SEKAI_DB")
        .env("HOME", empty_home.to_str().unwrap())
        .current_dir(directory.path());

    #[cfg(not(target_os = "macos"))]
    cmd.env_remove("XDG_DATA_HOME");

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["data"]["valid"], true);
}

#[test]
fn database_resolution_uses_user_default_when_file_exists() {
    // This test simulates the user-level default by setting HOME to a temp dir
    // and creating the expected platform path.
    let directory = tempfile::tempdir().unwrap();
    let fake_home = directory.path().join("home");

    #[cfg(target_os = "macos")]
    let user_db = fake_home.join("Library/Application Support/sekai/knowledge.db");
    #[cfg(not(target_os = "macos"))]
    let user_db = fake_home.join(".local/share/sekai/knowledge.db");

    fs::create_dir_all(user_db.parent().unwrap()).unwrap();

    // Initialize the user-level database and import fixture
    assert!(
        sekai(&["--db", user_db.to_str().unwrap(), "init"])
            .status
            .success()
    );
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codebase.json");
    assert!(
        sekai(&["--db", user_db.to_str().unwrap(), "import", fixture])
            .status
            .success()
    );

    // Run from a directory that does NOT have knowledge.db, with HOME pointing
    // to our fake home and SEKAI_DB unset.
    let work_dir = directory.path().join("work");
    fs::create_dir(&work_dir).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sekai"));
    cmd.args(["--json", "entity", "list"])
        .env("HOME", fake_home.to_str().unwrap())
        .env_remove("SEKAI_DB")
        .current_dir(&work_dir);

    // On non-macOS, also clear XDG_DATA_HOME so the fallback uses HOME
    #[cfg(not(target_os = "macos"))]
    cmd.env_remove("XDG_DATA_HOME");

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!json["data"].as_array().unwrap().is_empty());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn database_resolution_respects_xdg_data_home() {
    let directory = tempfile::tempdir().unwrap();
    let xdg_dir = directory.path().join("custom_xdg");
    let user_db = xdg_dir.join("sekai/knowledge.db");

    fs::create_dir_all(user_db.parent().unwrap()).unwrap();

    // Initialize and populate
    assert!(
        sekai(&["--db", user_db.to_str().unwrap(), "init"])
            .status
            .success()
    );
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codebase.json");
    assert!(
        sekai(&["--db", user_db.to_str().unwrap(), "import", fixture])
            .status
            .success()
    );

    // Run with XDG_DATA_HOME set to our custom location
    let work_dir = directory.path().join("work");
    fs::create_dir(&work_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sekai"))
        .args(["--json", "entity", "list"])
        .env("XDG_DATA_HOME", xdg_dir.to_str().unwrap())
        .env_remove("SEKAI_DB")
        .current_dir(&work_dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!json["data"].as_array().unwrap().is_empty());
}

#[test]
fn database_resolution_skips_user_default_when_file_missing() {
    // When user-level default does not exist, should fall back to CWD knowledge.db
    let directory = tempfile::tempdir().unwrap();
    let fake_home = directory.path().join("empty_home");
    fs::create_dir(&fake_home).unwrap();

    let work_dir = directory.path().join("work");
    fs::create_dir(&work_dir).unwrap();

    // Create a CWD knowledge.db
    let cwd_db = work_dir.join("knowledge.db");
    assert!(
        sekai(&["--db", cwd_db.to_str().unwrap(), "init"])
            .status
            .success()
    );

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sekai"));
    cmd.args(["--json", "validate"])
        .env("HOME", fake_home.to_str().unwrap())
        .env_remove("SEKAI_DB")
        .current_dir(&work_dir);

    #[cfg(not(target_os = "macos"))]
    cmd.env_remove("XDG_DATA_HOME");

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["data"]["valid"], true);
}
