//! SQLite/PostgreSQL conformance for append-only governed-subject provenance.

use base64::Engine as _;
use sekai_chisei::chisei::governed_subject_provenance::{
    ExportRecord, ProvenanceEnvelope, signing_key_from_hex,
};
use sekai_chisei::db::{postgres::PostgresDb, runtime_db::RuntimeDb, sekai::SekaiDb};
use std::sync::Arc;

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn record(binding: char, namespace: &str) -> ExportRecord {
    let key = signing_key_from_hex(&"09".repeat(32)).unwrap();
    ExportRecord {
        binding_digest: digest(binding),
        namespace: namespace.into(),
        envelope: ProvenanceEnvelope::issue(
            &key,
            "subject-1".into(),
            digest('1'),
            digest('2'),
            "operation-1".into(),
            1_000,
            2_000,
        )
        .unwrap(),
        public_key: base64::engine::general_purpose::STANDARD
            .encode(key.verifying_key().to_bytes()),
        created_at_ms: 1_000,
    }
}

fn exercise(db: &RuntimeDb, actor: &str, export_id: &str, namespace: &str) {
    let first = record('a', namespace);
    assert_eq!(
        db.put_governed_subject_provenance_export(actor, export_id, &first)
            .unwrap(),
        (first.clone(), true)
    );
    assert_eq!(
        db.put_governed_subject_provenance_export(actor, export_id, &first)
            .unwrap(),
        (first.clone(), false)
    );
    assert!(
        db.put_governed_subject_provenance_export(actor, export_id, &record('b', namespace))
            .unwrap_err()
            .contains("already bound")
    );
    assert_eq!(
        db.get_governed_subject_provenance_export(actor, export_id)
            .unwrap(),
        Some(first)
    );
    assert!(
        db.get_governed_subject_provenance_export("other", export_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn sqlite_provenance_export_conformance_and_restart() {
    let path = std::env::temp_dir().join(format!(
        "sekai-governed-subject-provenance-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let path = path.to_string_lossy().into_owned();
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&path).unwrap()));
    exercise(&db, "root", "export-sqlite", "sqlite-provenance");
    drop(db);
    let restarted = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(&path).unwrap()));
    assert!(
        restarted
            .get_governed_subject_provenance_export("root", "export-sqlite")
            .unwrap()
            .is_some()
    );
    std::fs::remove_file(path).ok();
}

fn postgres() -> RuntimeDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    };
    RuntimeDb::Postgres(Arc::new(db))
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_provenance_export_conformance_and_restart() {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let export_id = format!("export-{suffix}");
    let namespace = format!("postgres-provenance-{suffix}");
    exercise(&postgres(), "root", &export_id, &namespace);
    assert!(
        postgres()
            .get_governed_subject_provenance_export("root", &export_id)
            .unwrap()
            .is_some()
    );
}
