//! `sekaictl admin access unmarked apply` writes objects, so it opens the
//! store through the relocate writer fence and refuses a split pair whose
//! generations disagree (#2897). The read-only `list` keeps opening the
//! store as is.

use sekai_chisei::combined_stores::CombinedStoreSources;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::domain::Object;
use sekai_chisei::runtime_backend::BackendIdentity;
use sekai_chisei::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
use sekai_chisei::store_relocate::{align_split_generations, write_runtime_generation};
use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Output};

fn unmarked(sekai: &Path, chisei: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sekaictl"))
        .args(["admin", "access", "unmarked"])
        .args(args)
        .env("SEKAI_DB_PATH", sekai)
        .env("CHISEI_DB_PATH", chisei)
        .env("SEKAI_DB_BACKEND", "sqlite")
        .env_remove("SEKAI_DATABASE_URL")
        .env_remove("CHISEI_DATABASE_URL")
        .env_remove("SEKAI_DATA_DIR")
        .env_remove("SEKAI_STORE_PEER")
        .output()
        .expect("run sekaictl")
}

fn create_unmarked(store: &SekaiStore, id: &str) {
    store
        .create_object(&Object {
            id: id.into(),
            kind: "artifact".into(),
            name: id.into(),
            namespace: id.into(),
            external_id: format!("artifact:{id}"),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
}

fn marking(store: &SekaiStore, id: &str) -> Option<String> {
    store
        .get_object(id)
        .unwrap()
        .unwrap()
        .properties
        .get(OBJECT_CLASSIFICATION_PROPERTY)
        .cloned()
}

#[test]
fn unmarked_apply_refuses_a_fenced_pair_and_list_still_reads_it() {
    let dir = tempfile::tempdir().unwrap();
    let sekai = dir.path().join("sekai.db");
    let chisei = dir.path().join("chisei.db");
    let layout = CombinedStoreSources {
        backend: Some(BackendIdentity::Sqlite),
        default_sqlite_path: sekai.to_str().unwrap().into(),
        sekai_sqlite_path: Some(sekai.to_str().unwrap().into()),
        chisei_sqlite_path: Some(chisei.to_str().unwrap().into()),
        postgres_max_connections: 16,
        ..CombinedStoreSources::default()
    }
    .open()
    .unwrap();
    align_split_generations(&layout).unwrap();
    let store = layout.handles().0;
    create_unmarked(&store, "before");
    create_unmarked(&store, "after");

    let unfenced = unmarked(
        &sekai,
        &chisei,
        &["apply", "--namespace", "before", "--marking", "internal"],
    );
    assert!(
        unfenced.status.success(),
        "{}",
        String::from_utf8_lossy(&unfenced.stderr)
    );
    assert_eq!(marking(&store, "before").as_deref(), Some("internal"));

    // A one-sided restore leaves the Sekai store on another generation.
    write_runtime_generation(&layout.sekai_runtime(), 9).unwrap();
    let fenced = unmarked(
        &sekai,
        &chisei,
        &["apply", "--namespace", "after", "--marking", "internal"],
    );
    let stderr = String::from_utf8_lossy(&fenced.stderr);
    assert!(!fenced.status.success(), "{stderr}");
    assert!(stderr.contains("restamp"), "{stderr}");
    assert_eq!(marking(&store, "after"), None);

    let listed = unmarked(&sekai, &chisei, &["list", "--namespace", "after"]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("\"after\""));
}
