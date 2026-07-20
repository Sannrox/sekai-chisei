//! Overload, restart, and recovery behaviour.
//!
//! Issue #98 asks for load tests covering graceful overload, shutdown, restart,
//! and recovery, while its constraints exclude live providers, network access,
//! and unstable wall-clock thresholds from the deterministic suite. These
//! assert *behaviour* under contention and across a restart, never elapsed
//! time, so they do not flake on a loaded machine.
//!
//! Isolated in its own binary: the assertions read the process-global metrics
//! recorder, which a sibling test emitting the same series would disturb.

use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::Object;
use sekai_chisei::obs::signals;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn temp_db_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sekai-load-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("sekai.db")
}

fn object(id: &str) -> Object {
    Object {
        id: id.to_string(),
        kind: "load_probe".into(),
        name: id.to_string(),
        namespace: "load".into(),
        external_id: String::new(),
        properties: HashMap::from([("n".to_string(), id.to_string())]),
        created: 0,
        updated: 0,
    }
}

/// Far more concurrent writers than the pool has connections.
///
/// The pool caps at 16 for a persistent database, so this deliberately
/// oversubscribes it. Every writer must still complete: the contract under
/// overload is that callers queue, not that they fail.
#[test]
fn oversubscribed_writers_all_complete_without_deadlock() {
    sekai_chisei::obs::metrics::handle();

    let path = temp_db_path("overload");
    let _ = std::fs::remove_file(&path);
    let db = Arc::new(SekaiDb::new(path.to_str().expect("utf-8 path")).expect("open database"));

    const WRITERS: usize = 64;
    let completed = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|scope| {
        for index in 0..WRITERS {
            let db = Arc::clone(&db);
            let completed = Arc::clone(&completed);
            scope.spawn(move || {
                db.create_object(&object(&format!("overload-{index}")))
                    .expect("write under contention must succeed");
                completed.fetch_add(1, Ordering::Relaxed);
            });
        }
    });

    assert_eq!(
        completed.load(Ordering::Relaxed),
        WRITERS,
        "a writer was dropped under overload"
    );

    // Every one of those writers crossed the instrumented acquisition path.
    let rendered = sekai_chisei::obs::metrics::handle().render();
    assert!(
        rendered
            .lines()
            .any(|line| line.starts_with(signals::DB_WAIT)
                && line.contains(r#"wait_kind="connection_acquire""#)),
        "contention produced no db wait samples:\n{rendered}"
    );

    // Saturation is a ratio, and must remain one under contention.
    if let Some(line) = rendered
        .lines()
        .find(|line| line.starts_with(signals::SATURATION_RATIO) && line.contains("persistence"))
    {
        let value: f64 = line
            .rsplit(' ')
            .next()
            .and_then(|v| v.parse().ok())
            .expect("numeric saturation");
        assert!(
            (0.0..=1.0).contains(&value),
            "saturation left the unit range under load: {line}"
        );
    }

    let _ = std::fs::remove_file(&path);
}

/// Data written before a restart must be readable after one.
///
/// Dropping the `SekaiDb` closes its pool, which is the durable-state half of
/// a process restart; reopening reruns every migration against a populated
/// database.
#[test]
fn state_survives_restart_and_migrations_are_idempotent() {
    let path = temp_db_path("restart");
    let _ = std::fs::remove_file(&path);
    let path_str = path.to_str().expect("utf-8 path").to_string();

    {
        let db = SekaiDb::new(&path_str).expect("first open");
        db.create_object(&object("survivor")).expect("seed write");
    } // pool closed

    {
        let db = SekaiDb::new(&path_str).expect("reopen after restart");
        let recovered = db
            .get_object("survivor")
            .expect("read after restart")
            .expect("object did not survive restart");
        assert_eq!(recovered.id, "survivor");

        // A third open re-runs migrations against state the previous two left.
        db.create_object(&object("post-restart"))
            .expect("write after restart");
    }

    {
        let db = SekaiDb::new(&path_str).expect("third open");
        assert!(
            db.get_object("survivor").expect("read").is_some(),
            "restart lost previously durable state"
        );
        assert!(
            db.get_object("post-restart").expect("read").is_some(),
            "restart lost state written after the first restart"
        );
    }

    let _ = std::fs::remove_file(&path);
}

/// A failed write must not leave the pool unusable for later callers.
#[test]
fn pool_recovers_after_a_rejected_write() {
    let path = temp_db_path("recovery");
    let _ = std::fs::remove_file(&path);
    let db = SekaiDb::new(path.to_str().expect("utf-8 path")).expect("open database");

    db.create_object(&object("first")).expect("initial write");

    // Same id twice: the second must be refused.
    let duplicate = db.create_object(&object("first"));
    assert!(duplicate.is_err(), "duplicate id was accepted");

    // The connection that served the failure must return to the pool usable.
    db.create_object(&object("after-failure"))
        .expect("pool unusable after a rejected write");
    assert!(
        db.get_object("after-failure").expect("read").is_some(),
        "write after recovery was not durable"
    );

    let _ = std::fs::remove_file(&path);
}
