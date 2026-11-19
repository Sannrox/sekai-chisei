//! Database signal wiring, isolated in its own test binary.
//!
//! The Prometheus recorder is process-global. In a shared binary a sibling test
//! that emits `sekai_db_wait_seconds` directly would satisfy these assertions
//! even with the production instrumentation deleted — that exact false pass was
//! observed before this file was split out. Cargo gives each integration test
//! its own process, so nothing here emits a signal except the code under test.

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::obs::signals;

fn scrape() -> String {
    sekai_chisei::obs::metrics::handle().render()
}

#[test]
fn connection_acquisition_emits_wait_and_pool_saturation() {
    sekai_chisei::obs::metrics::handle();

    // Nothing has touched the database yet, so neither family should exist.
    let before = scrape();
    assert!(
        !before.contains(signals::DB_WAIT),
        "db wait family present before any database use:\n{before}"
    );
    assert!(
        persistence_saturation(&before).is_none(),
        "persistence saturation present before any database use:\n{before}"
    );

    // Constructing the database runs migrations, each acquiring a pooled
    // connection through the instrumented chokepoint.
    let db = RuntimeDb::Sqlite(std::sync::Arc::new(
        SekaiDb::new(":memory:").expect("open in-memory database"),
    ));
    // Saturation is sampled at checkout, so the sample taken for this held
    // connection counts it as in use. Scrape before releasing it.
    let held = db.conn();
    let after = scrape();
    drop(held);
    drop(db);

    let waits = after
        .lines()
        .filter(|line| line.starts_with(signals::DB_WAIT))
        .filter(|line| line.contains(r#"wait_kind="connection_acquire""#))
        .count();
    assert!(
        waits > 0,
        "connection acquisition recorded no db wait samples:\n{after}"
    );

    let value = persistence_saturation(&after)
        .unwrap_or_else(|| panic!("no persistence saturation series:\n{after}"));
    assert!(
        value > 0.0 && value <= 1.0,
        "a checked-out connection must count toward saturation, got {value}:\n{after}"
    );
}

/// The persistence saturation gauge value, if the series exists.
fn persistence_saturation(rendered: &str) -> Option<f64> {
    let line = rendered.lines().find(|line| {
        line.starts_with(signals::SATURATION_RATIO) && line.contains(r#"subsystem="persistence""#)
    })?;
    Some(
        line.rsplit(' ')
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("non-numeric saturation: {line}")),
    )
}
