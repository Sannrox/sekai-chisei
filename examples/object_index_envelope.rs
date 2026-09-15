//! Measure the #876 object-index envelope. Not the product indexer.
//!
//! ```text
//! cargo run --release --example object_index_envelope -- --objects 10000000
//! ```

use sekai_chisei::sekai::object_index_envelope::{
    EnvelopeScale, create_schema, measure, open_spike_db, source_matches_projection,
};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let objects = parse_objects(env::args().skip(1)).unwrap_or(10_000_000);
    let scale = match EnvelopeScale::from_objects(objects) {
        Ok(scale) => scale,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let path = env::temp_dir().join(format!(
        "sekai-object-index-envelope-{}.sqlite",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    let mut conn = match open_spike_db(path.to_str().unwrap_or(":memory:")) {
        Ok(conn) => conn,
        Err(error) => {
            eprintln!("open: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = create_schema(&conn) {
        eprintln!("schema: {error}");
        return ExitCode::from(1);
    }
    let timings = match measure(&mut conn, scale) {
        Ok(timings) => timings,
        Err(error) => {
            eprintln!("measure: {error}");
            return ExitCode::from(1);
        }
    };
    let matched = source_matches_projection(&conn).unwrap_or(false);
    println!("objects={}", timings.objects);
    println!("customers={}", scale.customers);
    println!("orders={}", scale.orders);
    println!("shipments={}", scale.shipments);
    println!(
        "initial_materialize_ms={}",
        timings.initial_materialize.as_millis()
    );
    println!("incremental_1k_ms={}", timings.incremental_1k.as_millis());
    println!("filter_p95_ms={}", timings.filter_p95.as_millis());
    println!("aggregate_p95_ms={}", timings.aggregate_p95.as_millis());
    println!("two_hop_p95_ms={}", timings.two_hop_p95.as_millis());
    println!("rebuild_ms={}", timings.rebuild.as_millis());
    println!("visible_shipments={}", timings.visible_shipments);
    println!("hidden_shipments={}", timings.hidden_shipments);
    println!("source_matches_projection={matched}");
    let _ = fs::remove_file(&path);
    if matched {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn parse_objects(mut args: impl Iterator<Item = String>) -> Option<i64> {
    while let Some(arg) = args.next() {
        if arg == "--objects" {
            return args.next()?.parse().ok();
        }
    }
    None
}
