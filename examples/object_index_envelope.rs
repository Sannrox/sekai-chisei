//! Measure the #876 object-index envelope. Not the product indexer.
//!
//! ```text
//! cargo run --release --example object_index_envelope -- --objects 10000000
//! ```

use sekai_chisei::sekai::object_index_envelope::{
    EnvelopeScale, create_schema, materialize_two_hop_projection, measure, open_spike_db,
    source_matches_projection, two_hop_customer_count, two_hop_hash_join, two_hop_nested_loop,
    two_hop_projection_count,
};
use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::Instant;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let objects = parse_flag(&args, "--objects")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000_000);
    let plan = parse_flag(&args, "--plan").unwrap_or_else(|| "sql-join".into());
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
    if plan == "sql-join" {
        let timings = match measure(&mut conn, scale) {
            Ok(timings) => timings,
            Err(error) => {
                eprintln!("measure: {error}");
                return ExitCode::from(1);
            }
        };
        let matched = source_matches_projection(&conn).unwrap_or(false);
        println!("plan=sql-join");
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
        return if matched {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    if let Err(error) = sekai_chisei::sekai::object_index_envelope::load_source(&mut conn, scale) {
        eprintln!("load: {error}");
        return ExitCode::from(1);
    }
    if let Err(error) = sekai_chisei::sekai::object_index_envelope::materialize(&conn) {
        eprintln!("materialize: {error}");
        return ExitCode::from(1);
    }
    let samples = 8usize;
    let mut times = Vec::new();
    let mut last = 0i64;
    for _ in 0..samples {
        let started = Instant::now();
        let count = match plan.as_str() {
            "hash-join" => two_hop_hash_join(&conn),
            "nested-loop" => two_hop_nested_loop(&conn),
            "sql-join-only" => two_hop_customer_count(&conn),
            "compare" => {
                let sql = sample_p95(8, || two_hop_customer_count(&conn));
                let hashed = sample_p95(8, || two_hop_hash_join(&conn));
                let built = Instant::now();
                if let Err(error) = materialize_two_hop_projection(&conn) {
                    eprintln!("hop projection: {error}");
                    return ExitCode::from(1);
                }
                let hop_build_ms = built.elapsed().as_millis();
                let projected = sample_p95(8, || two_hop_projection_count(&conn));
                match (sql, hashed, projected) {
                    (
                        Ok((sql_p95, sql_count)),
                        Ok((hash_p95, hash_count)),
                        Ok((proj_p95, proj_count)),
                    ) => {
                        println!("plan=compare");
                        println!("objects={}", scale.objects());
                        println!("sql_join_p95_ms={}", sql_p95.as_millis());
                        println!("hash_join_p95_ms={}", hash_p95.as_millis());
                        println!("hop_projection_build_ms={hop_build_ms}");
                        println!("hop_projection_query_p95_ms={}", proj_p95.as_millis());
                        println!("sql_join_count={sql_count}");
                        println!("hash_join_count={hash_count}");
                        println!("hop_projection_count={proj_count}");
                        println!(
                            "counts_match={}",
                            sql_count == hash_count && sql_count == proj_count
                        );
                        let _ = fs::remove_file(&path);
                        return if sql_count == hash_count && sql_count == proj_count {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::from(1)
                        };
                    }
                    (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                        eprintln!("two-hop: {error}");
                        return ExitCode::from(1);
                    }
                }
            }
            other => {
                eprintln!("unknown --plan {other}");
                return ExitCode::from(2);
            }
        };
        match count {
            Ok(value) => last = value,
            Err(error) => {
                eprintln!("two-hop: {error}");
                return ExitCode::from(1);
            }
        }
        times.push(started.elapsed());
    }
    times.sort();
    let idx = ((times.len() as f64) * 0.95).ceil() as usize;
    let p95 = times[idx.saturating_sub(1).min(times.len() - 1)];
    let expected = two_hop_customer_count(&conn).unwrap_or(-1);
    println!("plan={plan}");
    println!("objects={}", scale.objects());
    println!("customers={}", scale.customers);
    println!("orders={}", scale.orders);
    println!("shipments={}", scale.shipments);
    println!("two_hop_p95_ms={}", p95.as_millis());
    println!("two_hop_count={last}");
    println!("sql_join_count={expected}");
    println!("counts_match={}", last == expected);
    let _ = fs::remove_file(&path);
    if last == expected {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn sample_p95<T: Copy, E>(
    samples: usize,
    mut f: impl FnMut() -> Result<T, E>,
) -> Result<(std::time::Duration, T), E> {
    let mut times = Vec::with_capacity(samples);
    let mut last = None;
    for _ in 0..samples {
        let started = Instant::now();
        last = Some(f()?);
        times.push(started.elapsed());
    }
    times.sort();
    let idx = ((times.len() as f64) * 0.95).ceil() as usize;
    Ok((
        times[idx.saturating_sub(1).min(times.len() - 1)],
        last.expect("sampled"),
    ))
}

fn parse_flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find_map(|pair| {
        if pair[0] == name {
            Some(pair[1].clone())
        } else {
            None
        }
    })
}
