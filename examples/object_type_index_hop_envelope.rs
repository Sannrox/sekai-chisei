//! Measure two-hop on the #877 product membership projection.
//!
//! Nested-loop matches `EvaluateObjectSet` hops. Hash-join is the #889
//! throwaway candidate. Not a shipped engine pick.
//!
//! ```text
//! cargo run --release --example object_type_index_hop_envelope -- --objects 100000
//! ```

use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset, RowQuery};
use sekai_chisei::sekai::object_index_envelope::EnvelopeScale;
use sekai_chisei::sekai::object_type_index::{
    CONTRACT_VERSION, ObjectTypeDatasource, ObjectTypeIndexMember,
};
use std::collections::{HashMap, HashSet};
use std::env;
use std::process::ExitCode;
use std::time::Instant;

fn main() -> ExitCode {
    let objects = parse_objects(env::args().skip(1)).unwrap_or(100_000);
    let scale = match EnvelopeScale::from_objects(objects) {
        Ok(scale) => scale,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let db = match SekaiDb::new(":memory:") {
        Ok(db) => db,
        Err(error) => {
            eprintln!("open: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = seed(&db, scale) {
        eprintln!("seed: {error}");
        return ExitCode::from(1);
    }
    let load_started = Instant::now();
    let customers = match db.list_visible_index_members("sales", "Customer", &RowQuery::default()) {
        Ok(members) => members,
        Err(error) => {
            eprintln!("customers: {error}");
            return ExitCode::from(1);
        }
    };
    let orders = match db.list_visible_index_members("sales", "Order", &RowQuery::default()) {
        Ok(members) => members,
        Err(error) => {
            eprintln!("orders: {error}");
            return ExitCode::from(1);
        }
    };
    let shipments = match db.list_visible_index_members("sales", "Shipment", &RowQuery::default()) {
        Ok(members) => members,
        Err(error) => {
            eprintln!("shipments: {error}");
            return ExitCode::from(1);
        }
    };
    let load_ms = load_started.elapsed().as_millis();
    let nested = time_p95(8, || nested_two_hop(&customers, &orders, &shipments));
    let product = time_p95(8, || {
        nested_two_hop_all_paths(&customers, &orders, &shipments)
    });
    let hashed = time_p95(8, || hash_two_hop(&customers, &orders, &shipments));
    println!("objects={objects}");
    println!("customers={}", customers.len());
    println!("orders={}", orders.len());
    println!("shipments={}", shipments.len());
    println!("index_load_ms={load_ms}");
    println!("nested_loop_distinct_p95_ms={}", nested.0.as_millis());
    println!("nested_loop_distinct_count={}", nested.1);
    println!("product_all_paths_p95_ms={}", product.0.as_millis());
    println!("product_all_paths_count={}", product.1);
    println!("hash_join_p95_ms={}", hashed.0.as_millis());
    println!("hash_join_count={}", hashed.1);
    println!("distinct_counts_match={}", nested.1 == hashed.1);
    if nested.1 == hashed.1 && nested.1 > 0 && product.1 > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn seed(db: &SekaiDb, scale: EnvelopeScale) -> Result<(), String> {
    let digest = format!("sha256:{}", "a".repeat(64));
    create_kind(
        db,
        "ds-customers",
        "Customer",
        &digest,
        "customer_id",
        &[("customer_id", "customer_id"), ("region", "region")],
        scale.customers,
        |id| {
            HashMap::from([
                ("customer_id".into(), format!("c{id}")),
                ("region".into(), ["eu", "us", "ap"][id as usize % 3].into()),
                (
                    "hidden".into(),
                    if id % 100 == 0 { "1" } else { "0" }.into(),
                ),
            ])
        },
    )?;
    create_kind(
        db,
        "ds-orders",
        "Order",
        &digest,
        "order_id",
        &[
            ("order_id", "order_id"),
            ("customer_id", "customer_id"),
            ("amount", "amount"),
        ],
        scale.orders,
        |id| {
            HashMap::from([
                ("order_id".into(), format!("o{id}")),
                ("customer_id".into(), format!("c{}", id % scale.customers)),
                ("amount".into(), format!("{}", (id % 100) + 1)),
                (
                    "hidden".into(),
                    if id % 100 == 0 { "1" } else { "0" }.into(),
                ),
            ])
        },
    )?;
    create_kind(
        db,
        "ds-shipments",
        "Shipment",
        &digest,
        "shipment_id",
        &[
            ("shipment_id", "shipment_id"),
            ("order_id", "order_id"),
            ("amount", "amount"),
        ],
        scale.shipments,
        |id| {
            HashMap::from([
                ("shipment_id".into(), format!("s{id}")),
                ("order_id".into(), format!("o{}", id % scale.orders)),
                ("amount".into(), format!("{}", (id % 50) + 1)),
                (
                    "hidden".into(),
                    if id % 100 == 0 { "1" } else { "0" }.into(),
                ),
            ])
        },
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_kind(
    db: &SekaiDb,
    dataset_id: &str,
    kind: &str,
    digest: &str,
    key_column: &str,
    mapping: &[(&str, &str)],
    rows: i64,
    row: impl Fn(i64) -> HashMap<String, String>,
) -> Result<(), String> {
    let columns = mapping
        .iter()
        .map(|(name, _)| ColumnDef {
            name: (*name).into(),
            col_type: "string".into(),
            classification: "public".into(),
        })
        .chain([ColumnDef {
            name: "hidden".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }])
        .collect();
    db.create_dataset(&Dataset {
        id: dataset_id.into(),
        name: kind.to_ascii_lowercase(),
        columns,
        object_id: String::new(),
        created: 1,
    })?;
    let mut batch = Vec::with_capacity(1_000);
    for id in 0..rows {
        batch.push(row(id));
        if batch.len() == 1_000 {
            db.append_rows(dataset_id, &batch)?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        db.append_rows(dataset_id, &batch)?;
    }
    db.register_object_type_datasource(
        &ObjectTypeDatasource {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "sales".into(),
            kind: kind.into(),
            definition_digest: digest.into(),
            dataset_id: dataset_id.into(),
            key_column: key_column.into(),
            property_mapping: mapping
                .iter()
                .map(|(property, column)| ((*property).into(), (*column).into()))
                .collect(),
            hidden_column: "hidden".into(),
            edits_only: false,
        },
        10,
    )?;
    db.apply_object_type_index("sales", kind, true, 20)?;
    Ok(())
}

fn nested_two_hop(
    customers: &[ObjectTypeIndexMember],
    orders: &[ObjectTypeIndexMember],
    shipments: &[ObjectTypeIndexMember],
) -> usize {
    let mut paths: Vec<(&ObjectTypeIndexMember, &ObjectTypeIndexMember)> = Vec::new();
    for customer in customers {
        for order in orders {
            if join_matches(order, "customer_id", customer) {
                paths.push((customer, order));
            }
        }
    }
    let mut counted = HashSet::new();
    for (customer, order) in paths {
        for shipment in shipments {
            if join_matches(shipment, "order_id", order) {
                counted.insert(customer.source_key.as_str());
                break;
            }
        }
    }
    counted.len()
}

fn nested_two_hop_all_paths(
    customers: &[ObjectTypeIndexMember],
    orders: &[ObjectTypeIndexMember],
    shipments: &[ObjectTypeIndexMember],
) -> usize {
    let mut paths: Vec<&ObjectTypeIndexMember> = Vec::new();
    for customer in customers {
        for order in orders {
            if join_matches(order, "customer_id", customer) {
                paths.push(order);
            }
        }
    }
    let mut total = 0usize;
    for order in paths {
        for shipment in shipments {
            if join_matches(shipment, "order_id", order) {
                total += 1;
            }
        }
    }
    total
}

fn hash_two_hop(
    customers: &[ObjectTypeIndexMember],
    orders: &[ObjectTypeIndexMember],
    shipments: &[ObjectTypeIndexMember],
) -> usize {
    let mut orders_by_customer: HashMap<&str, Vec<&ObjectTypeIndexMember>> = HashMap::new();
    for order in orders {
        if let Some(customer_id) = order.properties.get("customer_id") {
            orders_by_customer
                .entry(customer_id.as_str())
                .or_default()
                .push(order);
        }
    }
    let mut orders_with_shipment = HashSet::new();
    for shipment in shipments {
        if let Some(order_id) = shipment.properties.get("order_id") {
            orders_with_shipment.insert(order_id.as_str());
        }
    }
    customers
        .iter()
        .filter(|customer| {
            orders_by_customer
                .get(customer.source_key.as_str())
                .is_some_and(|orders| {
                    orders
                        .iter()
                        .any(|order| orders_with_shipment.contains(order.source_key.as_str()))
                })
        })
        .count()
}

fn join_matches(
    child: &ObjectTypeIndexMember,
    join_property: &str,
    parent: &ObjectTypeIndexMember,
) -> bool {
    child
        .properties
        .get(join_property)
        .is_some_and(|value| value == &parent.source_key || value == &parent.object_id)
}

fn time_p95<T: Copy>(samples: usize, mut f: impl FnMut() -> T) -> (std::time::Duration, T) {
    let mut times = Vec::with_capacity(samples);
    let mut last = None;
    for _ in 0..samples {
        let started = Instant::now();
        last = Some(f());
        times.push(started.elapsed());
    }
    times.sort();
    let idx = ((times.len() as f64) * 0.95).ceil() as usize;
    (
        times[idx.saturating_sub(1).min(times.len() - 1)],
        last.expect("sampled"),
    )
}

fn parse_objects(mut args: impl Iterator<Item = String>) -> Option<i64> {
    while let Some(arg) = args.next() {
        if arg == "--objects" {
            return args.next()?.parse().ok();
        }
    }
    None
}
