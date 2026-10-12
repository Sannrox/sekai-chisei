//! Join and aggregate two governed datasets through the analytical profile.
//!
//! Seeds customer and order datasets that back an object type, runs a SQL
//! transform, and prints the run receipt.

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset};
use sekai_chisei::sekai::governed_transform::{
    AnalyticalSpec, CONTRACT_VERSION, GovernedTransform, TransformInput,
};
use std::collections::HashMap;
use std::sync::Arc;

fn column(name: &str) -> ColumnDef {
    ColumnDef {
        name: name.into(),
        col_type: "string".into(),
        classification: "public".into(),
    }
}

fn dataset(id: &str, columns: &[&str], object_id: &str) -> Dataset {
    Dataset {
        id: id.into(),
        name: id.into(),
        columns: columns.iter().copied().map(column).collect(),
        object_id: object_id.into(),
        created: 1,
    }
}

fn object(id: &str) -> Object {
    Object {
        id: id.into(),
        kind: "dataset".into(),
        name: id.into(),
        namespace: "ops".into(),
        external_id: format!("dataset:{id}"),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    }
}

fn main() -> Result<(), String> {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:")?));
    for (id, object_id) in [
        ("customers", "obj-customers"),
        ("orders", "obj-orders"),
        ("region_totals", "obj-region-totals"),
    ] {
        db.create_object(&object(object_id))?;
        let columns = if id == "orders" {
            vec!["id", "customer_id", "amount"]
        } else if id == "customers" {
            vec!["id", "region"]
        } else {
            vec!["region", "orders", "total"]
        };
        db.create_dataset(&dataset(id, &columns, object_id))?;
    }
    db.append_rows(
        "customers",
        &[
            HashMap::from([("id".into(), "c1".into()), ("region".into(), "east".into())]),
            HashMap::from([("id".into(), "c2".into()), ("region".into(), "west".into())]),
        ],
    )?;
    db.append_rows(
        "orders",
        &[
            HashMap::from([
                ("id".into(), "o1".into()),
                ("customer_id".into(), "c1".into()),
                ("amount".into(), "10".into()),
            ]),
            HashMap::from([
                ("id".into(), "o2".into()),
                ("customer_id".into(), "c1".into()),
                ("amount".into(), "7".into()),
            ]),
            HashMap::from([
                ("id".into(), "o3".into()),
                ("customer_id".into(), "c2".into()),
                ("amount".into(), "4".into()),
            ]),
        ],
    )?;
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: "region-totals".into(),
        input_dataset_id: "customers".into(),
        output_dataset_id: "region_totals".into(),
        steps: Vec::new(),
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: Some(AnalyticalSpec {
            inputs: vec![
                TransformInput {
                    alias: "customers".into(),
                    dataset_id: "customers".into(),
                },
                TransformInput {
                    alias: "orders".into(),
                    dataset_id: "orders".into(),
                },
            ],
            sql: "SELECT c.region AS region, COUNT(*) AS orders, SUM(o.amount) AS total \
                  FROM orders o JOIN customers c ON o.customer_id = c.id GROUP BY c.region"
                .into(),
            memory_limit_bytes: 0,
            time_limit_ms: 0,
        }),
    };
    let prepared = transform.prepare().map_err(|error| error.message())?;
    db.put_governed_transform(&prepared, 10)?;
    let run = db.run_governed_transform("ops", "region-totals", false, 20)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "run_id": run.run_id,
            "rows_in": run.rows_in,
            "rows_out": run.rows_out,
            "definition_digest": run.definition_digest,
            "input_digest": run.input_digest,
            "lineage_parent": run.lineage_parent,
            "quarantined": run.quarantined,
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}
