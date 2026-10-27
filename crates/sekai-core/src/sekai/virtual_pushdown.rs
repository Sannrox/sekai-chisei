//! Bounded virtual-table predicate pushdown (#689).
//!
//! A query compiles to a `sekai.virtual-pushdown/v1` plan. Eligible predicates
//! may push to the registered format adapter. Residual numeric predicates stay
//! local. Hidden or sensitive columns never push.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::sekai::dataset::RowFilter;
use crate::sekai::open_table::{FORMAT_ICEBERG, FORMAT_PARQUET, SNAPSHOT_CORRUPT};
use crate::shomei;

pub const PUSHDOWN_CONTRACT: &str = "sekai.virtual-pushdown/v1";
pub const EQUIVALENCE_FAILED: &str = "virtual pushdown result is not equivalent";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualPushdownPlan {
    pub contract_version: String,
    pub adapter: String,
    pub pushed_predicates: Vec<RowFilter>,
    pub residual_predicates: Vec<RowFilter>,
    pub pushed_columns: Vec<String>,
    pub local_digest: String,
    pub pushed_digest: String,
    pub equivalent: bool,
}

#[derive(Serialize)]
struct ResultPin<'a> {
    columns: &'a [String],
    rows: &'a [BTreeMap<String, String>],
}

pub fn classify_predicate(op: &str) -> Result<PredicateClass, String> {
    match op {
        "eq" | "neq" => Ok(PredicateClass::Pushed),
        "gt" | "gte" | "lt" | "lte" => Ok(PredicateClass::Residual),
        _ => Err("open table predicate is unsupported".into()),
    }
}

pub fn residual_column_is_numeric(col_type: &str) -> bool {
    matches!(col_type, "int" | "float")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateClass {
    Pushed,
    Residual,
}

pub fn split_predicates(filters: &[RowFilter]) -> Result<(Vec<RowFilter>, Vec<RowFilter>), String> {
    let mut pushed = Vec::new();
    let mut residual = Vec::new();
    for filter in filters {
        match classify_predicate(&filter.op)? {
            PredicateClass::Pushed => pushed.push(filter.clone()),
            PredicateClass::Residual => residual.push(filter.clone()),
        }
    }
    Ok((pushed, residual))
}

pub fn evaluate_local(
    rows: &[BTreeMap<String, String>],
    filters: &[RowFilter],
    columns: &[String],
) -> Result<Vec<BTreeMap<String, String>>, String> {
    project_matching(rows, filters, columns, true)
}

pub fn evaluate_adapter(
    format: &str,
    rows: &[BTreeMap<String, String>],
    pushed: &[RowFilter],
    residual: &[RowFilter],
    columns: &[String],
) -> Result<Vec<BTreeMap<String, String>>, String> {
    if !matches!(format, FORMAT_ICEBERG | FORMAT_PARQUET) {
        return Err("open table revision is unsupported".into());
    }
    for filter in pushed {
        if classify_predicate(&filter.op)? != PredicateClass::Pushed {
            return Err("open table predicate is unsupported".into());
        }
    }
    let after_push = project_matching(rows, pushed, &[], false)?;
    project_matching(&after_push, residual, columns, true)
}

pub fn result_digest(
    columns: &[String],
    rows: &[BTreeMap<String, String>],
) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&ResultPin { columns, rows })?
    ))
}

pub fn bind_plan(
    format: &str,
    columns: &[String],
    pushed: Vec<RowFilter>,
    residual: Vec<RowFilter>,
    local_rows: &[BTreeMap<String, String>],
    adapter_rows: &[BTreeMap<String, String>],
) -> Result<VirtualPushdownPlan, String> {
    let local_digest = result_digest(columns, local_rows)?;
    let pushed_digest = result_digest(columns, adapter_rows)?;
    if local_digest != pushed_digest || local_rows != adapter_rows {
        return Err(EQUIVALENCE_FAILED.into());
    }
    Ok(VirtualPushdownPlan {
        contract_version: PUSHDOWN_CONTRACT.into(),
        adapter: format.into(),
        pushed_predicates: pushed,
        residual_predicates: residual,
        pushed_columns: columns.to_vec(),
        local_digest,
        pushed_digest,
        equivalent: true,
    })
}

fn project_matching(
    rows: &[BTreeMap<String, String>],
    filters: &[RowFilter],
    columns: &[String],
    project: bool,
) -> Result<Vec<BTreeMap<String, String>>, String> {
    let mut out = Vec::new();
    for row in rows {
        if !row_matches(row, filters)? {
            continue;
        }
        if project {
            let mut projected = BTreeMap::new();
            for name in columns {
                let value = row.get(name).ok_or(SNAPSHOT_CORRUPT)?;
                projected.insert(name.clone(), value.clone());
            }
            out.push(projected);
        } else {
            out.push(row.clone());
        }
    }
    Ok(out)
}

fn row_matches(row: &BTreeMap<String, String>, filters: &[RowFilter]) -> Result<bool, String> {
    for filter in filters {
        let value = row.get(&filter.column).ok_or(SNAPSHOT_CORRUPT)?;
        if !value_matches(value, &filter.op, &filter.value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn value_matches(value: &str, op: &str, expected: &str) -> Result<bool, String> {
    match op {
        "eq" => Ok(value == expected),
        "neq" => Ok(value != expected),
        "gt" | "gte" | "lt" | "lte" => numeric_compare(value, op, expected),
        _ => Err("open table predicate is unsupported".into()),
    }
}

fn numeric_compare(value: &str, op: &str, expected: &str) -> Result<bool, String> {
    if let (Ok(left), Ok(right)) = (value.parse::<i64>(), expected.parse::<i64>()) {
        return cmp_ord(left, op, right);
    }
    let left = parse_number(value)?;
    let right = parse_number(expected)?;
    cmp_ord(left, op, right)
}

fn cmp_ord<T: PartialOrd>(left: T, op: &str, right: T) -> Result<bool, String> {
    match op {
        "gt" => Ok(left > right),
        "gte" => Ok(left >= right),
        "lt" => Ok(left < right),
        "lte" => Ok(left <= right),
        _ => Err("open table predicate is unsupported".into()),
    }
}

fn parse_number(value: &str) -> Result<f64, String> {
    value
        .parse::<f64>()
        .ok()
        .filter(|number| number.is_finite())
        .ok_or_else(|| "open table predicate is unsupported".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, city: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("id".into(), id.into()), ("city".into(), city.into())])
    }

    #[test]
    fn pushed_and_local_plans_match_on_eligible_predicates() {
        let rows = vec![row("1", "berlin"), row("2", "oslo")];
        let filters = vec![RowFilter {
            column: "city".into(),
            op: "eq".into(),
            value: "berlin".into(),
        }];
        let columns = vec!["id".into(), "city".into()];
        let (pushed, residual) = split_predicates(&filters).unwrap();
        assert!(residual.is_empty());
        let local = evaluate_local(&rows, &filters, &columns).unwrap();
        let adapter =
            evaluate_adapter(FORMAT_ICEBERG, &rows, &pushed, &residual, &columns).unwrap();
        let plan = bind_plan(FORMAT_ICEBERG, &columns, pushed, residual, &local, &adapter).unwrap();
        assert!(plan.equivalent);
        assert_eq!(plan.local_digest, plan.pushed_digest);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0]["city"], "berlin");
    }

    #[test]
    fn residual_numeric_predicates_stay_local() {
        let rows = vec![row("1", "berlin"), row("2", "oslo")];
        let filters = vec![
            RowFilter {
                column: "city".into(),
                op: "neq".into(),
                value: "oslo".into(),
            },
            RowFilter {
                column: "id".into(),
                op: "gt".into(),
                value: "0".into(),
            },
        ];
        let columns = vec!["id".into()];
        let (pushed, residual) = split_predicates(&filters).unwrap();
        assert_eq!(pushed.len(), 1);
        assert_eq!(residual.len(), 1);
        let local = evaluate_local(&rows, &filters, &columns).unwrap();
        let adapter =
            evaluate_adapter(FORMAT_PARQUET, &rows, &pushed, &residual, &columns).unwrap();
        let plan = bind_plan(FORMAT_PARQUET, &columns, pushed, residual, &local, &adapter).unwrap();
        assert_eq!(plan.residual_predicates[0].op, "gt");
        assert_eq!(local, adapter);
        assert_eq!(local[0]["id"], "1");
    }

    #[test]
    fn empty_authorized_projection_does_not_return_hidden_columns() {
        let rows = vec![row("1", "berlin")];
        let local = evaluate_local(&rows, &[], &[]).unwrap();
        assert_eq!(local.len(), 1);
        assert!(local[0].is_empty());
        let adapter = evaluate_adapter(FORMAT_ICEBERG, &rows, &[], &[], &[]).unwrap();
        assert_eq!(adapter, local);
    }

    #[test]
    fn integer_residual_predicates_do_not_use_float_rounding() {
        let rows = vec![
            BTreeMap::from([("id".into(), "9007199254740993".into())]),
            BTreeMap::from([("id".into(), "9007199254740992".into())]),
        ];
        let filters = vec![RowFilter {
            column: "id".into(),
            op: "gt".into(),
            value: "9007199254740992".into(),
        }];
        let columns = vec!["id".into()];
        let local = evaluate_local(&rows, &filters, &columns).unwrap();
        assert_eq!(local.len(), 1);
        assert_eq!(local[0]["id"], "9007199254740993");
    }

    #[test]
    fn unknown_operator_fails_explicitly() {
        assert!(classify_predicate("contains").is_err());
    }

    #[test]
    fn digest_mismatch_fails_closed() {
        let columns = vec!["id".into()];
        let local = vec![row("1", "berlin")];
        let other = vec![row("2", "oslo")];
        assert_eq!(
            bind_plan(
                FORMAT_ICEBERG,
                &columns,
                Vec::new(),
                Vec::new(),
                &local,
                &other
            )
            .unwrap_err(),
            EQUIVALENCE_FAILED
        );
    }
}
