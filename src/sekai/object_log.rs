//! Fail-closed dual-read of EvaluateObjectSet against a tagged object-log library.
//!
//! `SEKAI_OBJECT_INDEX_DUAL_READ` compares SQL hop engines. This gate compares
//! the SQL projection to in-process mikura `ObjectSet::evaluate` (ADR 0081).

use crate::sekai::object_set::{ObjectSetAggregation, ObjectSetDescriptor};
use crate::sekai::object_type_index::ObjectTypeIndexMember;
use mikura::{
    Aggregate, EvaluateRequest, EvaluateResponse, Hop, LocalCompute, ObjectSet, PropertyAcl, Store,
};
use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

pub const DUAL_READ_ENV: &str = "SEKAI_OBJECT_LOG_DUAL_READ";
pub const LOG_PATH_ENV: &str = "SEKAI_OBJECT_LOG";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectLogDualRead {
    pub enabled: bool,
    pub log_path: Option<PathBuf>,
}

impl ObjectLogDualRead {
    pub fn from_env() -> Self {
        Self {
            enabled: env::var(DUAL_READ_ENV).unwrap_or_default() == "1",
            log_path: env::var(LOG_PATH_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectLogCompareError {
    Disabled,
    MissingLog,
    Unsupported(&'static str),
    Evaluate(String),
    Mismatch {
        sql_roots: usize,
        sql_sum: i64,
        log: EvaluateResponse,
    },
}

impl ObjectLogCompareError {
    pub fn message(&self) -> String {
        match self {
            Self::Disabled => "object-log dual-read is off".into(),
            Self::MissingLog => {
                "object-log dual-read requires SEKAI_OBJECT_LOG to an existing mikura log".into()
            }
            Self::Unsupported(reason) => {
                format!("object-log dual-read cannot map request: {reason}")
            }
            Self::Evaluate(error) => format!("object-log evaluate failed: {error}"),
            Self::Mismatch {
                sql_roots,
                sql_sum,
                log,
            } => format!(
                "object-log dual-read mismatch: sql roots={sql_roots} sum={sql_sum} log roots={} sum={}",
                log.two_hop_count, log.sum_amount
            ),
        }
    }
}

pub fn map_evaluate_request(
    descriptor: &ObjectSetDescriptor,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    aggregation: &ObjectSetAggregation,
    acl: PropertyAcl,
) -> Result<EvaluateRequest, ObjectLogCompareError> {
    if !descriptor.property_filters.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "property filters are not expressible on the tagged object-log evaluate API",
        ));
    }
    if hops.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "object-log evaluate requires at least one hop",
        ));
    }
    let function = aggregation.function.to_ascii_lowercase();
    if function != "sum" && function != "count" {
        return Err(ObjectLogCompareError::Unsupported(
            "object-log evaluate compares count or sum only",
        ));
    }
    let sum_property = if aggregation.property.is_empty() {
        if function == "count" {
            String::new()
        } else {
            return Err(ObjectLogCompareError::Unsupported(
                "sum compare requires aggregation.property",
            ));
        }
    } else {
        aggregation.property.clone()
    };
    if function == "sum" && sum_property.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "sum compare requires aggregation.property",
        ));
    }
    let sum_kind = hops
        .last()
        .map(|hop| hop.far_kind.clone())
        .unwrap_or_else(|| descriptor.kind.clone());
    Ok(EvaluateRequest {
        root_kind: descriptor.kind.clone(),
        hops: hops
            .iter()
            .map(|hop| Hop {
                far_kind: hop.far_kind.clone(),
                join_property: hop.join_property.clone(),
            })
            .collect(),
        sum_kind,
        sum_property,
        aggregate: Aggregate::CountAndSum,
        acl,
    })
}

pub fn sql_compare_signature(
    paths: &[Vec<&ObjectTypeIndexMember>],
    aggregation: &ObjectSetAggregation,
) -> (usize, i64) {
    let mut roots = HashSet::new();
    let mut sum = 0i64;
    for path in paths {
        if let Some(root) = path.first() {
            roots.insert(root.source_key.as_str());
        }
        if let Some(leaf) = path.last()
            && !aggregation.property.is_empty()
            && let Some(amount) = leaf
                .properties
                .get(&aggregation.property)
                .and_then(|raw| raw.parse::<i64>().ok())
        {
            sum += amount;
        }
    }
    (roots.len(), sum)
}

pub fn compare_sql_to_log(
    config: &ObjectLogDualRead,
    descriptor: &ObjectSetDescriptor,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    aggregation: &ObjectSetAggregation,
    sql_paths: &[Vec<&ObjectTypeIndexMember>],
    acl: PropertyAcl,
) -> Result<(), ObjectLogCompareError> {
    if !config.enabled {
        return Err(ObjectLogCompareError::Disabled);
    }
    let path = config
        .log_path
        .as_deref()
        .ok_or(ObjectLogCompareError::MissingLog)?;
    compare_sql_to_log_path(path, descriptor, hops, aggregation, sql_paths, acl)
}

pub fn compare_sql_to_log_path(
    path: &Path,
    descriptor: &ObjectSetDescriptor,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    aggregation: &ObjectSetAggregation,
    sql_paths: &[Vec<&ObjectTypeIndexMember>],
    acl: PropertyAcl,
) -> Result<(), ObjectLogCompareError> {
    if !path.exists() {
        return Err(ObjectLogCompareError::MissingLog);
    }
    let request = map_evaluate_request(descriptor, hops, aggregation, acl)?;
    let store = Store::open(path).map_err(ObjectLogCompareError::Evaluate)?;
    let log = ObjectSet::new(LocalCompute)
        .evaluate(&store, &request)
        .map_err(|error| ObjectLogCompareError::Evaluate(format!("{error:?}")))?;
    let (sql_roots, sql_sum) = sql_compare_signature(sql_paths, aggregation);
    let sum_matches = request.sum_property.is_empty() || sql_sum == log.sum_amount;
    if sql_roots == log.two_hop_count && sum_matches {
        return Ok(());
    }
    Err(ObjectLogCompareError::Mismatch {
        sql_roots,
        sql_sum,
        log,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mikura::{BatchIngest, ObjectRecord};
    use std::collections::{BTreeMap, HashMap};

    fn member(kind: &str, key: &str, property: &str, value: &str) -> ObjectTypeIndexMember {
        ObjectTypeIndexMember {
            kind: kind.into(),
            source_key: key.into(),
            object_id: format!("{kind}:{key}"),
            properties: BTreeMap::from([(property.into(), value.into())]),
            ..ObjectTypeIndexMember::default()
        }
    }

    #[test]
    fn dual_read_matches_and_fails_closed_on_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("objects.mikura");
        let mut store = Store::create(&log).unwrap();
        BatchIngest::run(
            &mut store,
            vec![
                ObjectRecord {
                    r#gen: 1,
                    kind: "Customer".into(),
                    key: "c1".into(),
                    hidden: false,
                    props: HashMap::from([("region".into(), "eu".into())]),
                },
                ObjectRecord {
                    r#gen: 1,
                    kind: "Order".into(),
                    key: "o1".into(),
                    hidden: false,
                    props: HashMap::from([("customer_id".into(), "c1".into())]),
                },
                ObjectRecord {
                    r#gen: 1,
                    kind: "Shipment".into(),
                    key: "s1".into(),
                    hidden: false,
                    props: HashMap::from([
                        ("order_id".into(), "o1".into()),
                        ("amount".into(), "10".into()),
                    ]),
                },
                ObjectRecord {
                    r#gen: 1,
                    kind: "Shipment".into(),
                    key: "s-hidden".into(),
                    hidden: true,
                    props: HashMap::from([
                        ("order_id".into(), "o1".into()),
                        ("amount".into(), "99".into()),
                    ]),
                },
            ],
        )
        .unwrap();
        let descriptor = ObjectSetDescriptor {
            kind: "Customer".into(),
            ..ObjectSetDescriptor::default()
        };
        let hops = vec![
            crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Order".into(),
                join_property: "customer_id".into(),
                ..Default::default()
            },
            crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Shipment".into(),
                join_property: "order_id".into(),
                ..Default::default()
            },
        ];
        let aggregation = ObjectSetAggregation {
            function: "sum".into(),
            property: "amount".into(),
            group_by: "region".into(),
        };
        let customer = member("Customer", "c1", "region", "eu");
        let order = member("Order", "o1", "customer_id", "c1");
        let shipment = member("Shipment", "s1", "amount", "10");
        let paths = vec![vec![&customer, &order, &shipment]];
        compare_sql_to_log_path(
            &log,
            &descriptor,
            &hops,
            &aggregation,
            &paths,
            PropertyAcl::allow_all(),
        )
        .unwrap();

        BatchIngest::run(
            &mut store,
            vec![ObjectRecord {
                r#gen: 1,
                kind: "Shipment".into(),
                key: "s2".into(),
                hidden: false,
                props: HashMap::from([
                    ("order_id".into(), "o1".into()),
                    ("amount".into(), "5".into()),
                ]),
            }],
        )
        .unwrap();
        let err = compare_sql_to_log_path(
            &log,
            &descriptor,
            &hops,
            &aggregation,
            &paths,
            PropertyAcl::allow_all(),
        )
        .unwrap_err();
        assert!(matches!(err, ObjectLogCompareError::Mismatch { .. }));
    }

    #[test]
    fn filters_fail_closed_instead_of_dropping() {
        let descriptor = ObjectSetDescriptor {
            kind: "Customer".into(),
            property_filters: vec![crate::domain::PropertyFilter {
                key: "region".into(),
                op: "eq".into(),
                value: "eu".into(),
            }],
            ..ObjectSetDescriptor::default()
        };
        let err = map_evaluate_request(
            &descriptor,
            &[crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Order".into(),
                join_property: "customer_id".into(),
                ..Default::default()
            }],
            &ObjectSetAggregation {
                function: "count".into(),
                ..Default::default()
            },
            PropertyAcl::allow_all(),
        )
        .unwrap_err();
        assert!(matches!(err, ObjectLogCompareError::Unsupported(_)));
    }
}
