//! Fail-closed dual-read of EvaluateObjectSet against a tagged object-log library.
//!
//! `SEKAI_OBJECT_INDEX_DUAL_READ` compares SQL hop engines. This gate compares
//! the SQL projection to in-process mikura `ObjectSet::evaluate` (ADR 0081).

use crate::sekai::object_security::ObjectSecurityPolicy;
use crate::sekai::object_set::{ObjectSetAggregation, ObjectSetDescriptor};
use crate::sekai::object_type_index::ObjectTypeIndexMember;
use mikura::{
    Aggregate, EvaluateRequest, EvaluateResponse, Hop, LocalCompute, ObjectSet, PropertyAcl, Store,
};
use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DUAL_READ_ENV: &str = "SEKAI_OBJECT_LOG_DUAL_READ";
pub const LOG_PATH_ENV: &str = "SEKAI_OBJECT_LOG";
pub const SAMPLE_ENV: &str = "SEKAI_OBJECT_LOG_DUAL_READ_SAMPLE";
const DEFAULT_SAMPLE_N: u32 = 32;

static SAMPLE_TICK: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectLogDualRead {
    pub enabled: bool,
    pub log_path: Option<PathBuf>,
    /// Compare one of `sample_n` armed requests. `1` is CI. Unset soak
    /// defaults to 32 so enabling the flag is not a per-request Store open.
    pub sample_n: u32,
}

impl ObjectLogDualRead {
    pub fn from_env() -> Self {
        let enabled = env::var(DUAL_READ_ENV).unwrap_or_default() == "1";
        let sample_n = env::var(SAMPLE_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(if enabled { DEFAULT_SAMPLE_N } else { 1 });
        Self {
            enabled,
            log_path: env::var(LOG_PATH_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            sample_n: sample_n.max(1),
        }
    }

    fn take_sample(&self) -> bool {
        let n = u64::from(self.sample_n.max(1));
        SAMPLE_TICK
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(n)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectLogCompareError {
    Disabled,
    Unbounded,
    GrantNarrowed,
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
            Self::Unbounded => "object-log dual-read requires max_rows_scanned".into(),
            Self::GrantNarrowed => {
                "object-log dual-read soak is allow-all-only; property grants narrow visibility"
                    .into()
            }
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
    if !aggregation.group_by.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "group_by buckets are not expressible on the tagged object-log evaluate API",
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
    for hop in hops {
        let direction = hop.direction.trim();
        if !direction.is_empty() && !direction.eq_ignore_ascii_case("outgoing") {
            return Err(ObjectLogCompareError::Unsupported(
                "hop direction is not expressible on the tagged object-log evaluate API",
            ));
        }
    }
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
) -> Result<(usize, i64), ObjectLogCompareError> {
    if !aggregation.group_by.is_empty() {
        return Err(ObjectLogCompareError::Unsupported(
            "group_by buckets are not expressible on the tagged object-log evaluate API",
        ));
    }
    let mut roots = HashSet::new();
    let mut sum = 0i64;
    let summing = aggregation.function.eq_ignore_ascii_case("sum");
    for path in paths {
        if let Some(root) = path.first() {
            roots.insert(root.source_key.as_str());
        }
        if summing {
            if aggregation.property.is_empty() {
                return Err(ObjectLogCompareError::Unsupported(
                    "sum compare requires aggregation.property",
                ));
            }
            let leaf = path.last().ok_or(ObjectLogCompareError::Unsupported(
                "sum compare requires a leaf on every path",
            ))?;
            let raw = leaf.properties.get(&aggregation.property).ok_or(
                ObjectLogCompareError::Unsupported(
                    "sum property missing on a hop leaf; refusing vacuous compare",
                ),
            )?;
            let amount = raw.parse::<i64>().map_err(|_| {
                ObjectLogCompareError::Unsupported(
                    "sum property is not an i64; refusing vacuous compare",
                )
            })?;
            sum += amount;
        }
    }
    if paths.len() != roots.len() {
        return Err(ObjectLogCompareError::Unsupported(
            "path multiplicity is not expressible on the tagged object-log evaluate API",
        ));
    }
    Ok((roots.len(), sum))
}

/// Project clerk property grants into the tagged deny-list.
///
/// The tagged `PropertyAcl` public API is allow-all or a single deny. A
/// non-empty grant allow-list therefore cannot be witnessed without a false
/// allow-all compare. Callers skip the canary and keep the SQL answer.
pub fn project_object_log_acl<'a>(
    policies: impl IntoIterator<Item = Option<&'a ObjectSecurityPolicy>>,
) -> Result<PropertyAcl, ObjectLogCompareError> {
    for policy in policies.into_iter().flatten() {
        if policy
            .property_grants
            .as_ref()
            .is_some_and(|grants| !grants.is_empty())
        {
            return Err(ObjectLogCompareError::GrantNarrowed);
        }
    }
    Ok(PropertyAcl::allow_all())
}

pub fn compare_sql_to_log(
    config: &ObjectLogDualRead,
    descriptor: &ObjectSetDescriptor,
    hops: &[crate::sekai::object_set::ObjectSetTraversal],
    aggregation: &ObjectSetAggregation,
    sql_paths: &[Vec<&ObjectTypeIndexMember>],
    acl: PropertyAcl,
    max_rows_scanned: i32,
) -> Result<(), ObjectLogCompareError> {
    if !config.enabled {
        return Err(ObjectLogCompareError::Disabled);
    }
    if max_rows_scanned <= 0 {
        return Err(ObjectLogCompareError::Unbounded);
    }
    if !config.take_sample() {
        return Ok(());
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
    let (sql_roots, sql_sum) = sql_compare_signature(sql_paths, aggregation)?;
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
            group_by: String::new(),
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

    #[test]
    fn incoming_hop_fails_closed_instead_of_outbound() {
        let descriptor = ObjectSetDescriptor {
            kind: "Customer".into(),
            ..ObjectSetDescriptor::default()
        };
        let err = map_evaluate_request(
            &descriptor,
            &[crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Order".into(),
                join_property: "customer_id".into(),
                direction: "incoming".into(),
                ..Default::default()
            }],
            &ObjectSetAggregation {
                function: "count".into(),
                ..Default::default()
            },
            PropertyAcl::allow_all(),
        )
        .unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("direction"))
        );

        map_evaluate_request(
            &descriptor,
            &[crate::sekai::object_set::ObjectSetTraversal {
                far_kind: "Order".into(),
                join_property: "customer_id".into(),
                direction: "outgoing".into(),
                ..Default::default()
            }],
            &ObjectSetAggregation {
                function: "count".into(),
                ..Default::default()
            },
            PropertyAcl::allow_all(),
        )
        .unwrap();
    }

    #[test]
    fn group_by_path_multiplicity_and_non_i64_sum_fail_closed() {
        let aggregation = ObjectSetAggregation {
            function: "sum".into(),
            property: "amount".into(),
            group_by: "region".into(),
        };
        let customer = member("Customer", "c1", "region", "eu");
        let order = member("Order", "o1", "customer_id", "c1");
        let shipment = member("Shipment", "s1", "amount", "10");
        let err =
            sql_compare_signature(&[vec![&customer, &order, &shipment]], &aggregation).unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("group_by"))
        );

        let no_group = ObjectSetAggregation {
            function: "sum".into(),
            property: "amount".into(),
            group_by: String::new(),
        };
        let extra = member("Shipment", "s2", "amount", "5");
        let err = sql_compare_signature(
            &[
                vec![&customer, &order, &shipment],
                vec![&customer, &order, &extra],
            ],
            &no_group,
        )
        .unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("multiplicity"))
        );

        let bad = member("Shipment", "s1", "amount", "10.5");
        let err = sql_compare_signature(&[vec![&customer, &order, &bad]], &no_group).unwrap_err();
        assert!(
            matches!(err, ObjectLogCompareError::Unsupported(reason) if reason.contains("i64"))
        );
    }

    #[test]
    fn dual_read_refuses_unbounded_and_skips_unsampled_without_opening() {
        SAMPLE_TICK.store(0, Ordering::Relaxed);
        let config = ObjectLogDualRead {
            enabled: true,
            log_path: None,
            sample_n: 2,
        };
        let descriptor = ObjectSetDescriptor {
            kind: "Customer".into(),
            ..ObjectSetDescriptor::default()
        };
        let hops = [crate::sekai::object_set::ObjectSetTraversal {
            far_kind: "Order".into(),
            join_property: "customer_id".into(),
            ..Default::default()
        }];
        let aggregation = ObjectSetAggregation {
            function: "count".into(),
            ..Default::default()
        };
        let err = compare_sql_to_log(
            &config,
            &descriptor,
            &hops,
            &aggregation,
            &[],
            PropertyAcl::allow_all(),
            0,
        )
        .unwrap_err();
        assert!(matches!(err, ObjectLogCompareError::Unbounded));

        SAMPLE_TICK.store(1, Ordering::Relaxed);
        compare_sql_to_log(
            &config,
            &descriptor,
            &hops,
            &aggregation,
            &[],
            PropertyAcl::allow_all(),
            10,
        )
        .unwrap();
    }

    #[test]
    fn project_object_log_acl_skips_when_grants_narrow() {
        project_object_log_acl([None]).unwrap();
        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "sales".into(),
            kind: "Customer".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(vec![crate::sekai::object_security::PropertyGrant {
                property: "region".into(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            }]),
            value_instance_grants: None,
            required_purpose: None,
        };
        let err = project_object_log_acl([Some(&policy)]).unwrap_err();
        assert!(matches!(err, ObjectLogCompareError::GrantNarrowed));
    }
}
