//! Federated aggregate rules (ADR 0134), with no I/O.
//!
//! A tenant publishes an [`Allowance`]: which object type, dimensions,
//! measures and functions a federated query may use, and the minimum group
//! size `k`. [`coverage`] decides whether a tenant takes part in a query and,
//! if not, why. [`tenant_partial`] turns that tenant's grouped rows into a
//! partial that holds only group keys, counts and sums, drops groups smaller
//! than `k`, and optionally adds Laplace noise. [`combine`] merges partials
//! and suppresses again at the largest `k`. Stores and RPCs build on these
//! rules; this module never sees an object id.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The schema of a published allowance.
pub const ALLOWANCE_SCHEMA: &str = "sekai.federated-aggregate-allowance/v1";

/// A decomposable aggregate function (§2). An average is carried as a sum
/// and a count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateFunction {
    Count,
    Sum,
    Avg,
}

impl AggregateFunction {
    /// Parse a function name. `min`, `max`, `distinct` and percentiles are
    /// refused: each can reveal a single record's value, whatever `k` is.
    pub fn parse(name: &str) -> Result<Self, FederatedAggregateError> {
        match name {
            "count" => Ok(Self::Count),
            "sum" => Ok(Self::Sum),
            "avg" => Ok(Self::Avg),
            other => Err(FederatedAggregateError::RefusedFunction(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederatedAggregateError {
    /// A function other than `count`, `sum` or `avg`.
    RefusedFunction(String),
    /// An allowance or query that cannot be evaluated as given.
    Invalid(String),
}

impl std::fmt::Display for FederatedAggregateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RefusedFunction(name) => write!(
                f,
                "aggregate function {name:?} is refused; federated queries allow count, sum and avg"
            ),
            Self::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for FederatedAggregateError {}

/// What one tenant agrees a federated query may use (§1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowance {
    pub schema: String,
    pub namespace: String,
    pub object_type: String,
    /// Properties that may group results; their values leave the tenant.
    pub dimensions: BTreeSet<String>,
    /// Properties that may be summed or averaged.
    pub measures: BTreeSet<String>,
    pub functions: BTreeSet<AggregateFunction>,
    /// The minimum group size `k`.
    pub min_group_size: u64,
    /// Laplace noise scale on partial counts and sums; `None` adds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noise_scale: Option<f64>,
    /// Requesting tenants or spaces the allowance accepts.
    pub requesters: BTreeSet<String>,
}

impl Allowance {
    pub fn validate(&self) -> Result<(), FederatedAggregateError> {
        let invalid = |reason: &str| Err(FederatedAggregateError::Invalid(reason.into()));
        if self.schema != ALLOWANCE_SCHEMA {
            return invalid("allowance schema must be sekai.federated-aggregate-allowance/v1");
        }
        if self.namespace.trim().is_empty() || self.object_type.trim().is_empty() {
            return invalid("allowance namespace and object type are required");
        }
        if self.functions.is_empty() || self.requesters.is_empty() {
            return invalid("allowance must name at least one function and one requester");
        }
        if self.min_group_size < 2 {
            return invalid("allowance minimum group size must be at least 2");
        }
        if !self.dimensions.is_disjoint(&self.measures) {
            return invalid("a property cannot be both a dimension and a measure");
        }
        if self
            .noise_scale
            .is_some_and(|scale| !scale.is_finite() || scale <= 0.0)
        {
            return invalid("noise scale must be a positive finite number");
        }
        Ok(())
    }

    /// `sha256:` over the canonical JSON of the allowance; a query records
    /// the digest it ran under.
    pub fn digest(&self) -> Result<String, FederatedAggregateError> {
        self.validate()?;
        let canonical = serde_json::to_vec(self)
            .map_err(|error| FederatedAggregateError::Invalid(error.to_string()))?;
        Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
    }
}

/// One measured value of a query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measure {
    pub function: AggregateFunction,
    /// The measured property; `None` for `count`, which counts records.
    pub property: Option<String>,
}

/// The shape of a federated query, as each tenant sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Query {
    pub requester: String,
    /// The namespace whose object type is queried; an allowance covers one.
    pub namespace: String,
    pub object_type: String,
    pub dimensions: Vec<String>,
    pub measures: Vec<Measure>,
    /// Properties the filters read; they may only be dimensions (§3).
    pub filter_properties: Vec<String>,
    /// Digest of the complete filter predicates as the store evaluates them
    /// (operators and values), so two selections over the same properties
    /// are different queries. Empty when there are no filters.
    pub filters_digest: String,
}

impl Query {
    /// `sha256:` over the canonical JSON of the query. A partial records it,
    /// so partials of another query are never combined into this one.
    pub fn digest(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("a query always serializes");
        format!("sha256:{:x}", Sha256::digest(canonical))
    }
}

/// Why a tenant contributes nothing (§6). Reported without details of its
/// allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    NoAllowance,
    ObjectType,
    Dimension,
    Measure,
    Function,
    Requester,
}

/// Whether `allowance` covers `query`; the first uncovered part otherwise.
pub fn coverage(allowance: Option<&Allowance>, query: &Query) -> Result<(), ExclusionReason> {
    let Some(allowance) = allowance else {
        return Err(ExclusionReason::NoAllowance);
    };
    // Object types are namespace-scoped, so another namespace is another type.
    if allowance.namespace != query.namespace || allowance.object_type != query.object_type {
        return Err(ExclusionReason::ObjectType);
    }
    if !allowance.requesters.contains(&query.requester) {
        return Err(ExclusionReason::Requester);
    }
    if query
        .dimensions
        .iter()
        .chain(&query.filter_properties)
        .any(|property| !allowance.dimensions.contains(property))
    {
        return Err(ExclusionReason::Dimension);
    }
    for measure in &query.measures {
        if !allowance.functions.contains(&measure.function) {
            return Err(ExclusionReason::Function);
        }
        match (&measure.function, &measure.property) {
            (AggregateFunction::Count, None) => {}
            (AggregateFunction::Count, Some(_)) | (_, None) => {
                return Err(ExclusionReason::Measure);
            }
            (_, Some(property)) if !allowance.measures.contains(property) => {
                return Err(ExclusionReason::Measure);
            }
            _ => {}
        }
    }
    Ok(())
}

/// The values of one group's dimensions, in query order.
pub type GroupKey = Vec<String>;

/// A group's count and the sum of each measured property, in the order the
/// summed properties first appear in the query's measures. `count` and
/// `sums` are what is reported, noise included. `exact_count` is the true
/// group size: the plane's combine step uses it to apply the largest `k`
/// (federation runs inside one plane, §9), and it never reaches the
/// requester.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupPartial {
    pub count: f64,
    pub sums: Vec<f64>,
    pub exact_count: u64,
}

/// Noise a tenant added, reported with the result (§7).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NoiseReport {
    pub mechanism: NoiseMechanism,
    pub scale: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoiseMechanism {
    Laplace,
}

/// What one tenant returns: group keys and numbers only (§5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Partial {
    pub tenant: String,
    pub allowance_digest: String,
    /// The query this partial answers.
    pub query_digest: String,
    pub min_group_size: u64,
    #[serde(with = "group_list")]
    pub groups: BTreeMap<GroupKey, GroupPartial>,
    /// Groups dropped inside the tenant for being smaller than `k`.
    pub suppressed_groups: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noise: Option<NoiseReport>,
}

/// A source of uniform values in the open interval (0, 1). Injected, so
/// noise is deterministic under a seeded source in tests.
pub trait RandomSource {
    fn next_open_unit(&mut self) -> f64;
}

/// One Laplace sample with the given scale, by inverse transform.
fn laplace(scale: f64, random: &mut dyn RandomSource) -> f64 {
    let centered = random.next_open_unit() - 0.5;
    -scale * centered.signum() * (1.0 - 2.0 * centered.abs()).ln()
}

/// The properties `query` sums, in first-appearance order. An average sums
/// its property too.
fn summed_properties(query: &Query) -> Vec<&str> {
    let mut summed: Vec<&str> = Vec::new();
    for measure in &query.measures {
        if let Some(property) = measure.property.as_deref()
            && !summed.contains(&property)
        {
            summed.push(property);
        }
    }
    summed
}

/// Group maps travel as lists of `[key, group]` pairs: JSON object keys must
/// be strings, and a group key is a list of dimension values.
mod group_list {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::GroupKey;

    pub fn serialize<V: Serialize, S: Serializer>(
        groups: &BTreeMap<GroupKey, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(groups.iter())
    }

    pub fn deserialize<'de, V: Deserialize<'de>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<GroupKey, V>, D::Error> {
        let pairs = Vec::<(GroupKey, V)>::deserialize(deserializer)?;
        let count = pairs.len();
        let groups: BTreeMap<GroupKey, V> = pairs.into_iter().collect();
        if groups.len() != count {
            return Err(serde::de::Error::custom("duplicate group key"));
        }
        Ok(groups)
    }
}

/// One record as the tenant's evaluation yields it: its group key and the
/// value of each summed property, in [`summed_properties`] order.
pub struct Row {
    pub key: GroupKey,
    pub values: Vec<f64>,
}

/// Build one tenant's partial from its rows (§3–§5, §7). Groups smaller than
/// the allowance's `k` are dropped and counted before anything else; noise,
/// when the allowance asks for it, is added to what remains.
pub fn tenant_partial(
    tenant: &str,
    allowance: &Allowance,
    query: &Query,
    rows: impl IntoIterator<Item = Row>,
    random: &mut dyn RandomSource,
) -> Result<Partial, FederatedAggregateError> {
    let allowance_digest = allowance.digest()?;
    if let Err(reason) = coverage(Some(allowance), query) {
        return Err(FederatedAggregateError::Invalid(format!(
            "the allowance does not cover this query: {reason:?}"
        )));
    }
    let width = summed_properties(query).len();
    let mut exact: BTreeMap<GroupKey, (u64, Vec<f64>)> = BTreeMap::new();
    for row in rows {
        if row.key.len() != query.dimensions.len() || row.values.len() != width {
            return Err(FederatedAggregateError::Invalid(
                "a row does not match the query's dimensions and measures".into(),
            ));
        }
        let entry = exact
            .entry(row.key)
            .or_insert_with(|| (0, vec![0.0; width]));
        entry.0 += 1;
        for (sum, value) in entry.1.iter_mut().zip(row.values) {
            *sum += value;
        }
    }
    let total = exact.len() as u64;
    let mut groups: BTreeMap<GroupKey, GroupPartial> = exact
        .into_iter()
        .filter(|(_, (count, _))| *count >= allowance.min_group_size)
        .map(|(key, (count, sums))| {
            (
                key,
                GroupPartial {
                    count: count as f64,
                    sums,
                    exact_count: count,
                },
            )
        })
        .collect();
    let suppressed_groups = total - groups.len() as u64;
    let noise = allowance.noise_scale.map(|scale| {
        for group in groups.values_mut() {
            group.count += laplace(scale, random);
            for sum in &mut group.sums {
                *sum += laplace(scale, random);
            }
        }
        NoiseReport {
            mechanism: NoiseMechanism::Laplace,
            scale,
        }
    });
    Ok(Partial {
        tenant: tenant.into(),
        allowance_digest,
        query_digest: query.digest(),
        min_group_size: allowance.min_group_size,
        groups,
        suppressed_groups,
        noise,
    })
}

/// One combined group: per query measure, the value. A group's count
/// appears only when the query asks for `count`; otherwise it stays inside
/// the plane for suppression and averages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CombinedGroup {
    /// One value per query measure, in query order: the count, a sum, or a
    /// sum divided by the count. An average whose noisy count is below one,
    /// or any value that is not finite, is `None`: dividing by the exact
    /// count instead would reveal it.
    pub values: Vec<Option<f64>>,
}

/// The requester's result (§4–§7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Combined {
    #[serde(with = "group_list")]
    pub groups: BTreeMap<GroupKey, CombinedGroup>,
    /// Groups suppressed inside tenants plus groups suppressed on the
    /// combined result. Counted, never described.
    pub suppressed_groups: u64,
    /// The `k` the combined result was suppressed at: the largest among the
    /// contributing tenants.
    pub min_group_size: u64,
    pub contributors: Vec<String>,
    pub excluded: BTreeMap<String, ExclusionReason>,
    pub noise: BTreeMap<String, NoiseReport>,
}

/// Merge tenant partials and suppress again, on exact group sizes, at the
/// largest `k` among the contributing tenants. A partial whose group keys or
/// sums do not match the query is refused rather than merged.
pub fn combine(
    query: &Query,
    partials: &[Partial],
    excluded: BTreeMap<String, ExclusionReason>,
) -> Result<Combined, FederatedAggregateError> {
    let summed = summed_properties(query);
    let width = summed.len();
    let query_digest = query.digest();
    let mut tenants = BTreeSet::new();
    for partial in partials {
        if partial.query_digest != query_digest {
            return Err(FederatedAggregateError::Invalid(format!(
                "partial from {} answers another query",
                partial.tenant
            )));
        }
        if !tenants.insert(partial.tenant.as_str()) {
            return Err(FederatedAggregateError::Invalid(format!(
                "partial from {} is given twice",
                partial.tenant
            )));
        }
        if partial
            .groups
            .iter()
            .any(|(key, group)| key.len() != query.dimensions.len() || group.sums.len() != width)
        {
            return Err(FederatedAggregateError::Invalid(format!(
                "partial from {} does not match the query's dimensions and measures",
                partial.tenant
            )));
        }
    }
    let min_group_size = partials
        .iter()
        .map(|partial| partial.min_group_size)
        .max()
        .unwrap_or(0);
    let mut merged: BTreeMap<GroupKey, GroupPartial> = BTreeMap::new();
    for partial in partials {
        for (key, group) in &partial.groups {
            let entry = merged.entry(key.clone()).or_insert_with(|| GroupPartial {
                count: 0.0,
                sums: vec![0.0; width],
                exact_count: 0,
            });
            entry.count += group.count;
            entry.exact_count += group.exact_count;
            for (total, sum) in entry.sums.iter_mut().zip(&group.sums) {
                *total += sum;
            }
        }
    }
    let before = merged.len() as u64;
    let groups: BTreeMap<GroupKey, CombinedGroup> = merged
        .into_iter()
        .filter(|(_, group)| group.exact_count >= min_group_size)
        .map(|(key, group)| {
            let values = query
                .measures
                .iter()
                .map(|measure| {
                    let sum = |property: &str| {
                        summed
                            .iter()
                            .position(|summed| *summed == property)
                            .map_or(0.0, |index| group.sums[index])
                    };
                    let value = match (measure.function, measure.property.as_deref()) {
                        (AggregateFunction::Count, _) | (_, None) => group.count,
                        (AggregateFunction::Sum, Some(property)) => sum(property),
                        (AggregateFunction::Avg, Some(_)) if group.count < 1.0 => f64::NAN,
                        (AggregateFunction::Avg, Some(property)) => sum(property) / group.count,
                    };
                    value.is_finite().then_some(value)
                })
                .collect();
            (key, CombinedGroup { values })
        })
        .collect();
    let combined_suppressed = before - groups.len() as u64;
    Ok(Combined {
        suppressed_groups: partials
            .iter()
            .map(|partial| partial.suppressed_groups)
            .sum::<u64>()
            + combined_suppressed,
        min_group_size,
        contributors: partials
            .iter()
            .map(|partial| partial.tenant.clone())
            .collect(),
        noise: partials
            .iter()
            .filter_map(|partial| partial.noise.map(|noise| (partial.tenant.clone(), noise)))
            .collect(),
        excluded,
        groups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowance(k: u64) -> Allowance {
        Allowance {
            schema: ALLOWANCE_SCHEMA.into(),
            namespace: "supply".into(),
            object_type: "shipment".into(),
            dimensions: BTreeSet::from(["region".into()]),
            measures: BTreeSet::from(["weight".into()]),
            functions: BTreeSet::from([
                AggregateFunction::Count,
                AggregateFunction::Sum,
                AggregateFunction::Avg,
            ]),
            min_group_size: k,
            noise_scale: None,
            requesters: BTreeSet::from(["buyer".into()]),
        }
    }

    fn query() -> Query {
        Query {
            requester: "buyer".into(),
            namespace: "supply".into(),
            object_type: "shipment".into(),
            dimensions: vec!["region".into()],
            measures: vec![
                Measure {
                    function: AggregateFunction::Count,
                    property: None,
                },
                Measure {
                    function: AggregateFunction::Sum,
                    property: Some("weight".into()),
                },
                Measure {
                    function: AggregateFunction::Avg,
                    property: Some("weight".into()),
                },
            ],
            filter_properties: vec![],
            filters_digest: String::new(),
        }
    }

    fn rows(groups: &[(&str, &[f64])]) -> Vec<Row> {
        groups
            .iter()
            .flat_map(|(region, weights)| {
                weights.iter().map(|weight| Row {
                    key: vec![region.to_string()],
                    values: vec![*weight],
                })
            })
            .collect()
    }

    /// A seeded source: a fixed cycle of values in (0, 1).
    struct Cycle(Vec<f64>, usize);

    impl RandomSource for Cycle {
        fn next_open_unit(&mut self) -> f64 {
            let value = self.0[self.1 % self.0.len()];
            self.1 += 1;
            value
        }
    }

    fn no_noise() -> Cycle {
        Cycle(vec![0.5], 0)
    }

    #[test]
    fn min_max_and_distinct_are_refused() {
        for name in ["min", "max", "distinct", "p95"] {
            assert_eq!(
                AggregateFunction::parse(name),
                Err(FederatedAggregateError::RefusedFunction(name.into()))
            );
        }
        assert_eq!(AggregateFunction::parse("avg"), Ok(AggregateFunction::Avg));
    }

    #[test]
    fn coverage_reports_each_exclusion_with_a_reason() {
        let allowed = allowance(2);
        assert_eq!(coverage(Some(&allowed), &query()), Ok(()));
        assert_eq!(coverage(None, &query()), Err(ExclusionReason::NoAllowance));
        type Change = fn(&mut Query);
        let cases: [(Change, ExclusionReason); 6] = [
            (
                |q| q.object_type = "invoice".into(),
                ExclusionReason::ObjectType,
            ),
            (
                |q| q.namespace = "finance".into(),
                ExclusionReason::ObjectType,
            ),
            (|q| q.requester = "rival".into(), ExclusionReason::Requester),
            (
                |q| q.dimensions.push("customer".into()),
                ExclusionReason::Dimension,
            ),
            (
                |q| q.filter_properties.push("weight".into()),
                ExclusionReason::Dimension,
            ),
            (
                |q| q.measures[1].property = Some("price".into()),
                ExclusionReason::Measure,
            ),
        ];
        for (change, reason) in cases {
            let mut changed = query();
            change(&mut changed);
            assert_eq!(coverage(Some(&allowed), &changed), Err(reason));
        }
        let mut sum_only = allowance(2);
        sum_only.functions = BTreeSet::from([AggregateFunction::Sum]);
        assert_eq!(
            coverage(Some(&sum_only), &query()),
            Err(ExclusionReason::Function)
        );
    }

    /// Partials combine into the right count, sum and average.
    #[test]
    fn partials_combine_into_count_sum_and_average() {
        let first = tenant_partial(
            "acme",
            &allowance(2),
            &query(),
            rows(&[("north", &[1.0, 2.0, 3.0])]),
            &mut no_noise(),
        )
        .unwrap();
        let second = tenant_partial(
            "globex",
            &allowance(2),
            &query(),
            rows(&[("north", &[4.0, 6.0])]),
            &mut no_noise(),
        )
        .unwrap();
        let combined = combine(&query(), &[first, second], BTreeMap::new()).unwrap();
        let north = &combined.groups[&vec!["north".to_string()]];
        assert_eq!(north.values, vec![Some(5.0), Some(16.0), Some(3.2)]);
        assert_eq!(combined.contributors, vec!["acme", "globex"]);
    }

    /// A group below `k` is dropped inside its tenant, and a combined group
    /// below the largest `k` is dropped again; both are only counted.
    #[test]
    fn small_groups_are_suppressed_per_tenant_and_on_the_combined_result() {
        let acme = tenant_partial(
            "acme",
            &allowance(2),
            &query(),
            rows(&[("north", &[1.0, 2.0]), ("south", &[5.0])]),
            &mut no_noise(),
        )
        .unwrap();
        assert_eq!(acme.suppressed_groups, 1);
        assert!(!acme.groups.contains_key(&vec!["south".to_string()]));
        let globex = tenant_partial(
            "globex",
            &allowance(3),
            &query(),
            rows(&[("east", &[1.0, 1.0, 1.0])]),
            &mut no_noise(),
        )
        .unwrap();
        let combined = combine(
            &query(),
            &[acme, globex],
            BTreeMap::from([("initech".into(), ExclusionReason::Requester)]),
        )
        .unwrap();
        // north has two records: below the largest k of 3.
        assert_eq!(combined.min_group_size, 3);
        assert_eq!(
            combined.groups.keys().collect::<Vec<_>>(),
            vec![&vec!["east".to_string()]]
        );
        assert_eq!(combined.suppressed_groups, 2);
        assert_eq!(combined.excluded["initech"], ExclusionReason::Requester);
        let encoded = serde_json::to_string(&combined).unwrap();
        assert!(
            !encoded.contains("north") && !encoded.contains("south"),
            "{encoded}"
        );
        assert_eq!(
            serde_json::from_str::<Combined>(&encoded).unwrap(),
            combined
        );
    }

    /// Noise comes from the injected source, so a seeded source gives the
    /// same result, and its mechanism and scale are reported.
    #[test]
    fn noise_is_deterministic_under_a_seeded_source_and_reported() {
        let mut noisy = allowance(2);
        noisy.noise_scale = Some(1.5);
        let partial = |seed: Vec<f64>| {
            tenant_partial(
                "acme",
                &noisy,
                &query(),
                rows(&[("north", &[1.0, 2.0, 3.0])]),
                &mut Cycle(seed, 0),
            )
            .unwrap()
        };
        let first = partial(vec![0.2, 0.7]);
        assert_eq!(first, partial(vec![0.2, 0.7]));
        assert_ne!(first.groups, partial(vec![0.6, 0.1]).groups);
        assert_eq!(
            first.noise,
            Some(NoiseReport {
                mechanism: NoiseMechanism::Laplace,
                scale: 1.5
            })
        );
        let north = &first.groups[&vec!["north".to_string()]];
        let expected_count = 3.0 + -1.5 * (-1.0_f64) * (1.0 - 2.0 * 0.3_f64).ln();
        assert!((north.count - expected_count).abs() < 1e-12, "{north:?}");
        let combined = combine(&query(), &[first], BTreeMap::new()).unwrap();
        assert_eq!(combined.noise["acme"].scale, 1.5);
    }

    /// Combined suppression uses exact group sizes: noise can neither lift a
    /// small group over the largest `k` nor drop an eligible one. A partial
    /// that does not match the query is refused.
    #[test]
    fn combined_suppression_ignores_noise_and_mismatched_partials_are_refused() {
        let mut noisy = allowance(2);
        noisy.noise_scale = Some(50.0);
        // A large positive draw on the count of a two-record group.
        let lifted = tenant_partial(
            "acme",
            &noisy,
            &query(),
            rows(&[("north", &[1.0, 2.0])]),
            &mut Cycle(vec![0.999], 0),
        )
        .unwrap();
        assert!(lifted.groups[&vec!["north".to_string()]].count > 5.0);
        let strict = tenant_partial(
            "globex",
            &allowance(5),
            &query(),
            rows(&[("east", &[1.0; 5])]),
            &mut no_noise(),
        )
        .unwrap();
        let combined = combine(&query(), &[lifted, strict.clone()], BTreeMap::new()).unwrap();
        assert!(!combined.groups.contains_key(&vec!["north".to_string()]));

        // A partial of another query is refused, even with the same shape.
        let mut by_price = query();
        by_price.measures[1].property = Some("price".into());
        by_price.measures[2].property = Some("price".into());
        assert!(combine(&by_price, std::slice::from_ref(&strict), BTreeMap::new()).is_err());
        // So is one over another selection of the same properties.
        let mut southern = query();
        southern.filters_digest = "sha256:south".into();
        assert!(combine(&southern, std::slice::from_ref(&strict), BTreeMap::new()).is_err());
        // A tenant's partial counts once.
        assert!(combine(&query(), &[strict.clone(), strict.clone()], BTreeMap::new()).is_err());
        // An average over a noisy count below one is withheld, not infinite.
        let mut sunk = allowance(2);
        sunk.noise_scale = Some(50.0);
        let sunk = tenant_partial(
            "initech",
            &sunk,
            &query(),
            rows(&[("west", &[1.0, 2.0])]),
            &mut Cycle(vec![0.001], 0),
        )
        .unwrap();
        assert!(sunk.groups[&vec!["west".to_string()]].count < 1.0);
        let west = combine(&query(), &[sunk], BTreeMap::new()).unwrap();
        let west = &west.groups[&vec!["west".to_string()]];
        assert_eq!(west.values[2], None);
        let mut malformed = strict;
        malformed
            .groups
            .values_mut()
            .for_each(|group| group.sums.clear());
        assert!(combine(&query(), &[malformed], BTreeMap::new()).is_err());
    }

    #[test]
    fn an_allowance_digest_pins_its_content() {
        let first = allowance(2);
        let mut changed = allowance(2);
        changed.min_group_size = 5;
        assert!(first.digest().unwrap().starts_with("sha256:"));
        assert_ne!(first.digest().unwrap(), changed.digest().unwrap());
        assert_eq!(first.digest().unwrap(), allowance(2).digest().unwrap());
        let mut overlapping = allowance(2);
        overlapping.measures.insert("region".into());
        assert!(overlapping.validate().is_err());
    }
}
