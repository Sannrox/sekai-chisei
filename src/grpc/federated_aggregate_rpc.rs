//! FederatedAggregate (ADR 0134, #1997).
//!
//! The caller needs read on the requesting namespace, and nothing else: its
//! identity never reaches a participating namespace. Each participating
//! namespace takes part only under its own published allowance (#1921),
//! which stands in for namespace read for a federation principal bound to
//! that allowance, limited to the allowance's object type and properties.
//! Object ACLs, row policy and markings still apply to that principal
//! (authorization recorded on #1922).
//!
//! Order: coverage is decided for every namespace without reading data;
//! then a receipt is opened in the requesting namespace and in every
//! participating one (#1996); then each covered namespace evaluates over its
//! object type index, through the same scan as object-set aggregation, and
//! keeps only group keys, counts and sums, dropping groups below its `k`;
//! then the partials are combined and suppressed again; then every receipt
//! is closed. Only then does the result leave. Any failure aborts every
//! receipt, and a receipt someone else closed first (the stale sweep) fails
//! the query.

use super::*;
use crate::sekai::federated_aggregate::{
    self as rules, AggregateFunction, Allowance, ExclusionReason, Measure, Partial, Query,
    RandomSource, Row,
};
use crate::sekai::federated_receipt::{self, OpenReceipt, ReceiptOutcome, ReceiptRole};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

const MAX_NAMESPACES: usize = 16;
const MAX_DIMENSIONS: usize = 8;
const MAX_MEASURES: usize = 8;
/// Rows one namespace may scan for one query.
const MAX_ROWS_PER_NAMESPACE: i32 = 100_000;
const FILTER_OPERATORS: &[&str] = &["eq", "gt", "gte", "lt", "lte"];

/// Uniform values in the open interval (0, 1) from the operating system's
/// generator: 53 uniform bits, offset by half a step so neither end is hit.
struct OsRandom;

impl RandomSource for OsRandom {
    fn next_open_unit(&mut self) -> f64 {
        use rand::RngCore as _;
        let bits = rand::rngs::OsRng.next_u64() >> 11;
        (bits as f64 + 0.5) / (1u64 << 53) as f64
    }
}

/// The principal a namespace evaluates under: bound to the allowance
/// digest, so it is never a caller and changes with the allowance.
fn federation_principal(allowance_digest: &str) -> String {
    format!("federation:{allowance_digest}")
}

fn exclusion_name(reason: ExclusionReason) -> &'static str {
    match reason {
        ExclusionReason::NoAllowance => "no_allowance",
        ExclusionReason::ObjectType => "object_type",
        ExclusionReason::Dimension => "dimension",
        ExclusionReason::Measure => "measure",
        ExclusionReason::Function => "function",
        ExclusionReason::Requester => "requester",
        ExclusionReason::Unavailable => "unavailable",
        ExclusionReason::RestrictedProperty => "restricted_property",
    }
}

/// The request as the rules see it, with the filters to evaluate.
struct ParsedQuery {
    query: Query,
    namespaces: Vec<String>,
    filters: Vec<PropertyFilter>,
}

fn parse_request(request: FederatedAggregateRequest) -> Result<ParsedQuery, Status> {
    let invalid = |message: &str| Err(Status::invalid_argument(message.to_string()));
    if request.requester.trim().is_empty() || request.object_type.trim().is_empty() {
        return invalid("requester and object_type are required");
    }
    let mut namespaces = Vec::new();
    for namespace in request.namespaces {
        if namespace.trim().is_empty() {
            return invalid("participating namespaces must not be empty");
        }
        if !namespaces.contains(&namespace) {
            namespaces.push(namespace);
        }
    }
    if namespaces.is_empty() || namespaces.len() > MAX_NAMESPACES {
        return invalid("a federated aggregate names 1 to 16 participating namespaces");
    }
    if request.dimensions.len() > MAX_DIMENSIONS
        || request.measures.is_empty()
        || request.measures.len() > MAX_MEASURES
    {
        return invalid("a federated aggregate has up to 8 dimensions and 1 to 8 measures");
    }
    let mut dimensions = Vec::new();
    for dimension in request.dimensions {
        if !domain::is_valid_property_key(&dimension) || dimensions.contains(&dimension) {
            return invalid("dimensions must be distinct property keys");
        }
        dimensions.push(dimension);
    }
    let mut measures = Vec::new();
    for measure in request.measures {
        let function = AggregateFunction::parse(measure.function.trim())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let property = match (function, measure.property.trim()) {
            (AggregateFunction::Count, "") => None,
            (AggregateFunction::Count, _) => return invalid("count takes no property"),
            (_, "") => return invalid("sum and avg need a property"),
            (_, property) if !domain::is_valid_property_key(property) => {
                return invalid("measure property is not a property key");
            }
            (_, property) => Some(property.to_string()),
        };
        measures.push(Measure { function, property });
    }
    if request.filters.len() > crate::sekai::object_set::MAX_PROPERTY_FILTERS {
        return invalid("too many filters");
    }
    for filter in &request.filters {
        if !domain::is_valid_property_key(&filter.key)
            || !FILTER_OPERATORS.contains(&filter.op.as_str())
        {
            return invalid("filters take a property key and eq, gt, gte, lt or lte");
        }
    }
    let mut filter_properties: Vec<String> = request
        .filters
        .iter()
        .map(|filter| filter.key.clone())
        .collect();
    filter_properties.sort();
    filter_properties.dedup();
    let filters_digest = if request.filters.is_empty() {
        String::new()
    } else {
        let canonical: Vec<(&str, &str, &str)> = request
            .filters
            .iter()
            .map(|filter| {
                (
                    filter.key.as_str(),
                    filter.op.as_str(),
                    filter.value.as_str(),
                )
            })
            .collect();
        let encoded = serde_json::to_vec(&canonical).map_err(|_| Status::internal("filters"))?;
        format!("sha256:{:x}", Sha256::digest(encoded))
    };
    Ok(ParsedQuery {
        query: Query {
            requester: request.requester,
            object_type: request.object_type,
            dimensions,
            measures,
            filter_properties,
            filters_digest,
        },
        namespaces,
        filters: request.filters,
    })
}

fn number(raw: Option<&String>) -> Option<f64> {
    raw.and_then(|value| value.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite())
}

/// A namespace's rows from the members the federation principal may read:
/// per member, its dimension values and summed values. Members are counted
/// once by object id, so a member read twice can never make a group reach
/// `k`. A member missing a dimension or a summed value, or a filtered
/// property (a hidden cell is absent after projection, so a filter that
/// matched the stored value does not count), is left out. No other
/// property, and no object id or key, enters a row.
fn rows_from_members(
    query: &Query,
    members: Vec<crate::sekai::object_type_index::ObjectTypeIndexMember>,
) -> Vec<Row> {
    let summed = rules::summed_properties(query);
    let mut seen = std::collections::BTreeSet::new();
    members
        .into_iter()
        .filter(|member| seen.insert(member.object_id.clone()))
        .filter_map(|member| {
            if query
                .filter_properties
                .iter()
                .any(|property| !member.properties.contains_key(property))
            {
                return None;
            }
            let key = query
                .dimensions
                .iter()
                .map(|dimension| member.properties.get(dimension).cloned())
                .collect::<Option<Vec<String>>>()?;
            let values = summed
                .iter()
                .map(|property| number(member.properties.get(*property)))
                .collect::<Option<Vec<f64>>>()?;
            Some(Row { key, values })
        })
        .collect()
}

impl SekaiServiceImpl {
    pub(super) async fn federated_aggregate_rpc(
        &self,
        req: Request<FederatedAggregateRequest>,
    ) -> Result<Response<FederatedAggregateResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let parsed = parse_request(req.into_inner())?;
        let requester = parsed.query.requester.clone();
        // The requester asks; it is not part of the federation (ADR 0134
        // §3), and each namespace keeps one receipt per query.
        if parsed.namespaces.contains(&requester) {
            return Err(Status::invalid_argument(
                "the requesting namespace cannot also be a participating namespace",
            ));
        }
        // The caller's own read, on the requesting namespace only.
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &requester,
            false,
        )?;
        check_team_namespace(self.db.runtime(), &principals, &requester, false)?;
        let actor = principals.join(",");
        // Receipts a crashed query left open are aborted here, by whichever
        // replica runs a query next; the sweep decides each one once.
        if let Err(error) = federated_receipt::sweep_stale(
            self.db.runtime(),
            now_millis(),
            federated_receipt::DEFAULT_STALE_AFTER_MS,
        ) {
            tracing::warn!(%error, "stale federated aggregate receipts not swept");
        }

        // Coverage first, from allowances alone: no data is read yet.
        let mut covered: Vec<(String, Allowance, String)> = Vec::new();
        let mut excluded: BTreeMap<String, ExclusionReason> = BTreeMap::new();
        for namespace in &parsed.namespaces {
            match self.namespace_coverage(namespace, &parsed.query)? {
                Ok((allowance, digest)) => covered.push((namespace.clone(), allowance, digest)),
                Err(reason) => {
                    excluded.insert(namespace.clone(), reason);
                }
            }
        }

        let query_id = uuid::Uuid::new_v4().to_string();
        let query_digest = parsed.query.digest();
        let mut receipts: Vec<(String, ReceiptRole, String)> =
            vec![(requester.clone(), ReceiptRole::Requester, String::new())];
        for namespace in &parsed.namespaces {
            let digest = covered
                .iter()
                .find(|(covered, _, _)| covered == namespace)
                .map(|(_, _, digest)| digest.clone())
                .unwrap_or_default();
            receipts.push((namespace.clone(), ReceiptRole::Participant, digest));
        }
        let opened_at = now_millis();
        let mut opened = Vec::new();
        for (tenant, role, allowance_digest) in &receipts {
            let result = federated_receipt::open(
                self.db.runtime(),
                OpenReceipt {
                    query_id: query_id.clone(),
                    tenant: tenant.clone(),
                    role: *role,
                    requester: requester.clone(),
                    actor: actor.clone(),
                    query_digest: query_digest.clone(),
                    allowance_digest: allowance_digest.clone(),
                },
                opened_at,
            );
            match result {
                Ok(_) => opened.push(tenant.clone()),
                Err(error) => {
                    self.abort_receipts(&query_id, &opened, "receipt not opened");
                    return Err(Status::unavailable(format!(
                        "federated aggregate receipt unavailable: {error}"
                    )));
                }
            }
        }

        let evaluated = self.evaluate_partials(&parsed, &covered);
        let partials = match evaluated {
            Ok((partials, changed)) => {
                excluded.extend(changed);
                partials
            }
            Err(status) => {
                self.abort_receipts(&query_id, &opened, "evaluation failed");
                return Err(status);
            }
        };
        let combined = match rules::combine(&parsed.query, &partials, excluded.clone()) {
            Ok(combined) => combined,
            Err(error) => {
                self.abort_receipts(&query_id, &opened, "combine failed");
                return Err(Status::internal(error.to_string()));
            }
        };

        // Close every receipt before the result leaves: participants first, the
        // requester last, so a failed close never leaves a completed requester
        // outcome (an aborted participant cannot be reopened to match it).
        let closed_at = now_millis();
        let close_order = receipts
            .iter()
            .filter(|(_, role, _)| matches!(role, ReceiptRole::Participant))
            .chain(
                receipts
                    .iter()
                    .filter(|(_, role, _)| matches!(role, ReceiptRole::Requester)),
            );
        for (tenant, role, _) in close_order {
            let outcome = match role {
                ReceiptRole::Requester => ReceiptOutcome {
                    returned_groups: combined.groups.len() as u64,
                    suppressed_groups: combined.suppressed_groups,
                    excluded: combined.excluded.clone(),
                },
                ReceiptRole::Participant => {
                    let partial = partials.iter().find(|partial| partial.tenant == *tenant);
                    ReceiptOutcome {
                        returned_groups: partial.map_or(0, |p| p.groups.len() as u64),
                        suppressed_groups: partial.map_or(0, |p| p.suppressed_groups),
                        excluded: excluded
                            .get(tenant)
                            .map(|reason| BTreeMap::from([(tenant.clone(), *reason)]))
                            .unwrap_or_default(),
                    }
                }
            };
            if let Err(error) =
                federated_receipt::close(self.db.runtime(), &query_id, tenant, outcome, closed_at)
            {
                self.abort_receipts(&query_id, &opened, "receipt not closed");
                return Err(Status::aborted(format!(
                    "federated aggregate receipt could not be closed: {error}"
                )));
            }
        }

        Ok(Response::new(FederatedAggregateResponse {
            query_id,
            query_digest,
            groups: combined
                .groups
                .into_iter()
                .map(|(keys, group)| FederatedAggregateGroup {
                    keys,
                    values: group
                        .values
                        .into_iter()
                        .map(|value| FederatedAggregateValue {
                            present: value.is_some(),
                            value: value.unwrap_or(0.0),
                        })
                        .collect(),
                })
                .collect(),
            suppressed_groups: combined.suppressed_groups,
            min_group_size: combined.min_group_size,
            contributors: combined.contributors,
            excluded: combined
                .excluded
                .into_iter()
                .map(|(namespace, reason)| FederatedAggregateExclusion {
                    namespace,
                    reason: exclusion_name(reason).into(),
                })
                .collect(),
            noise: combined
                .noise
                .into_iter()
                .map(|(namespace, noise)| FederatedAggregateNoise {
                    namespace,
                    mechanism: "laplace".into(),
                    scale: noise.scale,
                })
                .collect(),
        }))
    }

    /// Whether `namespace` takes part, decided from its allowance and its
    /// namespace-wide property query rules, without reading any object.
    fn namespace_coverage(
        &self,
        namespace: &str,
        query: &Query,
    ) -> Result<Result<(Allowance, String), ExclusionReason>, Status> {
        let record = crate::sekai::federated_allowance::current(
            self.db.runtime(),
            namespace,
            &query.object_type,
        )
        .map_err(|_| Status::unavailable("federated aggregate allowance unavailable"))?;
        let allowance = record.as_ref().map(|record| &record.allowance);
        if let Err(reason) = rules::coverage(allowance, namespace, query) {
            return Ok(Err(reason));
        }
        let record = record.expect("coverage needs an allowance");
        // The schema's restricted classification holds whatever the
        // allowance names: the federation principal may not query such a
        // property, as no ordinary reader may.
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        let queried: Vec<String> = query
            .dimensions
            .iter()
            .chain(&query.filter_properties)
            .chain(query.measures.iter().filter_map(|m| m.property.as_ref()))
            .cloned()
            .collect();
        match ensure_property_query_allowed(
            &schema,
            &[federation_principal(&record.allowance_digest)],
            None,
            &query.object_type,
            queried,
        ) {
            Ok(()) => {}
            Err(status) if status.code() == tonic::Code::PermissionDenied => {
                return Ok(Err(ExclusionReason::RestrictedProperty));
            }
            Err(status) => return Err(status),
        }
        // A property the namespace does not let anyone query is not
        // covered, whatever the allowance says.
        let grouped = query.dimensions.iter().chain(&query.filter_properties);
        for (properties, reason) in [
            (grouped.collect::<Vec<_>>(), ExclusionReason::Dimension),
            (
                query
                    .measures
                    .iter()
                    .filter_map(|measure| measure.property.as_ref())
                    .collect(),
                ExclusionReason::Measure,
            ),
        ] {
            match ensure_property_grant_query_allowed(
                self.db.runtime(),
                Some(namespace),
                Some(&query.object_type),
                properties,
            ) {
                Ok(()) => {}
                Err(status) if status.code() == tonic::Code::PermissionDenied => {
                    return Ok(Err(reason));
                }
                Err(status) => return Err(status),
            }
        }
        // A namespace whose index cannot answer now is excluded and
        // reported (§6, §8), never evaluated on stale, quarantined or
        // half-rebuilt data.
        if self.ready_index(namespace, &query.object_type)?.is_none() {
            return Ok(Err(ExclusionReason::Unavailable));
        }
        Ok(Ok((record.allowance, record.allowance_digest)))
    }

    /// The index status of a namespace's type when it can answer: a
    /// datasource is bound, the index is neither stale nor quarantined, and
    /// no rebuild is under way or was left unfinished. A rebuild marks the
    /// kind not ready before it clears members and ready again only once it
    /// is complete (the readiness hop projections use), so a crashed
    /// rebuild stays not ready.
    fn ready_index(
        &self,
        namespace: &str,
        kind: &str,
    ) -> Result<Option<crate::sekai::object_type_index::ObjectTypeIndexStatus>, Status> {
        let runtime = self.db.runtime();
        if runtime
            .get_object_type_datasource(namespace, kind)
            .map_err(Status::internal)?
            .is_none()
        {
            return Ok(None);
        }
        let Some(status) = runtime
            .object_type_index_status(namespace, kind, now_millis())
            .map_err(Status::internal)?
            .filter(|status| !status.stale && status.quarantine_reason.is_empty())
        else {
            return Ok(None);
        };
        let Some(published) = runtime
            .get_published_definition_revision(namespace)
            .map_err(|_| Status::internal("definition revision unavailable"))?
        else {
            return Ok(None);
        };
        let rebuilt = runtime
            .hop_projection_kinds_ready(namespace, &[kind], &published.revision_digest)
            .map_err(Status::internal)?;
        Ok(rebuilt.then_some(status))
    }

    fn evaluate_partials(
        &self,
        parsed: &ParsedQuery,
        covered: &[(String, Allowance, String)],
    ) -> Result<(Vec<Partial>, BTreeMap<String, ExclusionReason>), Status> {
        let mut partials = Vec::new();
        let mut excluded = BTreeMap::new();
        for (namespace, allowance, digest) in covered {
            let Some(rows) = self.federated_rows(namespace, parsed, digest)? else {
                // The index changed under the scan: nothing of it is used.
                excluded.insert(namespace.clone(), ExclusionReason::Unavailable);
                continue;
            };
            partials.push(
                rules::tenant_partial(namespace, allowance, &parsed.query, rows, &mut OsRandom)
                    .map_err(|error| Status::internal(error.to_string()))?,
            );
        }
        Ok((partials, excluded))
    }

    /// One namespace's rows ([`rows_from_members`]), or `None` when its
    /// index is not ready ([`Self::ready_index`]) before or after the scan
    /// or changed while it was read. The index is read in one statement,
    /// so a member cannot move across a page boundary and be read twice.
    /// That read loads at most [`MAX_ROWS_PER_NAMESPACE`] + 1 members (its
    /// SQL limit); a larger index fails the query on the cost meter.
    fn federated_rows(
        &self,
        namespace: &str,
        parsed: &ParsedQuery,
        allowance_digest: &str,
    ) -> Result<Option<Vec<Row>>, Status> {
        let kind = &parsed.query.object_type;
        // Coverage checked the index; it may have changed since.
        let Some(status) = self.ready_index(namespace, kind)? else {
            return Ok(None);
        };
        let query = crate::sekai::dataset::RowQuery {
            filters: parsed
                .filters
                .iter()
                .map(|filter| crate::sekai::dataset::RowFilter {
                    column: filter.key.clone(),
                    op: filter.op.clone(),
                    value: filter.value.clone(),
                })
                .collect(),
            // One batch larger than the row bound: a single statement, hence
            // one consistent read; more rows than the bound fail on the meter.
            limit: MAX_ROWS_PER_NAMESPACE.saturating_add(1),
            ..Default::default()
        };
        let mut meter = crate::sekai::object_set::CostMeter::new(
            crate::sekai::object_set::ObjectSetCostLimit {
                max_rows_scanned: MAX_ROWS_PER_NAMESPACE,
                max_depth: 1,
                max_time_ms: 0,
            },
        );
        let principal = [federation_principal(allowance_digest)];
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        // Members are read whole, as the constrained object-set path reads
        // them: markings and row-policy inputs are often properties outside
        // the query, and authorization must see them. Rows take only the
        // query's properties afterwards.
        let members =
            self.scan_index_layer(namespace, kind, query, None, &mut meter, |member| {
                self.federation_visible(
                    member,
                    &principal,
                    (namespace, kind),
                    &schema,
                    status.indexed_at_ms,
                )
            })?;
        #[cfg(test)]
        tests::after_scan(self, namespace);
        let after = self.ready_index(namespace, kind)?;
        let unchanged = after.as_ref().is_some_and(|after| {
            (
                after.indexed_at_ms,
                after.last_dataset_row_id,
                after.member_count,
                after.stale,
                &after.quarantine_reason,
            ) == (
                status.indexed_at_ms,
                status.last_dataset_row_id,
                status.member_count,
                status.stale,
                &status.quarantine_reason,
            )
        });
        if !unchanged {
            return Ok(None);
        }
        Ok(Some(rows_from_members(&parsed.query, members)))
    }

    /// The index member's snapshot, cell-projected, when the federation
    /// principal may read it. The snapshot is what enters the aggregate,
    /// so it is what is authorized: it must be of this namespace and type,
    /// and row policy, markings and cell grants are evaluated on its
    /// values. A live object with the same id must be of the same
    /// namespace and type and pass the same checks too. The allowance
    /// stands in for namespace read; the object's ACL, row policy and
    /// markings decide as for any principal. A denial leaves the record
    /// out; an authorization outage fails.
    fn federation_visible(
        &self,
        member: &crate::sekai::object_type_index::ObjectTypeIndexMember,
        principal: &[String],
        scope: (&str, &str),
        schema: &schema::SchemaRegistry,
        indexed_at_ms: i64,
    ) -> Result<Option<domain::Object>, Status> {
        let (namespace, kind) = scope;
        let snapshot = domain::Object {
            id: member.object_id.clone(),
            kind: member.kind.clone(),
            name: member.source_key.clone(),
            namespace: member.namespace.clone(),
            external_id: member.source_key.clone(),
            properties: member.properties.clone().into_iter().collect(),
            created: indexed_at_ms,
            updated: indexed_at_ms,
        };
        let in_scope =
            |object: &domain::Object| object.namespace == namespace && object.kind == kind;
        if !in_scope(&snapshot) || is_reserved_governance_kind(&snapshot.kind) {
            return Ok(None);
        }
        let live = self
            .db
            .runtime()
            .get_object(&member.object_id)
            .map_err(Status::internal)?;
        if live.as_ref().is_some_and(|live| !in_scope(live)) {
            return Ok(None);
        }
        let hidden = |status: &Status| {
            matches!(
                status.code(),
                tonic::Code::NotFound | tonic::Code::PermissionDenied
            )
        };
        match check_object_acl_with_audit(
            self.db.runtime(),
            &self.security,
            &snapshot.id,
            principal,
            None,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
        ) {
            Ok(()) => {}
            Err(status) if hidden(&status) => return Ok(None),
            Err(status) => return Err(status),
        }
        for object in std::iter::once(&snapshot).chain(live.as_ref()) {
            match evaluate_active_object_policy(
                self.db.runtime(),
                object,
                principal,
                None,
                crate::sekai::object_security::ObjectSecurityOperation::Read,
                None,
            ) {
                Ok(Some(false)) => return Ok(None),
                Ok(_) => {}
                Err(status) if hidden(&status) => return Ok(None),
                Err(status) => return Err(status),
            }
            match enforce_object_marking_access(
                self.db.runtime(),
                object,
                principal,
                "federated_aggregate",
            ) {
                Ok(_) => {}
                Err(status) if hidden(&status) => return Ok(None),
                Err(status) => return Err(status),
            }
        }
        // Property and value-instance (cell) grants on the snapshot's own
        // values, as every read projects them: a hidden cell is absent, so
        // the record drops out of any group or measure that needs it.
        // Restricted properties are redacted as on every read.
        let projected = self
            .db
            .runtime()
            .project_object_property_grants(snapshot)
            .map_err(|_| Status::unavailable("object authorization unavailable"))?;
        Ok(Some(redact_restricted_properties(
            projected,
            schema,
            &self.security,
            principal,
        )))
    }

    /// Abort the receipts opened so far; best effort, since the stale sweep
    /// aborts any receipt left open.
    fn abort_receipts(&self, query_id: &str, tenants: &[String], reason: &str) {
        let now = now_millis();
        for tenant in tenants {
            if let Err(error) =
                federated_receipt::abort(self.db.runtime(), query_id, tenant, reason, now)
            {
                tracing::warn!(%error, "federated aggregate receipt not aborted; the sweep will");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };
    use crate::sekai::federated_aggregate::ALLOWANCE_SCHEMA;
    use crate::sekai::federated_receipt::ReceiptState;
    use crate::sekai::security;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(db))
    }

    fn grant_namespace(svc: &SekaiServiceImpl, namespace: &str, principal: &str) {
        let (_, grants) = svc
            .db
            .runtime()
            .ensure_team_namespace(namespace, principal, security::Role::Admin, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
    }

    /// A published `Shipment` type in `namespace`, indexed from `rows` of
    /// (key, region, weight).
    fn seed_shipments(svc: &SekaiServiceImpl, namespace: &str, rows: &[(&str, &str, &str)]) {
        seed_marked_shipments(svc, namespace, rows, &[]);
    }

    /// [`seed_shipments`], with an `access_marking` on the keys in `marked`.
    fn seed_marked_shipments(
        svc: &SekaiServiceImpl,
        namespace: &str,
        rows: &[(&str, &str, &str)],
        marked: &[(&str, &str)],
    ) {
        let member = DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Shipment".into(),
            definition_json: r#"{"name":"Shipment","properties":{"region":{"type":"string"},"weight":{"type":"number"},"secret":{"type":"string"}}}"#.into(),
            member_digest: String::new(),
        }
        .prepare(namespace)
        .unwrap();
        let revision = prepare_revision(
            namespace,
            "",
            [DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            }],
            true,
            "author",
            1,
        )
        .unwrap();
        let runtime = svc.db.runtime();
        runtime
            .seed_published_definition_revision(&revision, &[member])
            .unwrap();
        let dataset = format!("ds-{namespace}");
        runtime
            .create_dataset(&crate::sekai::dataset::Dataset {
                id: dataset.clone(),
                name: dataset.clone(),
                columns: [
                    "access_marking",
                    "hidden",
                    "key",
                    "region",
                    "secret",
                    "weight",
                ]
                .iter()
                .map(|name| crate::sekai::dataset::ColumnDef {
                    name: (*name).into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                })
                .collect(),
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        let rows: Vec<HashMap<String, String>> = rows
            .iter()
            .map(|(key, region, weight)| {
                HashMap::from([
                    ("key".to_string(), key.to_string()),
                    ("region".into(), region.to_string()),
                    ("weight".into(), weight.to_string()),
                    ("secret".into(), format!("secret-{key}")),
                    ("hidden".into(), "0".into()),
                    (
                        "access_marking".into(),
                        marked
                            .iter()
                            .find(|(marked, _)| marked == key)
                            .map_or(String::new(), |(_, marking)| marking.to_string()),
                    ),
                ])
            })
            .collect();
        runtime.append_rows(&dataset, &rows).unwrap();
        let binding = crate::sekai::object_type_index::ObjectTypeDatasource {
            contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            kind: "Shipment".into(),
            definition_digest: revision.revision_digest.clone(),
            dataset_id: dataset,
            key_column: "key".into(),
            property_mapping: [
                ("region", "region"),
                ("weight", "weight"),
                ("secret", "secret"),
                ("access_marking", "access_marking"),
            ]
            .iter()
            .map(|(property, column)| ((*property).into(), (*column).into()))
            .collect(),
            hidden_column: "hidden".into(),
            edits_only: false,
        }
        .prepare()
        .unwrap();
        runtime
            .register_object_type_datasource(&binding, 10)
            .unwrap();
        runtime
            .apply_object_type_index(namespace, "Shipment", true, 20)
            .unwrap();
    }

    fn allow(svc: &SekaiServiceImpl, namespace: &str, k: u64, noise: Option<f64>) {
        crate::sekai::federated_allowance::publish(
            svc.db.runtime(),
            Allowance {
                schema: ALLOWANCE_SCHEMA.into(),
                namespace: namespace.into(),
                object_type: "Shipment".into(),
                dimensions: BTreeSet::from(["region".into()]),
                measures: BTreeSet::from(["weight".into()]),
                functions: BTreeSet::from([
                    AggregateFunction::Count,
                    AggregateFunction::Sum,
                    AggregateFunction::Avg,
                ]),
                min_group_size: k,
                noise_scale: noise,
                requesters: BTreeSet::from(["buyer".into()]),
            },
            "opt in",
            "admin",
            1,
        )
        .unwrap();
    }

    fn measure(function: &str, property: &str) -> FederatedAggregateMeasure {
        FederatedAggregateMeasure {
            function: function.into(),
            property: property.into(),
        }
    }

    fn request(
        namespaces: &[&str],
        measures: Vec<FederatedAggregateMeasure>,
    ) -> FederatedAggregateRequest {
        FederatedAggregateRequest {
            requester: "buyer".into(),
            namespaces: namespaces.iter().map(|ns| ns.to_string()).collect(),
            object_type: "Shipment".into(),
            dimensions: vec!["region".into()],
            measures,
            filters: Vec::new(),
        }
    }

    fn as_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    /// Two namespaces with records the analyst cannot read, one without an
    /// allowance, one with noise.
    fn federation() -> SekaiServiceImpl {
        let svc = service();
        grant_namespace(&svc, "buyer", "analyst");
        seed_shipments(
            &svc,
            "north",
            &[
                ("n-1", "eu", "1"),
                ("n-2", "eu", "2"),
                ("n-3", "eu", "3"),
                ("n-4", "us", "7"),
            ],
        );
        seed_shipments(
            &svc,
            "south",
            &[("s-1", "eu", "4"), ("s-2", "eu", "6"), ("s-3", "us", "5")],
        );
        seed_shipments(&svc, "west", &[("w-1", "eu", "100"), ("w-2", "eu", "100")]);
        allow(&svc, "north", 2, None);
        allow(&svc, "south", 2, None);
        svc
    }

    /// Count, sum and average across two namespaces; a group below `k` is
    /// suppressed in its namespace; a namespace without an allowance is
    /// excluded and reported; receipts are written and closed in the
    /// requesting namespace and every participating one; no row, id, key or
    /// non-dimension value is returned.
    #[tokio::test]
    async fn totals_across_two_namespaces_with_suppression_exclusion_and_receipts() {
        let svc = federation();
        let response = svc
            .federated_aggregate(as_principal(
                request(
                    &["north", "south", "west"],
                    vec![
                        measure("count", ""),
                        measure("sum", "weight"),
                        measure("avg", "weight"),
                    ],
                ),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        // eu: north 1+2+3, south 4+6. us has one record in each namespace,
        // below k = 2, so both are dropped inside their namespaces.
        assert_eq!(response.groups.len(), 1);
        assert_eq!(response.groups[0].keys, ["eu"]);
        let values: Vec<_> = response.groups[0]
            .values
            .iter()
            .map(|value| (value.present, value.value))
            .collect();
        assert_eq!(values, [(true, 5.0), (true, 16.0), (true, 3.2)]);
        assert_eq!(response.suppressed_groups, 2);
        assert_eq!(response.min_group_size, 2);
        assert_eq!(response.contributors, ["north", "south"]);
        assert_eq!(response.excluded.len(), 1);
        assert_eq!(
            (
                response.excluded[0].namespace.as_str(),
                response.excluded[0].reason.as_str()
            ),
            ("west", "no_allowance")
        );
        assert!(response.noise.is_empty());
        let encoded = format!("{response:?}");
        for leaked in ["n-1", "s-1", "Shipment:", "secret", "\"us\"", "100"] {
            assert!(!encoded.contains(leaked), "{leaked} in {encoded}");
        }

        for (tenant, returned, suppressed) in [
            ("buyer", 1, 2),
            ("north", 1, 1),
            ("south", 1, 1),
            ("west", 0, 0),
        ] {
            let receipt = federated_receipt::get(svc.db.runtime(), &response.query_id, tenant)
                .unwrap()
                .unwrap_or_else(|| panic!("no receipt in {tenant}"));
            assert_eq!(receipt.state, ReceiptState::Completed, "{tenant}");
            assert_eq!(receipt.opened.query_digest, response.query_digest);
            let outcome = receipt.outcome.unwrap();
            assert_eq!(
                (outcome.returned_groups, outcome.suppressed_groups),
                (returned, suppressed),
                "{tenant}"
            );
            if tenant == "west" || tenant == "buyer" {
                assert_eq!(outcome.excluded["west"], ExclusionReason::NoAllowance);
            }
        }
        let north = federated_receipt::get(svc.db.runtime(), &response.query_id, "north")
            .unwrap()
            .unwrap();
        assert!(north.opened.allowance_digest.starts_with("sha256:"));
    }

    /// min and max are refused before anything is read or recorded.
    #[tokio::test]
    async fn min_and_max_are_refused() {
        let svc = federation();
        for function in ["min", "max", "distinct"] {
            let error = svc
                .federated_aggregate(as_principal(
                    request(&["north"], vec![measure(function, "weight")]),
                    "analyst",
                ))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{function}");
        }
        assert!(
            federated_receipt::list_for_tenant(svc.db.runtime(), "north", 10)
                .unwrap()
                .is_empty()
        );
    }

    /// A namespace with noise reports its mechanism and scale.
    #[tokio::test]
    async fn noise_parameters_are_returned() {
        let svc = federation();
        allow(&svc, "south", 2, Some(0.5));
        let response = svc
            .federated_aggregate(as_principal(
                request(&["north", "south"], vec![measure("count", "")]),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.noise.len(), 1);
        assert_eq!(
            (
                response.noise[0].namespace.as_str(),
                response.noise[0].mechanism.as_str(),
                response.noise[0].scale
            ),
            ("south", "laplace", 0.5)
        );
    }

    /// Authorization sees the whole record, not just the queried
    /// properties: a marking outside the query hides a record from the
    /// federation principal, which holds no clearance, and a row policy on
    /// a property outside the query still admits the records it permits.
    #[tokio::test]
    async fn markings_and_row_policy_outside_the_query_are_enforced() {
        let svc = service();
        grant_namespace(&svc, "buyer", "analyst");
        seed_marked_shipments(
            &svc,
            "north",
            &[("n-1", "eu", "1"), ("n-2", "eu", "2"), ("n-3", "eu", "3")],
            &[("n-3", "restricted")],
        );
        allow(&svc, "north", 2, None);
        let counted = svc
            .federated_aggregate(as_principal(
                request(&["north"], vec![measure("count", "")]),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(counted.groups.len(), 1, "{counted:?}");
        assert_eq!(
            counted.groups[0].values[0].value, 2.0,
            "the restricted record is hidden"
        );

        seed_shipments(
            &svc,
            "south",
            &[("s-1", "eu", "1"), ("s-2", "eu", "2"), ("s-3", "eu", "3")],
        );
        allow(&svc, "south", 2, None);
        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "south".into(),
            kind: "Shipment".into(),
            rules: ["secret-s-1", "secret-s-2"]
                .iter()
                .map(|value| crate::sekai::object_security::ObjectSecurityRule {
                    operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                    predicates: vec![
                        crate::sekai::object_security::ObjectSecurityPredicate::PropertyEquals {
                            property: "secret".into(),
                            value: (*value).into(),
                        },
                    ],
                })
                .collect(),
            property_grants: None,
            value_instance_grants: None,
            required_purpose: None,
        };
        let revision = svc
            .db
            .runtime()
            .put_object_security_policy(&policy, "root", "put-south", 1)
            .unwrap();
        // Activation covers the kinds with live objects; s-3 has one. s-1
        // and s-2 exist only in the index, so the policy reads their
        // `secret` from the index snapshot.
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: "Shipment:s-3".into(),
                kind: "Shipment".into(),
                name: "s-3".into(),
                namespace: "south".into(),
                external_id: "s-3".into(),
                properties: HashMap::from([
                    ("region".into(), "eu".into()),
                    ("weight".into(), "3".into()),
                    ("secret".into(), "secret-s-3".into()),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .runtime()
            .activate_object_security_policies(
                "south",
                &std::collections::BTreeMap::from([("Shipment".into(), revision.revision_digest)]),
                "root",
                "activate-south",
                2,
            )
            .unwrap();
        let response = svc
            .federated_aggregate(as_principal(
                request(&["south"], vec![measure("count", "")]),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.groups.len(), 1, "{response:?}");
        assert_eq!(response.groups[0].values[0].value, 2.0);
    }

    /// The noise source is uniform on (0, 1): Laplace samples drawn from it
    /// center on zero and take both signs.
    #[test]
    fn noise_from_the_os_source_is_centered_and_takes_both_signs() {
        let mut random = OsRandom;
        let samples: Vec<f64> = (0..20_000).map(|_| random.next_open_unit()).collect();
        assert!(samples.iter().all(|value| *value > 0.0 && *value < 1.0));
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!((mean - 0.5).abs() < 0.02, "uniform mean {mean}");
        assert!(samples.iter().any(|value| *value < 0.25));
        assert!(samples.iter().any(|value| *value > 0.75));
        // Laplace draws at unit scale, as tenant_partial makes them.
        let draws: Vec<f64> = (0..20_000)
            .map(|_| {
                let centered = random.next_open_unit() - 0.5;
                -centered.signum() * (1.0 - 2.0 * centered.abs()).ln()
            })
            .collect();
        let mean = draws.iter().sum::<f64>() / draws.len() as f64;
        // The standard deviation is about 1.41, so the mean of 20 000 draws
        // lies within 0.1 of zero far beyond six standard errors.
        assert!(mean.abs() < 0.1, "laplace mean {mean}");
        let negative = draws.iter().filter(|draw| **draw < 0.0).count();
        assert!((9_000..11_000).contains(&negative), "{negative} negative");
    }

    /// Cell (value-instance) grants apply as on every read: a hidden
    /// measure or dimension leaves the record out of what needs it, and a
    /// filter never matches a hidden cell.
    #[tokio::test]
    async fn hidden_cells_neither_count_nor_match_filters() {
        let svc = service();
        grant_namespace(&svc, "buyer", "analyst");
        seed_shipments(
            &svc,
            "east",
            &[
                ("e-1", "eu", "1"),
                ("e-2", "eu", "2"),
                ("e-3", "eu", "4"),
                ("e-4", "eu", "8"),
            ],
        );
        allow(&svc, "east", 2, None);
        // Activation covers kinds with live objects: e-1 has one.
        svc.db
            .runtime()
            .create_object(&domain::Object {
                id: "Shipment:e-1".into(),
                kind: "Shipment".into(),
                name: "e-1".into(),
                namespace: "east".into(),
                external_id: "e-1".into(),
                properties: HashMap::from([
                    ("region".into(), "eu".into()),
                    ("weight".into(), "1".into()),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        let cell = |key: &str, property: &str, value: &str| {
            crate::sekai::object_security::ValueInstanceGrant {
                object_id: format!("Shipment:{key}"),
                property: property.into(),
                value_digest: crate::sekai::object_security::value_instance_digest(value).unwrap(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            }
        };
        // e-3's weight and e-4's region are hidden cells.
        let grants = vec![
            cell("e-1", "region", "eu"),
            cell("e-1", "weight", "1"),
            cell("e-2", "region", "eu"),
            cell("e-2", "weight", "2"),
            cell("e-3", "region", "eu"),
            cell("e-4", "weight", "8"),
        ];
        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "east".into(),
            kind: "Shipment".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: None,
            value_instance_grants: Some(grants),
            required_purpose: None,
        };
        let revision = svc
            .db
            .runtime()
            .put_object_security_policy(&policy, "root", "put-east", 1)
            .unwrap();
        svc.db
            .runtime()
            .activate_object_security_policies(
                "east",
                &std::collections::BTreeMap::from([("Shipment".into(), revision.revision_digest)]),
                "root",
                "activate-east",
                2,
            )
            .unwrap();
        let response = svc
            .federated_aggregate(as_principal(
                request(
                    &["east"],
                    vec![measure("count", ""), measure("sum", "weight")],
                ),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.groups.len(), 1, "{response:?}");
        let values: Vec<f64> = response.groups[0]
            .values
            .iter()
            .map(|value| value.value)
            .collect();
        // e-3 lacks a visible weight and e-4 a visible region.
        assert_eq!(values, [2.0, 3.0]);

        // A filter on region does not match e-4's hidden region.
        let mut filtered = request(&["east"], vec![measure("count", "")]);
        filtered.dimensions.clear();
        filtered.filters = vec![PropertyFilter {
            key: "region".into(),
            op: "eq".into(),
            value: "eu".into(),
        }];
        let response = svc
            .federated_aggregate(as_principal(filtered, "analyst"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.groups.len(), 1, "{response:?}");
        assert_eq!(response.groups[0].values[0].value, 3.0);
    }

    /// A namespace whose index is quarantined or stale is excluded and
    /// reported, never evaluated.
    #[tokio::test]
    async fn a_quarantined_index_excludes_its_namespace() {
        let svc = federation();
        svc.db
            .runtime()
            .conn()
            .execute(
                "UPDATE sekai_object_type_index_status SET quarantine_reason = 'drift'
                 WHERE namespace = 'north'",
                [],
            )
            .unwrap();
        let response = svc
            .federated_aggregate(as_principal(
                request(&["north", "south"], vec![measure("count", "")]),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.contributors, ["south"]);
        assert_eq!(response.excluded.len(), 1);
        assert_eq!(
            (
                response.excluded[0].namespace.as_str(),
                response.excluded[0].reason.as_str()
            ),
            ("north", "unavailable")
        );
        let receipt = federated_receipt::get(svc.db.runtime(), &response.query_id, "north")
            .unwrap()
            .unwrap();
        assert_eq!(
            receipt.outcome.unwrap().excluded["north"],
            ExclusionReason::Unavailable
        );
    }

    /// The index snapshot is what is aggregated, so it is what is
    /// authorized: a snapshot marked beyond the principal's clearance stays
    /// out even when the live object is unmarked, and a live object of
    /// another namespace keeps its record out. A requester cannot also take
    /// part.
    #[tokio::test]
    async fn the_aggregated_snapshot_is_what_is_authorized() {
        let svc = service();
        grant_namespace(&svc, "buyer", "analyst");
        seed_marked_shipments(
            &svc,
            "north",
            &[
                ("n-1", "eu", "1"),
                ("n-2", "eu", "2"),
                ("n-3", "eu", "3"),
                ("n-4", "eu", "4"),
            ],
            &[("n-3", "restricted")],
        );
        allow(&svc, "north", 2, None);
        for (key, namespace) in [("n-3", "north"), ("n-2", "elsewhere")] {
            svc.db
                .runtime()
                .create_object(&domain::Object {
                    id: format!("Shipment:{key}"),
                    kind: "Shipment".into(),
                    name: key.into(),
                    namespace: namespace.into(),
                    external_id: key.into(),
                    properties: HashMap::from([("region".into(), "eu".into())]),
                    created: 1,
                    updated: 1,
                })
                .unwrap();
        }
        let response = svc
            .federated_aggregate(as_principal(
                request(
                    &["north"],
                    vec![measure("count", ""), measure("sum", "weight")],
                ),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.groups.len(), 1, "{response:?}");
        let values: Vec<f64> = response.groups[0]
            .values
            .iter()
            .map(|value| value.value)
            .collect();
        // n-1 and n-4 only.
        assert_eq!(values, [2.0, 5.0]);

        let error = svc
            .federated_aggregate(as_principal(
                request(&["north", "buyer"], vec![measure("count", "")]),
                "analyst",
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    type ScanHook = Box<dyn Fn(&SekaiServiceImpl, &str)>;

    thread_local! {
        /// Run after a namespace's index scan, before its status is read again.
        static AFTER_SCAN: std::cell::RefCell<Option<ScanHook>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn after_scan(svc: &SekaiServiceImpl, namespace: &str) {
        AFTER_SCAN.with(|hook| {
            if let Some(hook) = hook.borrow().as_ref() {
                hook(svc, namespace);
            }
        });
    }

    /// A member read twice counts once, so it cannot lift a one-record
    /// group to `k`.
    #[test]
    fn a_duplicated_member_does_not_reach_k() {
        let member = crate::sekai::object_type_index::ObjectTypeIndexMember {
            object_id: "Shipment:n-1".into(),
            properties: std::collections::BTreeMap::from([
                ("region".to_string(), "eu".to_string()),
                ("weight".to_string(), "1".to_string()),
            ])
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let parsed = parse_request(request(&["north"], vec![measure("count", "")])).unwrap();
        let rows = rows_from_members(&parsed.query, vec![member.clone(), member]);
        assert_eq!(rows.len(), 1);
        let allowance = Allowance {
            schema: ALLOWANCE_SCHEMA.into(),
            namespace: "north".into(),
            object_type: "Shipment".into(),
            dimensions: BTreeSet::from(["region".into()]),
            measures: BTreeSet::new(),
            functions: BTreeSet::from([AggregateFunction::Count]),
            min_group_size: 2,
            noise_scale: None,
            requesters: BTreeSet::from(["buyer".into()]),
        };
        let partial =
            rules::tenant_partial("north", &allowance, &parsed.query, rows, &mut OsRandom).unwrap();
        assert!(partial.groups.is_empty());
        assert_eq!(partial.suppressed_groups, 1);
    }

    /// An index that changes while it is read contributes nothing: the
    /// namespace is excluded as unavailable, in the result and its receipt.
    #[tokio::test]
    async fn an_index_change_during_the_scan_excludes_the_namespace() {
        let svc = federation();
        AFTER_SCAN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|svc: &SekaiServiceImpl, namespace: &str| {
                if namespace == "north" {
                    svc.db
                        .runtime()
                        .conn()
                        .execute(
                            "UPDATE sekai_object_type_index_status
                             SET member_count = member_count + 1 WHERE namespace = 'north'",
                            [],
                        )
                        .unwrap();
                }
            }));
        });
        let response = svc
            .federated_aggregate(as_principal(
                request(&["north", "south"], vec![measure("count", "")]),
                "analyst",
            ))
            .await;
        AFTER_SCAN.with(|hook| *hook.borrow_mut() = None);
        let response = response.unwrap().into_inner();
        assert_eq!(response.contributors, ["south"]);
        assert_eq!(
            (
                response.excluded[0].namespace.as_str(),
                response.excluded[0].reason.as_str()
            ),
            ("north", "unavailable")
        );
        let receipt = federated_receipt::get(svc.db.runtime(), &response.query_id, "north")
            .unwrap()
            .unwrap();
        let outcome = receipt.outcome.unwrap();
        assert_eq!(outcome.returned_groups, 0);
        assert_eq!(outcome.excluded["north"], ExclusionReason::Unavailable);
    }

    /// A rebuild marks the kind not ready before it clears members; one
    /// that stopped half-way (members cleared, status still healthy)
    /// excludes the namespace until it completes.
    #[tokio::test]
    async fn an_interrupted_rebuild_excludes_the_namespace() {
        let svc = federation();
        svc.db
            .runtime()
            .set_hop_projection_ready("north", "Shipment", false, 30)
            .unwrap();
        svc.db
            .runtime()
            .conn()
            .execute(
                "DELETE FROM sekai_object_type_index_member
                 WHERE namespace = 'north' AND source_key = 'n-1'",
                [],
            )
            .unwrap();
        let response = svc
            .federated_aggregate(as_principal(
                request(&["north", "south"], vec![measure("count", "")]),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.contributors, ["south"]);
        assert_eq!(
            (
                response.excluded[0].namespace.as_str(),
                response.excluded[0].reason.as_str()
            ),
            ("north", "unavailable")
        );
        // A completed rebuild makes it answer again.
        svc.db
            .runtime()
            .apply_object_type_index("north", "Shipment", true, 40)
            .unwrap();
        let response = svc
            .federated_aggregate(as_principal(
                request(&["north", "south"], vec![measure("count", "")]),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.contributors, ["north", "south"]);
    }

    /// A property the schema classifies restricted stays in its namespace
    /// even when the allowance names it: the namespace is excluded, and
    /// none of its values are returned.
    #[tokio::test]
    async fn a_restricted_property_excludes_its_namespace() {
        let svc = federation();
        let grant = security::Grant {
            id: "schema-admin".into(),
            object_id: "schema".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
        let property = |name: &str, kind: &str, classification: &str| PropertyDef {
            name: name.into(),
            r#type: kind.into(),
            required: false,
            description: String::new(),
            enum_values: vec![],
            link_kind: String::new(),
            compute_expr: String::new(),
            classification: classification.into(),
            struct_fields: vec![],
        };
        svc.create_schema_type(as_principal(
            CreateSchemaTypeRequest {
                r#type: Some(ObjectType {
                    kind: "Shipment".into(),
                    description: "shipments".into(),
                    properties: vec![
                        property("region", "string", "public"),
                        property("weight", "float", "sensitive"),
                    ],
                    ..Default::default()
                }),
            },
            "tester",
        ))
        .await
        .unwrap();
        let response = svc
            .federated_aggregate(as_principal(
                request(&["north", "south"], vec![measure("sum", "weight")]),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(response.groups.is_empty(), "{response:?}");
        assert!(response.contributors.is_empty());
        let reasons: Vec<_> = response
            .excluded
            .iter()
            .map(|exclusion| (exclusion.namespace.as_str(), exclusion.reason.as_str()))
            .collect();
        assert_eq!(
            reasons,
            [
                ("north", "restricted_property"),
                ("south", "restricted_property")
            ]
        );
        // Counting by a public dimension still works.
        let response = svc
            .federated_aggregate(as_principal(
                request(&["north", "south"], vec![measure("count", "")]),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.contributors, ["north", "south"]);
    }

    /// The federation principal is held to object ACLs like any principal,
    /// and the caller needs read on the requesting namespace, nothing more.
    #[tokio::test]
    async fn object_acls_apply_and_the_caller_needs_read_on_the_requester() {
        let svc = federation();
        // A grant to someone else makes n-1 private to them.
        let grant = security::Grant {
            id: "private-shipment".into(),
            object_id: "Shipment:n-1".into(),
            principal: "someone-else".into(),
            role: security::Role::Viewer,
            created: 1,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
        let response = svc
            .federated_aggregate(as_principal(
                request(&["north"], vec![measure("count", "")]),
                "analyst",
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.groups[0].values[0].value, 2.0);

        let error = svc
            .federated_aggregate(as_principal(
                request(&["north"], vec![measure("count", "")]),
                "stranger",
            ))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error.code(),
                tonic::Code::PermissionDenied | tonic::Code::NotFound
            ),
            "{error:?}"
        );
        // A requester the allowance does not accept is excluded.
        grant_namespace(&svc, "rival", "analyst");
        let mut rival = request(&["north"], vec![measure("count", "")]);
        rival.requester = "rival".into();
        let response = svc
            .federated_aggregate(as_principal(rival, "analyst"))
            .await
            .unwrap()
            .into_inner();
        assert!(response.groups.is_empty());
        assert_eq!(response.excluded[0].reason, "requester");
    }
}
