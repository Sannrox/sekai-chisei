//! Experimental permission-aware Search and GetSearchIndexStatus RPCs.

use super::*;
use crate::db::search_index::SearchIndexStore;
use crate::sekai::embedding_index::{EmbeddingError, EmbeddingStore};
use crate::sekai::search_index::{
    FUSION_PROFILE, POLICY_ATTRIBUTE_KEYS, SearchCandidate, SearchCandidateQuery, SearchIndex,
    SearchIndexError, SearchPolicyFilter, SearchQueryMode, SearchSourceKind, VectorCandidateQuery,
    dataset_classification_allows, live_object_match_fields, rrf_fuse, text_matches_query,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const SEARCH_CAPABILITY: &str = "sekai.search.query";
pub(crate) const SEARCH_STATUS_CAPABILITY: &str = "sekai.search.status";
pub(super) const DEFAULT_PAGE_SIZE: i32 = 20;
pub(crate) const MAX_PAGE_SIZE: i32 = 100;
pub(crate) const CANDIDATE_CAP: usize = 256;
const INDEX_OVERSCAN: usize = 10_000;

pub(super) async fn search(
    service: &SekaiServiceImpl,
    req: Request<SearchRequest>,
) -> Result<Response<SearchResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let purpose = request_purpose_presentation(&req, &principals);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    let namespace = input.namespace.trim();
    if namespace.is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    enforce_collaboration_namespace_for(
        service.db.runtime(),
        tenant_context.as_ref(),
        namespace,
        crate::enterprise::NamespaceAction::Discover,
    )?;
    check_team_namespace(service.db.runtime(), &principals, namespace, false)?;
    let namespace_read = enforce_collaboration_namespace(
        service.db.runtime(),
        tenant_context.as_ref(),
        namespace,
        false,
    )
    .is_ok();
    let source = match parse_search_source(&input.source)? {
        Some(SearchSourceKind::Object) if !namespace_read => {
            return Ok(Response::new(SearchResponse {
                hits: Vec::new(),
                count: 0,
                count_is_lower_bound: false,
                facets: Vec::new(),
                next_page_token: String::new(),
                authority: false,
                lag_ms: 0,
                ..Default::default()
            }));
        }
        None if !namespace_read => Some(SearchSourceKind::Dataset),
        source => source,
    };
    let page_size = normalize_page_size(input.page_size);
    let offset = parse_page_offset(&input.page_token)?;
    let weights = parse_hybrid_weights(&input)?;
    require_granted_search_properties(
        service.db.runtime(),
        namespace,
        &input.kinds,
        input
            .property_filters
            .iter()
            .map(|filter| filter.property.as_str())
            .chain(input.facets.iter().map(String::as_str)),
    )?;
    let now_ms = now_millis();
    service
        .db
        .runtime()
        .catch_up_search_namespace(namespace, now_ms)
        .map_err(search_status)?;
    let status = service
        .db
        .runtime()
        .status(namespace, now_ms)
        .map_err(search_status)?;
    let authority = resolve_principal_authority(service.db.runtime(), &principals)?;
    let presented_purpose = purpose
        .as_ref()
        .map(|item| item.purpose.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let policy_context = principal_policy_context_from(&principals, tenant_context.as_ref());
    let base_policy = SearchPolicyFilter {
        namespace: namespace.to_string(),
        namespace_authorized: true,
        kinds: Vec::new(),
        subjects: if policy_context.subjects.is_empty() {
            principals.clone()
        } else {
            policy_context.subjects.clone()
        },
        scopes: policy_context.scopes.clone(),
        clearance: authority.classification_ceiling_token(),
        visible_property_names: None,
        purpose: None,
        purpose_authorized: false,
    };
    let kind_scopes = if input.kinds.is_empty() {
        vec![Vec::new()]
    } else {
        let mut seen = BTreeSet::new();
        input
            .kinds
            .iter()
            .filter(|kind| seen.insert((*kind).clone()))
            .map(|kind| vec![kind.clone()])
            .collect::<Vec<_>>()
    };
    let mut candidates = Vec::new();
    let mut source_exhausted = true;
    for kinds in kind_scopes {
        let purpose_authorized =
            purpose_is_authorized(service.db.runtime(), namespace, &kinds, purpose.as_ref())?;
        let mut policy = base_policy.clone();
        policy.kinds = kinds;
        policy.purpose = if purpose_authorized {
            presented_purpose.clone()
        } else {
            None
        };
        policy.purpose_authorized = purpose_authorized;
        let (batch, exhausted) =
            query_search_candidates(service.db.runtime(), &input.text, source, &policy)?;
        if !exhausted {
            source_exhausted = false;
        }
        for candidate in batch {
            if candidates.iter().any(|existing: &SearchCandidate| {
                existing.source == candidate.source && existing.id == candidate.id
            }) {
                continue;
            }
            candidates.push(candidate);
        }
    }
    let mut visible = Vec::new();
    for candidate in candidates {
        if visible.len() >= CANDIDATE_CAP {
            break;
        }
        match candidate.source {
            SearchSourceKind::Object => {
                if let Some(hit) = live_object_hit(
                    service,
                    &candidate.id,
                    &input,
                    &principals,
                    tenant_context.as_ref(),
                    purpose.as_ref(),
                    None,
                )? {
                    visible.push(hit);
                }
            }
            SearchSourceKind::Dataset => {
                if let Some(hit) = live_dataset_hit(
                    service,
                    &candidate,
                    &input,
                    &principals,
                    tenant_context.as_ref(),
                    authority.classification_ceiling_token().as_deref(),
                    source,
                )? {
                    visible.push(hit);
                }
            }
        }
    }
    let mut capped = visible.len() >= CANDIDATE_CAP
        || (!source_exhausted && (!visible.is_empty() || !input.property_filters.is_empty()));
    let mut vector_lag_ms = 0;
    if let Some((text_weight, vector_weight)) = weights
        && vector_weight > 0.0
        && namespace_read
        && source != Some(SearchSourceKind::Dataset)
    {
        let route = service.embedding_route.as_ref().ok_or_else(|| {
            Status::failed_precondition("hybrid search needs an embedding route (combined mode)")
        })?;
        let mut vector_hits = Vec::new();
        for kind in vector_kinds(service.db.runtime(), namespace, &input.kinds)? {
            let mut policy = base_policy.clone();
            policy.kinds = vec![kind.object_kind.clone()];
            policy.purpose_authorized = purpose_is_authorized(
                service.db.runtime(),
                namespace,
                &policy.kinds,
                purpose.as_ref(),
            )?;
            if policy.purpose_authorized {
                policy.purpose = presented_purpose.clone();
            }
            let query = crate::composition::embedding_catch_up::embed_query(
                service.db.runtime(),
                namespace,
                &kind.object_kind,
                &input.text,
                |stored| route(stored),
                now_ms,
            )
            .await
            .map_err(embedding_status)?;
            vector_lag_ms = vector_lag_ms.max(query.lag_ms);
            let ranked = service
                .db
                .runtime()
                .vector_candidates(&VectorCandidateQuery {
                    spec_id: query.spec_id,
                    vector: query.vector,
                    policy,
                    limit: INDEX_OVERSCAN,
                })
                .map_err(search_status)?;
            for candidate in ranked {
                if vector_hits.len() >= CANDIDATE_CAP {
                    break;
                }
                if let Some(hit) = live_object_hit(
                    service,
                    &candidate.object_id,
                    &input,
                    &principals,
                    tenant_context.as_ref(),
                    purpose.as_ref(),
                    Some(&kind.properties),
                )? {
                    vector_hits.push(hit);
                }
            }
        }
        capped |= vector_hits.len() >= CANDIDATE_CAP;
        visible = fuse_hits(visible, vector_hits, text_weight, vector_weight);
    }
    let count = visible.len() as i64;
    let page = visible
        .iter()
        .skip(offset)
        .take(page_size)
        .map(|item| item.hit.clone())
        .collect::<Vec<_>>();
    let next_offset = offset.saturating_add(page.len());
    let next_page_token = if next_offset < visible.len() {
        next_offset.to_string()
    } else {
        String::new()
    };
    let facets = live_facets(&visible, &input.facets);
    Ok(Response::new(SearchResponse {
        hits: page,
        count,
        count_is_lower_bound: capped,
        facets,
        next_page_token,
        authority: false,
        lag_ms: status.lag_ms,
        fusion_profile: if weights.is_some() {
            FUSION_PROFILE.into()
        } else {
            String::new()
        },
        vector_lag_ms,
    }))
}

pub(super) async fn get_search_index_status(
    service: &SekaiServiceImpl,
    req: Request<GetSearchIndexStatusRequest>,
) -> Result<Response<GetSearchIndexStatusResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    let namespace = input.namespace.trim();
    if namespace.is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        namespace,
        false,
    )?;
    check_team_namespace(service.db.runtime(), &principals, namespace, false)?;
    let now_ms = now_millis();
    service
        .db
        .runtime()
        .catch_up_search_namespace(namespace, now_ms)
        .map_err(search_status)?;
    let status = service
        .db
        .runtime()
        .status(namespace, now_ms)
        .map_err(search_status)?;
    Ok(Response::new(GetSearchIndexStatusResponse {
        namespace: status.namespace,
        analyzer_version: status.analyzer_version,
        lag_ms: status.lag_ms,
        object_count: status.object_count,
        dataset_count: status.dataset_count,
        authority: false,
    }))
}

fn parse_search_source(source: &str) -> Result<Option<SearchSourceKind>, Status> {
    match source.trim() {
        "" | "all" => Ok(None),
        "object" => Ok(Some(SearchSourceKind::Object)),
        "dataset" => Ok(Some(SearchSourceKind::Dataset)),
        _ => Err(Status::invalid_argument(
            "source must be empty, object, or dataset",
        )),
    }
}

/// Hybrid weights `(text, vector)`, or none in text mode.
fn parse_hybrid_weights(input: &SearchRequest) -> Result<Option<(f64, f64)>, Status> {
    match input.mode.trim() {
        "" | "text" => return Ok(None),
        "hybrid" => {}
        _ => {
            return Err(Status::invalid_argument(
                "mode must be empty, text, or hybrid",
            ));
        }
    }
    if input.text.trim().is_empty() {
        return Err(Status::invalid_argument("hybrid search needs text"));
    }
    let weights = (input.text_weight, input.vector_weight);
    if [weights.0, weights.1]
        .iter()
        .any(|weight| !weight.is_finite() || *weight < 0.0)
    {
        return Err(Status::invalid_argument(
            "hybrid weights must be finite and not negative",
        ));
    }
    Ok(Some(if weights == (0.0, 0.0) {
        (1.0, 1.0)
    } else {
        weights
    }))
}

/// An object kind searched by vector, with its spec's source properties.
struct VectorKind {
    object_kind: String,
    properties: Vec<String>,
}

/// Kinds with a stored embedding spec, among `kinds` or all when empty.
/// A kind whose active policy withholds a source property is not searched:
/// its vectors carry text the caller may not read.
fn vector_kinds(
    db: &RuntimeDb,
    namespace: &str,
    kinds: &[String],
) -> Result<Vec<VectorKind>, Status> {
    let mut specs = BTreeMap::<String, Vec<String>>::new();
    for stored in db
        .list_embedding_specs(Some(namespace))
        .map_err(Status::internal)?
    {
        if kinds.is_empty() || kinds.contains(&stored.spec.object_kind) {
            specs
                .entry(stored.spec.object_kind)
                .or_insert(stored.spec.properties);
        }
    }
    let mut searched = Vec::new();
    for (object_kind, properties) in specs {
        let policy = db
            .active_object_policy(namespace, &object_kind)
            .map_err(|_| Status::unavailable("object authorization unavailable"))?;
        if policy.is_some_and(|policy| {
            policy.property_grants_enforced()
                && properties.iter().any(|name| {
                    !policy.allows_property_access(
                        name,
                        crate::sekai::object_security::PropertyGrantAccess::Read,
                    )
                })
        }) {
            continue;
        }
        searched.push(VectorKind {
            object_kind,
            properties,
        });
    }
    Ok(searched)
}

/// Fuse the visible text and vector hits under the RRF profile. A hit in
/// both lists keeps its text highlights.
fn fuse_hits(
    text: Vec<VisibleHit>,
    vector: Vec<VisibleHit>,
    text_weight: f64,
    vector_weight: f64,
) -> Vec<VisibleHit> {
    let key = |hit: &VisibleHit| (hit.hit.source.clone(), hit.hit.id.clone());
    let text_keys = text.iter().map(key).collect::<Vec<_>>();
    let vector_keys = vector.iter().map(key).collect::<Vec<_>>();
    let mut hits = BTreeMap::new();
    for hit in vector.into_iter().chain(text) {
        hits.insert(key(&hit), hit);
    }
    rrf_fuse(&[(&text_keys, text_weight), (&vector_keys, vector_weight)])
        .into_iter()
        .filter_map(|key| hits.remove(&key))
        .collect()
}

fn embedding_status(error: EmbeddingError) -> Status {
    match error {
        EmbeddingError::InvalidArgument(message) | EmbeddingError::Refused(message) => {
            Status::failed_precondition(message)
        }
        EmbeddingError::Model(message) | EmbeddingError::Conflict(message) => {
            Status::unavailable(message)
        }
        EmbeddingError::Storage(message) => Status::internal(message),
    }
}

fn normalize_page_size(page_size: i32) -> usize {
    if page_size <= 0 {
        DEFAULT_PAGE_SIZE as usize
    } else {
        page_size.min(MAX_PAGE_SIZE) as usize
    }
}

fn parse_page_offset(token: &str) -> Result<usize, Status> {
    if token.trim().is_empty() {
        return Ok(0);
    }
    token.parse::<usize>().map_err(|_| {
        Status::invalid_argument("page_token must be an offset from a previous Search response")
    })
}

fn purpose_is_authorized(
    db: &RuntimeDb,
    namespace: &str,
    kinds: &[String],
    presentation: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
) -> Result<bool, Status> {
    let Some(presented) = presentation.filter(|item| !item.purpose.is_empty()) else {
        return Ok(false);
    };
    if crate::sekai::markings::is_trusted_service_principal(&presented.actor) {
        return Ok(true);
    }
    let activation = db
        .get_object_security_activation(namespace)
        .map_err(Status::internal)?;
    let Some(activation) = activation else {
        return Ok(false);
    };
    let activation_digest =
        crate::sekai::object_security::object_security_activation_digest(&activation)
            .map_err(Status::internal)?;
    let kinds = if kinds.is_empty() {
        activation.policies.keys().cloned().collect::<Vec<_>>()
    } else {
        kinds.to_vec()
    };
    for kind in &kinds {
        if db
            .find_purpose_authorization(
                &presented.actor,
                &presented.purpose,
                namespace,
                kind,
                &activation_digest,
                now_millis(),
            )
            .map_err(|error| {
                if error.contains("unavailable") {
                    Status::unavailable("purpose authorization unavailable")
                } else {
                    Status::internal(error)
                }
            })?
            .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn query_search_candidates(
    db: &RuntimeDb,
    text: &str,
    source: Option<SearchSourceKind>,
    policy: &SearchPolicyFilter,
) -> Result<(Vec<SearchCandidate>, bool), Status> {
    let sources = match source {
        Some(kind) => vec![kind],
        None => vec![SearchSourceKind::Object, SearchSourceKind::Dataset],
    };
    let mut hits = Vec::new();
    let mut exhausted = true;
    for kind in sources {
        let batch = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: text.to_string(),
                source: Some(kind),
                policy: policy.clone(),
                limit: INDEX_OVERSCAN,
            })
            .map_err(search_status)?;
        if batch.len() >= INDEX_OVERSCAN {
            exhausted = false;
        }
        hits.extend(batch);
    }
    Ok((hits, exhausted))
}

fn require_granted_search_properties<'a>(
    db: &RuntimeDb,
    namespace: &str,
    kinds: &[String],
    properties: impl Iterator<Item = &'a str>,
) -> Result<(), Status> {
    let names = properties
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>();
    for name in &names {
        if POLICY_ATTRIBUTE_KEYS.contains(name) || name.starts_with('_') {
            return Err(Status::failed_precondition("ungranted search property"));
        }
    }
    if names.is_empty() || kinds.is_empty() {
        return Ok(());
    }
    for kind in kinds {
        let policy = db
            .active_object_policy(namespace, kind)
            .map_err(|_| Status::unavailable("object authorization unavailable"))?;
        let Some(policy) = policy else {
            continue;
        };
        if !policy.property_grants_enforced() {
            continue;
        }
        for name in &names {
            if matches!(*name, "kind" | "source") {
                continue;
            }
            if !policy.allows_property_access(
                name,
                crate::sekai::object_security::PropertyGrantAccess::Read,
            ) {
                return Err(Status::failed_precondition("ungranted search property"));
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct VisibleHit {
    hit: SearchHit,
    facet_values: BTreeMap<String, String>,
}

fn object_is_searchable(
    db: &RuntimeDb,
    security: &SecurityChecker,
    object: &crate::domain::Object,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
) -> bool {
    !is_reserved_governance_kind(&object.kind)
        && check_team_namespace(db, principals, &object.namespace, false).is_ok()
        && enforce_collaboration_namespace(db, tenant_context, &object.namespace, false).is_ok()
        && collaboration_object_permitted(
            db,
            tenant_context,
            object,
            crate::enterprise::NamespaceAction::Read,
        )
        .unwrap_or(false)
        && check_read(security, &object.id, principals).is_ok()
        && object_passes_marking(db, object, principals).unwrap_or(false)
        && object_passes_security_policy(
            db,
            object,
            principals,
            tenant_context,
            crate::sekai::object_security::ObjectSecurityOperation::Read,
            purpose,
        )
        .unwrap_or(false)
}

/// The live, policy-checked hit for an object candidate. A text candidate
/// must still match the query text. A vector candidate (`vector_sources`,
/// the spec's source properties) need not, but every source property the
/// object has must survive the caller's property projection.
fn live_object_hit(
    service: &SekaiServiceImpl,
    object_id: &str,
    input: &SearchRequest,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    purpose: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    vector_sources: Option<&[String]>,
) -> Result<Option<VisibleHit>, Status> {
    let Some(object) = service
        .db
        .runtime()
        .get_object(object_id)
        .map_err(Status::internal)?
    else {
        return Ok(None);
    };
    if object.namespace != input.namespace {
        return Ok(None);
    }
    if !object_is_searchable(
        service.db.runtime(),
        &service.security,
        &object,
        principals,
        tenant_context,
        purpose,
    ) {
        return Ok(None);
    }
    let mut live = object.clone();
    if let Ok(Some(policy)) = service
        .db
        .runtime()
        .active_object_policy(&object.namespace, &object.kind)
    {
        if input.property_filters.iter().any(|filter| {
            let property = filter.property.trim();
            policy.property_grants_enforced()
                && !policy.allows_property_access(
                    property,
                    crate::sekai::object_security::PropertyGrantAccess::Read,
                )
        }) || input.facets.iter().any(|field| {
            let property = field.trim();
            !matches!(property, "kind" | "source")
                && policy.property_grants_enforced()
                && !policy.allows_property_access(
                    property,
                    crate::sekai::object_security::PropertyGrantAccess::Read,
                )
        }) || (policy.value_instance_grants_enforced()
            && (input
                .property_filters
                .iter()
                .any(|filter| filter.property.trim() == "name")
                || input.facets.iter().any(|field| field.trim() == "name"))
            && !policy.allows_value_instance_access(
                &object.id,
                "name",
                &object.name,
                crate::sekai::object_security::PropertyGrantAccess::Read,
            ))
        {
            return Err(Status::failed_precondition("ungranted search property"));
        }
        policy.project_visible_properties(&mut live);
        policy.project_visible_value_instances(&mut live);
        if (policy.property_grants_enforced()
            && !policy.allows_property_access(
                "name",
                crate::sekai::object_security::PropertyGrantAccess::Read,
            ))
            || (policy.value_instance_grants_enforced()
                && !policy.allows_value_instance_access(
                    &live.id,
                    "name",
                    &live.name,
                    crate::sekai::object_security::PropertyGrantAccess::Read,
                ))
        {
            live.name.clear();
        }
    }
    if !live_object_matches_filters(&live, &input.property_filters) {
        return Ok(None);
    }
    if vector_sources.is_some_and(|sources| {
        sources
            .iter()
            .any(|name| object.properties.contains_key(name) && !live.properties.contains_key(name))
    }) {
        return Ok(None);
    }
    let matched = if input.text.trim().is_empty() {
        BTreeSet::new()
    } else {
        live_object_match_fields(&live, &input.text)
    };
    if vector_sources.is_none() && !input.text.trim().is_empty() && matched.is_empty() {
        return Ok(None);
    }
    Ok(Some(VisibleHit {
        hit: SearchHit {
            source: "object".into(),
            id: live.id.clone(),
            kind: live.kind.clone(),
            highlights: highlights_for_object(&live, &matched),
            authority: false,
        },
        facet_values: object_facet_values(&live, &input.facets),
    }))
}

fn live_dataset_hit(
    service: &SekaiServiceImpl,
    candidate: &SearchCandidate,
    input: &SearchRequest,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    clearance: Option<&str>,
    source: Option<SearchSourceKind>,
) -> Result<Option<VisibleHit>, Status> {
    let Some(dataset) = service
        .db
        .runtime()
        .get_dataset(&candidate.id)
        .map_err(Status::internal)?
    else {
        return Ok(None);
    };
    if !catalog_binding_discoverable(
        service.db.runtime(),
        &service.security,
        tenant_context,
        &dataset.object_id,
        principals,
    ) {
        return Ok(None);
    }
    if !live_dataset_matches_filters(&dataset, &input.property_filters, source)? {
        return Ok(None);
    }
    let mut fields = BTreeSet::new();
    if text_matches_query(&dataset.name, &input.text) {
        fields.insert("name".into());
    }
    for column in &dataset.columns {
        if !text_matches_query(&column.name, &input.text) {
            continue;
        }
        if !dataset_classification_allows(&column.classification, clearance) {
            continue;
        }
        fields.insert(format!("column:{}", column.name));
    }
    if fields.is_empty() {
        return Ok(None);
    }
    let facet_values = dataset_facet_values(&dataset, &input.facets);
    Ok(Some(VisibleHit {
        hit: SearchHit {
            source: "dataset".into(),
            id: dataset.id,
            kind: "dataset".into(),
            highlights: fields
                .into_iter()
                .map(|field| {
                    let text = if field == "name" {
                        dataset.name.clone()
                    } else {
                        field
                            .strip_prefix("column:")
                            .unwrap_or(field.as_str())
                            .to_string()
                    };
                    SearchHighlight { field, text }
                })
                .collect(),
            authority: false,
        },
        facet_values,
    }))
}

fn live_dataset_matches_filters(
    dataset: &crate::sekai::dataset::Dataset,
    filters: &[SearchPropertyFilter],
    source: Option<SearchSourceKind>,
) -> Result<bool, Status> {
    for filter in filters {
        match filter.property.as_str() {
            "name" => {
                if dataset.name != filter.value {
                    return Ok(false);
                }
            }
            _ if source == Some(SearchSourceKind::Dataset) => {
                return Err(Status::failed_precondition("ungranted search property"));
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn live_object_matches_filters(
    object: &crate::domain::Object,
    filters: &[SearchPropertyFilter],
) -> bool {
    filters.iter().all(|filter| {
        let expected = filter.value.as_str();
        if filter.property == "name" {
            object.name == expected
        } else {
            object
                .properties
                .get(&filter.property)
                .is_some_and(|value| value == expected)
        }
    })
}

fn highlights_for_object(
    object: &crate::domain::Object,
    matched: &BTreeSet<String>,
) -> Vec<SearchHighlight> {
    matched
        .iter()
        .filter_map(|field| {
            let text = if field == "name" {
                object.name.clone()
            } else {
                object.properties.get(field)?.clone()
            };
            Some(SearchHighlight {
                field: field.clone(),
                text,
            })
        })
        .collect()
}

fn object_facet_values(
    object: &crate::domain::Object,
    requested: &[String],
) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for field in requested {
        let value = match field.as_str() {
            "kind" => Some(object.kind.clone()),
            "source" => Some("object".into()),
            "name" => Some(object.name.clone()),
            other => object.properties.get(other).cloned(),
        };
        if let Some(value) = value {
            values.insert(field.clone(), value);
        }
    }
    values
}

fn dataset_facet_values(
    dataset: &crate::sekai::dataset::Dataset,
    requested: &[String],
) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for field in requested {
        let value = match field.as_str() {
            "kind" => Some("dataset".into()),
            "source" => Some("dataset".into()),
            "name" => Some(dataset.name.clone()),
            _ => None,
        };
        if let Some(value) = value {
            values.insert(field.clone(), value);
        }
    }
    values
}

fn live_facets(hits: &[VisibleHit], requested: &[String]) -> Vec<SearchFacet> {
    requested
        .iter()
        .map(|field| {
            let mut values: BTreeMap<String, i64> = BTreeMap::new();
            for hit in hits {
                if let Some(value) = hit.facet_values.get(field) {
                    *values.entry(value.clone()).or_insert(0) += 1;
                }
            }
            SearchFacet {
                field: field.clone(),
                values: values
                    .into_iter()
                    .map(|(value, count)| SearchFacetValue { value, count })
                    .collect(),
            }
        })
        .collect()
}

fn search_status(error: SearchIndexError) -> Status {
    match error {
        SearchIndexError::Unavailable(message) => Status::unavailable(message),
        SearchIndexError::InvalidArgument(message) => Status::invalid_argument(message),
        SearchIndexError::Storage(message) => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::object_security::{
        OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
        ObjectSecurityPredicate, ObjectSecurityRule, PropertyGrant, PropertyGrantAccess,
    };
    use crate::sekai::search_index::ANALYZER_VERSION;
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service_from(db: RuntimeDb) -> SekaiServiceImpl {
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
            db,
        )))
    }

    fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn object(id: &str, namespace: &str, name: &str, properties: &[(&str, &str)]) -> Object {
        Object {
            id: id.into(),
            kind: "note".into(),
            name: name.into(),
            namespace: namespace.into(),
            external_id: String::new(),
            properties: properties
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
            created: 1,
            updated: 1,
        }
    }

    fn dataset(id: &str, name: &str, object_id: &str, columns: &[(&str, &str)]) -> Dataset {
        Dataset {
            id: id.into(),
            name: name.into(),
            columns: columns
                .iter()
                .map(|(name, classification)| ColumnDef {
                    name: (*name).into(),
                    col_type: "string".into(),
                    classification: (*classification).into(),
                })
                .collect(),
            object_id: object_id.into(),
            created: 1,
            partition_keys: Vec::new(),
        }
    }

    fn activate_property_grants(db: &RuntimeDb, readable: &[&str]) {
        let policy = ObjectSecurityPolicy {
            contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "acme".into(),
            kind: "note".into(),
            rules: vec![ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(
                readable
                    .iter()
                    .map(|property| PropertyGrant {
                        property: (*property).into(),
                        access: PropertyGrantAccess::Read,
                    })
                    .collect(),
            ),
            value_instance_grants: None,
            required_purpose: None,
        };
        let revision = db
            .put_object_security_policy(&policy, "root", "put-search-grants", 1)
            .unwrap();
        let mut policies = BTreeMap::new();
        policies.insert("note".into(), revision.revision_digest);
        db.activate_object_security_policies("acme", &policies, "root", "activate-search", 2)
            .unwrap();
    }

    fn search_req(text: &str) -> SearchRequest {
        SearchRequest {
            namespace: "acme".into(),
            text: text.into(),
            kinds: Vec::new(),
            property_filters: Vec::new(),
            facets: Vec::new(),
            page_token: String::new(),
            page_size: 20,
            source: "object".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn visible_object_is_returned_with_live_highlights() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object("note-1", "acme", "alpha", &[("body", "join customers")]),
            "tester",
        )
        .unwrap();
        let svc = service_from(db);
        let response = search(
            &svc,
            with_named_principal(search_req("customers"), "tester"),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "note-1");
        assert_eq!(response.hits[0].source, "object");
        assert!(!response.authority);
        assert!(!response.count_is_lower_bound);
        assert_eq!(response.count, 1);
        assert!(
            response.hits[0]
                .highlights
                .iter()
                .any(|item| item.field == "body" && item.text.contains("customers"))
        );
    }

    #[tokio::test]
    async fn hidden_matches_do_not_displace_visible_hits_or_lower_bound_an_empty_page() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object("visible", "acme", "visible", &[("body", "shared token")]),
            "tester",
        )
        .unwrap();
        for index in 0..40 {
            db.create_object_with_audit(
                &object(
                    &format!("hidden-{index}"),
                    "acme",
                    "hidden",
                    &[("body", "shared token"), ("owner", "alice")],
                ),
                "alice",
            )
            .unwrap();
        }
        let svc = service_from(db);
        let mut req = search_req("shared");
        req.page_size = 5;
        let response = search(&svc, with_named_principal(req, "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            response
                .hits
                .iter()
                .map(|hit| hit.id.as_str())
                .collect::<Vec<_>>(),
            vec!["visible"]
        );
        assert_eq!(response.count, 1);
        assert!(!response.count_is_lower_bound);
        let empty = search(&svc, with_named_principal(search_req("missing"), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert!(empty.hits.is_empty());
        assert_eq!(empty.count, 0);
        assert!(!empty.count_is_lower_bound);
    }

    #[tokio::test]
    async fn ungranted_property_filter_fails_closed() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object(
                "note-1",
                "acme",
                "alpha",
                &[("body", "visible cell"), ("secret", "hidden token")],
            ),
            "tester",
        )
        .unwrap();
        activate_property_grants(&db, &["name", "body"]);
        let svc = service_from(db);
        let mut req = search_req("visible");
        req.kinds = vec!["note".into()];
        req.property_filters = vec![SearchPropertyFilter {
            property: "secret".into(),
            value: "hidden token".into(),
        }];
        let error = search(&svc, with_named_principal(req, "tester"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn ungranted_name_is_not_highlighted_or_faceted() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object("note-1", "acme", "secret-name", &[("body", "visible cell")]),
            "tester",
        )
        .unwrap();
        activate_property_grants(&db, &["body"]);
        let svc = service_from(db);
        let mut req = search_req("visible");
        req.kinds = vec!["note".into()];
        req.facets = vec!["name".into()];
        let error = search(&svc, with_named_principal(req, "tester"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        let mut allowed = search_req("visible");
        allowed.kinds = vec!["note".into()];
        let response = search(&svc, with_named_principal(allowed, "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.hits.len(), 1);
        assert!(
            response.hits[0]
                .highlights
                .iter()
                .all(|item| item.field != "name" && item.text != "secret-name")
        );
    }

    #[tokio::test]
    async fn hidden_cell_stops_producing_hits_after_live_projection() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object(
                "note-1",
                "acme",
                "alpha",
                &[("body", "visible cell"), ("secret", "hidden token")],
            ),
            "tester",
        )
        .unwrap();
        activate_property_grants(&db, &["name", "body"]);
        let svc = service_from(db);
        let hidden = search(&svc, with_named_principal(search_req("hidden"), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert!(hidden.hits.is_empty());
        assert_eq!(hidden.count, 0);
        let visible = search(&svc, with_named_principal(search_req("visible"), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(visible.hits.len(), 1);
    }

    #[tokio::test]
    async fn edits_appear_after_index_catch_up_and_match_rebuild() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object("note-1", "acme", "alpha", &[("body", "join customers")]),
            "tester",
        )
        .unwrap();
        let svc = service_from(db);
        let first = search(
            &svc,
            with_named_principal(search_req("customers"), "tester"),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(first.hits.len(), 1);
        let mut updated = object("note-1", "acme", "alpha", &[("body", "renamed ledger")]);
        updated.created = 1;
        updated.updated = 2;
        svc.db
            .runtime()
            .update_object_with_audit(&updated, "tester")
            .unwrap();
        let after_edit = search(&svc, with_named_principal(search_req("ledger"), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(after_edit.hits.len(), 1);
        svc.db
            .runtime()
            .rebuild_namespace("acme", now_millis())
            .unwrap();
        let after_rebuild = search(&svc, with_named_principal(search_req("ledger"), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(after_rebuild.hits.len(), 1);
        assert_eq!(after_rebuild.hits[0].id, after_edit.hits[0].id);
    }

    #[tokio::test]
    async fn dataset_metadata_is_discoverable_without_row_contents() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(&object("owner", "acme", "owner", &[]), "tester")
            .unwrap();
        db.create_dataset(&dataset(
            "ds-sales",
            "sales-renamed",
            "owner",
            &[("id", "public"), ("amount", "internal")],
        ))
        .unwrap();
        let svc = service_from(db);
        let mut req = search_req("sales");
        req.source = "dataset".into();
        let response = search(&svc, with_named_principal(req, "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].source, "dataset");
        assert_eq!(response.hits[0].id, "ds-sales");
    }

    #[tokio::test]
    async fn search_index_status_is_non_authoritative() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object("note-1", "acme", "alpha", &[("body", "join customers")]),
            "tester",
        )
        .unwrap();
        let svc = service_from(db);
        let status = get_search_index_status(
            &svc,
            with_named_principal(
                GetSearchIndexStatusRequest {
                    namespace: "acme".into(),
                },
                "tester",
            ),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(status.analyzer_version, ANALYZER_VERSION);
        assert!(!status.authority);
        assert!(status.object_count >= 1);
    }

    #[tokio::test]
    async fn facets_use_live_projection_not_highlights() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object(
                "note-1",
                "acme",
                "alpha",
                &[("body", "join customers"), ("status", "open")],
            ),
            "tester",
        )
        .unwrap();
        let svc = service_from(db);
        let mut req = search_req("customers");
        req.facets = vec!["status".into()];
        let response = search(&svc, with_named_principal(req, "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.facets.len(), 1);
        assert_eq!(response.facets[0].field, "status");
        assert_eq!(response.facets[0].values[0].value, "open");
        assert_eq!(response.facets[0].values[0].count, 1);
    }

    #[tokio::test]
    async fn dataset_name_filter_applies_and_unsupported_filters_fail_closed() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(&object("owner", "acme", "owner", &[]), "tester")
            .unwrap();
        db.create_dataset(&dataset(
            "ds-sales",
            "sales-renamed",
            "owner",
            &[("id", "public")],
        ))
        .unwrap();
        db.create_dataset(&dataset(
            "ds-other",
            "other-catalog",
            "owner",
            &[("id", "public")],
        ))
        .unwrap();
        let svc = service_from(db);
        let mut req = search_req("sales");
        req.source = "dataset".into();
        req.property_filters = vec![SearchPropertyFilter {
            property: "name".into(),
            value: "sales-renamed".into(),
        }];
        let response = search(&svc, with_named_principal(req, "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].id, "ds-sales");
        let mut denied = search_req("sales");
        denied.source = "dataset".into();
        denied.property_filters = vec![SearchPropertyFilter {
            property: "body".into(),
            value: "nope".into(),
        }];
        let error = search(&svc, with_named_principal(denied, "tester"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn last_page_does_not_repeat_a_continuation_token() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object("note-1", "acme", "alpha", &[("body", "shared token")]),
            "tester",
        )
        .unwrap();
        db.create_object_with_audit(
            &object("note-2", "acme", "beta", &[("body", "shared token")]),
            "tester",
        )
        .unwrap();
        let svc = service_from(db);
        let mut req = search_req("shared");
        req.page_size = 1;
        let first = search(&svc, with_named_principal(req.clone(), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first.hits.len(), 1);
        assert_eq!(first.next_page_token, "1");
        req.page_token = first.next_page_token;
        let second = search(&svc, with_named_principal(req.clone(), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second.hits.len(), 1);
        assert!(second.next_page_token.is_empty());
        req.page_token = "2".into();
        let empty = search(&svc, with_named_principal(req, "tester"))
            .await
            .unwrap()
            .into_inner();
        assert!(empty.hits.is_empty());
        assert!(empty.next_page_token.is_empty());
    }

    #[tokio::test]
    async fn unauthenticated_search_is_rejected() {
        let svc = service_from(RuntimeDb::memory());
        let error = search(&svc, Request::new(search_req("customers")))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }

    /// A topic embedder: one axis for cats, one for dogs, so "kitten" is
    /// near "cat" without sharing a word with it.
    struct Topic;

    #[async_trait::async_trait]
    impl chisei_provider::embedding::Embedder for Topic {
        fn model(&self) -> &str {
            "topic"
        }
        fn model_version(&self) -> &str {
            "v1"
        }
        fn external(&self) -> bool {
            false
        }
        async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
            let axis = |text: &str, words: &[&str]| {
                f32::from(u8::from(words.iter().any(|word| text.contains(word))))
            };
            Ok(texts
                .iter()
                .map(|text| {
                    vec![
                        axis(text, &["cat", "kitten"]),
                        axis(text, &["dog", "puppy"]),
                        0.01,
                    ]
                })
                .collect())
        }
    }

    fn topic_route() -> crate::composition::embedding_catch_up::EmbeddingRoute {
        Arc::new(|_| {
            Box::pin(async { Ok(Box::new(Topic) as Box<dyn chisei_provider::embedding::Embedder>) })
        })
    }

    async fn hybrid_service(db: RuntimeDb) -> SekaiServiceImpl {
        // Names share no word with the queries, so text matches only bodies.
        for (id, body, owner) in [
            ("cat-1", "cat sleeps", "tester"),
            ("kitten-1", "kitten naps", "tester"),
            ("puppy-1", "puppy runs", "tester"),
            ("kitten-hidden", "kitten secret", "alice"),
        ] {
            let mut properties = vec![("body", body)];
            if owner == "alice" {
                properties.push(("owner", owner));
            }
            db.create_object_with_audit(&object(id, "acme", "note", &properties), owner)
                .unwrap();
        }
        db.put_embedding_spec(&crate::sekai::embedding_index::StoredEmbeddingSpec {
            spec: crate::sekai::embedding_index::EmbeddingSpec {
                id: "notes".into(),
                namespace: "acme".into(),
                object_kind: "note".into(),
                properties: vec!["body".into()],
                chunk_chars: 1_000,
                dimension: 3,
                batch_size: 8,
            },
            model: "topic".into(),
            updated_by: "admin".into(),
            updated_at_ms: 1,
            revision: 0,
        })
        .unwrap();
        let route = topic_route();
        crate::composition::embedding_catch_up::catch_up_stored_specs(
            &db,
            |stored| route(stored),
            &|| 1_000,
        )
        .await
        .unwrap();
        service_from(db).with_embedding_route(route)
    }

    fn hybrid_req(text: &str) -> SearchRequest {
        SearchRequest {
            mode: "hybrid".into(),
            ..search_req(text)
        }
    }

    fn hit_ids(response: &SearchResponse) -> Vec<&str> {
        response.hits.iter().map(|hit| hit.id.as_str()).collect()
    }

    #[tokio::test]
    async fn hybrid_search_fuses_vector_hits_the_caller_may_read() {
        let svc = hybrid_service(RuntimeDb::memory()).await;
        let text = search(&svc, with_named_principal(search_req("cat"), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(hit_ids(&text), vec!["cat-1"]);
        assert!(text.fusion_profile.is_empty());

        let hybrid = search(&svc, with_named_principal(hybrid_req("cat"), "tester"))
            .await
            .unwrap()
            .into_inner();
        // In both lists first; the kitten only by meaning; the hidden kitten
        // never, though its vector is as near as the visible one.
        assert_eq!(hit_ids(&hybrid), vec!["cat-1", "kitten-1", "puppy-1"]);
        assert_eq!(hybrid.count, 3);
        assert_eq!(hybrid.fusion_profile, FUSION_PROFILE);
        assert_eq!(hybrid.vector_lag_ms, 0);
        let again = search(&svc, with_named_principal(hybrid_req("cat"), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(hit_ids(&again), hit_ids(&hybrid));

        let owner = search(&svc, with_named_principal(hybrid_req("cat"), "alice"))
            .await
            .unwrap()
            .into_inner();
        assert!(hit_ids(&owner).contains(&"kitten-hidden"), "{owner:?}");

        let mut vector_only = hybrid_req("cat");
        vector_only.text_weight = 0.0;
        vector_only.vector_weight = 1.0;
        let vector_only = search(&svc, with_named_principal(vector_only, "tester"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(&hit_ids(&vector_only)[..2], ["cat-1", "kitten-1"]);
    }

    #[tokio::test]
    async fn hybrid_search_skips_vectors_of_properties_the_caller_may_not_read() {
        let db = RuntimeDb::memory();
        let svc = hybrid_service(db.clone()).await;
        activate_property_grants(&db, &["name"]);
        let hybrid = search(&svc, with_named_principal(hybrid_req("kitten"), "tester"))
            .await
            .unwrap()
            .into_inner();
        assert!(hybrid.hits.is_empty(), "{hybrid:?}");
        assert_eq!(hybrid.count, 0);
    }

    #[tokio::test]
    async fn hybrid_search_without_an_embedding_route_fails_closed() {
        let db = RuntimeDb::memory();
        db.create_object_with_audit(
            &object("cat-1", "acme", "cat", &[("body", "cat")]),
            "tester",
        )
        .unwrap();
        let svc = service_from(db);
        let status = search(&svc, with_named_principal(hybrid_req("cat"), "tester"))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        let mut negative = hybrid_req("cat");
        negative.vector_weight = -1.0;
        let status = search(&svc, with_named_principal(negative, "tester"))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }
}
