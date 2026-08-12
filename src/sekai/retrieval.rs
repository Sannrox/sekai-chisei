use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, Link, Object};
use crate::sekai::ontology::OntologyRegistry;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, hash_map::Entry};
use std::fmt;
use std::time::{Duration, Instant};

pub const DEFAULT_MAX_DEPTH: u32 = 0;
pub const MAX_DEPTH: u32 = 3;
pub const DEFAULT_MAX_OBJECTS: u32 = 20;
pub const MAX_OBJECTS: u32 = 100;
pub const DEFAULT_MAX_LINKS: u32 = 40;
pub const MAX_LINKS: u32 = 200;
pub const MAX_ROOTS: usize = 32;
pub const MAX_RELATIONS: usize = 32;
pub const MAX_KIND_FILTERS: usize = 32;
pub const DEFAULT_MAX_SOURCE_ROWS: u32 = 200;
pub const MAX_SOURCE_ROWS: u32 = 1000;
pub const DEFAULT_MAX_DERIVED_ROWS: u32 = 100;
pub const MAX_DERIVED_ROWS: u32 = 500;
pub const DEFAULT_MAX_DERIVATION_STEPS: u32 = 12;
pub const MAX_DERIVATION_STEPS: u32 = 32;
pub const DEFAULT_MAX_TIME_MS: u32 = 100;
pub const MAX_TIME_MS: u32 = 1000;
pub const DEFAULT_MAX_EXPLANATION_BYTES: u64 = 1024 * 1024;
pub const MAX_EXPLANATION_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReasoningMode {
    #[default]
    AssertedOnly,
    Entailment,
}

impl ReasoningMode {
    pub fn parse(value: &str) -> Result<Self, RetrievalError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "asserted_only" => Ok(Self::AssertedOnly),
            "entailment" => Ok(Self::Entailment),
            _ => Err(RetrievalError::InvalidArgument(
                "reasoning_mode must be asserted_only or entailment".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RetrievalDirection {
    Outgoing,
    Incoming,
    #[default]
    Both,
}

impl RetrievalDirection {
    pub fn parse(value: &str) -> Result<Self, RetrievalError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "both" => Ok(Self::Both),
            "outgoing" => Ok(Self::Outgoing),
            "incoming" => Ok(Self::Incoming),
            _ => Err(RetrievalError::InvalidArgument(
                "direction must be outgoing, incoming, or both".into(),
            )),
        }
    }

    fn db_directions(self) -> &'static [Direction] {
        const OUTGOING: &[Direction] = &[Direction::Outgoing];
        const INCOMING: &[Direction] = &[Direction::Incoming];
        const BOTH: &[Direction] = &[Direction::Outgoing, Direction::Incoming];
        match self {
            Self::Outgoing => OUTGOING,
            Self::Incoming => INCOMING,
            Self::Both => BOTH,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrievalRoot {
    Object(String),
    External(String),
    Link(String),
}

#[derive(Debug, Clone, Default)]
pub struct RetrievalQuery {
    pub roots: Vec<RetrievalRoot>,
    pub relations: Vec<String>,
    pub direction: RetrievalDirection,
    pub max_depth: u32,
    pub max_objects: u32,
    pub max_links: u32,
    pub kind_filter: Vec<String>,
    pub reasoning_mode: ReasoningMode,
    pub max_source_rows: u32,
    pub max_derived_rows: u32,
    pub max_derivation_steps: u32,
    pub max_time_ms: u32,
    pub max_explanation_bytes: u64,
    pub initial_source_rows: u32,
    pub source_rows_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationStep {
    pub kind: &'static str,
    pub relation: String,
    pub from_id: String,
    pub to_id: String,
    pub source_fact_ids: Vec<String>,
    pub ontology_revision: String,
    pub rule: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Explanation {
    pub steps: Vec<DerivationStep>,
    pub source_fact_ids: Vec<String>,
    pub ontology_revision: String,
    pub derived: bool,
    pub steps_truncated: bool,
}

#[derive(Debug, Clone)]
pub struct RetrievalCandidate {
    pub object: Object,
    pub depth: u32,
    pub via_relation: String,
    pub affinity: f64,
    pub explanation: Explanation,
    requires_derivation: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RetrievalResult {
    pub candidates: Vec<RetrievalCandidate>,
    pub links: Vec<Link>,
    pub truncated: bool,
    pub unresolved_roots: u32,
    /// Count of roots that resolved to a reserved or unauthorized object.
    ///
    /// This is deliberately kept separate from `unresolved_roots` so the
    /// gRPC projection can make root denial observationally equivalent to a
    /// missing root without changing the retrieval engine's internal
    /// accounting or its unit-test diagnostics.
    pub denied_roots: u32,
    pub denied_objects: u32,
    pub truncated_objects: u32,
    pub truncated_links: u32,
    pub truncation_reasons: Vec<String>,
    pub source_rows: u32,
    pub derived_rows: u32,
    pub ontology_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrievalError {
    InvalidArgument(String),
    Storage(String),
}

impl fmt::Display for RetrievalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(message) | Self::Storage(message) => f.write_str(message),
        }
    }
}

/// A deterministic graph-context affinity score. Shorter paths are more
/// relevant; candidates reached from multiple distinct roots receive a small,
/// capped corroboration bonus. The cap keeps every depth-zero root ahead of
/// every traversed candidate.
pub fn context_affinity_score(depth: u32, root_hits: usize) -> f64 {
    let proximity = 1.0 / f64::from(depth.saturating_add(1));
    let corroboration = 0.05 * root_hits.saturating_sub(1).min(4) as f64;
    proximity + corroboration
}

struct CandidateState {
    object: Object,
    depth: u32,
    via_relation: String,
    origins: BTreeSet<String>,
    is_root: bool,
    path: Vec<Link>,
}

impl CandidateState {
    fn new(
        object: Object,
        depth: u32,
        via_relation: String,
        origin: String,
        is_root: bool,
    ) -> Self {
        Self {
            object,
            depth,
            via_relation,
            origins: BTreeSet::from([origin]),
            is_root,
            path: Vec::new(),
        }
    }

    fn observe(&mut self, depth: u32, via_relation: &str, origin: &str, is_root: bool) {
        self.origins.insert(origin.to_string());
        self.is_root |= is_root;
        if depth < self.depth
            || (depth == self.depth
                && !via_relation.is_empty()
                && (self.via_relation.is_empty() || via_relation < self.via_relation.as_str()))
        {
            self.depth = depth;
            self.via_relation = via_relation.to_string();
        }
        if is_root {
            self.depth = 0;
            self.via_relation.clear();
        }
    }

    fn observe_path(&mut self, path: &[Link]) {
        if self.path.is_empty() || path.len() < self.path.len() {
            self.path = path.to_vec();
        }
    }
}

pub fn retrieve<F, G>(
    db: &RuntimeDb,
    query: &RetrievalQuery,
    can_read: F,
    is_forbidden: G,
) -> Result<RetrievalResult, RetrievalError>
where
    F: Fn(&Object) -> bool,
    G: Fn(&Object) -> bool,
{
    retrieve_with_ontology_started(db, query, None, Instant::now(), can_read, is_forbidden)
}

pub fn retrieve_with_ontology<F, G>(
    db: &RuntimeDb,
    query: &RetrievalQuery,
    ontology: Option<&OntologyRegistry>,
    can_read: F,
    is_forbidden: G,
) -> Result<RetrievalResult, RetrievalError>
where
    F: Fn(&Object) -> bool,
    G: Fn(&Object) -> bool,
{
    retrieve_with_ontology_started(db, query, ontology, Instant::now(), can_read, is_forbidden)
}

pub fn retrieve_with_ontology_started<F, G>(
    db: &RuntimeDb,
    query: &RetrievalQuery,
    ontology: Option<&OntologyRegistry>,
    started: Instant,
    can_read: F,
    is_forbidden: G,
) -> Result<RetrievalResult, RetrievalError>
where
    F: Fn(&Object) -> bool,
    G: Fn(&Object) -> bool,
{
    if query.reasoning_mode == ReasoningMode::Entailment && ontology.is_none() {
        return Err(RetrievalError::InvalidArgument(
            "entailment reasoning requires an ontology snapshot".into(),
        ));
    }
    if query.roots.is_empty() {
        return Err(RetrievalError::InvalidArgument(
            "at least one context root is required".into(),
        ));
    }
    if query.roots.len() > MAX_ROOTS {
        return Err(RetrievalError::InvalidArgument(format!(
            "at most {MAX_ROOTS} context roots are allowed"
        )));
    }
    if query.relations.len() > MAX_RELATIONS {
        return Err(RetrievalError::InvalidArgument(format!(
            "at most {MAX_RELATIONS} relation filters are allowed"
        )));
    }
    if query.kind_filter.len() > MAX_KIND_FILTERS {
        return Err(RetrievalError::InvalidArgument(format!(
            "at most {MAX_KIND_FILTERS} kind filters are allowed"
        )));
    }
    for root in &query.roots {
        let value = match root {
            RetrievalRoot::Object(value)
            | RetrievalRoot::External(value)
            | RetrievalRoot::Link(value) => value,
        };
        validate_query_value(value, "context root", 256)?;
    }
    for relation in &query.relations {
        validate_query_value(relation, "relation filter", 128)?;
    }
    for kind in &query.kind_filter {
        validate_query_value(kind, "kind filter", 128)?;
    }

    // Proto scalar zero is intentionally the safest default: resolve only the
    // explicitly named roots and do not expand any neighboring relations.
    let max_depth = query.max_depth.min(MAX_DEPTH);
    let max_objects = bounded(query.max_objects, DEFAULT_MAX_OBJECTS, MAX_OBJECTS) as usize;
    let requested_link_cap = if max_depth == 0 {
        0
    } else {
        bounded(query.max_links, DEFAULT_MAX_LINKS, MAX_LINKS) as usize
    };
    let relations = query
        .relations
        .iter()
        .filter(|relation| !relation.is_empty())
        .cloned()
        .collect::<BTreeSet<_>>();
    let kinds = query
        .kind_filter
        .iter()
        .filter(|kind| !kind.is_empty())
        .cloned()
        .collect::<BTreeSet<_>>();
    let entailment_requested = query.reasoning_mode == ReasoningMode::Entailment;
    let max_source_rows = if entailment_requested {
        bounded(
            query.max_source_rows,
            DEFAULT_MAX_SOURCE_ROWS,
            MAX_SOURCE_ROWS,
        )
    } else {
        u32::MAX
    };
    let max_derived_rows = bounded(
        query.max_derived_rows,
        DEFAULT_MAX_DERIVED_ROWS,
        MAX_DERIVED_ROWS,
    );
    let max_steps = bounded(
        query.max_derivation_steps,
        DEFAULT_MAX_DERIVATION_STEPS,
        MAX_DERIVATION_STEPS,
    ) as usize;
    let max_time = if entailment_requested {
        Duration::from_millis(u64::from(bounded(
            query.max_time_ms,
            DEFAULT_MAX_TIME_MS,
            MAX_TIME_MS,
        )))
    } else {
        Duration::MAX
    };
    let max_explanation_bytes = if query.max_explanation_bytes == 0 {
        DEFAULT_MAX_EXPLANATION_BYTES
    } else {
        query.max_explanation_bytes.min(MAX_EXPLANATION_BYTES)
    };

    let mut result = RetrievalResult {
        source_rows: query.initial_source_rows,
        ..Default::default()
    };
    if query.source_rows_truncated {
        add_truncation(&mut result, "source_rows");
    }
    if let Some(ontology) = ontology {
        result.ontology_revision = ontology.revision();
    }
    let mut denied_ids = BTreeSet::new();
    let mut object_cache = HashMap::<String, Option<Object>>::new();
    let mut seeds = BTreeSet::<(String, String)>::new(); // (object id, root origin)
    let mut root_object_ids = BTreeSet::new();
    let mut explicit_links = BTreeMap::<String, Link>::new();
    let mut counted_source_ids = BTreeSet::new();

    for root in &query.roots {
        match root {
            RetrievalRoot::Object(id) => {
                let Some(object) = load_object(db, id, &mut object_cache)? else {
                    result.unresolved_roots = result.unresolved_roots.saturating_add(1);
                    continue;
                };
                if is_forbidden(&object) {
                    result.denied_roots = result.denied_roots.saturating_add(1);
                    continue;
                }
                if !can_read(&object) {
                    denied_ids.insert(object.id);
                    result.denied_roots = result.denied_roots.saturating_add(1);
                    continue;
                }
                let origin = format!("object:{}", object.id);
                root_object_ids.insert(object.id.clone());
                seeds.insert((object.id, origin));
            }
            RetrievalRoot::External(external_id) => {
                let Some(object) = db
                    .find_by_external_id(external_id)
                    .map_err(RetrievalError::Storage)?
                else {
                    result.unresolved_roots = result.unresolved_roots.saturating_add(1);
                    continue;
                };
                object_cache.insert(object.id.clone(), Some(object.clone()));
                if is_forbidden(&object) {
                    result.denied_roots = result.denied_roots.saturating_add(1);
                    continue;
                }
                if !can_read(&object) {
                    denied_ids.insert(object.id);
                    result.denied_roots = result.denied_roots.saturating_add(1);
                    continue;
                }
                let origin = format!("external:{}", object.external_id);
                root_object_ids.insert(object.id.clone());
                seeds.insert((object.id, origin));
            }
            RetrievalRoot::Link(id) => {
                let Some(link) = db.get_link(id).map_err(RetrievalError::Storage)? else {
                    result.unresolved_roots = result.unresolved_roots.saturating_add(1);
                    continue;
                };
                let from = load_object(db, &link.from_id, &mut object_cache)?;
                let to = load_object(db, &link.to_id, &mut object_cache)?;
                let (Some(from), Some(to)) = (from, to) else {
                    result.unresolved_roots = result.unresolved_roots.saturating_add(1);
                    continue;
                };
                if is_forbidden(&from) || is_forbidden(&to) {
                    result.denied_roots = result.denied_roots.saturating_add(1);
                    continue;
                }
                let from_allowed = can_read(&from);
                let to_allowed = can_read(&to);
                if !from_allowed {
                    denied_ids.insert(from.id.clone());
                }
                if !to_allowed {
                    denied_ids.insert(to.id.clone());
                }
                // A link root is a relationship, so exposing or expanding only
                // one side would reveal an inaccessible endpoint.
                if !from_allowed || !to_allowed {
                    result.denied_roots = result.denied_roots.saturating_add(1);
                    continue;
                }
                if entailment_requested && !counted_source_ids.contains(&link.id) {
                    if result.source_rows >= max_source_rows {
                        add_truncation(&mut result, "source_rows");
                        continue;
                    }
                    counted_source_ids.insert(link.id.clone());
                    result.source_rows = result.source_rows.saturating_add(1);
                }
                let origin = format!("link:{}", link.id);
                root_object_ids.insert(from.id.clone());
                root_object_ids.insert(to.id.clone());
                seeds.insert((from.id, origin.clone()));
                seeds.insert((to.id, origin));
                explicit_links.insert(link.id.clone(), link);
            }
        }
    }

    if root_object_ids.len() > max_objects {
        return Err(RetrievalError::InvalidArgument(
            "max_objects is too small to include every resolved context root".into(),
        ));
    }
    // Explicit link roots are part of the root set, not relation expansion.
    // Preserve them even for a roots-only request while keeping the absolute
    // response bound in force.
    let max_links = requested_link_cap
        .max(explicit_links.len())
        .min(MAX_LINKS as usize);

    let mut candidates = BTreeMap::<String, CandidateState>::new();
    let mut visited = HashSet::<(String, String)>::new(); // (origin, object id)
    let mut frontier = seeds
        .into_iter()
        .map(|(id, origin)| (id, origin, Vec::<Link>::new()))
        .collect::<Vec<_>>();
    for (id, origin, _) in &frontier {
        let object = load_object(db, id, &mut object_cache)?.ok_or_else(|| {
            RetrievalError::Storage(format!("resolved context root disappeared: {id}"))
        })?;
        candidates
            .entry(id.clone())
            .and_modify(|state| state.observe(0, "", origin, true))
            .or_insert_with(|| CandidateState::new(object, 0, String::new(), origin.clone(), true));
        visited.insert((origin.clone(), id.clone()));
    }

    let mut accepted_links = explicit_links;
    let mut overflow_link_ids = BTreeSet::new();
    let adjacency_scan_cap = if entailment_requested {
        max_source_rows.saturating_add(1) as usize
    } else {
        MAX_LINKS as usize + 1
    };
    let mut adjacency_cache = HashMap::<String, Vec<(Link, String)>>::new();

    'traversal: for depth in 0..max_depth {
        frontier.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        frontier.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
        let mut next_frontier = Vec::new();
        for (current_id, origin, path) in frontier {
            if started.elapsed() >= max_time {
                add_truncation(&mut result, "time");
                break 'traversal;
            }
            if result.source_rows >= max_source_rows && !adjacency_cache.contains_key(&current_id) {
                add_truncation(&mut result, "source_rows");
                break 'traversal;
            }
            // Cache adjacency once and borrow it; cloning the Vec<(Link, String)>
            // on every revisit copied every edge for each frontier re-touch.
            if let Entry::Vacant(entry) = adjacency_cache.entry(current_id.clone()) {
                entry.insert(load_bounded_adjacency(
                    db,
                    &current_id,
                    query.direction,
                    &relations,
                    adjacency_scan_cap,
                )?);
            }
            let adjacent = &adjacency_cache[&current_id];

            for (link, target_id) in adjacent {
                let Some(target) = load_object(db, &target_id, &mut object_cache)? else {
                    continue;
                };
                if is_forbidden(&target) || !can_read(&target) {
                    denied_ids.insert(target.id);
                    continue;
                }
                if !counted_source_ids.contains(&link.id) {
                    if result.source_rows >= max_source_rows {
                        add_truncation(&mut result, "source_rows");
                        break 'traversal;
                    }
                    counted_source_ids.insert(link.id.clone());
                    result.source_rows = result.source_rows.saturating_add(1);
                }
                if !accepted_links.contains_key(&link.id) && accepted_links.len() >= max_links {
                    if overflow_link_ids.len() <= MAX_LINKS as usize {
                        overflow_link_ids.insert(link.id.clone());
                    }
                    if !entailment_requested {
                        continue;
                    }
                } else if !accepted_links.contains_key(&link.id) {
                    accepted_links.insert(link.id.clone(), link.clone());
                }

                let next_depth = depth.saturating_add(1);
                let mut next_path = path.clone();
                next_path.push(link.clone());
                candidates
                    .entry(target.id.clone())
                    .and_modify(|state| {
                        state.observe(next_depth, &link.relation, &origin, false);
                        state.observe_path(&next_path);
                    })
                    .or_insert_with(|| {
                        let mut state = CandidateState::new(
                            target.clone(),
                            next_depth,
                            link.relation.clone(),
                            origin.clone(),
                            false,
                        );
                        state.path = next_path.clone();
                        state
                    });
                if visited.insert((origin.clone(), target.id.clone())) {
                    next_frontier.push((target.id, origin.clone(), next_path));
                }
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }

    let revision = result.ontology_revision.clone();
    let timed_out = started.elapsed() >= max_time;
    if timed_out {
        add_truncation(&mut result, "time");
    }
    let entailment = query.reasoning_mode == ReasoningMode::Entailment && !timed_out;
    let mut ranked = Vec::new();
    for state in candidates.into_values() {
        if started.elapsed() >= max_time && !state.is_root {
            add_truncation(&mut result, "time");
            continue;
        }
        let satisfies_filter = state.is_root
            || kinds.is_empty()
            || kinds.contains(&state.object.kind)
            || (entailment
                && ontology.is_some_and(|registry| {
                    kinds
                        .iter()
                        .any(|kind| registry.kind_satisfies_class(&state.object.kind, kind))
                }));
        if !satisfies_filter {
            continue;
        }
        let requires_derivation =
            !state.is_root && !kinds.is_empty() && !kinds.contains(&state.object.kind);
        let explanation = if started.elapsed() < max_time || state.is_root {
            explanation_for(
                &state,
                ontology,
                &kinds,
                &revision,
                max_steps,
                query.direction,
            )
        } else {
            add_truncation(&mut result, "time");
            Explanation::default()
        };
        ranked.push(RetrievalCandidate {
            affinity: context_affinity_score(state.depth, state.origins.len()),
            object: state.object,
            depth: state.depth,
            via_relation: state.via_relation,
            explanation,
            requires_derivation,
        });
    }
    if ranked
        .iter()
        .any(|candidate| candidate.explanation.steps_truncated)
    {
        add_truncation(&mut result, "derivation_steps");
    }
    ranked.retain(|candidate| {
        !candidate.requires_derivation || !candidate.explanation.steps_truncated
    });
    let total_derived_rows = ranked
        .iter()
        .filter(|candidate| candidate.explanation.derived)
        .count()
        .min(u32::MAX as usize) as u32;
    ranked.sort_by(candidate_order);
    let mut retained_derived = 0u32;
    for candidate in &mut ranked {
        let derived_row = u32::from(candidate.explanation.derived);
        if retained_derived.saturating_add(derived_row) <= max_derived_rows {
            retained_derived = retained_derived.saturating_add(derived_row);
        } else {
            // A derivation proof is atomic: never retain a prefix that does
            // not establish the candidate's asserted class or relation.
            candidate
                .explanation
                .steps
                .retain(|step| step.kind != "derived");
        }
        candidate.explanation.derived = candidate
            .explanation
            .steps
            .iter()
            .any(|step| step.kind == "derived");
    }
    if retained_derived < total_derived_rows {
        add_truncation(&mut result, "derived_rows");
    }
    ranked.retain(|candidate| !candidate.requires_derivation || candidate.explanation.derived);

    let mut explanation_bytes = 0u64;
    for candidate in &mut ranked {
        let candidate_bytes = explanation_payload_bytes(&candidate.explanation);
        if explanation_bytes.saturating_add(candidate_bytes) <= max_explanation_bytes {
            explanation_bytes = explanation_bytes.saturating_add(candidate_bytes);
            continue;
        }
        add_truncation(&mut result, "explanation_bytes");
        candidate.explanation = Explanation::default();
    }
    ranked.retain(|candidate| !candidate.requires_derivation || candidate.explanation.derived);
    let eligible_ids = ranked
        .iter()
        .map(|candidate| candidate.object.id.clone())
        .collect::<HashSet<_>>();
    result.truncated_objects = to_u32(ranked.len().saturating_sub(max_objects));
    ranked.truncate(max_objects);
    result.derived_rows = ranked
        .iter()
        .filter(|candidate| candidate.explanation.derived)
        .count()
        .min(u32::MAX as usize) as u32;
    let returned_ids = ranked
        .iter()
        .map(|candidate| candidate.object.id.clone())
        .collect::<HashSet<_>>();

    let mut links = Vec::new();
    let mut object_truncated_links = 0usize;
    for link in accepted_links.into_values() {
        if returned_ids.contains(&link.from_id) && returned_ids.contains(&link.to_id) {
            links.push(link);
        } else if eligible_ids.contains(&link.from_id) && eligible_ids.contains(&link.to_id) {
            object_truncated_links = object_truncated_links.saturating_add(1);
        }
    }
    links.sort_by(|left, right| {
        left.relation
            .cmp(&right.relation)
            .then_with(|| left.from_id.cmp(&right.from_id))
            .then_with(|| left.to_id.cmp(&right.to_id))
            .then_with(|| left.id.cmp(&right.id))
    });

    result.candidates = ranked;
    result.links = links;
    result.denied_objects = to_u32(denied_ids.len());
    result.truncated_links = to_u32(
        overflow_link_ids
            .len()
            .saturating_add(object_truncated_links),
    );
    result.truncated = result.truncated_objects > 0
        || result.truncated_links > 0
        || !result.truncation_reasons.is_empty();
    Ok(result)
}

fn derivation_step_bytes(step: &DerivationStep) -> u64 {
    32 + step.kind.len() as u64
        + step.relation.len() as u64
        + step.from_id.len() as u64
        + step.to_id.len() as u64
        + step.ontology_revision.len() as u64
        + step.rule.len() as u64
        + step
            .source_fact_ids
            .iter()
            .map(|id| id.len() as u64 + 8)
            .sum::<u64>()
}

fn explanation_payload_bytes(explanation: &Explanation) -> u64 {
    32 + explanation.ontology_revision.len() as u64
        + explanation
            .source_fact_ids
            .iter()
            .map(|id| id.len() as u64 + 8)
            .sum::<u64>()
        + explanation
            .steps
            .iter()
            .map(derivation_step_bytes)
            .sum::<u64>()
}

fn add_truncation(result: &mut RetrievalResult, reason: &str) {
    if !result
        .truncation_reasons
        .iter()
        .any(|existing| existing == reason)
    {
        result.truncation_reasons.push(reason.to_string());
    }
}

fn explanation_for(
    state: &CandidateState,
    ontology: Option<&OntologyRegistry>,
    kinds: &BTreeSet<String>,
    revision: &str,
    max_steps: usize,
    direction: RetrievalDirection,
) -> Explanation {
    let mut explanation = Explanation {
        ontology_revision: revision.to_string(),
        ..Default::default()
    };
    if state.is_root {
        explanation.steps.push(DerivationStep {
            kind: "asserted",
            relation: String::new(),
            from_id: state.object.id.clone(),
            to_id: state.object.id.clone(),
            source_fact_ids: vec![state.object.id.clone()],
            ontology_revision: revision.to_string(),
            rule: "root",
        });
        explanation.source_fact_ids.push(state.object.id.clone());
    } else {
        for link in &state.path {
            explanation.source_fact_ids.push(link.id.clone());
            explanation.steps.push(DerivationStep {
                kind: "asserted",
                relation: link.relation.clone(),
                from_id: link.from_id.clone(),
                to_id: link.to_id.clone(),
                source_fact_ids: vec![link.id.clone()],
                ontology_revision: revision.to_string(),
                rule: "graph_link",
            });
        }
    }
    if let Some(registry) = ontology {
        let transitive_endpoints = transitive_endpoints(&state.path, direction);
        let transitive = transitive_endpoints.is_some()
            && registry
                .constraints_for_mapped_relation(&state.path[0].relation)
                .iter()
                .any(|relation| relation.transitive);
        if transitive {
            let (from_id, to_id) = transitive_endpoints.expect("checked above");
            explanation.derived = true;
            explanation.steps.push(DerivationStep {
                kind: "derived",
                relation: state.path[0].relation.clone(),
                from_id,
                to_id,
                source_fact_ids: explanation.source_fact_ids.clone(),
                ontology_revision: revision.to_string(),
                rule: "transitive",
            });
        }
        if !kinds.is_empty()
            && !kinds.contains(&state.object.kind)
            && let Some(class) = kinds
                .iter()
                .find(|class| registry.kind_satisfies_class(&state.object.kind, class))
        {
            explanation.derived = true;
            let path = registry
                .kind_entailment_path(&state.object.kind, class)
                .unwrap_or_default();
            let mapped_class = path
                .first()
                .map(|(from, _, _)| from.clone())
                .unwrap_or_else(|| class.clone());
            let ontology_fact = format!("ontology:class:{mapped_class}");
            explanation.source_fact_ids.push(ontology_fact.clone());
            explanation.steps.push(DerivationStep {
                kind: "derived",
                relation: "is_a".into(),
                from_id: state.object.kind.clone(),
                to_id: mapped_class,
                source_fact_ids: vec![state.object.id.clone(), ontology_fact],
                ontology_revision: revision.to_string(),
                rule: "mapping",
            });
            for (from, to, rule) in path {
                let ontology_facts = vec![
                    format!("ontology:class:{from}"),
                    format!("ontology:class:{to}"),
                ];
                explanation.source_fact_ids.extend(ontology_facts.clone());
                explanation.steps.push(DerivationStep {
                    kind: "derived",
                    relation: "is_a".into(),
                    from_id: from,
                    to_id: to,
                    source_fact_ids: ontology_facts,
                    ontology_revision: revision.to_string(),
                    rule,
                });
            }
            if !explanation.source_fact_ids.contains(&state.object.id) {
                explanation.source_fact_ids.push(state.object.id.clone());
            }
        }
    }
    if explanation.steps.len() > max_steps {
        explanation.steps.truncate(max_steps);
        explanation.steps_truncated = true;
        explanation.derived = explanation.steps.iter().any(|step| step.kind == "derived");
    }
    explanation.source_fact_ids.sort();
    explanation.source_fact_ids.dedup();
    explanation
}

fn transitive_endpoints(path: &[Link], direction: RetrievalDirection) -> Option<(String, String)> {
    if path.len() < 2 || !path.iter().all(|link| link.relation == path[0].relation) {
        return None;
    }
    let outgoing = path.windows(2).all(|pair| pair[0].to_id == pair[1].from_id);
    let incoming = path.windows(2).all(|pair| pair[0].from_id == pair[1].to_id);
    match direction {
        RetrievalDirection::Outgoing if outgoing => {
            Some((path.first()?.from_id.clone(), path.last()?.to_id.clone()))
        }
        RetrievalDirection::Incoming if incoming => {
            Some((path.last()?.from_id.clone(), path.first()?.to_id.clone()))
        }
        RetrievalDirection::Both if outgoing => {
            Some((path.first()?.from_id.clone(), path.last()?.to_id.clone()))
        }
        RetrievalDirection::Both if incoming => {
            Some((path.last()?.from_id.clone(), path.first()?.to_id.clone()))
        }
        _ => None,
    }
}

fn load_bounded_adjacency(
    db: &RuntimeDb,
    object_id: &str,
    direction: RetrievalDirection,
    relations: &BTreeSet<String>,
    scan_cap: usize,
) -> Result<Vec<(Link, String)>, RetrievalError> {
    let mut adjacent = Vec::new();
    if relations.is_empty() {
        for db_direction in direction.db_directions() {
            append_bounded_links(db, object_id, "", db_direction, scan_cap, &mut adjacent)?;
        }
        sort_and_bound_adjacency(&mut adjacent, scan_cap);
        return Ok(adjacent);
    }

    for relation in relations {
        if adjacent.len() >= scan_cap {
            break;
        }
        let remaining = scan_cap - adjacent.len();
        let mut matching = Vec::new();
        for db_direction in direction.db_directions() {
            append_bounded_links(
                db,
                object_id,
                relation,
                db_direction,
                remaining,
                &mut matching,
            )?;
        }
        sort_and_bound_adjacency(&mut matching, remaining);
        adjacent.extend(matching);
    }
    sort_and_bound_adjacency(&mut adjacent, scan_cap);
    Ok(adjacent)
}

fn append_bounded_links(
    db: &RuntimeDb,
    object_id: &str,
    relation: &str,
    direction: &Direction,
    limit: usize,
    adjacent: &mut Vec<(Link, String)>,
) -> Result<(), RetrievalError> {
    let links = db
        .get_links_limited(object_id, relation, direction, limit)
        .map_err(RetrievalError::Storage)?;
    adjacent.extend(links.into_iter().map(|link| {
        let target_id = match direction {
            Direction::Outgoing => link.to_id.clone(),
            Direction::Incoming => link.from_id.clone(),
        };
        (link, target_id)
    }));
    Ok(())
}

fn sort_and_bound_adjacency(adjacent: &mut Vec<(Link, String)>, cap: usize) {
    adjacent.sort_by(|(left_link, left_target), (right_link, right_target)| {
        left_link
            .relation
            .cmp(&right_link.relation)
            .then_with(|| left_link.id.cmp(&right_link.id))
            .then_with(|| left_target.cmp(right_target))
    });
    adjacent.dedup_by(|(left_link, left_target), (right_link, right_target)| {
        left_link.id == right_link.id && left_target == right_target
    });
    adjacent.truncate(cap);
}

fn bounded(value: u32, default: u32, cap: u32) -> u32 {
    if value == 0 { default } else { value.min(cap) }
}

fn validate_query_value(value: &str, label: &str, max_chars: usize) -> Result<(), RetrievalError> {
    if value.is_empty()
        || value != value.trim()
        || value.chars().count() > max_chars
        || value.chars().any(char::is_control)
    {
        return Err(RetrievalError::InvalidArgument(format!(
            "invalid {label} {value:?}"
        )));
    }
    Ok(())
}

fn to_u32(value: usize) -> u32 {
    value.min(u32::MAX as usize) as u32
}

fn load_object(
    db: &RuntimeDb,
    id: &str,
    cache: &mut HashMap<String, Option<Object>>,
) -> Result<Option<Object>, RetrievalError> {
    if let Some(object) = cache.get(id) {
        return Ok(object.clone());
    }
    let object = db.get_object(id).map_err(RetrievalError::Storage)?;
    cache.insert(id.to_string(), object.clone());
    Ok(object)
}

fn candidate_order(left: &RetrievalCandidate, right: &RetrievalCandidate) -> Ordering {
    right
        .affinity
        .total_cmp(&left.affinity)
        .then_with(|| left.depth.cmp(&right.depth))
        .then_with(|| left.via_relation.cmp(&right.via_relation))
        .then_with(|| left.object.namespace.cmp(&right.object.namespace))
        .then_with(|| left.object.kind.cmp(&right.object.kind))
        .then_with(|| left.object.name.cmp(&right.object.name))
        .then_with(|| left.object.id.cmp(&right.object.id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::ontology::{Cardinality, OntologyClass, OntologyRelation};
    use std::collections::HashMap;

    fn object(id: &str, kind: &str) -> Object {
        Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: "test".into(),
            external_id: format!("{kind}:{id}"),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }
    }

    fn link(id: &str, from_id: &str, to_id: &str, relation: &str) -> Link {
        Link {
            id: id.into(),
            from_id: from_id.into(),
            to_id: to_id.into(),
            relation: relation.into(),
            created: 0,
        }
    }

    fn graph() -> RuntimeDb {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for (id, kind) in [
            ("root", "service"),
            ("a", "component"),
            ("b", "component"),
            ("deep", "file"),
        ] {
            db.create_object(&object(id, kind)).unwrap();
        }
        db.create_link(&link("z-link", "root", "b", "contains"))
            .unwrap();
        db.create_link(&link("a-link", "root", "a", "contains"))
            .unwrap();
        db.create_link(&link("deep-link", "a", "deep", "depends_on"))
            .unwrap();
        db
    }

    fn reasoning_ontology() -> OntologyRegistry {
        OntologyRegistry::from_parts(
            vec![
                OntologyClass {
                    name: "Resource".into(),
                    description: String::new(),
                    superclasses: Vec::new(),
                    equivalent_classes: Vec::new(),
                    disjoint_classes: Vec::new(),
                    properties: Vec::new(),
                    is_builtin: false,
                    mapped_kind: String::new(),
                },
                OntologyClass {
                    name: "Component".into(),
                    description: String::new(),
                    superclasses: vec!["Intermediate".into()],
                    equivalent_classes: vec!["Asset".into()],
                    disjoint_classes: Vec::new(),
                    properties: Vec::new(),
                    is_builtin: false,
                    mapped_kind: "component".into(),
                },
                OntologyClass {
                    name: "Intermediate".into(),
                    description: String::new(),
                    superclasses: vec!["Resource".into()],
                    equivalent_classes: Vec::new(),
                    disjoint_classes: Vec::new(),
                    properties: Vec::new(),
                    is_builtin: false,
                    mapped_kind: String::new(),
                },
                OntologyClass {
                    name: "Asset".into(),
                    description: String::new(),
                    superclasses: Vec::new(),
                    equivalent_classes: Vec::new(),
                    disjoint_classes: Vec::new(),
                    properties: Vec::new(),
                    is_builtin: false,
                    mapped_kind: String::new(),
                },
            ],
            vec![OntologyRelation {
                name: "impacts".into(),
                description: String::new(),
                domain: "Resource".into(),
                range: "Resource".into(),
                cardinality: Cardinality::default(),
                inverse: String::new(),
                transitive: true,
                is_builtin: false,
                mapped_relation: "impacts".into(),
            }],
        )
    }

    #[test]
    fn entailment_mode_adds_subclass_results_without_changing_the_default() {
        let db = graph();
        let query = RetrievalQuery {
            roots: vec![RetrievalRoot::Object("root".into())],
            kind_filter: vec!["Resource".into()],
            max_depth: 1,
            ..Default::default()
        };
        let asserted = retrieve(&db, &query, |_| true, |_| false).unwrap();
        assert_eq!(asserted.candidates.len(), 1);

        let ontology = reasoning_ontology();
        let entailed = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                reasoning_mode: ReasoningMode::Entailment,
                ..query
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        let component = entailed
            .candidates
            .iter()
            .find(|candidate| candidate.object.id == "a")
            .unwrap();
        assert!(component.explanation.derived);
        assert!(
            component
                .explanation
                .steps
                .iter()
                .any(|step| step.rule == "subclass")
        );
        assert_eq!(component.explanation.ontology_revision, ontology.revision());

        let equivalent = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                kind_filter: vec!["Asset".into()],
                max_depth: 1,
                reasoning_mode: ReasoningMode::Entailment,
                ..Default::default()
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        assert!(equivalent.candidates.iter().any(|candidate| {
            candidate.object.id == "a"
                && candidate
                    .explanation
                    .steps
                    .iter()
                    .any(|step| step.rule == "equivalence")
        }));

        let directly_mapped = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                kind_filter: vec!["Component".into()],
                max_depth: 1,
                reasoning_mode: ReasoningMode::Entailment,
                ..Default::default()
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        assert!(directly_mapped.candidates.iter().any(|candidate| {
            candidate.object.id == "a"
                && candidate
                    .explanation
                    .steps
                    .iter()
                    .any(|step| step.rule == "mapping")
        }));

        let proof_bounded = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                kind_filter: vec!["Resource".into()],
                max_depth: 1,
                reasoning_mode: ReasoningMode::Entailment,
                max_derived_rows: 1,
                ..Default::default()
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        assert_eq!(
            proof_bounded
                .candidates
                .iter()
                .filter(|candidate| candidate.object.kind == "component")
                .count(),
            1
        );
        assert!(
            proof_bounded
                .truncation_reasons
                .contains(&"derived_rows".into())
        );
    }

    #[test]
    fn transitive_derivation_cites_asserted_links_and_obeys_bounds() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for id in ["a", "b", "c"] {
            db.create_object(&object(id, "component")).unwrap();
        }
        db.create_link(&link("impact-1", "a", "b", "impacts"))
            .unwrap();
        db.create_link(&link("impact-2", "b", "c", "impacts"))
            .unwrap();
        let ontology = reasoning_ontology();
        let result = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("a".into())],
                relations: vec!["impacts".into()],
                direction: RetrievalDirection::Outgoing,
                max_depth: 2,
                reasoning_mode: ReasoningMode::Entailment,
                ..Default::default()
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        let derived = result
            .candidates
            .iter()
            .find(|candidate| candidate.object.id == "c")
            .unwrap();
        assert!(derived.explanation.derived);
        assert_eq!(
            derived.explanation.source_fact_ids,
            vec!["impact-1", "impact-2"]
        );

        let step_bounded = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("a".into())],
                relations: vec!["impacts".into()],
                direction: RetrievalDirection::Outgoing,
                max_depth: 2,
                reasoning_mode: ReasoningMode::Entailment,
                max_derivation_steps: 2,
                ..Default::default()
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        assert!(
            step_bounded
                .truncation_reasons
                .contains(&"derivation_steps".into())
        );

        let memory_bounded = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("a".into())],
                max_depth: 2,
                reasoning_mode: ReasoningMode::Entailment,
                max_explanation_bytes: 1,
                ..Default::default()
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        assert!(
            memory_bounded
                .truncation_reasons
                .contains(&"explanation_bytes".into())
        );

        let source_bounded = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("a".into())],
                max_depth: 2,
                reasoning_mode: ReasoningMode::Entailment,
                max_source_rows: 1,
                ..Default::default()
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        assert_eq!(source_bounded.source_rows, 1);
        assert!(
            source_bounded
                .truncation_reasons
                .contains(&"source_rows".into())
        );

        let timed_out = retrieve_with_ontology_started(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("a".into())],
                max_depth: 2,
                reasoning_mode: ReasoningMode::Entailment,
                max_time_ms: 1,
                ..Default::default()
            },
            Some(&ontology),
            Instant::now() - Duration::from_millis(2),
            |_| true,
            |_| false,
        )
        .unwrap();
        assert!(timed_out.truncation_reasons.contains(&"time".into()));
        assert_eq!(timed_out.candidates.len(), 1);
    }

    #[test]
    fn denied_intermediate_cannot_contribute_to_derivation_or_metadata() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for id in ["a", "hidden", "c"] {
            db.create_object(&object(id, "component")).unwrap();
        }
        db.create_link(&link("hidden-1", "a", "hidden", "impacts"))
            .unwrap();
        db.create_link(&link("hidden-2", "hidden", "c", "impacts"))
            .unwrap();
        let result = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("a".into())],
                max_depth: 3,
                reasoning_mode: ReasoningMode::Entailment,
                ..Default::default()
            },
            Some(&reasoning_ontology()),
            |object| object.id != "hidden",
            |_| false,
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.source_rows, 0);
        assert_eq!(result.derived_rows, 0);
        assert!(result.truncation_reasons.is_empty());
    }

    #[test]
    fn source_row_accounting_deduplicates_asserted_facts() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for id in ["a", "b"] {
            db.create_object(&object(id, "component")).unwrap();
        }
        db.create_link(&link("ab", "a", "b", "impacts")).unwrap();
        let result = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![
                    RetrievalRoot::Object("a".into()),
                    RetrievalRoot::Object("b".into()),
                ],
                max_depth: 1,
                reasoning_mode: ReasoningMode::Entailment,
                ..Default::default()
            },
            Some(&reasoning_ontology()),
            |_| true,
            |_| false,
        )
        .unwrap();
        assert_eq!(result.source_rows, 1);
    }

    #[test]
    fn ontology_content_changes_produce_a_new_snapshot_revision() {
        let first = reasoning_ontology();
        let mut second = reasoning_ontology();
        second.register_class(OntologyClass {
            name: "NewClass".into(),
            description: String::new(),
            superclasses: Vec::new(),
            equivalent_classes: Vec::new(),
            disjoint_classes: Vec::new(),
            properties: Vec::new(),
            is_builtin: false,
            mapped_kind: String::new(),
        });
        assert_ne!(first.revision(), second.revision());
    }

    #[test]
    fn missing_ontology_references_cannot_participate_in_entailment() {
        let registry = OntologyRegistry::from_parts(
            vec![OntologyClass {
                name: "Visible".into(),
                description: String::new(),
                superclasses: vec!["Hidden".into()],
                equivalent_classes: Vec::new(),
                disjoint_classes: Vec::new(),
                properties: Vec::new(),
                is_builtin: false,
                mapped_kind: "component".into(),
            }],
            Vec::new(),
        );
        assert!(!registry.kind_satisfies_class("component", "Hidden"));
    }

    #[test]
    fn transitive_explanations_follow_direction_and_reject_mixed_paths() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for id in ["a", "b", "c", "x"] {
            db.create_object(&object(id, "component")).unwrap();
        }
        for asserted in [
            link("ab", "a", "b", "impacts"),
            link("bc", "b", "c", "impacts"),
            link("ax", "a", "x", "impacts"),
        ] {
            db.create_link(&asserted).unwrap();
        }
        let ontology = reasoning_ontology();
        let incoming = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("c".into())],
                relations: vec!["impacts".into()],
                direction: RetrievalDirection::Incoming,
                max_depth: 2,
                reasoning_mode: ReasoningMode::Entailment,
                ..Default::default()
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        let step = incoming
            .candidates
            .iter()
            .find(|candidate| candidate.object.id == "a")
            .unwrap()
            .explanation
            .steps
            .iter()
            .find(|step| step.rule == "transitive")
            .unwrap();
        assert_eq!(step.from_id, "a");
        assert_eq!(step.to_id, "c");

        let mixed = retrieve_with_ontology(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("b".into())],
                relations: vec!["impacts".into()],
                direction: RetrievalDirection::Both,
                max_depth: 2,
                reasoning_mode: ReasoningMode::Entailment,
                ..Default::default()
            },
            Some(&ontology),
            |_| true,
            |_| false,
        )
        .unwrap();
        let x = mixed
            .candidates
            .iter()
            .find(|candidate| candidate.object.id == "x")
            .unwrap();
        assert!(
            !x.explanation
                .steps
                .iter()
                .any(|step| step.rule == "transitive")
        );
    }

    #[test]
    fn ranks_roots_then_nearest_candidates_deterministically() {
        let db = graph();
        let result = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::External("service:root".into())],
                max_depth: 2,
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap();

        let ids = result
            .candidates
            .iter()
            .map(|candidate| candidate.object.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["root", "a", "b", "deep"]);
        assert_eq!(result.candidates[0].depth, 0);
        assert_eq!(result.candidates[1].affinity, 0.5);
        assert_eq!(result.candidates[3].depth, 2);
    }

    #[test]
    fn honors_direction_and_relation_allowlist() {
        let db = graph();
        let result = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("a".into())],
                relations: vec!["contains".into()],
                direction: RetrievalDirection::Incoming,
                max_depth: 3,
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap();

        assert_eq!(result.candidates.len(), 2);
        assert_eq!(result.candidates[0].object.id, "a");
        assert_eq!(result.candidates[1].object.id, "root");
        assert!(result.links.iter().all(|link| link.relation == "contains"));
    }

    #[test]
    fn affinity_rewards_candidates_reached_from_multiple_roots() {
        let db = graph();
        let result = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![
                    RetrievalRoot::Object("root".into()),
                    RetrievalRoot::Object("deep".into()),
                ],
                direction: RetrievalDirection::Both,
                max_depth: 2,
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap();

        let shared = result
            .candidates
            .iter()
            .find(|candidate| candidate.object.id == "a")
            .unwrap();
        let single_root = result
            .candidates
            .iter()
            .find(|candidate| candidate.object.id == "b")
            .unwrap();
        assert_eq!(shared.depth, 1);
        assert_eq!(shared.affinity, 0.55);
        assert_eq!(single_root.affinity, 0.5);
        assert!(shared.affinity > single_root.affinity);
    }

    #[test]
    fn link_root_includes_both_authorized_endpoints_at_depth_zero() {
        let db = graph();
        let result = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Link("a-link".into())],
                max_depth: 0,
                max_links: 0,
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap();

        let roots = result
            .candidates
            .iter()
            .filter(|candidate| candidate.depth == 0)
            .map(|candidate| candidate.object.id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(roots, BTreeSet::from(["a", "root"]));
        assert_eq!(result.candidates.len(), 2);
        assert!(result.links.iter().any(|link| link.id == "a-link"));
    }

    #[test]
    fn zero_depth_object_root_does_not_expand_neighbors() {
        let db = graph();
        let result = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                max_depth: 0,
                max_links: 0,
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap();

        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].object.id, "root");
        assert!(result.links.is_empty());
        assert!(!result.truncated);
    }

    #[test]
    fn never_traverses_through_denied_or_forbidden_objects() {
        let db = graph();
        let denied = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                max_depth: 3,
                ..Default::default()
            },
            |object| object.id != "a",
            |object| object.id == "b",
        )
        .unwrap();

        let ids = denied
            .candidates
            .iter()
            .map(|candidate| candidate.object.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["root"]);
        assert_eq!(denied.denied_objects, 2);
        assert!(!ids.contains(&"deep"));
        assert!(denied.links.is_empty());
    }

    #[test]
    fn reports_unresolved_and_hard_bounded_results() {
        let db = graph();
        let result = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![
                    RetrievalRoot::Object("root".into()),
                    RetrievalRoot::Object("missing".into()),
                ],
                max_depth: u32::MAX,
                max_objects: 2,
                max_links: 1,
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap();

        assert_eq!(result.unresolved_roots, 1);
        assert!(result.candidates.len() <= 2);
        assert!(result.links.len() <= 1);
        assert!(result.truncated);
        assert!(result.truncated_links > 0 || result.truncated_objects > 0);
    }

    #[test]
    fn rejects_unbounded_filter_lists() {
        let db = graph();
        let relations = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                relations: (0..=MAX_RELATIONS)
                    .map(|index| format!("relation-{index}"))
                    .collect(),
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap_err();
        assert!(matches!(relations, RetrievalError::InvalidArgument(_)));

        let kinds = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                kind_filter: (0..=MAX_KIND_FILTERS)
                    .map(|index| format!("kind-{index}"))
                    .collect(),
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap_err();
        assert!(matches!(kinds, RetrievalError::InvalidArgument(_)));

        let empty_relation = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                relations: vec![String::new()],
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap_err();
        assert!(matches!(empty_relation, RetrievalError::InvalidArgument(_)));
    }

    #[test]
    fn wide_adjacency_is_scanned_and_returned_with_hard_caps() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&object("root", "service")).unwrap();
        for index in 0..300 {
            let id = format!("node-{index:03}");
            db.create_object(&object(&id, "component")).unwrap();
            db.create_link(&link(&format!("link-{index:03}"), "root", &id, "contains"))
                .unwrap();
        }

        let result = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                direction: RetrievalDirection::Outgoing,
                max_depth: 1,
                max_objects: 100,
                max_links: 3,
                // Entailment-only budgets do not alter asserted traversal.
                max_source_rows: 1,
                max_time_ms: 1,
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap();

        assert_eq!(result.candidates.len(), 4);
        assert_eq!(result.links.len(), 3);
        assert!(result.truncated);
        assert!(result.truncated_links > 0);
    }

    #[test]
    fn traversal_depth_is_absolutely_capped_at_three() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for id in ["d0", "d1", "d2", "d3", "d4"] {
            db.create_object(&object(id, "node")).unwrap();
        }
        for depth in 0..4 {
            db.create_link(&link(
                &format!("depth-{depth}"),
                &format!("d{depth}"),
                &format!("d{}", depth + 1),
                "contains",
            ))
            .unwrap();
        }

        let result = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("d0".into())],
                direction: RetrievalDirection::Outgoing,
                max_depth: u32::MAX,
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap();
        let ids = result
            .candidates
            .iter()
            .map(|candidate| candidate.object.id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids, BTreeSet::from(["d0", "d1", "d2", "d3"]));
        assert!(!ids.contains("d4"));
    }

    #[test]
    fn roots_are_returned_even_when_kind_filter_does_not_match() {
        let db = graph();
        let result = retrieve(
            &db,
            &RetrievalQuery {
                roots: vec![RetrievalRoot::Object("root".into())],
                kind_filter: vec!["file".into()],
                max_depth: 2,
                ..Default::default()
            },
            |_| true,
            |_| false,
        )
        .unwrap();

        assert_eq!(result.candidates[0].object.id, "root");
        assert_eq!(result.candidates[0].depth, 0);
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.object.id == "deep")
        );
    }
}
