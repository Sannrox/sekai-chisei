use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, Link, Object};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

pub const DEFAULT_MAX_DEPTH: u32 = 0;
pub const MAX_DEPTH: u32 = 3;
pub const DEFAULT_MAX_OBJECTS: u32 = 20;
pub const MAX_OBJECTS: u32 = 100;
pub const DEFAULT_MAX_LINKS: u32 = 40;
pub const MAX_LINKS: u32 = 200;
pub const MAX_ROOTS: usize = 32;
pub const MAX_RELATIONS: usize = 32;
pub const MAX_KIND_FILTERS: usize = 32;

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
}

#[derive(Debug, Clone)]
pub struct RetrievalCandidate {
    pub object: Object,
    pub depth: u32,
    pub via_relation: String,
    pub affinity: f64,
}

#[derive(Debug, Clone, Default)]
pub struct RetrievalResult {
    pub candidates: Vec<RetrievalCandidate>,
    pub links: Vec<Link>,
    pub truncated: bool,
    pub unresolved_roots: u32,
    pub denied_objects: u32,
    pub truncated_objects: u32,
    pub truncated_links: u32,
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
}

pub fn retrieve<F, G>(
    db: &SekaiDb,
    query: &RetrievalQuery,
    can_read: F,
    is_forbidden: G,
) -> Result<RetrievalResult, RetrievalError>
where
    F: Fn(&Object) -> bool,
    G: Fn(&Object) -> bool,
{
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

    let mut result = RetrievalResult::default();
    let mut denied_ids = BTreeSet::new();
    let mut object_cache = HashMap::<String, Option<Object>>::new();
    let mut seeds = BTreeSet::<(String, String)>::new(); // (object id, root origin)
    let mut root_object_ids = BTreeSet::new();
    let mut explicit_links = BTreeMap::<String, Link>::new();

    for root in &query.roots {
        match root {
            RetrievalRoot::Object(id) => {
                let Some(object) = load_object(db, id, &mut object_cache)? else {
                    result.unresolved_roots = result.unresolved_roots.saturating_add(1);
                    continue;
                };
                if is_forbidden(&object) {
                    result.unresolved_roots = result.unresolved_roots.saturating_add(1);
                    continue;
                }
                if !can_read(&object) {
                    denied_ids.insert(object.id);
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
                    result.unresolved_roots = result.unresolved_roots.saturating_add(1);
                    continue;
                }
                if !can_read(&object) {
                    denied_ids.insert(object.id);
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
                    result.unresolved_roots = result.unresolved_roots.saturating_add(1);
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
                    continue;
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
    let mut frontier = seeds.into_iter().collect::<Vec<_>>();
    for (id, origin) in &frontier {
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
    let adjacency_scan_cap = MAX_LINKS as usize + 1;
    let mut adjacency_cache = HashMap::<String, Vec<(Link, String)>>::new();

    for depth in 0..max_depth {
        frontier.sort();
        frontier.dedup();
        let mut next_frontier = Vec::new();
        for (current_id, origin) in frontier {
            let adjacent = if let Some(adjacent) = adjacency_cache.get(&current_id) {
                adjacent.clone()
            } else {
                let adjacent = load_bounded_adjacency(
                    db,
                    &current_id,
                    query.direction,
                    &relations,
                    adjacency_scan_cap,
                )?;
                adjacency_cache.insert(current_id.clone(), adjacent.clone());
                adjacent
            };

            for (link, target_id) in adjacent {
                if !accepted_links.contains_key(&link.id) && accepted_links.len() >= max_links {
                    if overflow_link_ids.len() <= MAX_LINKS as usize {
                        overflow_link_ids.insert(link.id);
                    }
                    continue;
                }
                let Some(target) = load_object(db, &target_id, &mut object_cache)? else {
                    continue;
                };
                if is_forbidden(&target) || !can_read(&target) {
                    denied_ids.insert(target.id);
                    continue;
                }

                if !accepted_links.contains_key(&link.id) {
                    accepted_links.insert(link.id.clone(), link.clone());
                }

                let next_depth = depth.saturating_add(1);
                candidates
                    .entry(target.id.clone())
                    .and_modify(|state| state.observe(next_depth, &link.relation, &origin, false))
                    .or_insert_with(|| {
                        CandidateState::new(
                            target.clone(),
                            next_depth,
                            link.relation.clone(),
                            origin.clone(),
                            false,
                        )
                    });
                if visited.insert((origin.clone(), target.id.clone())) {
                    next_frontier.push((target.id, origin.clone()));
                }
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }

    let mut ranked = candidates
        .into_values()
        .filter(|state| state.is_root || kinds.is_empty() || kinds.contains(&state.object.kind))
        .map(|state| RetrievalCandidate {
            affinity: context_affinity_score(state.depth, state.origins.len()),
            object: state.object,
            depth: state.depth,
            via_relation: state.via_relation,
        })
        .collect::<Vec<_>>();
    ranked.sort_by(candidate_order);
    let eligible_ids = ranked
        .iter()
        .map(|candidate| candidate.object.id.clone())
        .collect::<HashSet<_>>();
    result.truncated_objects = to_u32(ranked.len().saturating_sub(max_objects));
    ranked.truncate(max_objects);
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
    result.truncated = result.truncated_objects > 0 || result.truncated_links > 0;
    Ok(result)
}

fn load_bounded_adjacency(
    db: &SekaiDb,
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
    db: &SekaiDb,
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
    db: &SekaiDb,
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

    fn graph() -> SekaiDb {
        let db = SekaiDb::new(":memory:").unwrap();
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
        let db = SekaiDb::new(":memory:").unwrap();
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
        let db = SekaiDb::new(":memory:").unwrap();
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
