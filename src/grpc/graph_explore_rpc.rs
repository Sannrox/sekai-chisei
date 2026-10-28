//! Experimental ExpandNeighborhood and FindPaths RPCs (#1562).
//!
//! Both walk links in either direction from read roots the caller can see. Every
//! hop applies the same policy as `Traverse`: row policy in the store query, then
//! object visibility (namespace, collaboration, ACL, marking, security policy),
//! purpose, the delegated actor's markings, and the marking join along the path.
//! A hidden object, and every link to it, is omitted rather than returned as a
//! placeholder, and never counts against a budget, so counts, paths and flags
//! describe only the caller's visible graph.

use super::authorized_query_lifecycle::permitted_hop_paths;
use super::*;
use crate::sekai::classification_lattice::{ClassificationLattice, PathClassification};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const NEIGHBORHOOD_CAPABILITY: &str = "sekai.relations.neighborhood";
pub(crate) const PATHS_CAPABILITY: &str = "sekai.relations.paths";
pub(crate) const MAX_DEPTH: i32 = 4;
pub(crate) const MAX_SEEDS: usize = 100;
pub(crate) const MAX_FAN_OUT: i32 = 1_000;
pub(crate) const MAX_NODES: i32 = 1_000;
pub(crate) const MAX_PATHS: i32 = 100;
/// Visible neighbors examined per request. Past it a walk stops and reports a lower bound.
pub(crate) const EXAMINATION_BUDGET: usize = 50_000;
/// Raw link rows, visible or not, a request may scan. Past it the request fails with
/// ResourceExhausted before any authorization work on those rows, protecting the server
/// from very high-degree nodes. Far above the visible budget, so it binds only there.
pub(crate) const SCAN_LIMIT: usize = 200_000;
const DEFAULT_FAN_OUT: i32 = 100;
const DEFAULT_NODES: i32 = 100;
const DEFAULT_PATHS: i32 = 10;

pub(super) async fn expand_neighborhood(
    service: &SekaiServiceImpl,
    req: Request<ExpandNeighborhoodRequest>,
) -> Result<Response<ExpandNeighborhoodResponse>, Status> {
    let mut walker = Walker::new(service, &req)?;
    let input = req.into_inner();
    if input.seed_ids.is_empty() || input.seed_ids.len() > MAX_SEEDS {
        return Err(Status::invalid_argument(format!(
            "seed_ids must hold 1 to {MAX_SEEDS} ids"
        )));
    }
    let depth = bounded(input.depth, 1, MAX_DEPTH, "depth")?;
    let fan_out = bounded(
        input.fan_out_cap,
        DEFAULT_FAN_OUT,
        MAX_FAN_OUT,
        "fan_out_cap",
    )?;
    let limit = bounded(input.limit, DEFAULT_NODES, MAX_NODES, "limit")?;
    walker.relations = input.relations;
    walker.kinds = input.object_kinds.into_iter().collect();

    let mut objects = HashMap::new();
    let mut admitted = HashSet::new();
    let mut returned = Vec::new();
    let mut visited = BTreeSet::new();
    let mut states_of: HashMap<String, Vec<State>> = HashMap::new();
    let mut frontier = Vec::new();
    for id in &input.seed_ids {
        let seed = walker.root(id, "expand-neighborhood")?;
        if admitted.insert(seed.id.clone()) {
            for state in walker.root_states(&seed) {
                visited.insert(state.clone());
                states_of
                    .entry(seed.id.clone())
                    .or_default()
                    .push(state.clone());
                frontier.push(state);
            }
            returned.push(seed.clone());
            objects.insert(seed.id.clone(), seed);
        }
    }
    // Counted means visible within `depth`; admitted means returned and expanded.
    // A node one parent could not admit may still be admitted through another, and
    // an admitted node reached under a new classification is expanded again.
    let mut counted: HashSet<String> = admitted.clone();
    let mut capped_before_last_level = HashSet::new();
    let mut exhausted = false;
    let mut links = Vec::new();
    let mut link_ids = HashSet::new();
    let mut last_level = Vec::new();
    'levels: for level in 1..=depth {
        let mut next = Vec::new();
        for state in &frontier {
            let node: domain::Object = objects[&state.0].clone();
            let mut expanded = 0;
            for (link, object) in walker.candidates(&node)? {
                let children = walker.hop_states(state, &node, &object)?;
                if children.is_empty() {
                    continue;
                }
                if !walker.charge() {
                    exhausted = true;
                    break 'levels;
                }
                counted.insert(object.id.clone());
                if !admitted.contains(&object.id) {
                    if expanded == fan_out {
                        if level < depth {
                            capped_before_last_level.insert(object.id.clone());
                        }
                        continue;
                    }
                    expanded += 1;
                    admitted.insert(object.id.clone());
                    returned.push(object.clone());
                    last_level.push(object.id.clone());
                }
                if link_ids.insert(link.id.clone()) {
                    links.push(link);
                }
                objects.insert(object.id.clone(), object);
                for child in children {
                    if visited.insert(child.clone()) {
                        states_of
                            .entry(child.0.clone())
                            .or_default()
                            .push(child.clone());
                        next.push(child);
                    }
                }
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
        if level < depth {
            last_level.clear();
        }
    }
    let total = counted.len() as i64;
    // A node capped before the last level may be admitted later through another
    // parent, but its expansion from that level was skipped, so stay conservative.
    let lower_bound = exhausted || !capped_before_last_level.is_empty();
    returned.truncate(limit as usize);
    let truncated = (returned.len() as i64) < total;
    let page: HashSet<&str> = returned.iter().map(|object| object.id.as_str()).collect();
    // Nodes first admitted at the last level were never expanded; pick up links among
    // returned nodes whose hop the marking join permits from a recorded state of
    // either end, exactly as a traversal over that link would.
    for id in last_level.iter().filter(|id| page.contains(id.as_str())) {
        for link in walker.links(id)? {
            if !page.contains(link.from_id.as_str())
                || !page.contains(link.to_id.as_str())
                || link_ids.contains(&link.id)
            {
                continue;
            }
            let (from, to) = (&objects[&link.from_id], &objects[&link.to_id]);
            let mut permitted = false;
            for (near, far) in [(from, to), (to, from)] {
                for state in states_of.get(&near.id).into_iter().flatten() {
                    if !walker.hop_states(state, near, far)?.is_empty() {
                        permitted = true;
                        break;
                    }
                }
            }
            if permitted {
                link_ids.insert(link.id.clone());
                links.push(link);
            }
        }
    }
    links.retain(|link| page.contains(link.from_id.as_str()) && page.contains(link.to_id.as_str()));
    let objects = walker.project(returned)?;
    Ok(Response::new(ExpandNeighborhoodResponse {
        objects: objects.iter().map(to_proto_obj).collect(),
        links: links.iter().map(to_proto_link).collect(),
        total_count: total,
        total_is_lower_bound: lower_bound,
        truncated,
    }))
}

/// A walk state: an object reached under one marking-joined path classification.
/// `None` for a trusted service principal, whose hops are never marking-restricted.
type State = (String, Option<PathClassification>);

pub(super) async fn find_paths(
    service: &SekaiServiceImpl,
    req: Request<FindPathsRequest>,
) -> Result<Response<FindPathsResponse>, Status> {
    let mut walker = Walker::new(service, &req)?;
    let input = req.into_inner();
    if input.from_id.is_empty() || input.to_id.is_empty() {
        return Err(Status::invalid_argument("from_id and to_id required"));
    }
    let max_depth = bounded(input.max_depth, MAX_DEPTH, MAX_DEPTH, "max_depth")?;
    let limit = bounded(input.limit, DEFAULT_PATHS, MAX_PATHS, "limit")? as usize;
    walker.relations = input.relations;
    let from = walker.root(&input.from_id, "find-paths")?;
    let to = walker.root(&input.to_id, "find-paths")?;
    if from.id == to.id {
        return Ok(Response::new(FindPathsResponse {
            paths: vec![ObjectPath {
                object_ids: vec![from.id.clone()],
                links: Vec::new(),
            }],
            objects: walker
                .project(vec![from])?
                .iter()
                .map(to_proto_obj)
                .collect(),
            truncated: false,
        }));
    }

    // Level-synchronous BFS over (object, classification) states, keeping every
    // same-level parent: each recorded edge is permitted from that exact parent
    // state, so every reconstructed path passes the marking join hop by hop.
    let mut objects = HashMap::from([(from.id.clone(), from.clone())]);
    let mut level_of: BTreeMap<State, i32> = BTreeMap::new();
    let mut parents: BTreeMap<State, Vec<(State, domain::Link)>> = BTreeMap::new();
    let mut frontier = Vec::new();
    for state in walker.root_states(&from) {
        level_of.insert(state.clone(), 0);
        frontier.push(state);
    }
    let mut targets = Vec::new();
    let mut exhausted = false;
    'levels: for level in 1..=max_depth {
        let mut next = Vec::new();
        for state in &frontier {
            let node = objects[&state.0].clone();
            for (link, object) in walker.candidates(&node)? {
                let children = walker.hop_states(state, &node, &object)?;
                if children.is_empty() {
                    continue;
                }
                if !walker.charge() {
                    exhausted = true;
                    break 'levels;
                }
                for child in children {
                    match level_of.get(&child) {
                        None => {
                            level_of.insert(child.clone(), level);
                            parents.insert(child.clone(), vec![(state.clone(), link.clone())]);
                            objects.insert(object.id.clone(), object.clone());
                            if child.0 == to.id {
                                targets.push(child.clone());
                            }
                            next.push(child);
                        }
                        Some(seen) if *seen == level => parents
                            .entry(child)
                            .or_default()
                            .push((state.clone(), link.clone())),
                        Some(_) => {}
                    }
                }
            }
        }
        if !targets.is_empty() {
            break;
        }
        frontier = next;
    }
    let mut found = BTreeMap::new();
    let mut more = false;
    for target in &targets {
        more |= collect_paths(target, &from.id, &parents, limit, &mut found);
    }
    // A spent budget may have cut the search short, so paths can be missing.
    let truncated = exhausted || more;
    let paths: Vec<ObjectPath> = found.into_values().collect();
    let on_paths: BTreeSet<&str> = paths
        .iter()
        .flat_map(|path| path.object_ids.iter().map(String::as_str))
        .collect();
    let path_objects = on_paths
        .into_iter()
        .filter_map(|id| objects.get(id).cloned())
        .collect();
    let path_objects = walker.project(path_objects)?;
    Ok(Response::new(FindPathsResponse {
        paths,
        objects: path_objects.iter().map(to_proto_obj).collect(),
        truncated,
    }))
}

/// Walks parent edges back from `target` to the source object, adding each path
/// once (keyed by its ids and links, so the order is stable). Returns true when
/// more than `limit` distinct paths exist.
fn collect_paths(
    target: &State,
    source: &str,
    parents: &BTreeMap<State, Vec<(State, domain::Link)>>,
    limit: usize,
    out: &mut BTreeMap<(Vec<String>, Vec<String>), ObjectPath>,
) -> bool {
    fn walk(
        state: &State,
        source: &str,
        parents: &BTreeMap<State, Vec<(State, domain::Link)>>,
        ids: &mut Vec<String>,
        links: &mut Vec<domain::Link>,
        limit: usize,
        out: &mut BTreeMap<(Vec<String>, Vec<String>), ObjectPath>,
    ) -> bool {
        if state.0 == source && !parents.contains_key(state) {
            let object_ids: Vec<String> = ids.iter().rev().cloned().collect();
            let link_ids: Vec<String> = links.iter().rev().map(|link| link.id.clone()).collect();
            let key = (object_ids.clone(), link_ids);
            if out.contains_key(&key) {
                return false;
            }
            if out.len() == limit {
                return true;
            }
            out.insert(
                key,
                ObjectPath {
                    object_ids,
                    links: links.iter().rev().map(to_proto_link).collect(),
                },
            );
            return false;
        }
        for (parent, link) in parents.get(state).into_iter().flatten() {
            ids.push(parent.0.clone());
            links.push(link.clone());
            let more = walk(parent, source, parents, ids, links, limit, out);
            ids.pop();
            links.pop();
            if more {
                return true;
            }
        }
        false
    }
    let mut ids = vec![target.0.clone()];
    walk(
        target,
        source,
        parents,
        &mut ids,
        &mut Vec::new(),
        limit,
        out,
    )
}

/// `0` selects the default; values past `max` or below zero are refused.
fn bounded(value: i32, default: i32, max: i32, field: &str) -> Result<i32, Status> {
    match value {
        0 => Ok(default),
        1.. if value <= max => Ok(value),
        _ => Err(Status::invalid_argument(format!(
            "{field} must be between 1 and {max}"
        ))),
    }
}

/// One request's view of the visible graph: caller identity, compiled policy, root
/// classifications, and per-object verdicts and neighbor lists cached for the request.
struct Walker<'a> {
    service: &'a SekaiServiceImpl,
    principals: Vec<String>,
    policy_context: crate::sekai::object_security::PrincipalPolicyContext,
    purpose: Option<crate::sekai::purpose_authorization::PurposePresentation>,
    tenant_context: Option<RequestEnterpriseContext>,
    authority: markings::PrincipalAuthority,
    relations: Vec<String>,
    kinds: HashSet<String>,
    /// Classifications each read root starts under.
    paths: HashMap<String, BTreeSet<PathClassification>>,
    /// Hop-independent verdict per object id.
    readable: HashMap<String, bool>,
    /// Readable neighbors per expanded object, so several path states share one fetch.
    expanded: HashMap<String, Vec<(domain::Link, domain::Object)>>,
    recorded_purposes: HashSet<(String, String)>,
    examined: usize,
    scanned: usize,
}

impl<'a> Walker<'a> {
    fn new<T: 'static>(service: &'a SekaiServiceImpl, req: &Request<T>) -> Result<Self, Status> {
        let principals = caller_principals(req);
        require_authenticated(&principals)?;
        let authority = resolve_principal_authority(service.db.runtime(), &principals)?;
        Ok(Self {
            service,
            policy_context: principal_policy_context(req),
            purpose: request_purpose_presentation(req, &principals),
            tenant_context: request_tenant_context(service.db.runtime(), req)?,
            principals,
            authority,
            relations: Vec::new(),
            kinds: HashSet::new(),
            paths: HashMap::new(),
            readable: HashMap::new(),
            expanded: HashMap::new(),
            recorded_purposes: HashSet::new(),
            examined: 0,
            scanned: 0,
        })
    }

    fn db(&self) -> &'a RuntimeDb {
        self.service.db.runtime()
    }

    fn trusted(&self) -> bool {
        markings::is_trusted_service_principal(&self.authority.principal)
    }

    /// A start object the caller may read. A denial is the same not-found as a missing
    /// id, so a probe cannot learn that a hidden object exists; outages stay visible.
    fn root(&mut self, id: &str, operation: &str) -> Result<domain::Object, Status> {
        let object = self
            .db()
            .get_object_with_policy_context(id, &self.policy_context)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("not found"))?;
        let operation = format!("{operation}:{}", object.id);
        require_purpose_for_kind(
            self.db(),
            &object.namespace,
            &object.kind,
            self.purpose.as_ref(),
            &operation,
        )
        .map_err(hide_read_root_as_missing)?;
        let (object, _) = require_visible_read_root(
            self.db(),
            &self.service.security,
            object,
            &self.principals,
            self.tenant_context.as_ref(),
            &operation,
            self.purpose.as_ref(),
        )
        .map_err(hide_read_root_as_missing)?;
        let lattice = self
            .db()
            .get_classification_lattice(&object.namespace)
            .map_err(|_| Status::unavailable("classification lattice unavailable"))?;
        let digest = lattice
            .as_ref()
            .map(ClassificationLattice::digest)
            .transpose()
            .map_err(Status::internal)?;
        self.paths
            .entry(object.id.clone())
            .or_default()
            .insert(PathClassification {
                namespace: object.namespace.clone(),
                lattice_digest: digest,
                token: markings::object_marking_token(&object).map(str::to_string),
            });
        self.readable.insert(object.id.clone(), true);
        Ok(object)
    }

    /// Search states a root starts in: one per recorded classification.
    fn root_states(&self, root: &domain::Object) -> Vec<State> {
        if self.trusted() {
            return vec![(root.id.clone(), None)];
        }
        self.paths
            .get(&root.id)
            .into_iter()
            .flatten()
            .map(|path| (root.id.clone(), Some(path.clone())))
            .collect()
    }

    fn relations(&self) -> Vec<String> {
        if self.relations.is_empty() {
            vec![String::new()]
        } else {
            self.relations.clone()
        }
    }

    /// Links of `id` in both directions over the requested relations, row policy applied.
    fn links(&mut self, id: &str) -> Result<Vec<domain::Link>, Status> {
        let mut links = Vec::new();
        for direction in [domain::Direction::Outgoing, domain::Direction::Incoming] {
            for relation in self.relations() {
                links.extend(self.scan_links(id, &relation, &direction)?);
            }
        }
        Ok(links)
    }

    /// Readable neighbors of `node` over the requested relations in both directions,
    /// sorted by relation, neighbor id and link id. Marking joins along a path are
    /// checked separately per hop. Links are read within the scan limit first, so the
    /// neighbor objects loaded next are bounded by the same limit.
    fn candidates(
        &mut self,
        node: &domain::Object,
    ) -> Result<Vec<(domain::Link, domain::Object)>, Status> {
        if let Some(cached) = self.expanded.get(&node.id) {
            return Ok(cached.clone());
        }
        let mut neighbors = HashMap::new();
        let mut candidates = Vec::new();
        for direction in [domain::Direction::Outgoing, domain::Direction::Incoming] {
            for relation in self.relations() {
                let links = self.scan_links(&node.id, &relation, &direction)?;
                if links.is_empty() {
                    continue;
                }
                for object in self
                    .db()
                    .get_linked_objects_with_policy_context(
                        &node.id,
                        &relation,
                        &direction,
                        &self.policy_context,
                    )
                    .map_err(Status::internal)?
                {
                    neighbors.insert(object.id.clone(), object);
                }
                for link in links {
                    let far = match direction {
                        domain::Direction::Outgoing => link.to_id.clone(),
                        domain::Direction::Incoming => link.from_id.clone(),
                    };
                    candidates.push((link, far));
                }
            }
        }
        candidates.sort_by(|(a, a_far), (b, b_far)| {
            (&a.relation, a_far, &a.id).cmp(&(&b.relation, b_far, &b.id))
        });
        candidates.dedup_by(|(a, _), (b, _)| a.id == b.id);
        let mut visible = Vec::new();
        for (link, far) in candidates {
            let Some(object) = neighbors.get(&far) else {
                continue;
            };
            if !self.readable(object)? {
                continue;
            }
            visible.push((link, object.clone()));
        }
        self.expanded.insert(node.id.clone(), visible.clone());
        Ok(visible)
    }

    /// Links of `id` in one direction over one relation, read with a store-level limit
    /// of the remaining [`SCAN_LIMIT`] plus one; overflowing it fails the request
    /// before any neighbor object is loaded.
    fn scan_links(
        &mut self,
        id: &str,
        relation: &str,
        direction: &domain::Direction,
    ) -> Result<Vec<domain::Link>, Status> {
        let remaining = SCAN_LIMIT.saturating_sub(self.scanned);
        let links = self
            .db()
            .get_links_with_policy_context_limited(
                id,
                relation,
                direction,
                &self.policy_context,
                remaining + 1,
            )
            .map_err(Status::internal)?;
        if links.len() > remaining {
            return Err(Status::resource_exhausted(
                "link scan limit reached; narrow relations, seeds or depth",
            ));
        }
        self.scanned += links.len();
        Ok(links)
    }

    /// Charges one authorized hop to the visible examination budget; false once spent.
    /// Only hops that pass every check count, so hidden structure cannot move the flags.
    fn charge(&mut self) -> bool {
        self.examined += 1;
        self.examined <= EXAMINATION_BUDGET
    }

    /// The states `object` is reached in from exactly `state` of `parent`.
    fn hop_states(
        &self,
        state: &State,
        parent: &domain::Object,
        object: &domain::Object,
    ) -> Result<Vec<State>, Status> {
        let Some(path) = &state.1 else {
            return Ok(vec![(object.id.clone(), None)]);
        };
        let only = HashMap::from([(parent.id.clone(), BTreeSet::from([path.clone()]))]);
        let hops = permitted_hop_paths(self.db(), &self.authority, &only, Some(parent), object)
            .map_err(marking_unavailable)?;
        Ok(match hops {
            None => vec![(object.id.clone(), None)],
            Some(hops) => hops
                .into_iter()
                .map(|hop| (object.id.clone(), Some(hop)))
                .collect(),
        })
    }

    /// Hop-independent checks, cached per object id.
    fn readable(&mut self, object: &domain::Object) -> Result<bool, Status> {
        if let Some(readable) = self.readable.get(&object.id) {
            return Ok(*readable);
        }
        let readable = self.readable_object(object)?;
        self.readable.insert(object.id.clone(), readable);
        Ok(readable)
    }

    fn readable_object(&mut self, object: &domain::Object) -> Result<bool, Status> {
        if !self.kinds.is_empty() && !self.kinds.contains(&object.kind) {
            return Ok(false);
        }
        if !purpose_kind_permitted(
            self.db(),
            &object.namespace,
            &object.kind,
            self.purpose.as_ref(),
        )? {
            return Ok(false);
        }
        if let Some(actor) = self
            .tenant_context
            .as_ref()
            .and_then(|context| context.act.as_ref())
            && !object_passes_marking(self.db(), object, std::slice::from_ref(actor))?
        {
            return Ok(false);
        }
        if !object_is_visible_for_purpose(
            self.db(),
            &self.service.security,
            object,
            &self.principals,
            self.tenant_context.as_ref(),
            crate::sekai::object_security::ObjectSecurityOperation::Read,
            self.purpose.as_ref(),
        ) {
            return Ok(false);
        }
        purpose_allows_kind(
            self.db(),
            &object.namespace,
            &object.kind,
            self.purpose.as_ref(),
            &mut self.recorded_purposes,
        )
    }

    /// Applies property grants and redaction to returned objects, as every read does.
    fn project(&self, objects: Vec<domain::Object>) -> Result<Vec<domain::Object>, Status> {
        self.service.resolve_computed_for_responses_with_policy(
            objects,
            &self.principals,
            Some(&self.policy_context),
            self.tenant_context.as_ref(),
            self.purpose.as_ref(),
        )
    }
}

fn marking_unavailable(error: String) -> Status {
    Status::unavailable(format!("marking evaluation unavailable: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service_from(db: RuntimeDb) -> SekaiServiceImpl {
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
            db,
        )))
    }

    fn as_tester<T>(payload: T) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::from_static("tester"));
        req
    }

    fn add(db: &RuntimeDb, id: &str, kind: &str) {
        let object = domain::Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        };
        db.create_object_with_audit(&object, "tester").unwrap();
    }

    /// An object with any grant is readable only by its grantees, so a grant to
    /// `alice` hides it from `tester`.
    fn hide(svc: &SekaiServiceImpl, id: &str) {
        let grant = crate::sekai::security::Grant {
            id: format!("grant-{id}"),
            object_id: id.into(),
            principal: "alice".into(),
            role: crate::sekai::security::Role::Viewer,
            created: 0,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }

    fn link(db: &RuntimeDb, id: &str, from: &str, to: &str, relation: &str) {
        db.create_link(&domain::Link {
            id: id.into(),
            from_id: from.into(),
            to_id: to.into(),
            relation: relation.into(),
            created: 1,
        })
        .unwrap();
    }

    fn paths_req(from: &str, to: &str) -> FindPathsRequest {
        FindPathsRequest {
            from_id: from.into(),
            to_id: to.into(),
            max_depth: 0,
            relations: Vec::new(),
            limit: MAX_PATHS,
        }
    }

    fn neighborhood_req(seed: &str, depth: i32) -> ExpandNeighborhoodRequest {
        ExpandNeighborhoodRequest {
            seed_ids: vec![seed.into()],
            relations: Vec::new(),
            object_kinds: Vec::new(),
            depth,
            fan_out_cap: 0,
            limit: 0,
        }
    }

    fn ids(objects: &[Object]) -> Vec<String> {
        objects.iter().map(|object| object.id.clone()).collect()
    }

    fn path_keys(paths: &[ObjectPath]) -> Vec<(Vec<String>, Vec<String>)> {
        let mut keys: Vec<_> = paths
            .iter()
            .map(|path| {
                (
                    path.object_ids.clone(),
                    path.links.iter().map(|link| link.id.clone()).collect(),
                )
            })
            .collect();
        keys.sort();
        keys
    }

    /// All shortest undirected simple paths by plain BFS over the full link list.
    fn reference_paths(
        links: &[(String, String, String)],
        from: &str,
        to: &str,
        max_depth: usize,
    ) -> Vec<(Vec<String>, Vec<String>)> {
        let mut found = Vec::new();
        let mut frontier = vec![(vec![from.to_string()], Vec::<String>::new())];
        for _ in 0..max_depth {
            let mut next = Vec::new();
            for (ids, link_ids) in &frontier {
                let last = ids.last().unwrap();
                for (id, a, b) in links {
                    let far = if a == last {
                        b
                    } else if b == last {
                        a
                    } else {
                        continue;
                    };
                    if ids.contains(far) {
                        continue;
                    }
                    let mut ids = ids.clone();
                    ids.push(far.clone());
                    let mut link_ids = link_ids.clone();
                    link_ids.push(id.clone());
                    if far == to {
                        found.push((ids, link_ids));
                    } else {
                        next.push((ids, link_ids));
                    }
                }
            }
            if !found.is_empty() {
                break;
            }
            frontier = next;
        }
        found.sort();
        found
    }

    #[tokio::test]
    async fn shortest_paths_match_a_reference_bfs() {
        let db = RuntimeDb::memory();
        for index in 0..30 {
            add(&db, &format!("n{index:02}"), "node");
        }
        // Deterministic sparse graph: a ring plus pseudo-random chords.
        let mut links = Vec::new();
        for index in 0..30u64 {
            let chord = (index * 7 + 3) % 30;
            for (offset, to) in [(0, (index + 1) % 30), (1, chord)] {
                if to == index {
                    continue;
                }
                let id = format!("l{index:02}-{offset}");
                let (from, to) = (format!("n{index:02}"), format!("n{to:02}"));
                let relation = if offset == 0 { "next" } else { "chord" };
                link(&db, &id, &from, &to, relation);
                links.push((id, from, to));
            }
        }
        let svc = service_from(db);
        let mut connected = 0;
        for from in ["n00", "n04", "n09", "n27"] {
            for index in 0..30 {
                let to = format!("n{index:02}");
                if to == from {
                    continue;
                }
                let response = find_paths(&svc, as_tester(paths_req(from, &to)))
                    .await
                    .unwrap()
                    .into_inner();
                assert!(!response.truncated, "{from}->{to}");
                let expected = reference_paths(&links, from, &to, MAX_DEPTH as usize);
                connected += usize::from(!expected.is_empty());
                assert_eq!(path_keys(&response.paths), expected, "{from}->{to}");
            }
        }
        assert!(
            connected > 40,
            "the fixture must exercise real paths: {connected}"
        );
    }

    #[tokio::test]
    async fn a_hidden_intermediate_leaves_no_path_and_no_trace() {
        let db = RuntimeDb::memory();
        for id in ["a", "b", "c", "d", "x", "y", "p", "q", "h", "h2"] {
            add(&db, id, "node");
        }
        // a-h-b is shorter than a-c-d-b, but h is hidden.
        link(&db, "ah", "a", "h", "r");
        link(&db, "hb", "h", "b", "r");
        link(&db, "ac", "a", "c", "r");
        link(&db, "cd", "c", "d", "r");
        link(&db, "db", "d", "b", "r");
        // x and y are joined only through hidden h2; p and q are not joined at all.
        link(&db, "xh", "x", "h2", "r");
        link(&db, "hy", "h2", "y", "r");
        let svc = service_from(db);
        hide(&svc, "h");
        hide(&svc, "h2");

        let response = find_paths(&svc, as_tester(paths_req("a", "b")))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            path_keys(&response.paths),
            vec![(
                vec!["a".to_string(), "c".into(), "d".into(), "b".into()],
                vec!["ac".to_string(), "cd".into(), "db".into()]
            )]
        );
        assert!(!ids(&response.objects).contains(&"h".to_string()));

        let through_hidden = find_paths(&svc, as_tester(paths_req("x", "y")))
            .await
            .unwrap()
            .into_inner();
        let unlinked = find_paths(&svc, as_tester(paths_req("p", "q")))
            .await
            .unwrap()
            .into_inner();
        assert!(through_hidden.paths.is_empty());
        assert_eq!(through_hidden.truncated, unlinked.truncated);
        assert_eq!(through_hidden.objects.len(), unlinked.objects.len());

        let hidden = find_paths(&svc, as_tester(paths_req("a", "h")))
            .await
            .unwrap_err();
        let missing = find_paths(&svc, as_tester(paths_req("a", "nowhere")))
            .await
            .unwrap_err();
        assert_eq!(hidden.code(), missing.code());
        assert_eq!(hidden.message(), missing.message());

        let around = expand_neighborhood(&svc, as_tester(neighborhood_req("x", 2)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ids(&around.objects), ["x"], "x has no visible neighbor");
        assert_eq!(around.total_count, 1);
        assert!(around.links.is_empty());
    }

    #[tokio::test]
    async fn neighborhoods_honor_depth_relations_kinds_and_fan_out() {
        let db = RuntimeDb::memory();
        for id in ["s", "a", "b", "c", "e"] {
            add(&db, id, "node");
        }
        add(&db, "d", "other");
        link(&db, "sa", "s", "a", "r1");
        link(&db, "ab", "a", "b", "r1");
        link(&db, "bc", "c", "b", "r1");
        link(&db, "sd", "s", "d", "r2");
        link(&db, "se", "s", "e", "r1");
        let svc = service_from(db);

        let one = expand_neighborhood(&svc, as_tester(neighborhood_req("s", 1)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ids(&one.objects), ["s", "a", "e", "d"]);
        assert_eq!(one.total_count, 4);

        let mut req = neighborhood_req("s", 3);
        req.relations = vec!["r1".into()];
        let deep = expand_neighborhood(&svc, as_tester(req))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            ids(&deep.objects),
            ["s", "a", "e", "b", "c"],
            "incoming links are followed too"
        );
        assert_eq!(deep.links.len(), 4);

        let mut req = neighborhood_req("s", 1);
        req.object_kinds = vec!["other".into()];
        let kinds = expand_neighborhood(&svc, as_tester(req))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ids(&kinds.objects), ["s", "d"]);

        let mut req = neighborhood_req("s", 2);
        req.fan_out_cap = 1;
        let capped = expand_neighborhood(&svc, as_tester(req))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ids(&capped.objects), ["s", "a", "b"]);
        assert_eq!(capped.total_count, 5, "capped neighbors are still counted");
        assert!(capped.total_is_lower_bound && capped.truncated);

        let refused = expand_neighborhood(&svc, as_tester(neighborhood_req("s", MAX_DEPTH + 1)))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn a_capped_node_is_admitted_through_another_parent_and_boundary_links_are_returned() {
        let db = RuntimeDb::memory();
        for id in ["s", "t", "a", "b", "x", "y"] {
            add(&db, id, "node");
        }
        // s caps at one neighbor (a), which must not stop t from admitting b.
        link(&db, "sa", "s", "a", "r");
        link(&db, "sb", "s", "b", "r");
        link(&db, "tb", "t", "b", "r");
        // Triangle x-y-z: at depth 1 from x, y and z are boundary nodes joined by yz.
        add(&db, "z", "node");
        link(&db, "xy", "x", "y", "r");
        link(&db, "xz", "x", "z", "r");
        link(&db, "yz", "y", "z", "r");
        let svc = service_from(db);

        let mut req = neighborhood_req("s", 1);
        req.seed_ids.push("t".into());
        req.fan_out_cap = 1;
        let response = expand_neighborhood(&svc, as_tester(req))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ids(&response.objects), ["s", "t", "a", "b"]);
        assert_eq!(response.total_count, 4);
        assert!(!response.truncated);

        let triangle = expand_neighborhood(&svc, as_tester(neighborhood_req("x", 1)))
            .await
            .unwrap()
            .into_inner();
        let mut link_ids: Vec<_> = triangle.links.iter().map(|link| link.id.as_str()).collect();
        link_ids.sort_unstable();
        assert_eq!(link_ids, ["xy", "xz", "yz"]);
    }

    /// The page is capped and the count is exact, whatever the machine load:
    /// this asserts work done, not elapsed time (#1919).
    #[tokio::test]
    async fn ten_thousand_neighbors_return_a_capped_page_and_an_exact_count() {
        let db = RuntimeDb::memory();
        add(&db, "hub", "node");
        for index in 0..10_000 {
            let id = format!("v{index:05}");
            add(&db, &id, "node");
            link(&db, &format!("l{index:05}"), "hub", &id, "r");
        }
        for index in 0..50 {
            let id = format!("hidden{index:02}");
            add(&db, &id, "node");
            link(&db, &format!("lh{index:02}"), "hub", &id, "r");
        }
        let svc = service_from(db);
        for index in 0..50 {
            hide(&svc, &format!("hidden{index:02}"));
        }
        let mut req = neighborhood_req("hub", 1);
        req.limit = 50;
        let response = expand_neighborhood(&svc, as_tester(req))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.objects.len(), 50);
        assert_eq!(
            response.total_count, 10_001,
            "hidden neighbors are not counted"
        );
        assert!(response.truncated);
        assert!(
            !response.total_is_lower_bound,
            "depth 1 leaves nothing unexpanded"
        );
        assert!(
            ids(&response.objects)
                .iter()
                .all(|id| !id.starts_with("hidden"))
        );
    }
}
