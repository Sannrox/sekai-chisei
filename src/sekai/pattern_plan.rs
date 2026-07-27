//! Versioned multi-hop pattern plan IR and bounded SQLite executor (#375).
//!
//! Research freeze: `docs/research/145-semantic-pattern-query.md`.
//!
//! v1 is read-only, asserted-graph only. Plans are ephemeral (not stored).
//! Domain concepts stay out of the core contract; fixtures use neutral kinds
//! and relation names. No SQL / SPARQL / Cypher dialect is exposed.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{Direction, Link, Object};
use crate::sekai::retrieval;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::time::{Duration, Instant};

/// Wire / plan version id for the v1 pattern plan IR.
pub const PLAN_VERSION_V1: &str = "pattern_plan/v1";

/// Known plan version identifiers (additive only).
pub fn known_plan_versions() -> &'static [&'static str] {
    &[PLAN_VERSION_V1]
}

// Reuse retrieval hard bounds so multi-hop and context retrieval share ceilings.
pub const DEFAULT_MAX_DEPTH: u32 = retrieval::MAX_DEPTH;
pub const MAX_DEPTH: u32 = retrieval::MAX_DEPTH;
pub const DEFAULT_MAX_ROWS: u32 = retrieval::DEFAULT_MAX_OBJECTS;
pub const MAX_ROWS: u32 = retrieval::MAX_OBJECTS;
pub const DEFAULT_MAX_TIME_MS: u32 = retrieval::DEFAULT_MAX_TIME_MS;
pub const MAX_TIME_MS: u32 = retrieval::MAX_TIME_MS;
pub const DEFAULT_MAX_SOURCE_ROWS: u32 = retrieval::DEFAULT_MAX_SOURCE_ROWS;
pub const MAX_SOURCE_ROWS: u32 = retrieval::MAX_SOURCE_ROWS;
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = retrieval::DEFAULT_MAX_EXPLANATION_BYTES;
pub const MAX_MEMORY_BYTES: u64 = retrieval::MAX_EXPLANATION_BYTES;
pub const MAX_STEPS: usize = 32;
pub const MAX_VAR_NAME_CHARS: usize = 64;
pub const MAX_KIND_FILTERS: usize = retrieval::MAX_KIND_FILTERS;

/// Hard bounds applied to a pattern plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternPlanBounds {
    pub max_depth: u32,
    pub max_rows: u32,
    pub max_time_ms: u32,
    pub max_memory_bytes: u64,
    pub max_source_rows: u32,
}

impl Default for PatternPlanBounds {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_rows: DEFAULT_MAX_ROWS,
            max_time_ms: DEFAULT_MAX_TIME_MS,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_source_rows: DEFAULT_MAX_SOURCE_ROWS,
        }
    }
}

impl PatternPlanBounds {
    /// Normalize wire zeros to defaults and clamp absolute caps.
    pub fn normalize(raw: PatternPlanBounds) -> Self {
        Self {
            max_depth: if raw.max_depth == 0 {
                DEFAULT_MAX_DEPTH
            } else {
                raw.max_depth.min(MAX_DEPTH)
            },
            max_rows: if raw.max_rows == 0 {
                DEFAULT_MAX_ROWS
            } else {
                raw.max_rows.min(MAX_ROWS)
            },
            max_time_ms: if raw.max_time_ms == 0 {
                DEFAULT_MAX_TIME_MS
            } else {
                raw.max_time_ms.min(MAX_TIME_MS)
            },
            max_memory_bytes: if raw.max_memory_bytes == 0 {
                DEFAULT_MAX_MEMORY_BYTES
            } else {
                raw.max_memory_bytes.min(MAX_MEMORY_BYTES)
            },
            max_source_rows: if raw.max_source_rows == 0 {
                DEFAULT_MAX_SOURCE_ROWS
            } else {
                raw.max_source_rows.min(MAX_SOURCE_ROWS)
            },
        }
    }
}

/// Match a single node into a named variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchNodeStep {
    pub var: String,
    pub object_id: String,
    pub external_id: String,
    /// Optional kind constraint after resolve (empty = any).
    pub kind: String,
}

/// Expand one relation hop from `from_var` into `to_var`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandEdgeStep {
    pub from_var: String,
    pub to_var: String,
    pub relation: String,
    pub direction: Direction,
    pub kind_filter: Vec<String>,
}

/// Project bound variables into result rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BindStep {
    /// Empty means project all currently bound variables in definition order.
    pub vars: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternStep {
    MatchNode(MatchNodeStep),
    ExpandEdge(ExpandEdgeStep),
    Bind(BindStep),
}

/// Versioned, read-only multi-hop pattern plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternPlan {
    pub version: String,
    pub bounds: PatternPlanBounds,
    pub steps: Vec<PatternStep>,
}

/// One result row: variable → object id (and optional full object).
#[derive(Debug, Clone, Default)]
pub struct PatternBinding {
    pub vars: BTreeMap<String, String>,
    pub objects: BTreeMap<String, Object>,
}

#[derive(Debug, Clone, Default)]
pub struct PatternExecuteResult {
    pub plan_version: String,
    pub rows: Vec<PatternBinding>,
    pub truncated: bool,
    pub truncation_reasons: Vec<String>,
    /// Edges examined under authorization (never includes hidden object names).
    pub source_rows: u32,
}

/// Deterministic EXPLAIN over plan shape only — no graph side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternExplainStep {
    pub index: u32,
    pub op: String,
    pub summary: String,
    pub vars_in: Vec<String>,
    pub vars_out: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternExplainResult {
    pub plan_version: String,
    pub bounds: PatternPlanBounds,
    pub steps: Vec<PatternExplainStep>,
    pub expand_edge_count: u32,
    pub projected_vars: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternPlanError {
    InvalidArgument(String),
    PolicyDenied(String),
    Storage(String),
}

impl fmt::Display for PatternPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(m) | Self::PolicyDenied(m) | Self::Storage(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl std::error::Error for PatternPlanError {}

/// Authorization callback for hop-time object visibility.
///
/// Implementations must fail closed: `false` is indistinguishable from absence
/// at the executor boundary (no secret names in errors or counts).
pub type ObjectVisibleFn<'a> = dyn Fn(&Object) -> bool + 'a;

/// Plan-time visibility of relation / kind *names* (ontology ACL).
///
/// When a name is not visible, the executor fails closed with a non-disclosing
/// policy denial that never echoes the secret name.
pub type NameVisibleFn<'a> = dyn Fn(&str) -> bool + 'a;

fn validate_var_name(name: &str) -> Result<(), PatternPlanError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(PatternPlanError::InvalidArgument(
            "variable name must be non-empty".into(),
        ));
    }
    if trimmed.len() > MAX_VAR_NAME_CHARS {
        return Err(PatternPlanError::InvalidArgument(format!(
            "variable name exceeds {MAX_VAR_NAME_CHARS} characters"
        )));
    }
    if trimmed != name {
        return Err(PatternPlanError::InvalidArgument(
            "variable name must be canonical (no leading/trailing whitespace)".into(),
        ));
    }
    let mut chars = trimmed.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(PatternPlanError::InvalidArgument(
            "variable name must start with ASCII letter or underscore".into(),
        ));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(PatternPlanError::InvalidArgument(
            "variable name must be ASCII alphanumeric or underscore".into(),
        ));
    }
    Ok(())
}

fn parse_expand_direction(value: &str) -> Result<Direction, PatternPlanError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "outgoing" => Ok(Direction::Outgoing),
        "incoming" => Ok(Direction::Incoming),
        "both" => Err(PatternPlanError::InvalidArgument(
            "expand_edge direction must be outgoing or incoming (not both)".into(),
        )),
        _ => Err(PatternPlanError::InvalidArgument(
            "expand_edge direction must be outgoing or incoming".into(),
        )),
    }
}

/// Normalize and validate a plan without reading the graph.
///
/// Plan-time name visibility is applied when callbacks are provided. Hidden
/// relation/kind names yield a non-disclosing [`PatternPlanError::PolicyDenied`].
pub fn validate_plan(
    plan: &PatternPlan,
    relation_visible: Option<&NameVisibleFn<'_>>,
    kind_visible: Option<&NameVisibleFn<'_>>,
) -> Result<PatternPlan, PatternPlanError> {
    if plan.version.trim() != PLAN_VERSION_V1 {
        return Err(PatternPlanError::InvalidArgument(format!(
            "unknown pattern plan version {:?}; expected {}",
            plan.version.trim(),
            PLAN_VERSION_V1
        )));
    }
    if plan.steps.is_empty() {
        return Err(PatternPlanError::InvalidArgument(
            "pattern plan steps must be non-empty".into(),
        ));
    }
    if plan.steps.len() > MAX_STEPS {
        return Err(PatternPlanError::InvalidArgument(format!(
            "pattern plan exceeds max steps ({MAX_STEPS})"
        )));
    }

    let bounds = PatternPlanBounds::normalize(plan.bounds.clone());
    let mut bound_vars: BTreeSet<String> = BTreeSet::new();
    let mut definition_order: Vec<String> = Vec::new();
    let mut expand_count: u32 = 0;
    let mut has_bind = false;
    let mut normalized_steps = Vec::with_capacity(plan.steps.len());

    for (index, step) in plan.steps.iter().enumerate() {
        match step {
            PatternStep::MatchNode(m) => {
                validate_var_name(&m.var)?;
                let object_set = !m.object_id.trim().is_empty();
                let external_set = !m.external_id.trim().is_empty();
                if object_set == external_set {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: match_node requires exactly one of object_id or external_id"
                    )));
                }
                if object_set && m.object_id.trim() != m.object_id {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: object_id must be canonical"
                    )));
                }
                if external_set && m.external_id.trim() != m.external_id {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: external_id must be canonical"
                    )));
                }
                if !m.kind.is_empty() {
                    if m.kind.trim() != m.kind || m.kind.trim().is_empty() {
                        return Err(PatternPlanError::InvalidArgument(format!(
                            "step {index}: kind must be canonical when set"
                        )));
                    }
                    if let Some(vis) = kind_visible
                        && !vis(&m.kind)
                    {
                        return Err(PatternPlanError::PolicyDenied("access denied".into()));
                    }
                }
                if bound_vars.contains(&m.var) {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: variable {:?} is already bound",
                        m.var
                    )));
                }
                bound_vars.insert(m.var.clone());
                definition_order.push(m.var.clone());
                normalized_steps.push(PatternStep::MatchNode(MatchNodeStep {
                    var: m.var.clone(),
                    object_id: m.object_id.clone(),
                    external_id: m.external_id.clone(),
                    kind: m.kind.clone(),
                }));
            }
            PatternStep::ExpandEdge(e) => {
                validate_var_name(&e.from_var)?;
                validate_var_name(&e.to_var)?;
                if e.relation.trim().is_empty() {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: expand_edge relation must be non-empty"
                    )));
                }
                if e.relation.trim() != e.relation {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: relation must be canonical"
                    )));
                }
                if let Some(vis) = relation_visible
                    && !vis(&e.relation)
                {
                    return Err(PatternPlanError::PolicyDenied("access denied".into()));
                }
                if !bound_vars.contains(&e.from_var) {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: expand_edge from_var {:?} is not bound",
                        e.from_var
                    )));
                }
                if bound_vars.contains(&e.to_var) {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: expand_edge to_var {:?} is already bound",
                        e.to_var
                    )));
                }
                if e.kind_filter.len() > MAX_KIND_FILTERS {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: kind_filter exceeds max ({MAX_KIND_FILTERS})"
                    )));
                }
                for kind in &e.kind_filter {
                    if kind.trim().is_empty() || kind.trim() != kind.as_str() {
                        return Err(PatternPlanError::InvalidArgument(format!(
                            "step {index}: kind_filter entries must be non-empty canonical names"
                        )));
                    }
                    if let Some(vis) = kind_visible
                        && !vis(kind)
                    {
                        return Err(PatternPlanError::PolicyDenied("access denied".into()));
                    }
                }
                expand_count = expand_count.saturating_add(1);
                if expand_count > bounds.max_depth {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "pattern plan expand_edge count ({expand_count}) exceeds max_depth ({})",
                        bounds.max_depth
                    )));
                }
                let direction = e.direction.clone();
                bound_vars.insert(e.to_var.clone());
                definition_order.push(e.to_var.clone());
                normalized_steps.push(PatternStep::ExpandEdge(ExpandEdgeStep {
                    from_var: e.from_var.clone(),
                    to_var: e.to_var.clone(),
                    relation: e.relation.clone(),
                    direction,
                    kind_filter: e.kind_filter.clone(),
                }));
            }
            PatternStep::Bind(b) => {
                if has_bind {
                    return Err(PatternPlanError::InvalidArgument(
                        "pattern plan may contain at most one bind step".into(),
                    ));
                }
                has_bind = true;
                let mut seen = BTreeSet::new();
                let mut vars = Vec::new();
                if b.vars.is_empty() {
                    // Deferred: filled after full pass with definition order.
                    vars = definition_order.clone();
                } else {
                    for var in &b.vars {
                        validate_var_name(var)?;
                        if !bound_vars.contains(var) {
                            return Err(PatternPlanError::InvalidArgument(format!(
                                "step {index}: bind var {:?} is not bound",
                                var
                            )));
                        }
                        if !seen.insert(var.clone()) {
                            return Err(PatternPlanError::InvalidArgument(format!(
                                "step {index}: bind var {:?} is duplicated",
                                var
                            )));
                        }
                        vars.push(var.clone());
                    }
                }
                if vars.is_empty() {
                    return Err(PatternPlanError::InvalidArgument(format!(
                        "step {index}: bind projects no variables"
                    )));
                }
                normalized_steps.push(PatternStep::Bind(BindStep { vars }));
            }
        }
    }

    if !has_bind {
        // Implicit bind of all vars in definition order.
        if definition_order.is_empty() {
            return Err(PatternPlanError::InvalidArgument(
                "pattern plan binds no variables".into(),
            ));
        }
        normalized_steps.push(PatternStep::Bind(BindStep {
            vars: definition_order,
        }));
    }

    // Ensure at least one match_node seeds the plan.
    if !normalized_steps
        .iter()
        .any(|s| matches!(s, PatternStep::MatchNode(_)))
    {
        return Err(PatternPlanError::InvalidArgument(
            "pattern plan requires at least one match_node step".into(),
        ));
    }

    Ok(PatternPlan {
        version: PLAN_VERSION_V1.into(),
        bounds,
        steps: normalized_steps,
    })
}

/// Deterministic EXPLAIN of plan shape. Does not touch the graph.
pub fn explain_plan(
    plan: &PatternPlan,
    relation_visible: Option<&NameVisibleFn<'_>>,
    kind_visible: Option<&NameVisibleFn<'_>>,
) -> Result<PatternExplainResult, PatternPlanError> {
    let normalized = validate_plan(plan, relation_visible, kind_visible)?;
    let mut steps = Vec::with_capacity(normalized.steps.len());
    let mut bound: BTreeSet<String> = BTreeSet::new();
    let mut expand_edge_count = 0u32;
    let mut projected_vars = Vec::new();

    for (index, step) in normalized.steps.iter().enumerate() {
        match step {
            PatternStep::MatchNode(m) => {
                let root = if !m.object_id.is_empty() {
                    "object_id"
                } else {
                    "external_id"
                };
                let kind_note = if m.kind.is_empty() {
                    String::new()
                } else {
                    format!(" kind={}", m.kind)
                };
                let summary = format!("match_node var={} via {}{}", m.var, root, kind_note);
                let vars_out = vec![m.var.clone()];
                steps.push(PatternExplainStep {
                    index: index as u32,
                    op: "match_node".into(),
                    summary,
                    vars_in: Vec::new(),
                    vars_out: vars_out.clone(),
                });
                bound.insert(m.var.clone());
            }
            PatternStep::ExpandEdge(e) => {
                expand_edge_count = expand_edge_count.saturating_add(1);
                let dir = direction_to_wire(&e.direction);
                let filter = if e.kind_filter.is_empty() {
                    String::new()
                } else {
                    format!(" kind_filter={}", e.kind_filter.join(","))
                };
                let summary = format!(
                    "expand_edge {} -[{} {}]-> {}{}",
                    e.from_var, e.relation, dir, e.to_var, filter
                );
                steps.push(PatternExplainStep {
                    index: index as u32,
                    op: "expand_edge".into(),
                    summary,
                    vars_in: vec![e.from_var.clone()],
                    vars_out: vec![e.to_var.clone()],
                });
                bound.insert(e.to_var.clone());
            }
            PatternStep::Bind(b) => {
                projected_vars = b.vars.clone();
                steps.push(PatternExplainStep {
                    index: index as u32,
                    op: "bind".into(),
                    summary: format!("bind vars={}", b.vars.join(",")),
                    vars_in: b.vars.clone(),
                    vars_out: b.vars.clone(),
                });
            }
        }
    }

    Ok(PatternExplainResult {
        plan_version: PLAN_VERSION_V1.into(),
        bounds: normalized.bounds,
        steps,
        expand_edge_count,
        projected_vars,
    })
}

fn estimate_env_bytes(env: &BTreeMap<String, String>) -> u64 {
    let mut total = 64u64; // map overhead baseline
    for (k, v) in env {
        total = total
            .saturating_add(k.len() as u64)
            .saturating_add(v.len() as u64)
            .saturating_add(24);
    }
    total
}

fn push_truncation(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|r| r == reason) {
        reasons.push(reason.into());
    }
}

fn link_target<'a>(link: &'a Link, direction: &Direction) -> &'a str {
    match direction {
        Direction::Outgoing => link.to_id.as_str(),
        Direction::Incoming => link.from_id.as_str(),
    }
}

fn sort_links_deterministically(links: &mut [Link], direction: &Direction) {
    links.sort_by(|a, b| {
        let ta = link_target(a, direction);
        let tb = link_target(b, direction);
        ta.cmp(tb)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.relation.cmp(&b.relation))
    });
}

fn sort_rows_deterministically(rows: &mut [PatternBinding], project: &[String]) {
    rows.sort_by(|a, b| {
        for var in project {
            let va = a.vars.get(var).map(String::as_str).unwrap_or("");
            let vb = b.vars.get(var).map(String::as_str).unwrap_or("");
            match va.cmp(vb) {
                std::cmp::Ordering::Equal => {}
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    });
}

/// Execute a validated pattern plan against the asserted graph.
///
/// Hop-time ACL: when `object_visible` returns false, the hop is treated as
/// absent — no permission error, no existence leak via counts or messages.
pub fn execute_plan(
    db: &RuntimeDb,
    plan: &PatternPlan,
    include_objects: bool,
    object_visible: &ObjectVisibleFn<'_>,
    relation_visible: Option<&NameVisibleFn<'_>>,
    kind_visible: Option<&NameVisibleFn<'_>>,
) -> Result<PatternExecuteResult, PatternPlanError> {
    let started = Instant::now();
    let normalized = validate_plan(plan, relation_visible, kind_visible)?;
    let bounds = &normalized.bounds;
    let deadline = started + Duration::from_millis(u64::from(bounds.max_time_ms));

    // Active environments: each is a binding of var → object id.
    let mut envs: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];
    let mut object_cache: HashMap<String, Object> = HashMap::new();
    let mut source_rows: u32 = 0;
    let mut truncated = false;
    let mut truncation_reasons: Vec<String> = Vec::new();
    let mut memory_bytes: u64 = 0;
    let mut projected: Vec<String> = Vec::new();

    for step in &normalized.steps {
        if Instant::now() >= deadline {
            truncated = true;
            push_truncation(&mut truncation_reasons, "max_time_ms");
            envs.clear();
            break;
        }
        match step {
            PatternStep::MatchNode(m) => {
                let mut next = Vec::new();
                for mut env in envs.drain(..) {
                    if Instant::now() >= deadline {
                        truncated = true;
                        push_truncation(&mut truncation_reasons, "max_time_ms");
                        break;
                    }
                    let resolved = if !m.object_id.is_empty() {
                        db.get_object(&m.object_id)
                            .map_err(PatternPlanError::Storage)?
                    } else {
                        db.find_by_external_id(&m.external_id)
                            .map_err(PatternPlanError::Storage)?
                    };
                    // Missing and unauthorized are indistinguishable.
                    let Some(object) = resolved else {
                        continue;
                    };
                    if !object_visible(&object) {
                        continue;
                    }
                    if !m.kind.is_empty() && object.kind != m.kind {
                        continue;
                    }
                    env.insert(m.var.clone(), object.id.clone());
                    memory_bytes = memory_bytes.saturating_add(estimate_env_bytes(&env));
                    if memory_bytes > bounds.max_memory_bytes {
                        truncated = true;
                        push_truncation(&mut truncation_reasons, "max_memory_bytes");
                        break;
                    }
                    object_cache.insert(object.id.clone(), object);
                    next.push(env);
                }
                envs = next;
            }
            PatternStep::ExpandEdge(e) => {
                let mut next = Vec::new();
                'envs: for env in envs.drain(..) {
                    if Instant::now() >= deadline {
                        truncated = true;
                        push_truncation(&mut truncation_reasons, "max_time_ms");
                        break;
                    }
                    let Some(from_id) = env.get(&e.from_var).cloned() else {
                        continue;
                    };
                    let mut links = db
                        .get_links(&from_id, &e.relation, &e.direction)
                        .map_err(PatternPlanError::Storage)?;
                    sort_links_deterministically(&mut links, &e.direction);
                    for link in links {
                        if Instant::now() >= deadline {
                            truncated = true;
                            push_truncation(&mut truncation_reasons, "max_time_ms");
                            break 'envs;
                        }
                        if source_rows >= bounds.max_source_rows {
                            truncated = true;
                            push_truncation(&mut truncation_reasons, "max_source_rows");
                            break 'envs;
                        }
                        source_rows = source_rows.saturating_add(1);
                        let target_id = link_target(&link, &e.direction).to_string();
                        let object = if let Some(cached) = object_cache.get(&target_id) {
                            cached.clone()
                        } else {
                            match db
                                .get_object(&target_id)
                                .map_err(PatternPlanError::Storage)?
                            {
                                Some(obj) => {
                                    object_cache.insert(obj.id.clone(), obj.clone());
                                    obj
                                }
                                None => continue,
                            }
                        };
                        // Hop-time ACL re-check: denied targets are absent.
                        if !object_visible(&object) {
                            continue;
                        }
                        if !e.kind_filter.is_empty()
                            && !e.kind_filter.iter().any(|k| k == &object.kind)
                        {
                            continue;
                        }
                        let mut child = env.clone();
                        child.insert(e.to_var.clone(), object.id.clone());
                        memory_bytes = memory_bytes.saturating_add(estimate_env_bytes(&child));
                        if memory_bytes > bounds.max_memory_bytes {
                            truncated = true;
                            push_truncation(&mut truncation_reasons, "max_memory_bytes");
                            break 'envs;
                        }
                        next.push(child);
                    }
                }
                envs = next;
            }
            PatternStep::Bind(b) => {
                projected = b.vars.clone();
                // Bind is the terminal projection step.
            }
        }
    }

    let mut rows: Vec<PatternBinding> = Vec::with_capacity(envs.len());
    for env in envs {
        let mut binding = PatternBinding::default();
        for var in &projected {
            if let Some(id) = env.get(var) {
                binding.vars.insert(var.clone(), id.clone());
                if include_objects && let Some(obj) = object_cache.get(id) {
                    binding.objects.insert(var.clone(), obj.clone());
                }
            }
        }
        rows.push(binding);
    }
    sort_rows_deterministically(&mut rows, &projected);

    if rows.len() as u32 > bounds.max_rows {
        rows.truncate(bounds.max_rows as usize);
        truncated = true;
        push_truncation(&mut truncation_reasons, "max_rows");
    }

    Ok(PatternExecuteResult {
        plan_version: PLAN_VERSION_V1.into(),
        rows,
        truncated,
        truncation_reasons,
        source_rows,
    })
}

/// Build an expand-edge direction from a wire string during plan construction.
pub fn direction_from_wire(value: &str) -> Result<Direction, PatternPlanError> {
    parse_expand_direction(value)
}

/// Wire string for a direction used in EXPLAIN / responses.
pub fn direction_to_wire(direction: &Direction) -> &'static str {
    match direction {
        Direction::Outgoing => "outgoing",
        Direction::Incoming => "incoming",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::domain::Link;
    use std::sync::Arc;

    fn db() -> RuntimeDb {
        RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    fn object(id: &str, kind: &str, name: &str) -> Object {
        Object {
            id: id.into(),
            kind: kind.into(),
            name: name.into(),
            namespace: "default".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        }
    }

    fn link(id: &str, from: &str, to: &str, relation: &str) -> Link {
        Link {
            id: id.into(),
            from_id: from.into(),
            to_id: to.into(),
            relation: relation.into(),
            created: 0,
        }
    }

    /// Alice-style multi-hop fixture (≥3 edge steps), domain-neutral kinds.
    fn alice_fixture(db: &RuntimeDb) {
        for (id, kind, name) in [
            ("n-a", "entity", "alice"),
            ("n-b", "entity", "company"),
            ("n-c", "entity", "project"),
            ("n-d", "entity", "dataset"),
            ("n-secret", "entity", "secret-hop"),
            ("n-after-secret", "entity", "after-secret"),
        ] {
            db.create_object(&object(id, kind, name)).unwrap();
        }
        db.create_link(&link("e1", "n-a", "n-b", "rel_works_for"))
            .unwrap();
        db.create_link(&link("e2", "n-b", "n-c", "rel_owns"))
            .unwrap();
        db.create_link(&link("e3", "n-c", "n-d", "rel_uses"))
            .unwrap();
        // Parallel path through a secret intermediate.
        db.create_link(&link("es1", "n-a", "n-secret", "rel_works_for"))
            .unwrap();
        db.create_link(&link("es2", "n-secret", "n-after-secret", "rel_owns"))
            .unwrap();
    }

    fn three_hop_plan() -> PatternPlan {
        PatternPlan {
            version: PLAN_VERSION_V1.into(),
            bounds: PatternPlanBounds {
                max_depth: 3,
                max_rows: 20,
                max_time_ms: 500,
                max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
                max_source_rows: 200,
            },
            steps: vec![
                PatternStep::MatchNode(MatchNodeStep {
                    var: "A".into(),
                    object_id: "n-a".into(),
                    external_id: String::new(),
                    kind: String::new(),
                }),
                PatternStep::ExpandEdge(ExpandEdgeStep {
                    from_var: "A".into(),
                    to_var: "B".into(),
                    relation: "rel_works_for".into(),
                    direction: Direction::Outgoing,
                    kind_filter: vec![],
                }),
                PatternStep::ExpandEdge(ExpandEdgeStep {
                    from_var: "B".into(),
                    to_var: "C".into(),
                    relation: "rel_owns".into(),
                    direction: Direction::Outgoing,
                    kind_filter: vec![],
                }),
                PatternStep::ExpandEdge(ExpandEdgeStep {
                    from_var: "C".into(),
                    to_var: "D".into(),
                    relation: "rel_uses".into(),
                    direction: Direction::Outgoing,
                    kind_filter: vec![],
                }),
                PatternStep::Bind(BindStep {
                    vars: vec!["A".into(), "B".into(), "C".into(), "D".into()],
                }),
            ],
        }
    }

    fn allow_all(_obj: &Object) -> bool {
        true
    }

    #[test]
    fn plan_version_id_is_stable() {
        assert_eq!(PLAN_VERSION_V1, "pattern_plan/v1");
        assert!(known_plan_versions().contains(&PLAN_VERSION_V1));
    }

    #[test]
    fn unknown_plan_version_is_invalid() {
        let mut plan = three_hop_plan();
        plan.version = "pattern_plan/v0".into();
        let err = validate_plan(&plan, None, None).unwrap_err();
        assert!(matches!(err, PatternPlanError::InvalidArgument(_)));
        assert!(err.to_string().contains("unknown pattern plan version"));
    }

    #[test]
    fn unbound_from_var_is_invalid() {
        let plan = PatternPlan {
            version: PLAN_VERSION_V1.into(),
            bounds: PatternPlanBounds::default(),
            steps: vec![PatternStep::ExpandEdge(ExpandEdgeStep {
                from_var: "A".into(),
                to_var: "B".into(),
                relation: "rel".into(),
                direction: Direction::Outgoing,
                kind_filter: vec![],
            })],
        };
        let err = validate_plan(&plan, None, None).unwrap_err();
        assert!(matches!(err, PatternPlanError::InvalidArgument(_)));
    }

    #[test]
    fn expand_count_exceeding_max_depth_is_invalid() {
        let mut plan = three_hop_plan();
        plan.bounds.max_depth = 2;
        let err = validate_plan(&plan, None, None).unwrap_err();
        assert!(matches!(err, PatternPlanError::InvalidArgument(_)));
        assert!(err.to_string().contains("max_depth"));
    }

    #[test]
    fn multi_hop_fixture_returns_authorized_bindings() {
        let db = db();
        alice_fixture(&db);
        let plan = three_hop_plan();
        let result = execute_plan(&db, &plan, false, &allow_all, None, None).unwrap();
        assert_eq!(result.plan_version, PLAN_VERSION_V1);
        assert_eq!(result.rows.len(), 1);
        let row = &result.rows[0];
        assert_eq!(row.vars.get("A").map(String::as_str), Some("n-a"));
        assert_eq!(row.vars.get("B").map(String::as_str), Some("n-b"));
        assert_eq!(row.vars.get("C").map(String::as_str), Some("n-c"));
        assert_eq!(row.vars.get("D").map(String::as_str), Some("n-d"));
        assert!(!result.truncated);
    }

    #[test]
    fn denied_intermediate_hop_fails_closed_without_leak() {
        let db = db();
        alice_fixture(&db);
        let plan = three_hop_plan();
        // Hide the secret intermediate; authorized path through n-b remains.
        let visible = |obj: &Object| obj.id != "n-secret" && obj.id != "n-after-secret";
        let result = execute_plan(&db, &plan, false, &visible, None, None).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.rows[0].vars.get("B").map(String::as_str),
            Some("n-b")
        );
        // No secret ids in any binding.
        for row in &result.rows {
            for id in row.vars.values() {
                assert_ne!(id, "n-secret");
                assert_ne!(id, "n-after-secret");
            }
        }
        // Path that must pass through the secret intermediate fails closed as empty
        // (not a permission error) when that hop is denied.
        let secret_only = PatternPlan {
            version: PLAN_VERSION_V1.into(),
            bounds: PatternPlanBounds::default(),
            steps: vec![
                PatternStep::MatchNode(MatchNodeStep {
                    var: "A".into(),
                    object_id: "n-a".into(),
                    external_id: String::new(),
                    kind: String::new(),
                }),
                PatternStep::ExpandEdge(ExpandEdgeStep {
                    from_var: "A".into(),
                    to_var: "S".into(),
                    relation: "rel_works_for".into(),
                    direction: Direction::Outgoing,
                    kind_filter: vec![],
                }),
                PatternStep::ExpandEdge(ExpandEdgeStep {
                    from_var: "S".into(),
                    to_var: "T".into(),
                    relation: "rel_owns".into(),
                    direction: Direction::Outgoing,
                    kind_filter: vec![],
                }),
                PatternStep::Bind(BindStep {
                    vars: vec!["A".into(), "S".into(), "T".into()],
                }),
            ],
        };
        // Hide the public company so only the secret intermediate remains as a
        // works_for target — then deny that intermediate.
        let deny_secret_path = |obj: &Object| {
            obj.id != "n-b" && obj.id != "n-c" && obj.id != "n-d" && obj.id != "n-secret"
        };
        let denied = execute_plan(&db, &secret_only, false, &deny_secret_path, None, None).unwrap();
        // Secret intermediate denied → empty, not error.
        assert!(denied.rows.is_empty());
        // Truncation / errors must not embed secret names.
        for reason in &denied.truncation_reasons {
            assert!(!reason.contains("secret"));
            assert!(!reason.contains("n-secret"));
        }
    }

    #[test]
    fn same_plan_is_deterministic() {
        let db = db();
        alice_fixture(&db);
        // Add a second target for non-unique expansion ordering stress.
        db.create_object(&object("n-b2", "entity", "company-2"))
            .unwrap();
        db.create_link(&link("e1b", "n-a", "n-b2", "rel_works_for"))
            .unwrap();
        db.create_link(&link("e2b", "n-b2", "n-c", "rel_owns"))
            .unwrap();

        let plan = three_hop_plan();
        let a = execute_plan(&db, &plan, false, &allow_all, None, None).unwrap();
        let b = execute_plan(&db, &plan, false, &allow_all, None, None).unwrap();
        let av: Vec<_> = a.rows.iter().map(|r| r.vars.clone()).collect();
        let bv: Vec<_> = b.rows.iter().map(|r| r.vars.clone()).collect();
        assert_eq!(av, bv);
        assert_eq!(a.truncation_reasons, b.truncation_reasons);
        assert_eq!(a.source_rows, b.source_rows);
        // Ordering stable: n-b before n-b2 by object id.
        let bs: Vec<_> = a
            .rows
            .iter()
            .map(|r| r.vars.get("B").cloned().unwrap_or_default())
            .collect();
        assert_eq!(bs, vec!["n-b".to_string(), "n-b2".to_string()]);
    }

    #[test]
    fn max_rows_truncation_is_stable() {
        let db = db();
        alice_fixture(&db);
        for i in 0..5 {
            let id = format!("n-extra-{i}");
            db.create_object(&object(&id, "entity", &id)).unwrap();
            db.create_link(&link(&format!("ex{i}"), "n-c", &id, "rel_uses"))
                .unwrap();
        }
        let mut plan = three_hop_plan();
        plan.bounds.max_rows = 2;
        let a = execute_plan(&db, &plan, false, &allow_all, None, None).unwrap();
        let b = execute_plan(&db, &plan, false, &allow_all, None, None).unwrap();
        assert!(a.truncated);
        assert!(a.truncation_reasons.iter().any(|r| r == "max_rows"));
        assert_eq!(a.rows.len(), 2);
        let av: Vec<_> = a.rows.iter().map(|r| r.vars.clone()).collect();
        let bv: Vec<_> = b.rows.iter().map(|r| r.vars.clone()).collect();
        assert_eq!(av, bv);
        assert_eq!(a.truncation_reasons, b.truncation_reasons);
    }

    #[test]
    fn explain_is_stable_and_side_effect_free() {
        let plan = three_hop_plan();
        let e1 = explain_plan(&plan, None, None).unwrap();
        let e2 = explain_plan(&plan, None, None).unwrap();
        assert_eq!(e1, e2);
        assert_eq!(e1.plan_version, PLAN_VERSION_V1);
        assert_eq!(e1.expand_edge_count, 3);
        assert_eq!(e1.projected_vars, vec!["A", "B", "C", "D"]);
        assert_eq!(e1.steps.len(), 5);
        assert_eq!(e1.steps[0].op, "match_node");
        assert_eq!(e1.steps[1].op, "expand_edge");
        assert_eq!(e1.steps[4].op, "bind");
        // EXPLAIN does not need a database and must not invent data paths.
        for step in &e1.steps {
            assert!(!step.summary.contains("n-secret"));
            assert!(!step.summary.contains("found="));
        }
    }

    #[test]
    fn plan_time_hidden_relation_is_non_disclosing_policy_denial() {
        let plan = three_hop_plan();
        let relation_visible = |name: &str| name != "rel_owns";
        let err = validate_plan(&plan, Some(&relation_visible), None).unwrap_err();
        assert!(matches!(err, PatternPlanError::PolicyDenied(_)));
        assert_eq!(err.to_string(), "access denied");
        assert!(!err.to_string().contains("rel_owns"));
        // EXPLAIN uses the same gate.
        let err = explain_plan(&plan, Some(&relation_visible), None).unwrap_err();
        assert!(matches!(err, PatternPlanError::PolicyDenied(_)));
        assert!(!err.to_string().contains("rel_owns"));
    }

    #[test]
    fn missing_root_is_empty_not_error() {
        let db = db();
        let plan = three_hop_plan();
        let result = execute_plan(&db, &plan, false, &allow_all, None, None).unwrap();
        assert!(result.rows.is_empty());
    }
}
