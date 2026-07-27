//! Session-scoped, non-authoritative scenario overlay (#362 / research #148).
//!
//! Merges ordered hypothesis deltas over an authorized graph projection and
//! returns domain-neutral impact sets. Overlay evaluation never mutates
//! canonical objects, links, or temporal assertions.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{Direction, Link, Object};
use crate::sekai::retrieval;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};

/// Epistemic class stamped on every scenario artifact.
pub const EPISTEMIC_CLASS_HYPOTHESIS: &str = "hypothesis";

/// Default / hard caps for scenario-specific budgets (retrieval-class reuse).
pub const DEFAULT_MAX_DELTAS: u32 = 64;
pub const MAX_DELTAS: u32 = 256;
pub const DEFAULT_MAX_EXPANSION_WORK_UNITS: u32 = 200;
pub const MAX_EXPANSION_WORK_UNITS: u32 = 2_000;
pub const MAX_SEEDS: usize = 32;
pub const MAX_ID_LEN: usize = 256;
pub const MAX_PROPERTY_KEY_LEN: usize = 128;
pub const MAX_PROPERTY_VALUE_LEN: usize = 4_096;
pub const MAX_RELATION_LEN: usize = 128;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BaseMode {
    #[default]
    Current,
}

impl BaseMode {
    pub fn parse(value: &str) -> Result<Self, ScenarioError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "current" => Ok(Self::Current),
            // Temporal as-of is reserved until history wiring is in scope.
            "temporal" | "as_of" | "valid_at" => Err(ScenarioError::InvalidArgument(
                "temporal as-of base is not enabled in this vertical; use base_mode=current".into(),
            )),
            other => Err(ScenarioError::InvalidArgument(format!(
                "unknown base_mode {other:?}; expected current"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaOp {
    SetProperty {
        object_id: String,
        key: String,
        value: String,
    },
    RemoveProperty {
        object_id: String,
        key: String,
    },
    AddLink {
        link_id: String,
        from_id: String,
        to_id: String,
        relation: String,
    },
    RemoveLink {
        link_id: String,
    },
}

/// Wire fields used to construct a [`DeltaOp`] from gRPC / adapters.
#[derive(Debug, Clone, Default)]
pub struct DeltaOpInput<'a> {
    pub op: &'a str,
    pub object_id: &'a str,
    pub property_key: &'a str,
    pub property_value: &'a str,
    pub link_id: &'a str,
    pub from_id: &'a str,
    pub to_id: &'a str,
    pub relation: &'a str,
}

impl DeltaOp {
    pub fn parse(input: DeltaOpInput<'_>) -> Result<Self, ScenarioError> {
        match input.op.trim().to_ascii_lowercase().as_str() {
            "set_property" => {
                require_nonempty(input.object_id, "object_id for set_property")?;
                require_nonempty(input.property_key, "property_key for set_property")?;
                Ok(Self::SetProperty {
                    object_id: input.object_id.to_string(),
                    key: input.property_key.to_string(),
                    value: input.property_value.to_string(),
                })
            }
            "remove_property" => {
                require_nonempty(input.object_id, "object_id for remove_property")?;
                require_nonempty(input.property_key, "property_key for remove_property")?;
                Ok(Self::RemoveProperty {
                    object_id: input.object_id.to_string(),
                    key: input.property_key.to_string(),
                })
            }
            "add_link" => {
                require_nonempty(input.link_id, "link_id for add_link")?;
                require_nonempty(input.from_id, "from_id for add_link")?;
                require_nonempty(input.to_id, "to_id for add_link")?;
                require_nonempty(input.relation, "relation for add_link")?;
                Ok(Self::AddLink {
                    link_id: input.link_id.to_string(),
                    from_id: input.from_id.to_string(),
                    to_id: input.to_id.to_string(),
                    relation: input.relation.to_string(),
                })
            }
            "remove_link" => {
                require_nonempty(input.link_id, "link_id for remove_link")?;
                Ok(Self::RemoveLink {
                    link_id: input.link_id.to_string(),
                })
            }
            other => Err(ScenarioError::InvalidArgument(format!(
                "unknown scenario delta op {other:?}; expected set_property, remove_property, add_link, or remove_link"
            ))),
        }
    }

    fn conflict_key(&self) -> String {
        match self {
            Self::SetProperty { object_id, key, .. } | Self::RemoveProperty { object_id, key } => {
                format!("property:{object_id}:{key}")
            }
            Self::AddLink { link_id, .. } | Self::RemoveLink { link_id } => {
                format!("link:{link_id}")
            }
        }
    }

    fn op_label(&self) -> &'static str {
        match self {
            Self::SetProperty { .. } => "set_property",
            Self::RemoveProperty { .. } => "remove_property",
            Self::AddLink { .. } => "add_link",
            Self::RemoveLink { .. } => "remove_link",
        }
    }

    fn referenced_object_ids(&self) -> Vec<&str> {
        match self {
            Self::SetProperty { object_id, .. } | Self::RemoveProperty { object_id, .. } => {
                vec![object_id.as_str()]
            }
            Self::AddLink { from_id, to_id, .. } => vec![from_id.as_str(), to_id.as_str()],
            Self::RemoveLink { .. } => Vec::new(),
        }
    }

    fn referenced_link_id(&self) -> Option<&str> {
        match self {
            Self::AddLink { link_id, .. } | Self::RemoveLink { link_id } => Some(link_id.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypothesisDelta {
    pub id: String,
    pub op: DeltaOp,
}

#[derive(Debug, Clone, Default)]
pub struct ScenarioBounds {
    pub max_depth: u32,
    pub max_objects: u32,
    pub max_links: u32,
    pub max_time_ms: u32,
    pub max_explanation_bytes: u64,
    pub max_deltas: u32,
    pub max_expansion_work_units: u32,
}

impl ScenarioBounds {
    fn clamp(&self) -> ClampedBounds {
        ClampedBounds {
            max_depth: self.max_depth.min(retrieval::MAX_DEPTH),
            max_objects: bounded(
                self.max_objects,
                retrieval::DEFAULT_MAX_OBJECTS,
                retrieval::MAX_OBJECTS,
            ) as usize,
            max_links: bounded(
                self.max_links,
                retrieval::DEFAULT_MAX_LINKS,
                retrieval::MAX_LINKS,
            ) as usize,
            max_time: Duration::from_millis(u64::from(bounded(
                self.max_time_ms,
                retrieval::DEFAULT_MAX_TIME_MS,
                retrieval::MAX_TIME_MS,
            ))),
            max_explanation_bytes: if self.max_explanation_bytes == 0 {
                retrieval::DEFAULT_MAX_EXPLANATION_BYTES
            } else {
                self.max_explanation_bytes
                    .min(retrieval::MAX_EXPLANATION_BYTES)
            },
            max_deltas: bounded(self.max_deltas, DEFAULT_MAX_DELTAS, MAX_DELTAS) as usize,
            max_expansion_work_units: bounded(
                self.max_expansion_work_units,
                DEFAULT_MAX_EXPANSION_WORK_UNITS,
                MAX_EXPANSION_WORK_UNITS,
            ) as usize,
        }
    }
}

struct ClampedBounds {
    max_depth: u32,
    max_objects: usize,
    max_links: usize,
    max_time: Duration,
    max_explanation_bytes: u64,
    max_deltas: usize,
    max_expansion_work_units: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ScenarioRequest {
    pub namespace: String,
    pub base_mode: BaseMode,
    pub seed_object_ids: Vec<String>,
    pub deltas: Vec<HypothesisDelta>,
    pub bounds: ScenarioBounds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactRow {
    pub target_kind: String,
    pub object_id: String,
    pub link_id: String,
    pub property_key: String,
    pub op: String,
    pub delta_ids: Vec<String>,
    pub explanation_steps: Vec<String>,
    pub before_value: String,
    pub after_value: String,
}

#[derive(Debug, Clone, Default)]
pub struct ScenarioResult {
    pub epistemic_class: String,
    pub scenario_id: String,
    pub base_mode: String,
    pub namespace: String,
    pub impact_rows: Vec<ImpactRow>,
    pub truncated: bool,
    pub truncation_reasons: Vec<String>,
    pub expansion_work_units: u32,
    pub applied_deltas: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScenarioError {
    InvalidArgument(String),
    Storage(String),
    Conflict(String),
}

impl fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(message) | Self::Storage(message) | Self::Conflict(message) => {
                f.write_str(message)
            }
        }
    }
}

/// In-memory overlay view used during evaluation. Never written to storage.
#[derive(Debug, Clone, Default)]
struct OverlayView {
    objects: HashMap<String, Object>,
    /// Present links by id (canonical plus hypothetical adds, minus removes).
    links: HashMap<String, Link>,
    removed_link_ids: HashSet<String>,
}

/// Create → apply deltas → project impact as one request-scoped evaluation.
///
/// The function is side-effect free with respect to `db` write methods: it only
/// reads objects and links. Callers must not promote impact rows to mutations.
pub fn evaluate_scenario<F>(
    db: &RuntimeDb,
    request: &ScenarioRequest,
    scenario_id: impl Into<String>,
    can_read: F,
) -> Result<ScenarioResult, ScenarioError>
where
    F: Fn(&Object) -> bool,
{
    validate_request(request)?;
    let bounds = request.bounds.clamp();
    let started = Instant::now();
    let mut result = ScenarioResult {
        epistemic_class: EPISTEMIC_CLASS_HYPOTHESIS.into(),
        scenario_id: scenario_id.into(),
        base_mode: request.base_mode.as_str().into(),
        namespace: request.namespace.clone(),
        ..Default::default()
    };

    // Fail closed on same-key conflicts before any expansion work.
    let mut conflict_keys = HashMap::<String, String>::new();
    for delta in &request.deltas {
        let key = delta.op.conflict_key();
        if let Some(prior) = conflict_keys.insert(key.clone(), delta.id.clone()) {
            return Err(ScenarioError::Conflict(format!(
                "conflicting hypothesis deltas on {key}: {prior} and {}",
                delta.id
            )));
        }
    }

    if request.deltas.len() > bounds.max_deltas {
        add_truncation(&mut result, "deltas");
    }
    let deltas: Vec<&HypothesisDelta> = request.deltas.iter().take(bounds.max_deltas).collect();

    let mut overlay = OverlayView::default();
    let mut work_units: usize = 0;
    let mut explanation_bytes: u64 = 0;
    let mut authorized_object_ids = BTreeSet::new();
    let mut seed_ids = BTreeSet::new();

    // Resolve seeds under ACL. Denied seeds are skipped without disclosure.
    for seed_id in &request.seed_object_ids {
        if time_exceeded(started, bounds.max_time, &mut result) {
            break;
        }
        work_units = work_units.saturating_add(1);
        if work_units > bounds.max_expansion_work_units {
            add_truncation(&mut result, "expansion_work_units");
            break;
        }
        let Some(object) = load_object(db, seed_id, &mut overlay)? else {
            continue;
        };
        if object.namespace != request.namespace {
            // Cross-namespace seeds are treated as unresolved, not denied.
            continue;
        }
        if !can_read(&object) {
            // Deny non-disclosure: no seed id, count, or reason leaks.
            continue;
        }
        if authorized_object_ids.len() >= bounds.max_objects {
            add_truncation(&mut result, "objects");
            break;
        }
        authorized_object_ids.insert(object.id.clone());
        seed_ids.insert(object.id.clone());
        overlay.objects.insert(object.id.clone(), object);
    }

    // Structural expansion from authorized seeds (incident edges only).
    // Propagation is structural adjacency — never temporal causality.
    let mut frontier: Vec<(String, u32)> = seed_ids.iter().map(|id| (id.clone(), 0)).collect();
    let mut visited = seed_ids.clone();
    let mut accepted_links = 0usize;
    'expand: while let Some((object_id, depth)) = frontier.pop() {
        if time_exceeded(started, bounds.max_time, &mut result) {
            break;
        }
        if depth >= bounds.max_depth {
            continue;
        }
        work_units = work_units.saturating_add(1);
        if work_units > bounds.max_expansion_work_units {
            add_truncation(&mut result, "expansion_work_units");
            break;
        }
        let links = db
            .get_links(&object_id, "", &Direction::Outgoing)
            .map_err(ScenarioError::Storage)?;
        let incoming = db
            .get_links(&object_id, "", &Direction::Incoming)
            .map_err(ScenarioError::Storage)?;
        for link in links.into_iter().chain(incoming) {
            work_units = work_units.saturating_add(1);
            if work_units > bounds.max_expansion_work_units {
                add_truncation(&mut result, "expansion_work_units");
                break 'expand;
            }
            if accepted_links >= bounds.max_links {
                add_truncation(&mut result, "links");
                break 'expand;
            }
            let from = match load_object(db, &link.from_id, &mut overlay)? {
                Some(object) => object,
                None => continue,
            };
            let to = match load_object(db, &link.to_id, &mut overlay)? {
                Some(object) => object,
                None => continue,
            };
            if from.namespace != request.namespace || to.namespace != request.namespace {
                continue;
            }
            // Both endpoints must be readable; partial visibility is omitted.
            if !can_read(&from) || !can_read(&to) {
                continue;
            }
            if authorized_object_ids.len() >= bounds.max_objects
                && !authorized_object_ids.contains(&from.id)
                && !authorized_object_ids.contains(&to.id)
            {
                add_truncation(&mut result, "objects");
                break 'expand;
            }
            for endpoint in [from, to] {
                if authorized_object_ids.insert(endpoint.id.clone()) {
                    if authorized_object_ids.len() > bounds.max_objects {
                        authorized_object_ids.remove(&endpoint.id);
                        add_truncation(&mut result, "objects");
                        break 'expand;
                    }
                    overlay
                        .objects
                        .insert(endpoint.id.clone(), endpoint.clone());
                    if !visited.contains(&endpoint.id) && depth < bounds.max_depth {
                        visited.insert(endpoint.id.clone());
                        frontier.push((endpoint.id.clone(), depth + 1));
                    }
                }
            }
            if !overlay.links.contains_key(&link.id) && !overlay.removed_link_ids.contains(&link.id)
            {
                overlay.links.insert(link.id.clone(), link);
                accepted_links = accepted_links.saturating_add(1);
            }
        }
    }

    // Apply ordered hypothesis deltas against the overlay view only.
    let mut impact_rows = Vec::new();
    for delta in deltas {
        if time_exceeded(started, bounds.max_time, &mut result) {
            break;
        }
        work_units = work_units.saturating_add(1);
        if work_units > bounds.max_expansion_work_units {
            add_truncation(&mut result, "expansion_work_units");
            break;
        }

        // Authz re-check for every referenced object/link.
        if !delta_authorized(db, &request.namespace, delta, &mut overlay, &can_read)? {
            // Denied material never contributes to impact, counts, or steps.
            continue;
        }

        match apply_delta(&mut overlay, delta)? {
            Some(row) => {
                let step_bytes = row
                    .explanation_steps
                    .iter()
                    .map(|s| s.len() as u64)
                    .sum::<u64>()
                    .saturating_add(row.delta_ids.iter().map(|s| s.len() as u64).sum());
                if explanation_bytes.saturating_add(step_bytes) > bounds.max_explanation_bytes {
                    add_truncation(&mut result, "explanation_bytes");
                    break;
                }
                explanation_bytes = explanation_bytes.saturating_add(step_bytes);
                result.applied_deltas = result.applied_deltas.saturating_add(1);
                impact_rows.push(row);
            }
            None => {
                // No-op (e.g. remove missing property) — not an impact row.
            }
        }
    }

    result.impact_rows = impact_rows;
    result.expansion_work_units = work_units.min(u32::MAX as usize) as u32;
    result.epistemic_class = EPISTEMIC_CLASS_HYPOTHESIS.into();
    Ok(result)
}

fn validate_request(request: &ScenarioRequest) -> Result<(), ScenarioError> {
    if request.namespace.trim().is_empty() || request.namespace.trim() != request.namespace {
        return Err(ScenarioError::InvalidArgument(
            "canonical namespace required".into(),
        ));
    }
    if request.seed_object_ids.len() > MAX_SEEDS {
        return Err(ScenarioError::InvalidArgument(format!(
            "at most {MAX_SEEDS} seed object ids are allowed"
        )));
    }
    for seed in &request.seed_object_ids {
        validate_id(seed, "seed_object_id", MAX_ID_LEN)?;
    }
    if request.deltas.len() > MAX_DELTAS as usize {
        return Err(ScenarioError::InvalidArgument(format!(
            "at most {MAX_DELTAS} hypothesis deltas are allowed"
        )));
    }
    let mut seen_ids = HashSet::new();
    for delta in &request.deltas {
        validate_id(&delta.id, "delta.id", MAX_ID_LEN)?;
        if !seen_ids.insert(delta.id.clone()) {
            return Err(ScenarioError::InvalidArgument(format!(
                "duplicate hypothesis delta id {}",
                delta.id
            )));
        }
        match &delta.op {
            DeltaOp::SetProperty {
                object_id,
                key,
                value,
            } => {
                validate_id(object_id, "delta.object_id", MAX_ID_LEN)?;
                validate_id(key, "delta.property_key", MAX_PROPERTY_KEY_LEN)?;
                if value.len() > MAX_PROPERTY_VALUE_LEN {
                    return Err(ScenarioError::InvalidArgument(format!(
                        "property_value exceeds {MAX_PROPERTY_VALUE_LEN} bytes"
                    )));
                }
            }
            DeltaOp::RemoveProperty { object_id, key } => {
                validate_id(object_id, "delta.object_id", MAX_ID_LEN)?;
                validate_id(key, "delta.property_key", MAX_PROPERTY_KEY_LEN)?;
            }
            DeltaOp::AddLink {
                link_id,
                from_id,
                to_id,
                relation,
            } => {
                validate_id(link_id, "delta.link_id", MAX_ID_LEN)?;
                validate_id(from_id, "delta.from_id", MAX_ID_LEN)?;
                validate_id(to_id, "delta.to_id", MAX_ID_LEN)?;
                validate_id(relation, "delta.relation", MAX_RELATION_LEN)?;
            }
            DeltaOp::RemoveLink { link_id } => {
                validate_id(link_id, "delta.link_id", MAX_ID_LEN)?;
            }
        }
    }
    Ok(())
}

fn delta_authorized<F>(
    db: &RuntimeDb,
    namespace: &str,
    delta: &HypothesisDelta,
    overlay: &mut OverlayView,
    can_read: &F,
) -> Result<bool, ScenarioError>
where
    F: Fn(&Object) -> bool,
{
    for object_id in delta.op.referenced_object_ids() {
        let Some(object) = load_object(db, object_id, overlay)? else {
            return Ok(false);
        };
        if object.namespace != namespace || !can_read(&object) {
            return Ok(false);
        }
    }
    if let Some(link_id) = delta.op.referenced_link_id() {
        match &delta.op {
            DeltaOp::RemoveLink { .. } => {
                let Some(link) = load_link(db, link_id, overlay)? else {
                    return Ok(false);
                };
                let from = load_object(db, &link.from_id, overlay)?;
                let to = load_object(db, &link.to_id, overlay)?;
                let (Some(from), Some(to)) = (from, to) else {
                    return Ok(false);
                };
                if from.namespace != namespace
                    || to.namespace != namespace
                    || !can_read(&from)
                    || !can_read(&to)
                {
                    return Ok(false);
                }
            }
            DeltaOp::AddLink { from_id, to_id, .. } => {
                // Endpoints already checked via referenced_object_ids.
                let _ = (from_id, to_id);
            }
            _ => {}
        }
    }
    Ok(true)
}

fn apply_delta(
    overlay: &mut OverlayView,
    delta: &HypothesisDelta,
) -> Result<Option<ImpactRow>, ScenarioError> {
    let epistemic = EPISTEMIC_CLASS_HYPOTHESIS;
    match &delta.op {
        DeltaOp::SetProperty {
            object_id,
            key,
            value,
        } => {
            let object = overlay.objects.get_mut(object_id).ok_or_else(|| {
                ScenarioError::Storage(format!("authorized object missing in overlay: {object_id}"))
            })?;
            let before = object.properties.get(key).cloned().unwrap_or_default();
            object.properties.insert(key.clone(), value.clone());
            Ok(Some(ImpactRow {
                target_kind: "property".into(),
                object_id: object_id.clone(),
                link_id: String::new(),
                property_key: key.clone(),
                op: delta.op.op_label().into(),
                delta_ids: vec![delta.id.clone()],
                explanation_steps: vec![format!(
                    "{epistemic}:set_property object={object_id} key={key} delta={}",
                    delta.id
                )],
                before_value: before,
                after_value: value.clone(),
            }))
        }
        DeltaOp::RemoveProperty { object_id, key } => {
            let object = overlay.objects.get_mut(object_id).ok_or_else(|| {
                ScenarioError::Storage(format!("authorized object missing in overlay: {object_id}"))
            })?;
            let Some(before) = object.properties.remove(key) else {
                return Ok(None);
            };
            Ok(Some(ImpactRow {
                target_kind: "property".into(),
                object_id: object_id.clone(),
                link_id: String::new(),
                property_key: key.clone(),
                op: delta.op.op_label().into(),
                delta_ids: vec![delta.id.clone()],
                explanation_steps: vec![format!(
                    "{epistemic}:remove_property object={object_id} key={key} delta={}",
                    delta.id
                )],
                before_value: before,
                after_value: String::new(),
            }))
        }
        DeltaOp::AddLink {
            link_id,
            from_id,
            to_id,
            relation,
        } => {
            if overlay.links.contains_key(link_id) {
                return Ok(None);
            }
            let link = Link {
                id: link_id.clone(),
                from_id: from_id.clone(),
                to_id: to_id.clone(),
                relation: relation.clone(),
                created: 0,
            };
            overlay.removed_link_ids.remove(link_id);
            overlay.links.insert(link_id.clone(), link);
            Ok(Some(ImpactRow {
                target_kind: "link".into(),
                object_id: String::new(),
                link_id: link_id.clone(),
                property_key: String::new(),
                op: delta.op.op_label().into(),
                delta_ids: vec![delta.id.clone()],
                explanation_steps: vec![format!(
                    "{epistemic}:add_link link={link_id} from={from_id} to={to_id} relation={relation} delta={}",
                    delta.id
                )],
                before_value: String::new(),
                after_value: format!("{from_id}->{to_id}:{relation}"),
            }))
        }
        DeltaOp::RemoveLink { link_id } => {
            // Link may exist only on the base graph if expansion did not load it.
            let Some(link) = overlay.links.remove(link_id) else {
                // Attempt to mark removed even if not in overlay map yet.
                overlay.removed_link_ids.insert(link_id.clone());
                return Ok(Some(ImpactRow {
                    target_kind: "link".into(),
                    object_id: String::new(),
                    link_id: link_id.clone(),
                    property_key: String::new(),
                    op: delta.op.op_label().into(),
                    delta_ids: vec![delta.id.clone()],
                    explanation_steps: vec![format!(
                        "{epistemic}:remove_link link={link_id} delta={}",
                        delta.id
                    )],
                    before_value: link_id.clone(),
                    after_value: String::new(),
                }));
            };
            overlay.removed_link_ids.insert(link_id.clone());
            Ok(Some(ImpactRow {
                target_kind: "link".into(),
                object_id: String::new(),
                link_id: link_id.clone(),
                property_key: String::new(),
                op: delta.op.op_label().into(),
                delta_ids: vec![delta.id.clone()],
                explanation_steps: vec![format!(
                    "{epistemic}:remove_link link={link_id} from={} to={} relation={} delta={}",
                    link.from_id, link.to_id, link.relation, delta.id
                )],
                before_value: format!("{}->{}:{}", link.from_id, link.to_id, link.relation),
                after_value: String::new(),
            }))
        }
    }
}

fn load_object(
    db: &RuntimeDb,
    id: &str,
    overlay: &mut OverlayView,
) -> Result<Option<Object>, ScenarioError> {
    if let Some(object) = overlay.objects.get(id) {
        return Ok(Some(object.clone()));
    }
    let object = db.get_object(id).map_err(ScenarioError::Storage)?;
    if let Some(ref object) = object {
        overlay.objects.insert(object.id.clone(), object.clone());
    }
    Ok(object)
}

fn load_link(
    db: &RuntimeDb,
    id: &str,
    overlay: &mut OverlayView,
) -> Result<Option<Link>, ScenarioError> {
    if overlay.removed_link_ids.contains(id) {
        return Ok(None);
    }
    if let Some(link) = overlay.links.get(id) {
        return Ok(Some(link.clone()));
    }
    let link = db.get_link(id).map_err(ScenarioError::Storage)?;
    if let Some(ref link) = link {
        overlay.links.insert(link.id.clone(), link.clone());
    }
    Ok(link)
}

fn time_exceeded(started: Instant, max_time: Duration, result: &mut ScenarioResult) -> bool {
    if started.elapsed() >= max_time {
        add_truncation(result, "time");
        true
    } else {
        false
    }
}

fn add_truncation(result: &mut ScenarioResult, reason: &str) {
    result.truncated = true;
    if !result.truncation_reasons.iter().any(|r| r == reason) {
        result.truncation_reasons.push(reason.into());
    }
}

fn bounded(value: u32, default: u32, max: u32) -> u32 {
    if value == 0 { default } else { value.min(max) }
}

fn require_nonempty(value: &str, field: &str) -> Result<(), ScenarioError> {
    if value.trim().is_empty() {
        Err(ScenarioError::InvalidArgument(format!(
            "{field} is required"
        )))
    } else {
        Ok(())
    }
}

fn validate_id(value: &str, field: &str, max_len: usize) -> Result<(), ScenarioError> {
    if value.is_empty() || value.len() > max_len {
        return Err(ScenarioError::InvalidArgument(format!(
            "{field} must be 1..{max_len} bytes"
        )));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(ScenarioError::InvalidArgument(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Domain adapter fixture helpers (warehouse-style): deltas only, no physics.
// ---------------------------------------------------------------------------

/// Warehouse-style adapter fixture: given a removed assignment link, propose
/// a capacity-release property delta. Emits deltas only; never mutates graph.
pub fn warehouse_release_capacity_deltas(
    removed_assignment_link_id: &str,
    warehouse_object_id: &str,
    released_units: u32,
) -> Vec<HypothesisDelta> {
    vec![
        HypothesisDelta {
            id: format!("adapter-remove-{removed_assignment_link_id}"),
            op: DeltaOp::RemoveLink {
                link_id: removed_assignment_link_id.to_string(),
            },
        },
        HypothesisDelta {
            id: format!("adapter-capacity-{warehouse_object_id}"),
            op: DeltaOp::SetProperty {
                object_id: warehouse_object_id.to_string(),
                key: "free_capacity_units".into(),
                value: released_units.to_string(),
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use std::sync::Arc;

    fn object(id: &str, namespace: &str, props: &[(&str, &str)]) -> Object {
        Object {
            id: id.into(),
            kind: "widget".into(),
            name: id.into(),
            namespace: namespace.into(),
            external_id: format!("widget:{id}"),
            properties: props
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            created: 1,
            updated: 1,
        }
    }

    fn link(id: &str, from: &str, to: &str, relation: &str) -> Link {
        Link {
            id: id.into(),
            from_id: from.into(),
            to_id: to.into(),
            relation: relation.into(),
            created: 1,
        }
    }

    fn db_with_graph() -> RuntimeDb {
        let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
        for o in [
            object("wh-1", "ops", &[("free_capacity_units", "2")]),
            object("ship-1", "ops", &[("status", "docked")]),
            object("secret", "ops", &[("status", "classified")]),
            object("other-ns", "other", &[("x", "1")]),
        ] {
            db.create_object(&o).unwrap();
        }
        db.create_link(&link("assign-1", "wh-1", "ship-1", "assigned_to"))
            .unwrap();
        db.create_link(&link("secret-link", "wh-1", "secret", "contains"))
            .unwrap();
        db
    }

    fn allow_except<'a>(denied: &'a [&'a str]) -> impl Fn(&Object) -> bool + 'a {
        move |object: &Object| !denied.contains(&object.id.as_str())
    }

    #[test]
    fn evaluate_applies_deltas_and_labels_hypothesis() {
        let db = db_with_graph();
        let deltas = warehouse_release_capacity_deltas("assign-1", "wh-1", 5);
        let result = evaluate_scenario(
            &db,
            &ScenarioRequest {
                namespace: "ops".into(),
                seed_object_ids: vec!["wh-1".into()],
                deltas,
                bounds: ScenarioBounds {
                    max_depth: 1,
                    max_objects: 20,
                    max_links: 20,
                    ..Default::default()
                },
                ..Default::default()
            },
            "scenario-1",
            allow_except(&[]),
        )
        .unwrap();

        assert_eq!(result.epistemic_class, EPISTEMIC_CLASS_HYPOTHESIS);
        assert_eq!(result.applied_deltas, 2);
        assert_eq!(result.impact_rows.len(), 2);
        assert!(
            result
                .impact_rows
                .iter()
                .all(|row| row.delta_ids.iter().all(|id| id.starts_with("adapter-")))
        );
        let capacity = result
            .impact_rows
            .iter()
            .find(|row| row.property_key == "free_capacity_units")
            .unwrap();
        assert_eq!(capacity.before_value, "2");
        assert_eq!(capacity.after_value, "5");
        assert_eq!(capacity.op, "set_property");
    }

    #[test]
    fn evaluation_never_mutates_canonical_graph() {
        let db = db_with_graph();
        let before_object = db.get_object("wh-1").unwrap().unwrap();
        let before_link = db.get_link("assign-1").unwrap().unwrap();
        let before_links = db
            .get_links("wh-1", "", &Direction::Outgoing)
            .unwrap()
            .len();

        let _ = evaluate_scenario(
            &db,
            &ScenarioRequest {
                namespace: "ops".into(),
                seed_object_ids: vec!["wh-1".into()],
                deltas: warehouse_release_capacity_deltas("assign-1", "wh-1", 99),
                bounds: ScenarioBounds {
                    max_depth: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
            "scenario-mut",
            |_| true,
        )
        .unwrap();

        let after_object = db.get_object("wh-1").unwrap().unwrap();
        assert_eq!(
            before_object.properties.get("free_capacity_units"),
            after_object.properties.get("free_capacity_units")
        );
        assert_eq!(before_object.updated, after_object.updated);
        let after_link = db.get_link("assign-1").unwrap().unwrap();
        assert_eq!(before_link.id, after_link.id);
        assert_eq!(
            before_links,
            db.get_links("wh-1", "", &Direction::Outgoing)
                .unwrap()
                .len()
        );
    }

    #[test]
    fn denied_targets_never_appear_in_impact_or_metadata() {
        let db = db_with_graph();
        let result = evaluate_scenario(
            &db,
            &ScenarioRequest {
                namespace: "ops".into(),
                seed_object_ids: vec!["wh-1".into(), "secret".into()],
                deltas: vec![
                    HypothesisDelta {
                        id: "d-secret".into(),
                        op: DeltaOp::SetProperty {
                            object_id: "secret".into(),
                            key: "status".into(),
                            value: "leaked".into(),
                        },
                    },
                    HypothesisDelta {
                        id: "d-ok".into(),
                        op: DeltaOp::SetProperty {
                            object_id: "wh-1".into(),
                            key: "free_capacity_units".into(),
                            value: "3".into(),
                        },
                    },
                    HypothesisDelta {
                        id: "d-secret-link".into(),
                        op: DeltaOp::RemoveLink {
                            link_id: "secret-link".into(),
                        },
                    },
                ],
                bounds: ScenarioBounds {
                    max_depth: 2,
                    max_objects: 20,
                    max_links: 20,
                    ..Default::default()
                },
                ..Default::default()
            },
            "scenario-deny",
            allow_except(&["secret"]),
        )
        .unwrap();

        assert_eq!(result.applied_deltas, 1);
        assert_eq!(result.impact_rows.len(), 1);
        assert_eq!(result.impact_rows[0].object_id, "wh-1");
        let blob = format!("{:?}", result);
        assert!(!blob.contains("secret"));
        assert!(!blob.contains("leaked"));
        assert!(!result.truncation_reasons.iter().any(|r| r.contains("deny")));
    }

    #[test]
    fn same_key_conflict_fails_closed() {
        let db = db_with_graph();
        let err = evaluate_scenario(
            &db,
            &ScenarioRequest {
                namespace: "ops".into(),
                seed_object_ids: vec!["wh-1".into()],
                deltas: vec![
                    HypothesisDelta {
                        id: "a".into(),
                        op: DeltaOp::SetProperty {
                            object_id: "wh-1".into(),
                            key: "free_capacity_units".into(),
                            value: "1".into(),
                        },
                    },
                    HypothesisDelta {
                        id: "b".into(),
                        op: DeltaOp::SetProperty {
                            object_id: "wh-1".into(),
                            key: "free_capacity_units".into(),
                            value: "2".into(),
                        },
                    },
                ],
                ..Default::default()
            },
            "scenario-conflict",
            |_| true,
        )
        .unwrap_err();
        match err {
            ScenarioError::Conflict(message) => {
                assert!(message.contains("conflicting"));
                assert!(message.contains("a") && message.contains("b"));
            }
            other => panic!("expected conflict, got {other}"),
        }
    }

    #[test]
    fn each_bound_can_truncate_independently() {
        let db = db_with_graph();
        // deltas bound
        let many: Vec<HypothesisDelta> = (0..10)
            .map(|i| HypothesisDelta {
                id: format!("d{i}"),
                op: DeltaOp::SetProperty {
                    object_id: "wh-1".into(),
                    key: format!("k{i}"),
                    value: "v".into(),
                },
            })
            .collect();
        let result = evaluate_scenario(
            &db,
            &ScenarioRequest {
                namespace: "ops".into(),
                seed_object_ids: vec!["wh-1".into()],
                deltas: many,
                bounds: ScenarioBounds {
                    max_deltas: 3,
                    max_depth: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
            "scenario-bound-deltas",
            |_| true,
        )
        .unwrap();
        assert!(result.truncated);
        assert!(result.truncation_reasons.iter().any(|r| r == "deltas"));
        assert_eq!(result.applied_deltas, 3);

        // expansion_work_units bound
        let result = evaluate_scenario(
            &db,
            &ScenarioRequest {
                namespace: "ops".into(),
                seed_object_ids: vec!["wh-1".into()],
                deltas: vec![HypothesisDelta {
                    id: "d0".into(),
                    op: DeltaOp::SetProperty {
                        object_id: "wh-1".into(),
                        key: "k".into(),
                        value: "v".into(),
                    },
                }],
                bounds: ScenarioBounds {
                    max_depth: 3,
                    max_expansion_work_units: 1,
                    max_objects: 20,
                    max_links: 20,
                    ..Default::default()
                },
                ..Default::default()
            },
            "scenario-bound-work",
            |_| true,
        )
        .unwrap();
        assert!(result.truncated);
        assert!(
            result
                .truncation_reasons
                .iter()
                .any(|r| r == "expansion_work_units")
        );
    }

    #[test]
    fn concurrent_evaluations_are_isolated() {
        let db = db_with_graph();
        let left = evaluate_scenario(
            &db,
            &ScenarioRequest {
                namespace: "ops".into(),
                seed_object_ids: vec!["wh-1".into()],
                deltas: vec![HypothesisDelta {
                    id: "left".into(),
                    op: DeltaOp::SetProperty {
                        object_id: "wh-1".into(),
                        key: "free_capacity_units".into(),
                        value: "10".into(),
                    },
                }],
                ..Default::default()
            },
            "scenario-left",
            |_| true,
        )
        .unwrap();
        let right = evaluate_scenario(
            &db,
            &ScenarioRequest {
                namespace: "ops".into(),
                seed_object_ids: vec!["wh-1".into()],
                deltas: vec![HypothesisDelta {
                    id: "right".into(),
                    op: DeltaOp::SetProperty {
                        object_id: "wh-1".into(),
                        key: "free_capacity_units".into(),
                        value: "20".into(),
                    },
                }],
                ..Default::default()
            },
            "scenario-right",
            |_| true,
        )
        .unwrap();
        assert_eq!(left.impact_rows[0].after_value, "10");
        assert_eq!(right.impact_rows[0].after_value, "20");
        assert_eq!(
            db.get_object("wh-1")
                .unwrap()
                .unwrap()
                .properties
                .get("free_capacity_units")
                .map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn warehouse_adapter_emits_deltas_only() {
        let deltas = warehouse_release_capacity_deltas("assign-1", "wh-1", 4);
        assert_eq!(deltas.len(), 2);
        assert!(matches!(deltas[0].op, DeltaOp::RemoveLink { .. }));
        assert!(matches!(deltas[1].op, DeltaOp::SetProperty { .. }));
        // Adapter has no db handle and no write path — pure delta construction.
    }

    #[test]
    fn base_mode_rejects_temporal_without_scope_creep() {
        let err = BaseMode::parse("temporal").unwrap_err();
        assert!(matches!(err, ScenarioError::InvalidArgument(_)));
    }
}
