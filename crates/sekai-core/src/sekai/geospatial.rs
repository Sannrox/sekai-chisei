//! Governed geospatial property observation and query (#680).

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{
    DEFAULT_LIST_LIMIT, ListFilter, MAX_LIST_LIMIT, Object, is_valid_property_key,
};
use crate::sekai::audit::{Decision, DecisionFilter};
use crate::sekai::object_security::PrincipalPolicyContext;

pub const VALUE_CONTRACT: &str = "sekai.geospatial-value/v1";
pub const QUERY_CONTRACT: &str = "sekai.geospatial-query/v1";
pub const CRS_EPSG_4326: &str = "EPSG:4326";
const EARTH_RADIUS_M: f64 = 6_371_000.0;
const COORD_EPSILON: f64 = 1e-9;
const BOUNDARY_EPSILON: f64 = 1e-12;
/// Most positions a `line` value may hold.
pub const MAX_LINE_POSITIONS: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GeoPoint {
    pub lon: f64,
    pub lat: f64,
}

/// One admitted `sekai.geospatial-value/v1` shape. Non-exhaustive so a new
/// kind does not break callers outside the crate.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum GeospatialGeometry {
    Point(GeoPoint),
    /// An ordered path of at least two positions (#2334).
    Line(Vec<GeoPoint>),
    Polygon(Vec<GeoPoint>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct GeospatialValue {
    pub geometry: GeospatialGeometry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeospatialOperator {
    Point,
    Distance,
    Contains,
    Intersects,
}

impl GeospatialOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Point => "point",
            Self::Distance => "distance",
            Self::Contains => "contains",
            Self::Intersects => "intersects",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "point" => Ok(Self::Point),
            "distance" => Ok(Self::Distance),
            "contains" => Ok(Self::Contains),
            "intersects" => Ok(Self::Intersects),
            _ => Err("geospatial_query_invalid: unsupported operator".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GeospatialQuery {
    pub namespace: String,
    pub kind: Option<String>,
    pub property: String,
    pub operator: GeospatialOperator,
    pub geometry: GeospatialValue,
    pub max_distance_m: Option<f64>,
    pub limit: i32,
    pub offset: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeospatialQueryPage {
    pub contract_version: String,
    pub namespace: String,
    pub property: String,
    pub operator: String,
    pub total: i32,
    pub hits: Vec<Object>,
}

pub fn parse_geospatial_value(raw: &str) -> Result<GeospatialValue, String> {
    parse_geospatial_value_json(raw, true)
}

/// Parse a stored `sekai.geospatial-value/v1` property. None when the value
/// is not an admitted geometry.
pub fn stored_geospatial_value(raw: &str) -> Option<GeospatialValue> {
    parse_geospatial_value_json(raw, false).ok()
}

fn parse_geospatial_value_json(raw: &str, query: bool) -> Result<GeospatialValue, String> {
    let invalid = |detail: &str| {
        if query {
            format!("geospatial_query_invalid: {detail}")
        } else {
            format!("geospatial_value_invalid: {detail}")
        }
    };
    let value: Value = serde_json::from_str(raw).map_err(|_| invalid("geometry must be JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("geometry must be a JSON object"))?;
    for key in object.keys() {
        if !matches!(key.as_str(), "type" | "kind" | "crs" | "coordinates") {
            return Err(invalid("geometry has unknown fields"));
        }
    }
    let type_name = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("geometry type is required"))?;
    if type_name != VALUE_CONTRACT {
        return Err(invalid("unsupported geospatial value version"));
    }
    let crs = object
        .get("crs")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("geometry crs is required"))?;
    if crs != CRS_EPSG_4326 {
        return Err(invalid("only EPSG:4326 is admitted"));
    }
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("geometry kind is required"))?;
    let coordinates = object
        .get("coordinates")
        .ok_or_else(|| invalid("geometry coordinates are required"))?;
    let geometry = match kind {
        "point" => GeospatialGeometry::Point(parse_point(coordinates, &invalid)?),
        "line" => GeospatialGeometry::Line(parse_line(coordinates, &invalid)?),
        "polygon" => GeospatialGeometry::Polygon(parse_polygon(coordinates, &invalid)?),
        _ => return Err(invalid("geometry kind must be point, line, or polygon")),
    };
    Ok(GeospatialValue { geometry })
}

fn parse_point(value: &Value, invalid: &dyn Fn(&str) -> String) -> Result<GeoPoint, String> {
    let coords = value
        .as_array()
        .ok_or_else(|| invalid("point coordinates must be [lon, lat]"))?;
    if coords.len() != 2 {
        return Err(invalid("point coordinates must be [lon, lat]"));
    }
    read_point(coords, invalid)
}

fn parse_line(value: &Value, invalid: &dyn Fn(&str) -> String) -> Result<Vec<GeoPoint>, String> {
    let coords = value
        .as_array()
        .ok_or_else(|| invalid("line coordinates must be a list of positions"))?;
    if coords.len() < 2 {
        return Err(invalid("line must contain at least two positions"));
    }
    if coords.len() > MAX_LINE_POSITIONS {
        return Err(invalid("line must contain at most 1000 positions"));
    }
    let path = read_positions(coords, "line", invalid)?;
    // Matching interpolates raw longitudes, so a segment must take the short
    // way round; one spanning more than 180 degrees would cross the antimeridian.
    if path
        .windows(2)
        .any(|edge| (edge[1].lon - edge[0].lon).abs() > 180.0)
    {
        return Err(invalid("line segments must not cross the antimeridian"));
    }
    Ok(path)
}

fn parse_polygon(value: &Value, invalid: &dyn Fn(&str) -> String) -> Result<Vec<GeoPoint>, String> {
    let coords = value
        .as_array()
        .ok_or_else(|| invalid("polygon coordinates must be a closed ring"))?;
    if coords.len() < 4 {
        return Err(invalid("polygon must contain at least four positions"));
    }
    let ring = read_positions(coords, "polygon", invalid)?;
    if !points_equal(ring[0], *ring.last().expect("closed ring")) {
        return Err(invalid("polygon ring must be closed"));
    }
    Ok(ring)
}

fn read_positions(
    coords: &[Value],
    kind: &str,
    invalid: &dyn Fn(&str) -> String,
) -> Result<Vec<GeoPoint>, String> {
    let mut points = Vec::with_capacity(coords.len());
    for position in coords {
        let pair = position
            .as_array()
            .filter(|pair| pair.len() == 2)
            .ok_or_else(|| invalid(&format!("{kind} position must be [lon, lat]")))?;
        points.push(read_point(pair, invalid)?);
    }
    Ok(points)
}

fn read_point(coords: &[Value], invalid: &dyn Fn(&str) -> String) -> Result<GeoPoint, String> {
    let lon = coords[0]
        .as_f64()
        .ok_or_else(|| invalid("longitude must be a finite number"))?;
    let lat = coords[1]
        .as_f64()
        .ok_or_else(|| invalid("latitude must be a finite number"))?;
    if !lon.is_finite() || !lat.is_finite() {
        return Err(invalid("coordinates must be finite"));
    }
    if !(-180.0..=180.0).contains(&lon) || !(-90.0..=90.0).contains(&lat) {
        return Err(invalid("coordinates must be valid EPSG:4326 positions"));
    }
    Ok(GeoPoint { lon, lat })
}

#[allow(clippy::too_many_arguments)]
pub fn parse_geospatial_query(
    namespace: &str,
    kind: Option<&str>,
    property: &str,
    operator: &str,
    geometry_json: &str,
    max_distance_m: Option<f64>,
    limit: i32,
    offset: i32,
) -> Result<GeospatialQuery, String> {
    let namespace = namespace.trim();
    if namespace.is_empty() {
        return Err("geospatial_query_denied: cross-namespace query is not allowed".into());
    }
    if namespace.contains('/') || namespace.contains('\0') {
        return Err("geospatial_query_denied: cross-namespace query is not allowed".into());
    }
    let kind = match kind.map(str::trim).filter(|value| !value.is_empty()) {
        Some(kind) if kind.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') => {
            Some(kind.to_string())
        }
        Some(_) => return Err("geospatial_query_invalid: kind is invalid".into()),
        None => None,
    };
    if !is_valid_property_key(property) {
        return Err("geospatial_query_invalid: property is invalid".into());
    }
    let operator = GeospatialOperator::parse(operator)?;
    let geometry = parse_geospatial_value(geometry_json)?;
    match operator {
        GeospatialOperator::Point | GeospatialOperator::Distance => {
            if !matches!(geometry.geometry, GeospatialGeometry::Point(_)) {
                return Err("geospatial_query_invalid: operator requires a point".into());
            }
        }
        GeospatialOperator::Contains | GeospatialOperator::Intersects => {}
    }
    let max_distance_m = match (operator, max_distance_m) {
        (GeospatialOperator::Distance, Some(distance))
            if distance.is_finite() && distance > 0.0 =>
        {
            Some(distance)
        }
        (GeospatialOperator::Distance, _) => {
            return Err(
                "geospatial_query_invalid: distance requires a positive max_distance_m".into(),
            );
        }
        (_, Some(_)) => {
            return Err(
                "geospatial_query_invalid: max_distance_m is only valid for distance".into(),
            );
        }
        (_, None) => None,
    };
    if offset < 0 {
        return Err("geospatial_query_invalid: offset must be zero or greater".into());
    }
    Ok(GeospatialQuery {
        namespace: namespace.to_string(),
        kind,
        property: property.to_string(),
        operator,
        geometry,
        max_distance_m,
        limit,
        offset,
    })
}

pub fn evaluate_geospatial_match(stored: &str, query: &GeospatialQuery) -> bool {
    let Some(value) = stored_geospatial_value(stored) else {
        return false;
    };
    match query.operator {
        GeospatialOperator::Point => match (&value.geometry, &query.geometry.geometry) {
            (GeospatialGeometry::Point(stored), GeospatialGeometry::Point(expected)) => {
                points_equal(*stored, *expected)
            }
            _ => false,
        },
        GeospatialOperator::Distance => {
            let max_distance_m = query.max_distance_m.unwrap_or(0.0);
            match (&value.geometry, &query.geometry.geometry) {
                (GeospatialGeometry::Point(stored), GeospatialGeometry::Point(origin)) => {
                    haversine_m(*stored, *origin) <= max_distance_m
                }
                (GeospatialGeometry::Line(path), GeospatialGeometry::Point(origin)) => path
                    .windows(2)
                    .any(|edge| distance_to_segment_m(*origin, edge[0], edge[1]) <= max_distance_m),
                _ => false,
            }
        }
        GeospatialOperator::Contains => {
            geometry_contains(&value.geometry, &query.geometry.geometry)
        }
        GeospatialOperator::Intersects => {
            geometries_intersect(&value.geometry, &query.geometry.geometry)
        }
    }
}

pub fn query_geospatial(
    db: &RuntimeDb,
    actor: &str,
    query: &GeospatialQuery,
    now_ms: i64,
) -> Result<GeospatialQueryPage, String> {
    if actor.trim().is_empty() {
        return Err("geospatial_query_invalid: actor is required".into());
    }
    db.reject_ungranted_property_query(
        Some(query.namespace.as_str()),
        query.kind.as_deref(),
        [query.property.as_str()],
    )?;
    let context = PrincipalPolicyContext {
        delegated_subject: None,
        subjects: vec![actor.to_string()],
        scopes: Vec::new(),
    }
    .normalized();
    let filter = ListFilter {
        namespace: Some(query.namespace.clone()),
        kind: query.kind.clone(),
        limit: i32::MAX,
        offset: 0,
        ..Default::default()
    };
    let (candidates, _) =
        db.list_objects_with_total_for_policy_context(&filter, &[actor], &[], &context)?;
    let mut matches = Vec::new();
    for object in candidates {
        let projected = db.project_object_property_grants(object)?;
        let Some(raw) = projected.properties.get(&query.property) else {
            continue;
        };
        if evaluate_geospatial_match(raw, query) {
            matches.push(projected);
        }
    }
    matches.sort_by(|left, right| left.id.cmp(&right.id));
    let total = i32::try_from(matches.len()).unwrap_or(i32::MAX);
    let offset = usize::try_from(query.offset.max(0)).unwrap_or(0);
    let limit = if query.limit <= 0 {
        DEFAULT_LIST_LIMIT as usize
    } else {
        query.limit.min(MAX_LIST_LIMIT) as usize
    };
    let hits = matches.into_iter().skip(offset).take(limit).collect();
    audit_query(db, actor, query, total, now_ms)?;
    Ok(GeospatialQueryPage {
        contract_version: QUERY_CONTRACT.to_string(),
        namespace: query.namespace.clone(),
        property: query.property.clone(),
        operator: query.operator.as_str().to_string(),
        total,
        hits,
    })
}

fn audit_query(
    db: &RuntimeDb,
    actor: &str,
    query: &GeospatialQuery,
    total: i32,
    now_ms: i64,
) -> Result<(), String> {
    db.record_decision(&Decision {
        // A query per millisecond is not unique; the UUID keeps each its own decision.
        id: format!(
            "geospatial.query:{}:{now_ms}:{}",
            query.namespace,
            uuid::Uuid::new_v4().simple()
        ),
        timestamp: now_ms,
        actor: actor.to_string(),
        action: "geospatial.query".into(),
        reason: format!("recorded {QUERY_CONTRACT} authorized match set"),
        evidence: HashMap::from([
            ("contract_version".into(), QUERY_CONTRACT.into()),
            ("namespace".into(), query.namespace.clone()),
            ("property".into(), query.property.clone()),
            ("operator".into(), query.operator.as_str().to_string()),
            ("total".into(), total.to_string()),
            ("write_authority".into(), "false".into()),
            ("permit_authority".into(), "false".into()),
        ]),
        target_id: query.namespace.clone(),
        outcome: "matched".into(),
    })
}

fn haversine_m(left: GeoPoint, right: GeoPoint) -> f64 {
    let lat1 = left.lat.to_radians();
    let lat2 = right.lat.to_radians();
    let dlat = (right.lat - left.lat).to_radians();
    let dlon = (right.lon - left.lon).to_radians();
    let sin_dlat = (dlat / 2.0).sin();
    let sin_dlon = (dlon / 2.0).sin();
    let harmonic = sin_dlat * sin_dlat + lat1.cos() * lat2.cos() * sin_dlon * sin_dlon;
    let central = 2.0 * harmonic.sqrt().atan2((1.0 - harmonic).sqrt());
    EARTH_RADIUS_M * central
}

/// Meters from `point` to the nearest point of the segment. The nearest point
/// is found in an equirectangular projection centred on `point`, which is
/// accurate for segments short against the Earth's radius; the distance to it
/// is great-circle.
fn distance_to_segment_m(point: GeoPoint, start: GeoPoint, end: GeoPoint) -> f64 {
    // The segment is moved whole by a multiple of 360 degrees so its midpoint
    // lies within 180 degrees of `point`; that copy is the one nearest the
    // point, so a query point across the antimeridian still sees the line as
    // near. The segment keeps its own span (at most 180 degrees, checked at
    // parse), so it is never turned the long way round.
    let half = (end.lon - start.lon) / 2.0;
    let middle = point.lon + (start.lon + half - point.lon + 540.0).rem_euclid(360.0) - 180.0;
    let start = GeoPoint {
        lon: middle - half,
        lat: start.lat,
    };
    let end = GeoPoint {
        lon: middle + half,
        lat: end.lat,
    };
    let scale = point.lat.to_radians().cos();
    let (ax, ay) = ((start.lon - point.lon) * scale, start.lat - point.lat);
    let (bx, by) = ((end.lon - point.lon) * scale, end.lat - point.lat);
    let (dx, dy) = (bx - ax, by - ay);
    let length = dx * dx + dy * dy;
    let t = if length == 0.0 {
        0.0
    } else {
        (-(ax * dx + ay * dy) / length).clamp(0.0, 1.0)
    };
    let nearest = GeoPoint {
        lon: start.lon + (end.lon - start.lon) * t,
        lat: start.lat + (end.lat - start.lat) * t,
    };
    haversine_m(point, nearest)
}

fn points_equal(left: GeoPoint, right: GeoPoint) -> bool {
    (left.lon - right.lon).abs() <= COORD_EPSILON && (left.lat - right.lat).abs() <= COORD_EPSILON
}

/// Whether `outer` holds all of `inner`. A line holds a point on it; a polygon
/// holds a line or another polygon when every segment of it lies inside the
/// ring. A point or line never holds a line or polygon.
fn geometry_contains(outer: &GeospatialGeometry, inner: &GeospatialGeometry) -> bool {
    use GeospatialGeometry::{Line, Point, Polygon};
    match (outer, inner) {
        (Point(left), Point(right)) => points_equal(*left, *right),
        (Line(path), Point(point)) => on_path(*point, path),
        (Polygon(ring), Point(point)) => point_in_polygon(*point, ring),
        // A polygon holds another when it holds the other's whole ring.
        (Polygon(ring), Line(path) | Polygon(path)) => {
            !paths_cross(path, ring)
                && path
                    .windows(2)
                    .all(|edge| segment_in_polygon(edge[0], edge[1], ring))
        }
        (Point(_) | Line(_), Line(_) | Polygon(_)) => false,
    }
}

fn geometries_intersect(left: &GeospatialGeometry, right: &GeospatialGeometry) -> bool {
    use GeospatialGeometry::{Line, Point, Polygon};
    match (left, right) {
        (Point(left), Point(right)) => points_equal(*left, *right),
        (Point(point), Line(path)) | (Line(path), Point(point)) => on_path(*point, path),
        (Point(point), Polygon(ring)) | (Polygon(ring), Point(point)) => {
            point_in_polygon(*point, ring)
        }
        (Line(left), Line(right)) => paths_touch(left, right),
        (Line(path), Polygon(ring)) | (Polygon(ring), Line(path)) => {
            path.iter().any(|point| point_in_polygon(*point, ring)) || paths_touch(path, ring)
        }
        (Polygon(left), Polygon(right)) => polygons_intersect(left, right),
    }
}

/// Whether the whole segment lies in the ring, given that no ring edge properly
/// crosses it. The segment can still leave a concave ring through a vertex or
/// along an edge, so it is split wherever a ring vertex lies on it and the
/// middle of every piece must be inside.
fn segment_in_polygon(start: GeoPoint, end: GeoPoint, ring: &[GeoPoint]) -> bool {
    let (dx, dy) = (end.lon - start.lon, end.lat - start.lat);
    let length = dx * dx + dy * dy;
    let mut cuts = vec![0.0, 1.0];
    if length > 0.0 {
        cuts.extend(
            ring.iter()
                .filter(|vertex| point_on_segment(**vertex, start, end))
                .map(|vertex| {
                    ((vertex.lon - start.lon) * dx + (vertex.lat - start.lat) * dy) / length
                }),
        );
    }
    cuts.sort_by(f64::total_cmp);
    let at = |t: f64| GeoPoint {
        lon: start.lon + dx * t,
        lat: start.lat + dy * t,
    };
    point_in_polygon(start, ring)
        && point_in_polygon(end, ring)
        && cuts
            .windows(2)
            .all(|pair| point_in_polygon(at((pair[0] + pair[1]) / 2.0), ring))
}

fn on_path(point: GeoPoint, path: &[GeoPoint]) -> bool {
    path.windows(2)
        .any(|edge| point_on_segment(point, edge[0], edge[1]))
}

/// Whether a segment of `left` properly crosses a segment of `right`.
fn paths_cross(left: &[GeoPoint], right: &[GeoPoint]) -> bool {
    left.windows(2).any(|a| {
        right
            .windows(2)
            .any(|b| segments_intersect(a[0], a[1], b[0], b[1]))
    })
}

/// Whether two paths cross or share a point, including an end on the other path.
fn paths_touch(left: &[GeoPoint], right: &[GeoPoint]) -> bool {
    paths_cross(left, right)
        || left.iter().any(|point| on_path(*point, right))
        || right.iter().any(|point| on_path(*point, left))
}

fn polygons_intersect(left: &[GeoPoint], right: &[GeoPoint]) -> bool {
    if left.iter().any(|point| point_in_polygon(*point, right))
        || right.iter().any(|point| point_in_polygon(*point, left))
    {
        return true;
    }
    for left_edge in left.windows(2) {
        for right_edge in right.windows(2) {
            if segments_intersect(left_edge[0], left_edge[1], right_edge[0], right_edge[1]) {
                return true;
            }
        }
    }
    false
}

fn point_in_polygon(point: GeoPoint, ring: &[GeoPoint]) -> bool {
    if ring.len() < 4 {
        return false;
    }
    if on_boundary(point, ring) {
        return true;
    }
    let mut inside = false;
    for edge in ring.windows(2) {
        let start = edge[0];
        let end = edge[1];
        let straddles = (start.lat > point.lat) != (end.lat > point.lat);
        if straddles {
            let crossing =
                (end.lon - start.lon) * (point.lat - start.lat) / (end.lat - start.lat) + start.lon;
            if point.lon < crossing {
                inside = !inside;
            }
        }
    }
    inside
}

fn on_boundary(point: GeoPoint, ring: &[GeoPoint]) -> bool {
    ring.windows(2)
        .any(|edge| point_on_segment(point, edge[0], edge[1]))
}

fn point_on_segment(point: GeoPoint, start: GeoPoint, end: GeoPoint) -> bool {
    // A repeated position leaves a zero-length segment, which holds only itself.
    if points_equal(start, end) {
        return points_equal(point, start);
    }
    let cross = (point.lon - start.lon) * (end.lat - start.lat)
        - (point.lat - start.lat) * (end.lon - start.lon);
    if cross.abs() > BOUNDARY_EPSILON {
        return false;
    }
    let dot = (point.lon - start.lon) * (end.lon - start.lon)
        + (point.lat - start.lat) * (end.lat - start.lat);
    let length = (end.lon - start.lon).powi(2) + (end.lat - start.lat).powi(2);
    dot >= -BOUNDARY_EPSILON && dot <= length + BOUNDARY_EPSILON
}

fn segments_intersect(a1: GeoPoint, a2: GeoPoint, b1: GeoPoint, b2: GeoPoint) -> bool {
    fn orient(origin: GeoPoint, first: GeoPoint, second: GeoPoint) -> f64 {
        (first.lon - origin.lon) * (second.lat - origin.lat)
            - (first.lat - origin.lat) * (second.lon - origin.lon)
    }
    let o1 = orient(a1, a2, b1);
    let o2 = orient(a1, a2, b2);
    let o3 = orient(b1, b2, a1);
    let o4 = orient(b1, b2, a2);
    (o1 * o2 < 0.0) && (o3 * o4 < 0.0)
}

pub fn latest_geospatial_audit(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<Option<Decision>, String> {
    let decisions = db.list_decisions(&DecisionFilter {
        action: Some("geospatial.query".into()),
        target_id: Some(namespace.into()),
        limit: 8,
        ..Default::default()
    })?;
    Ok(decisions.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::object_security::{
        OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
        ObjectSecurityPredicate, ObjectSecurityRule, PropertyGrant, PropertyGrantAccess,
    };
    use std::collections::BTreeMap;

    const BERLIN: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[13.405,52.52]}"#;
    const NEAR_BERLIN: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[13.41,52.52]}"#;
    const PARIS: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[2.3522,48.8566]}"#;
    const BERLIN_RING: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"polygon","crs":"EPSG:4326","coordinates":[[13.0,52.0],[14.0,52.0],[14.0,53.0],[13.0,53.0],[13.0,52.0]]}"#;
    const CROSSING_RING: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"polygon","crs":"EPSG:4326","coordinates":[[13.5,51.5],[14.5,51.5],[14.5,52.5],[13.5,52.5],[13.5,51.5]]}"#;

    fn point_query(operator: &str, geometry: &str, max_distance_m: Option<f64>) -> GeospatialQuery {
        parse_geospatial_query(
            "sites",
            Some("site"),
            "location",
            operator,
            geometry,
            max_distance_m,
            20,
            0,
        )
        .unwrap()
    }

    fn site(id: &str, owner: &str, location: &str) -> Object {
        Object {
            id: id.into(),
            kind: "site".into(),
            name: id.into(),
            namespace: "sites".into(),
            external_id: id.into(),
            properties: HashMap::from([
                ("owner".into(), owner.into()),
                ("location".into(), location.into()),
                ("secret".into(), "classified".into()),
            ]),
            created: 1,
            updated: 1,
        }
    }

    fn activate_policy(
        db: &RuntimeDb,
        key: &str,
        grants: &[(&str, PropertyGrantAccess)],
        owner_only: bool,
    ) {
        let predicates = if owner_only {
            vec![ObjectSecurityPredicate::SubjectEqualsProperty {
                property: "owner".into(),
            }]
        } else {
            vec![ObjectSecurityPredicate::AllowAll]
        };
        let policy = ObjectSecurityPolicy {
            contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "sites".into(),
            kind: "site".into(),
            rules: vec![ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates,
            }],
            property_grants: Some(
                grants
                    .iter()
                    .map(|(property, access)| PropertyGrant {
                        property: (*property).into(),
                        access: *access,
                    })
                    .collect(),
            ),
            value_instance_grants: None,
            required_purpose: None,
        };
        let revision = db
            .put_object_security_policy(&policy, "root", &format!("put-{key}"), 1)
            .unwrap();
        db.activate_object_security_policies(
            "sites",
            &BTreeMap::from([("site".into(), revision.revision_digest)]),
            "root",
            &format!("activate-{key}"),
            2,
        )
        .unwrap();
    }

    #[test]
    fn authorized_point_distance_contains_and_intersects_match() {
        assert!(evaluate_geospatial_match(
            BERLIN,
            &point_query("point", BERLIN, None)
        ));
        assert!(!evaluate_geospatial_match(
            NEAR_BERLIN,
            &point_query("point", BERLIN, None)
        ));
        assert!(evaluate_geospatial_match(
            NEAR_BERLIN,
            &point_query("distance", BERLIN, Some(1_000.0))
        ));
        assert!(!evaluate_geospatial_match(
            PARIS,
            &point_query("distance", BERLIN, Some(1_000.0))
        ));
        assert!(evaluate_geospatial_match(
            BERLIN_RING,
            &point_query("contains", BERLIN, None)
        ));
        assert!(!evaluate_geospatial_match(
            BERLIN_RING,
            &point_query("contains", PARIS, None)
        ));
        assert!(evaluate_geospatial_match(
            BERLIN_RING,
            &point_query("intersects", CROSSING_RING, None)
        ));
        assert!(!evaluate_geospatial_match(
            BERLIN_RING,
            &point_query("intersects", PARIS, None)
        ));
    }

    fn geometry(kind: &str, coordinates: &str) -> String {
        format!(
            r#"{{"type":"sekai.geospatial-value/v1","kind":"{kind}","crs":"EPSG:4326","coordinates":{coordinates}}}"#
        )
    }

    #[test]
    fn line_values_need_two_to_max_valid_positions() {
        assert!(parse_geospatial_value(&geometry("line", "[[13.0,52.0],[14.0,52.0]]")).is_ok());
        for (coordinates, detail) in [
            ("[[13.0,52.0]]", "at least two"),
            ("[[13.0,52.0],[14.0]]", "position must be [lon, lat]"),
            ("[[13.0,52.0],[14.0,95.0]]", "valid EPSG:4326"),
            ("[[179.0,0.0],[-179.0,0.0]]", "antimeridian"),
        ] {
            let err = parse_geospatial_value(&geometry("line", coordinates)).unwrap_err();
            assert!(err.contains(detail), "{coordinates}: {err}");
        }
        let too_many = format!(
            "[{}]",
            (0..=MAX_LINE_POSITIONS)
                .map(|i| format!("[{}.0,0.0]", i % 180))
                .collect::<Vec<_>>()
                .join(",")
        );
        let err = parse_geospatial_value(&geometry("line", &too_many)).unwrap_err();
        assert!(err.contains("at most 1000"), "{err}");
    }

    #[test]
    fn line_distance_contains_and_intersects() {
        // An east-west road through Berlin's latitude, past both sides of
        // BERLIN_RING.
        let road = geometry("line", "[[12.5,52.52],[14.5,52.52]]");
        let outside = geometry("line", "[[2.0,48.0],[3.0,48.0]]");
        // About 556 m north of the road's middle, far from both ends.
        let north = geometry("point", "[13.5,52.525]");
        assert!(evaluate_geospatial_match(
            &road,
            &point_query("distance", &north, Some(600.0))
        ));
        assert!(!evaluate_geospatial_match(
            &road,
            &point_query("distance", &north, Some(500.0))
        ));
        // The query point is across the antimeridian from a line about 2 km away.
        let date_line = geometry("line", "[[-179.99,0.0],[-179.0,0.0]]");
        assert!(evaluate_geospatial_match(
            &date_line,
            &point_query(
                "distance",
                &geometry("point", "[179.99,0.0]"),
                Some(5_000.0)
            )
        ));
        // A repeated position, as a GPS track may hold, is no wildcard.
        let repeated = geometry("line", "[[13.0,52.0],[13.0,52.0],[14.0,52.0]]");
        for query in [
            point_query("intersects", PARIS, None),
            point_query("contains", PARIS, None),
            point_query("intersects", &outside, None),
        ] {
            assert!(!evaluate_geospatial_match(&repeated, &query), "{query:?}");
        }
        assert!(evaluate_geospatial_match(
            &repeated,
            &point_query("intersects", &geometry("point", "[13.5,52.0]"), None)
        ));
        // The near end of a segment almost 180 degrees long, about 1,670 km away.
        assert!(evaluate_geospatial_match(
            &geometry("line", "[[-170.0,0.0],[5.0,0.0]]"),
            &point_query(
                "distance",
                &geometry("point", "[20.0,0.0]"),
                Some(2_000_000.0)
            )
        ));
        // A short line across the query point's antipodal meridian is far away.
        assert!(!evaluate_geospatial_match(
            &geometry("line", "[[-90.0,0.0],[-70.0,0.0]]"),
            &point_query(
                "distance",
                &geometry("point", "[100.0,0.0]"),
                Some(1_000_000.0)
            )
        ));
        // The road crosses this ring with no position of its own inside it.
        let pierced = geometry(
            "polygon",
            "[[13.4,52.4],[13.6,52.4],[13.6,52.6],[13.4,52.6],[13.4,52.4]]",
        );
        assert!(evaluate_geospatial_match(
            &road,
            &point_query("intersects", &pierced, None)
        ));
        assert!(!evaluate_geospatial_match(
            &outside,
            &point_query("intersects", BERLIN_RING, None)
        ));
        let inner = geometry("line", "[[13.2,52.2],[13.8,52.8]]");
        assert!(evaluate_geospatial_match(
            BERLIN_RING,
            &point_query("contains", &inner, None)
        ));
        assert!(!evaluate_geospatial_match(
            BERLIN_RING,
            &point_query("contains", &road, None)
        ));
        assert!(!evaluate_geospatial_match(
            BERLIN_RING,
            &point_query("contains", &outside, None)
        ));
        // Both ends inside a U-shaped ring, but the line crosses its notch.
        let u_ring = geometry(
            "polygon",
            "[[0.0,0.0],[3.0,0.0],[3.0,3.0],[2.0,3.0],[2.0,1.0],[1.0,1.0],[1.0,3.0],[0.0,3.0],[0.0,0.0]]",
        );
        let across_notch = geometry("line", "[[0.5,2.0],[2.5,2.0]]");
        assert!(!evaluate_geospatial_match(
            &u_ring,
            &point_query("contains", &across_notch, None)
        ));
        // Along the top edges and across the notch's open mouth: every touch
        // is on the boundary, yet the middle is outside.
        let across_mouth = geometry("line", "[[0.5,3.0],[2.5,3.0]]");
        assert!(!evaluate_geospatial_match(
            &u_ring,
            &point_query("contains", &across_mouth, None)
        ));
        // A rectangle with corners in both arms spans the notch.
        let spanning = geometry(
            "polygon",
            "[[0.5,1.5],[2.5,1.5],[2.5,2.5],[0.5,2.5],[0.5,1.5]]",
        );
        assert!(!evaluate_geospatial_match(
            &u_ring,
            &point_query("contains", &spanning, None)
        ));
        let along_left_arm = geometry("line", "[[0.5,0.5],[0.5,2.5]]");
        assert!(evaluate_geospatial_match(
            &u_ring,
            &point_query("contains", &along_left_arm, None)
        ));
        // Touching a corner, or running along an edge, shares a point.
        let square = geometry(
            "polygon",
            "[[0.0,0.0],[1.0,0.0],[1.0,1.0],[0.0,1.0],[0.0,0.0]]",
        );
        for touching in ["[[-1.0,0.0],[2.0,0.0]]", "[[-1.0,1.0],[1.0,-1.0]]"] {
            assert!(
                evaluate_geospatial_match(
                    &geometry("line", touching),
                    &point_query("intersects", &square, None)
                ),
                "{touching}"
            );
        }
        let crossing = geometry("line", "[[13.5,52.0],[13.5,53.0]]");
        assert!(evaluate_geospatial_match(
            &road,
            &point_query("intersects", &crossing, None)
        ));
        assert!(evaluate_geospatial_match(
            &road,
            &point_query("contains", &geometry("point", "[13.25,52.52]"), None)
        ));
    }

    #[test]
    fn invalid_query_fails_before_objects_are_examined() {
        let db = RuntimeDb::memory();
        db.create_object(&site("berlin", "alice", BERLIN)).unwrap();
        let err = parse_geospatial_query(
            "sites",
            Some("site"),
            "location",
            "distance",
            BERLIN,
            None,
            20,
            0,
        )
        .unwrap_err();
        assert!(err.starts_with("geospatial_query_invalid:"));
        let err =
            parse_geospatial_query("", None, "location", "point", BERLIN, None, 20, 0).unwrap_err();
        assert_eq!(
            err,
            "geospatial_query_denied: cross-namespace query is not allowed"
        );
        let err = parse_geospatial_query(
            "sites",
            Some("site"),
            "location",
            "point",
            r#"{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:3857","coordinates":[13.4,52.5]}"#,
            None,
            20,
            0,
        )
        .unwrap_err();
        assert!(err.contains("EPSG:4326"));
        assert!(latest_geospatial_audit(&db, "sites").unwrap().is_none());
    }

    #[test]
    fn invalid_or_foreign_stored_geometry_is_a_non_match() {
        let query = point_query("point", BERLIN, None);
        assert!(!evaluate_geospatial_match("not-json", &query));
        assert!(!evaluate_geospatial_match(
            r#"{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:3857","coordinates":[13.405,52.52]}"#,
            &query
        ));
        assert!(!evaluate_geospatial_match(BERLIN_RING, &query));
        // A kind this binary does not know, as a newer writer may store, is a
        // non-match rather than an error or a misread shape.
        assert!(!evaluate_geospatial_match(
            &geometry("curve", "[[13.405,52.52],[13.5,52.6]]"),
            &query
        ));
    }

    #[test]
    fn hidden_and_unknown_properties_share_the_unavailable_result() {
        let db = RuntimeDb::memory();
        db.create_object(&site("berlin", "alice", BERLIN)).unwrap();
        activate_policy(
            &db,
            "owner-only",
            &[("owner", PropertyGrantAccess::Read)],
            false,
        );
        let query = point_query("point", BERLIN, None);
        let hidden = query_geospatial(&db, "alice", &query, 10).unwrap_err();
        let unknown = parse_geospatial_query(
            "sites",
            Some("site"),
            "nosuch",
            "point",
            BERLIN,
            None,
            20,
            0,
        )
        .unwrap();
        let unknown = query_geospatial(&db, "alice", &unknown, 11).unwrap_err();
        assert_eq!(hidden, unknown);
        assert_eq!(
            hidden,
            "object_security_denied: property filter is not granted"
        );
        assert!(latest_geospatial_audit(&db, "sites").unwrap().is_none());
    }

    #[test]
    fn hidden_and_absent_objects_are_indistinguishable() {
        let db = RuntimeDb::memory();
        db.create_object(&site("berlin", "alice", BERLIN)).unwrap();
        db.create_object(&site("paris", "bob", PARIS)).unwrap();
        activate_policy(
            &db,
            "owner-row",
            &[
                ("owner", PropertyGrantAccess::Read),
                ("location", PropertyGrantAccess::Read),
            ],
            true,
        );
        let query = point_query("distance", BERLIN, Some(2_000_000.0));
        let with_hidden = query_geospatial(&db, "alice", &query, 20).unwrap();
        assert_eq!(with_hidden.total, 1);
        assert_eq!(with_hidden.hits.len(), 1);
        assert_eq!(with_hidden.hits[0].id, "berlin");
        assert!(!with_hidden.hits[0].properties.contains_key("secret"));

        db.delete_object("paris").unwrap();
        let after_absent = query_geospatial(&db, "alice", &query, 21).unwrap();
        assert_eq!(after_absent.total, with_hidden.total);
        assert_eq!(
            after_absent
                .hits
                .iter()
                .map(|hit| hit.id.as_str())
                .collect::<Vec<_>>(),
            with_hidden
                .hits
                .iter()
                .map(|hit| hit.id.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn two_queries_in_one_millisecond_record_two_decisions() {
        let db = RuntimeDb::memory();
        db.create_object(&site("berlin", "alice", BERLIN)).unwrap();
        activate_policy(
            &db,
            "location-same-ms",
            &[("location", PropertyGrantAccess::Read)],
            false,
        );
        let query = point_query("distance", BERLIN, Some(1_000.0));
        query_geospatial(&db, "alice", &query, 60).unwrap();
        query_geospatial(&db, "alice", &query, 60).unwrap();
        let decisions = db
            .list_decisions(&DecisionFilter {
                action: Some("geospatial.query".into()),
                target_id: Some(query.namespace.clone()),
                limit: 8,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 2);
        assert_ne!(decisions[0].id, decisions[1].id);
        let prefix = format!("geospatial.query:{}:60:", query.namespace);
        assert!(
            decisions
                .iter()
                .all(|decision| decision.id.starts_with(&prefix))
        );
    }

    #[test]
    fn counts_and_pages_cover_only_the_authorized_match_set() {
        let db = RuntimeDb::memory();
        db.create_object(&site("berlin", "alice", BERLIN)).unwrap();
        db.create_object(&site("nearby", "alice", NEAR_BERLIN))
            .unwrap();
        db.create_object(&site("paris", "alice", PARIS)).unwrap();
        activate_policy(
            &db,
            "location-page",
            &[("location", PropertyGrantAccess::Read)],
            false,
        );
        let mut query = point_query("distance", BERLIN, Some(1_000.0));
        query.limit = 1;
        query.offset = 0;
        let first = query_geospatial(&db, "alice", &query, 30).unwrap();
        query.offset = 1;
        let second = query_geospatial(&db, "alice", &query, 31).unwrap();
        assert_eq!(first.total, 2);
        assert_eq!(second.total, 2);
        assert_eq!(first.hits.len(), 1);
        assert_eq!(second.hits.len(), 1);
        assert_ne!(first.hits[0].id, second.hits[0].id);
        assert!(
            !first
                .hits
                .iter()
                .chain(second.hits.iter())
                .any(|hit| hit.id == "paris")
        );
        let audit = latest_geospatial_audit(&db, "sites").unwrap().unwrap();
        assert_eq!(
            audit.evidence.get("operator").map(String::as_str),
            Some("distance")
        );
        assert_eq!(
            audit.evidence.get("property").map(String::as_str),
            Some("location")
        );
        assert_eq!(
            audit.evidence.get("namespace").map(String::as_str),
            Some("sites")
        );
        assert_eq!(audit.evidence.get("total").map(String::as_str), Some("2"));
        assert!(
            !audit.evidence.values().any(|value| value.contains('[')
                || value.contains("EPSG")
                || value.contains("52.52"))
        );
    }

    #[test]
    fn revocation_applies_on_the_next_query() {
        let db = RuntimeDb::memory();
        db.create_object(&site("berlin", "alice", BERLIN)).unwrap();
        activate_policy(
            &db,
            "location-before-revoke",
            &[("location", PropertyGrantAccess::Read)],
            false,
        );
        let query = point_query("point", BERLIN, None);
        assert_eq!(query_geospatial(&db, "alice", &query, 40).unwrap().total, 1);
        activate_policy(
            &db,
            "owner-after-revoke",
            &[("owner", PropertyGrantAccess::Read)],
            false,
        );
        assert_eq!(
            query_geospatial(&db, "alice", &query, 41).unwrap_err(),
            "object_security_denied: property filter is not granted"
        );
    }

    #[test]
    fn sqlite_and_reusable_postgres_list_share_the_in_process_evaluator() {
        let query = point_query("contains", BERLIN, None);
        assert!(evaluate_geospatial_match(BERLIN_RING, &query));
        let db = RuntimeDb::memory();
        assert_eq!(db.backend_name(), "sqlite");
        db.create_object(&site("zone", "alice", BERLIN_RING))
            .unwrap();
        let page = query_geospatial(&db, "alice", &query, 50).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.hits[0].id, "zone");
    }
}
