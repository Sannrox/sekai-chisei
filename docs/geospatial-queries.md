# Governed geospatial queries

Issue: [#680](https://github.com/Sannrox/sekai-chisei/issues/680)  
Decision: [ADR 0044](decisions/0044-governed-geospatial-queries.md)

A stored location is a `sekai.geospatial-value/v1` claim on a named object
property. Version 1 admits `point`, `line`, and `polygon` in `EPSG:4326` only.
A `line` is an ordered list of 2 to 1,000 `[lon, lat]` positions, such as a
road segment, pipeline, or route. A line segment may not cross the
antimeridian (span more than 180 degrees of longitude). A polygon is a closed ring of at least four
positions. Spatial comparison is a `sekai.geospatial-query/v1` effect, not write or permit
authority. The named property is authorized before any match, count, or page.

```text
sekaictl admin geospatial query --namespace sites --kind site \
  --property location --operator distance \
  --geometry '{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[13.405,52.52]}' \
  --max-distance-m 1500
```

Operators are `point`, `distance`, `contains`, and `intersects`. `point` and
`distance` take a point. `distance` matches a stored point within
`max_distance_m`, or a stored line whose nearest point is within it.
`intersects` matches any pair of kinds that share a point. `contains` matches
when the stored geometry holds the whole query geometry. A polygon holds a
line or polygon when every segment of it lies inside the ring. A line
holds a point on it. Boundaries count as inside. A reader older than the
`line` kind treats a stored line as invalid geometry, a non-match. Hidden and
unknown property names return the same unavailable result. Hidden and absent
objects are indistinguishable. Invalid query geometry fails before objects are
examined. Invalid or foreign stored geometry is a non-match. Audit records
operator, property, namespace, and total — not coordinates. SQLite and the
reusable PostgreSQL graph surface share the same in-process evaluator after
the existing object-security list.
