# Local twins from a tenant shape

A local twin is an offline copy of a tenant for developers and agents. It carries no real object values (#1735). It is built in two steps:

1. `sekai::synthetic_shape::shape_of` reads a tenant's object type definitions, objects and links, and returns a `sekai.twin-shape/v1` shape:
   - the definitions;
   - per kind, the object count and the number of objects per marking;
   - per property, a numeric range or opaque;
   - per relation and pair of kinds, the link count.
2. `ShapeDomain` is a synthetic domain. The synthetic tenant generator (`sekai::synthetic::generate`, then `apply` into a synthetic namespace) builds and loads the twin from it, deterministically from a seed.

## What the shape keeps

- **No string** is kept, since a repeated string may still be an identifier. Enum values come from the definition, and booleans are sampled.
- **Numeric ranges** only from at least 5 public values of a public property, not all equal and neither end zero, rounded strictly outward to two significant figures, so the extreme values are not published.
- **Everything else** is opaque. The twin fills opaque strings with placeholders and opaque numbers with zero.

Built-in kinds and links to them are left out, since the target already has the built-ins. Markings keep their proportions per kind, so need-to-know behaves as in the tenant. A twin enforces only the standard classifications, so a shape with a namespace lattice token is refused. A twin holds at most 50,000 objects and 200,000 links. A kind that implements a tenant interface is refused, since the twin schema has only the built-in interfaces. A kind with a required link, computed or struct property cannot be generated and is refused.
