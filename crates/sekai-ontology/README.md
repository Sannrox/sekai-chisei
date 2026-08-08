# sekai ontology

`sekai` stores explicit ontology definitions in one portable SQLite file. It
runs one command and exits; the library offers the same operations in process.

## Quick start

```bash
sekai --db knowledge.db init
sekai --db knowledge.db import ontology.json
sekai --db knowledge.db export
sekai --db knowledge.db validate
sekai --db knowledge.db --json explain Api
sekai --db knowledge.db --json query Api --direction outbound --depth 2
sekai --db knowledge.db --json find interface
sekai --db knowledge.db --json ask "What does Api depend on?"
sekai --json diff before.json after.json
sekai --db knowledge.db --json entity list
sekai --db knowledge.db --json relation list
sekai --db knowledge.db directory init
sekai --db knowledge.db directory index ~/Projects --kind WorkspaceDirectory --prune
sekai --db knowledge.db directory tree ~/Projects
```

The database is resolved in this order (first match wins):

1. `--db <path>` (explicit flag)
2. `SEKAI_DB` environment variable
3. The nearest existing `.sekai/knowledge.db` while walking upward from the
   current directory
4. User-level default when the file exists:
   - macOS: `~/Library/Application Support/sekai/knowledge.db`
   - Linux: `${XDG_DATA_HOME:-~/.local/share}/sekai/knowledge.db`
5. `knowledge.db` in the current directory

This lets `~/Projects/.sekai/knowledge.db` describe a workspace while
`~/Projects/project-a/.sekai/knowledge.db` overrides it for one project.
Explicit `--db` or `SEKAI_DB` remains the escape hatch for scripts and
cross-scope inspection.

Import accepts a versioned JSON document:

```json
{
  "schema_version": 1,
  "classes": [
    { "name": "Component" },
    { "name": "Api", "superclasses": ["Component"] }
  ],
  "relations": [
    { "name": "depends_on", "domain": "Api", "range": "Component" }
  ],
  "provenance": [
    { "subject": "Api", "source": "src/api.rs", "locator": "struct Api", "confidence": 1.0 }
  ]
}
```

Imports update definitions by name in one transaction. Definitions must refer
to classes present in either the file or the existing database. Unknown
fields, unsupported schema versions, invalid references, inheritance cycles,
invalid cardinalities, and invalid provenance are rejected.

`export` writes the complete logical ontology as the same versioned document
accepted by `import`. Classes, relations, and provenance records are ordered
deterministically, so the output is suitable for review and round trips without
depending on the private SQLite table layout. Use `export --json` to wrap that
document in the stable command envelope used by other read commands.

## Bounded traversal

`query <name>` traverses relation definitions from a starting class. Direction
is `outbound`, `inbound`, or `both` (the default); `--relation <name>` limits
traversal to one relation name. Depth defaults to 1, depth 0 returns empty
reached-class and relation lists, and depths through 32 are supported. A class
is expanded at most once, so cycles terminate. Reached classes and traversed
relations are deduplicated and ordered by name.

```bash
sekai --db knowledge.db --json query Api --direction both --relation depends_on --depth 3
```

The JSON envelope's `data` contains `start`, the effective `options`, `classes`,
and `relations`. A missing start exits 3; a valid start with no matching edge
succeeds with empty lists. Invalid directions and depths above 32 exit 2.

## Deterministic discovery

`find <text>` searches class and relation names, descriptions, properties, and
relation endpoints. Results are ranked deterministically and include the fields
that matched. An empty result is successful and returns an empty `matches` list
in JSON mode.

```bash
sekai --db knowledge.db --json find interface
```

`diff <before> <after>` compares two raw ontology JSON documents, two
`export --json` envelopes, or two SQLite ontology databases. It reports added,
removed, and semantically changed classes, relations, and provenance records;
ordering-only changes are ignored.

```bash
sekai --json diff before.json after.json
```

## Read-only natural-language queries

`ask <question>` is a conservative Natural Language frontend over the existing
typed operations. It does not call a model, access the network, or mutate the
database. Supported forms compile to one bounded `explain` or `query` plan:

```bash
sekai --db knowledge.db ask "What is Api?"
sekai --db knowledge.db ask "What does Api depend on?"
sekai --db knowledge.db ask "What depends on Database?"
sekai --db knowledge.db ask "What is related to Api?"
```

The JSON response always exposes the interpretation and typed plan before the
answer. Ambiguous or unsupported questions return candidates without executing
a plan and exit 2. Mutations such as `import` remain explicit commands.

## Process contract

`export --json`, `explain --json`, `query --json`, `find --json`, `diff --json`,
`ask --json`, and `validate --json` return an envelope with `schema_version`,
`command`, and `data`. Structured results are written to stdout and diagnostics
to stderr.

| Exit | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Invalid command, option, or input document |
| 3 | Named class not found |
| 4 | Database cannot be opened or read |
| 5 | Ontology validation failed |

`ask` also uses exit 2 for an ambiguous or unsupported question. A successful
`find` with no matches and a `diff` with changes both exit 0; inspect their JSON
data rather than using a failure exit code as a change indicator.

The JSON contract is version 1. New optional fields may be added within version
1; incompatible changes require a new schema version.

## Directory facts

The portable ontology keeps class/relation definitions separate from local
filesystem facts. `directory init` installs the `Directory`,
`WorkspaceDirectory`, `ProjectDirectory`, and transitive `contains` vocabulary.
`directory index` then stores deterministic directory entities and direct
parent-child links in the same SQLite file.

```bash
sekai --db ~/Projects/.sekai/knowledge.db init
sekai --db ~/Projects/.sekai/knowledge.db directory init
sekai --db ~/Projects/.sekai/knowledge.db directory index ~/Projects \
  --kind WorkspaceDirectory --prune

sekai --db ~/Projects/project-a/.sekai/knowledge.db init
sekai --db ~/Projects/project-a/.sekai/knowledge.db directory init
sekai --db ~/Projects/project-a/.sekai/knowledge.db directory index . \
  --kind ProjectDirectory --prune
```

`directory tree` renders a bounded human hierarchy. `directory query` returns
bounded links and reached entities in the same stable JSON envelope style as
ontology queries. `directory export` and `directory import` exchange a
versioned subtree document; `directory import -` reads from stdin. Indexing
skips hidden directories by default, never follows symlinks, and only prunes
stale facts when `--prune` is explicit.

## Agent skill

The matching agent skill is embedded in the binary and installs offline:

```bash
sekai skill install --path /chosen/skill/directory
sekai skill path --path /chosen/skill/directory
sekai skill install --path /chosen/skill/directory --uninstall
```

Without `--path`, `SEKAI_SKILL_PATH` is used, followed by
`$HOME/.agents/skills/sekai-ontology`. The named directory receives `SKILL.md`
directly. Reinstalling an unchanged skill exits 10. A modified or unrecognized
file is never overwritten or removed and exits 11; `--force` explicitly
replaces it during installation.

## Installation

Tagged releases publish prebuilt `sekai` archives for macOS and Linux on
Arm64 and x86-64. The supported Homebrew installation does not require Rust:

```bash
brew install Sannrox/tap/sekai
```
