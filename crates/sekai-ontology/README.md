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
sekai --db knowledge.db --json entity list
sekai --db knowledge.db --json relation list
```

Set `SEKAI_DB` instead of passing `--db`. The default is `knowledge.db`.

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

## Process contract

`export --json`, `explain --json`, `query --json`, and `validate --json` return an envelope with
`schema_version`, `command`, and `data`. Structured results are written to
stdout and diagnostics to stderr.

| Exit | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Invalid command, option, or input document |
| 3 | Named class not found |
| 4 | Database cannot be opened or read |
| 5 | Ontology validation failed |

The JSON contract is version 1. New optional fields may be added within version
1; incompatible changes require a new schema version.

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
