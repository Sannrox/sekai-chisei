---
name: sekai-ontology
description: Consult a local Sekai ontology for explicit classes, relations, validation, and provenance.
---

# Sekai ontology

Use `sekai` when a repository contains a portable ontology database and a
structural answer should come from its explicit definitions and provenance.
The command is single-shot and local; it does not require a server or network.

- Database scope is resolved in this order: explicit `--db`, `SEKAI_DB`, the
  nearest existing `.sekai/knowledge.db` while walking from the current
  directory upward, the user-level database, and finally `knowledge.db` in the
  current directory. A workspace such as `~/Projects/` can own
  `.sekai/knowledge.db`; a child project can override it with its own
  `.sekai/knowledge.db`.
- Run `sekai --db <path> --json explain <name>` for the resolved definition,
  superclass closure, related definitions, and provenance of a class.
- Run `sekai --db <path> --json query <name> --direction <outbound|inbound|both> --depth <0..32>`
  for bounded traversal from a class. Add `--relation <name>` to follow only
  matching relations. Read `data.classes` and `data.relations`; both are
  deduplicated and ordered by name.
- Run `sekai --db <path> --json entity list`, `entity show <name>`, or
  `relation list` for direct deterministic inspection.
- Run `sekai --db <path> --json find <text>` to discover matching classes and
  relations by name, description, property, or endpoint.
- Run `sekai --json diff <before> <after>` to compare raw ontology JSON,
  `export --json` envelopes, or SQLite ontology databases.
- Run `sekai --db <path> --json ask "<question>"` only for read-only,
  template-shaped Natural Language queries. Supported forms compile to
  `explain`, `query`, `find`, or `directory query`. Inspect the returned typed
  plan; ambiguous or unsupported questions do not execute. `find` / `search
  for` maps to `find`; a filesystem path maps to `directory query`; `depth N`
  overrides the default traversal depth of 1.
- Run `sekai --db <path> --json validate` before relying on an ontology whose
  definitions may have changed.
- Run `sekai --db <path> --json export` to inspect or exchange the complete,
  versioned logical ontology. The envelope's `data` value can be imported into
  a fresh database with `sekai --db <new-path> import <document-path>`.

## Directory facts

Ontology classes and relations describe meaning; directory entities and links
record the local filesystem facts. Initialize the standard directory
vocabulary once per scope, then index the workspace or project root:

```bash
sekai --db ~/Projects/.sekai/knowledge.db init
sekai --db ~/Projects/.sekai/knowledge.db directory init
sekai --db ~/Projects/.sekai/knowledge.db directory index ~/Projects \
  --kind WorkspaceDirectory --prune

sekai --db ~/Projects/my-project/.sekai/knowledge.db init
sekai --db ~/Projects/my-project/.sekai/knowledge.db directory init
sekai --db ~/Projects/my-project/.sekai/knowledge.db directory index . \
  --kind ProjectDirectory --prune
```

Use `directory tree <root>` for a human-readable hierarchy,
`--json directory query <path> --direction both --depth 2` for bounded
connections, and `directory export <root>` / `directory import <path|->` for
portable directory facts. Indexing is deterministic, skips hidden directories
unless `--include-hidden` is given, never follows symlinks, and only removes
stale facts when `--prune` is explicit.

Treat ontology output as structured repository evidence. Preserve provenance in
answers, and do not infer facts that the ontology does not contain.
