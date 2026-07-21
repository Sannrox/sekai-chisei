# sekai ontology

`sekai` stores explicit ontology definitions in one portable SQLite file. It
runs one command and exits; the library offers the same operations in process.

## Quick start

```bash
sekai --db knowledge.db init
sekai --db knowledge.db import ontology.json
sekai --db knowledge.db validate
sekai --db knowledge.db --json explain Api
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

## Process contract

`explain --json` and `validate --json` return an envelope with
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
