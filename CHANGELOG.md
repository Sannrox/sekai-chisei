# Changelog

## 0.2.1

### Security

- Enforce namespace authorization for egress checks, model affinity, and
  request-selected evolution analytics and writes.
- Restrict global evolution reports, patterns, variance, A/B results,
  templates, and unscoped enhancement to control-plane administrators.
- Bound OpenAI-compatible, Anthropic, and buffered gateway responses to
  32 MiB before parsing or continued accumulation.

## 0.2.0

### Migration

Deprecated expert commands have moved under `sekaictl admin`. The old
top-level aliases have been removed:

| Removed command | Replacement |
| --- | --- |
| `sekaictl credential` | `sekaictl admin access credential` |
| `sekaictl team` | `sekaictl admin access team` |
| `sekaictl gateway` | `sekaictl admin gateway` |
| `sekaictl action` | `sekaictl admin governance action` |
| `sekaictl memory` | `sekaictl admin governance memory` |
| `sekaictl gunshi` | `sekaictl admin governance gunshi` |
| `sekaictl governed-subject` | `sekaictl admin governance subject` |
| `sekaictl attest` | `sekaictl admin assurance attest` |
| `sekaictl compliance` | `sekaictl admin assurance compliance` |
| `sekaictl provenance` | `sekaictl admin assurance provenance` |
| `sekaictl replay` | `sekaictl admin assurance replay` |
| `sekaictl federation` | `sekaictl admin federation` |

Invoking a removed path exits with a migration message naming its canonical
replacement. Command handlers, server authorization, protocols, and persisted
state are unchanged.
