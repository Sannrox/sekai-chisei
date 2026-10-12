# Egress privacy scan

Before a prepared payload leaves for a provider, chisei runs the privacy leak
checker. This page describes when it runs, what it scans, and how it refuses.

## When it runs

- Providers in the safe set skip the scan. The safe set is always `ollama`
  plus every provider in `CHISEI_SAFE_EGRESS_PROVIDERS`.
- For every other provider, leak rules (`leak_rule` objects in the global and
  request namespace) are checked against the payload.
- For `Sensitive` data, the namespace's other objects also contribute
  known-entity literals.

## Entity scan contract

- The scan window is up to 500 non-`leak_rule` objects in the namespace
  (`ENTITY_SCAN_LIMIT`). Every object in the window is scanned.
- Each object contributes its `name` and `external_id` when they are at least
  four characters. Literals are de-duplicated case-insensitively and match on
  word boundaries, case-insensitively.
- An object opts out of contributing literals with the property
  `chisei.egress.entity_scan=false`. It still counts toward the window.
- The scan is truncated only when the namespace holds more than 500 such
  objects. A truncated scan cannot prove the payload is safe, so it blocks
  every payload to a non-safe provider, whatever the payload contains.

## Refusals

| Cause | Planning warning / ExecutePlan `FAILED_PRECONDITION` | `EgressDecision.reasons` |
| --- | --- | --- |
| Truncated entity scan | `privacy_scan_truncated: entity scan incomplete, outbound payload blocked` | `privacy_scan_truncated` |
| Blocking leak-rule or entity match | `privacy leak checker blocked outbound payload` | `leak_checker <label> <n> match(es)` |

When both apply, the truncated-scan refusal wins. Leak audit decisions
(`chisei.privacy`, `leak_check` / `execute_leak_check`) record
`scan_truncated=true|false` as evidence.

To clear a truncated-scan refusal, route the work to a safe provider or keep
the namespace at 500 objects or fewer.
