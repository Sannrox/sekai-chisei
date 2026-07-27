# Region/site pins for leases and permits

Issue: [#293](https://github.com/Sannrox/sekai-chisei/issues/293)  
Design freeze: [research/292-multi-region-consistency.md](research/292-multi-region-consistency.md)

## Consistency class

Coordination leases and online permit redemption use
`region_pinned_single_writer`:

- Each durable lease and signed online permit carries a `site_id` pin.
- The process stamps its pin from `SEKAI_SITE_ID` (default `"local"`).
- Refresh, release, takeover, and redeem **fail closed** when the caller site
  does not match the durable pin.
- Single-region deployments keep the default pin and need no topology mode.

## Operator configuration

```bash
# Default single-region pin (community SQLite and single-AZ PostgreSQL).
SEKAI_SITE_ID=local

# Multi-region: distinct non-empty id per site. No wildcards.
# SEKAI_SITE_ID=us-east-1
```

Validation rejects empty values and `*` / `?` wildcards. Invalid values fall
back to `"local"` with a warning at process start.

## Visibility

- `GetLease` / acquire responses expose `Lease.site_id`.
- Signed permits and redemption records include `site_id` for evidence.
- Redeem audit evidence attributes include `site_id`.

## Handoff (non-goal for v1)

v1 ships **without** a lease/permit handoff RPC. The pin is permanent for the
lease key generation and permit lifetime. Operators drain work in-region.

If handoff is added later, it must be an explicit audited path that serializes
old-pin refusal before new-pin acceptance, never allowing dual active redeem or
acquire under lag. See the freeze handoff note in the research doc.

## Related

- [leases.md](leases.md)
- [external-action-execution.md](external-action-execution.md)
- Budget multi-region topology is #294 and is out of scope here.
