# sekai-connector-template

Source connector built on `sekai-source-sdk`. Generate a copy with:

```sh
sekaictl admin connectors new <name> --out <dir> [--sdk-path <checkout>]
```

## Layout

- `src/source.rs`: the real source. Fill in `check`, `discover`, and
  `read_page` (`read_batch`). `read_change_feed` (`read_changes`) is optional;
  keep `UnsupportedOrdering` unless the source has a stable epoch and a
  contiguous sequence.
- `src/fake.rs`: fixed in-memory source for local development and tests.
- `src/transport.rs`: `ApplySourceBatch` and `GetSourceSyncState` over gRPC.
- `src/lib.rs`: `run_once` replays the outbox, reads the page after the
  plane-committed cursor, and commits it as one transaction.
- `connector.json`: configuration. Credentials are environment variable
  names (`credential_env`, `source_credential_env`), never values. A config
  that contains secret-like text is refused.

## Run

1. Register a descriptor for the source and record kind (use `discover` to
   draft it), then put its digest in `type_digest`.
2. Export the variables named in `connector.json`.
3. `cargo run -- --config connector.json` (add `--fake` to sync the fake
   source).

The outbox under `outbox_dir` keeps the exact pending batch across restarts.
Keep the same directory between runs.

## Conformance

```sh
cargo test
```

runs the SDK conformance kit against the fake source: `check` reads no
records, discovery is deterministic and drafts one descriptor, and pages
commit as a resumable chain. Add the same checks for `Source` once it talks to
a test instance of the real system.

## Sandbox (optional)

The connector is one process with no inbound ports. It needs outbound access
to the source system and the control plane, read access to `connector.json`,
and write access to `outbox_dir`. Any process sandbox that grants exactly
that, for example [kekkai](https://github.com/Sannrox/kekkai), can wrap
`cargo run`. Nothing here requires one.
