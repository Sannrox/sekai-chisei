# sekai-source-sdk

Versioned crate for out-of-process source adapters. It exposes the
`sekai.source-batch` builder, durable outbox, snapshot and change-feed
runners, `check`/`discover`, and the offline conformance kit.

The control plane re-exports the contract types. Adapters outside this
repository depend on this crate only. New connectors start from
`../sekai-connector-template` (`sekaictl admin connectors new`), which the
workspace builds and tests against this crate on every change.

```sh
cargo test -p sekai-source-sdk --locked
cargo run -p sekai-source-sdk --example out_of_tree_adapter --locked
```

A breaking change to the public API requires a major version bump. CI
parses the crate source into `public-api.txt` (types, fields, variants,
and function arity). Additive and incompatible changes both require
updating that snapshot; incompatible changes also require a major bump.
`conformance_suite_digest()` hashes the crate version, batch and discovery
contract versions, and `src/conformance.rs`, so a suite-behavior change
cannot keep the previous certification pin.
