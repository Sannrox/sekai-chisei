# hoshi-ontology/v1 reference package

The ontology package of the game reference workload, copied unchanged from
`crates/hoshi-core/data/ontology/hoshi-v1.json` in Sannrox/hoshi at commit
`cd18824f447445ac61345a085841705b36479dae`.

`crates/sekai-ontology/tests/reference_packages.rs` pins its SHA-256 and
validates it with the same offline import and `validate` checks as any
ontology package. `tests/hoshi_reference_actions.rs` runs governed Action
scenarios against its Fleet and Planet classes through the public gRPC API.

To re-pin, copy the file at a new commit, update the commit above and the
digest in the test.
