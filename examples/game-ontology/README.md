# game-ontology/v1 reference package

The ontology package of the game reference workload: players own planets,
fleets are stationed at planets, and players ally.

`crates/sekai-ontology/tests/reference_packages.rs` validates it with the same
offline import and `validate` checks as any ontology package. The synthetic
`GameWorkload` builds its tenant from it, and `tests/game_reference_actions.rs`
runs governed Action scenarios against its Fleet and Planet classes through the
public gRPC API.
