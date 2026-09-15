//! Forces Cargo to compile the `chisei-gateway` binary when this package is tested
//! so sibling process smokes can spawn it from `target/debug`.

#[test]
fn chisei_gateway_binary_is_built() {
    let path = env!("CARGO_BIN_EXE_chisei-gateway");
    assert!(
        std::path::Path::new(path).is_file(),
        "expected gateway binary at {path}"
    );
}
