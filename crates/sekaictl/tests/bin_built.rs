//! Forces Cargo to compile the `sekaictl` binary when this package is tested
//! so sibling process smokes can spawn it from `target/debug`.

#[test]
fn sekaictl_binary_is_built() {
    let path = env!("CARGO_BIN_EXE_sekaictl");
    assert!(
        std::path::Path::new(path).is_file(),
        "expected sekaictl binary at {path}"
    );
}
