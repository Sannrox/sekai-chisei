//! Line-count ceilings for the three service files split in #872.

use std::fs;
use std::path::Path;

const CEILING: usize = 2000;

const SERVICE_FILES: &[&str] = &[
    "src/grpc/sekai_service.rs",
    "src/grpc/chisei_service.rs",
    "crates/chisei-gateway/src/gateway.rs",
];

fn line_count(path: &Path) -> usize {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .lines()
        .count()
}

#[test]
fn service_facades_stay_under_the_agreed_ceiling() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for relative in SERVICE_FILES {
        let path = root.join(relative);
        let lines = line_count(&path);
        if lines > CEILING {
            violations.push(format!("{relative}: {lines} > {CEILING}"));
        }
    }
    assert!(
        violations.is_empty(),
        "service files exceeded the #872 ceiling of {CEILING} lines:\n{}",
        violations.join("\n")
    );
}
