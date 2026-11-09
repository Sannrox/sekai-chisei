//! The runtime talks to the plane only over gRPC: no control-plane package
//! is in its dependency graph, directly or transitively.

use std::collections::{BTreeMap, BTreeSet};

const CONTROL_PLANE: [&str; 3] = ["sekai-chisei", "sekai-core", "chisei-core"];

/// Each package in the workspace lock file, by name, with the names it
/// depends on.
fn lock_graph() -> BTreeMap<String, Vec<String>> {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .expect("workspace Cargo.lock");
    let mut graph = BTreeMap::new();
    for package in lock.split("[[package]]").skip(1) {
        let mut name = None;
        let mut dependencies = Vec::new();
        let mut in_dependencies = false;
        for line in package.lines().map(str::trim) {
            if let Some(value) = line.strip_prefix("name = ") {
                name = Some(value.trim_matches('"').to_string());
            } else if line == "dependencies = [" {
                in_dependencies = true;
            } else if in_dependencies && line == "]" {
                in_dependencies = false;
            } else if in_dependencies {
                let entry = line.trim_end_matches(',').trim_matches('"');
                let dependency = entry.split(' ').next().unwrap_or(entry);
                dependencies.push(dependency.to_string());
            }
        }
        graph
            .entry(name.expect("package name"))
            .or_insert_with(Vec::new)
            .extend(dependencies);
    }
    graph
}

#[test]
fn the_runtime_never_links_the_control_plane() {
    let graph = lock_graph();
    let mut seen = BTreeSet::new();
    let mut stack = vec!["sekai-connector-runtime".to_string()];
    while let Some(package) = stack.pop() {
        if !seen.insert(package.clone()) {
            continue;
        }
        stack.extend(graph.get(&package).into_iter().flatten().cloned());
    }
    assert!(seen.contains("sekai-client"), "the walk reached the client");
    for package in CONTROL_PLANE {
        assert!(!seen.contains(package), "the runtime depends on {package}");
    }
}
