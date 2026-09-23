//! Source guard for PostgreSQL parameter binding (#1155).
//!
//! The synchronous client rejects a Rust value whose width differs from the
//! type PostgreSQL inferred for the placeholder, and PostgreSQL text rejects
//! NUL. These shapes compiled and passed SQLite CI while every PostgreSQL call
//! through them failed, so this test keeps them out of the PostgreSQL modules.

use std::fs;
use std::path::Path;

fn postgres_sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut sources = fs::read_dir(&dir)
        .expect("src/db")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("postgres") && name.ends_with(".rs"))
        })
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&path).expect("read postgres module"),
            )
        })
        .collect::<Vec<_>>();
    sources.sort();
    assert!(sources.len() > 20, "expected the PostgreSQL modules");
    sources
}

/// `$n` whose first use sits beside an integer literal is inferred as
/// `integer`, so an `i64` bind fails unless the placeholder is cast.
fn uncast_placeholder_beside_integer_literal(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut index = 0;
    while let Some(offset) = line[index..].find('$') {
        let start = index + offset;
        let mut end = start + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        index = end.max(start + 1);
        if end == start + 1 || line[end..].starts_with("::") {
            continue;
        }
        let before = line[..start].trim_end();
        let after = line[end..].trim_start();
        let literal_after = [" <= 0", " >= 0", " < 0", " > 0"]
            .iter()
            .any(|suffix| line[end..].starts_with(suffix));
        if literal_after || (before.ends_with("GREATEST(") && after.starts_with(", 0")) {
            return true;
        }
    }
    false
}

#[test]
fn postgres_placeholders_beside_integer_literals_are_cast() {
    let mut offenders = Vec::new();
    for (name, source) in postgres_sources() {
        for (number, line) in source.lines().enumerate() {
            if uncast_placeholder_beside_integer_literal(line) {
                offenders.push(format!("{name}:{}: {}", number + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "cast placeholders compared with integer literals (for example `$4::bigint <= 0`):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn postgres_text_parameters_are_not_nul_joined() {
    let mut offenders = Vec::new();
    for (name, source) in postgres_sources() {
        for (number, line) in source.lines().enumerate() {
            if line.contains("format!(") && line.contains("\\0") {
                offenders.push(format!("{name}:{}: {}", number + 1, line.trim()));
            }
        }
        for (number, line) in source.lines().enumerate() {
            if line.trim_start().starts_with('"') && line.contains("\\0{") {
                offenders.push(format!("{name}:{}: {}", number + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "use postgres::advisory_lock_key instead of NUL-joined text:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn guard_recognizes_the_shapes_it_rejects() {
    assert!(uncast_placeholder_beside_integer_literal(
        "VALUES ($1, $2, $3, GREATEST($4, 0))"
    ));
    assert!(uncast_placeholder_beside_integer_literal(
        "AND ($4 <= 0 OR created_at_ms >= $4)"
    ));
    assert!(!uncast_placeholder_beside_integer_literal(
        "VALUES ($1, $2, $3, GREATEST($4::bigint, 0))"
    ));
    assert!(!uncast_placeholder_beside_integer_literal(
        "AND ($4::bigint <= 0 OR created_at_ms >= $4)"
    ));
    assert!(!uncast_placeholder_beside_integer_literal(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"
    ));
}
