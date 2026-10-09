//! Shrink-only list of SQLite-only RPCs and admin projections (#1316).
//!
//! Community PostgreSQL fail-closed methods in `RuntimeDb` are the evidence.
//! The maturity table's Real backend column is a projection of this list.
//! The list may only shrink: port a surface, then remove it and lower `limit`.

use crate::rpc_maturity::{RpcMaturityTable, parse_docs_rows, pascal_to_snake};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const SQLITE_ONLY_SURFACES_CONTRACT: &str = "sekai.sqlite-only-surfaces/v1";
pub const SQLITE_ONLY_SURFACES_JSON: &str =
    include_str!("../tests/fixtures/sqlite_only_surfaces/v1.json");
pub const RUNTIME_DB_SRC: &str = include_str!("db/runtime_db.rs");
pub const SQLITE_ONLY_SURFACE_LIMIT: usize = 33;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqliteOnlyKind {
    Rpc,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SqliteOnlySurface {
    pub id: String,
    pub kind: SqliteOnlyKind,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SqliteOnlySurfaces {
    pub version: String,
    pub issue: u64,
    pub limit: usize,
    pub surfaces: Vec<SqliteOnlySurface>,
}

impl SqliteOnlySurfaces {
    pub fn load() -> Result<Self, String> {
        let list: Self = serde_json::from_str(SQLITE_ONLY_SURFACES_JSON)
            .map_err(|error| format!("parse sqlite-only surfaces: {error}"))?;
        list.validate()?;
        Ok(list)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != SQLITE_ONLY_SURFACES_CONTRACT {
            return Err(format!(
                "unsupported sqlite-only list version {:?}; expected {SQLITE_ONLY_SURFACES_CONTRACT:?}",
                self.version
            ));
        }
        if self.issue != 1316 {
            return Err(format!(
                "sqlite-only list issue must be 1316, got {}",
                self.issue
            ));
        }
        if self.limit != SQLITE_ONLY_SURFACE_LIMIT {
            return Err(format!(
                "sqlite-only limit must be {SQLITE_ONLY_SURFACE_LIMIT}, got {}",
                self.limit
            ));
        }
        if self.surfaces.len() > self.limit {
            return Err(format!(
                "sqlite-only list grew to {} surfaces; limit is {} and the list may only shrink",
                self.surfaces.len(),
                self.limit
            ));
        }
        if self.surfaces.len() != self.limit {
            return Err(format!(
                "sqlite-only list has {} surfaces but limit is {}; decrease both when a surface is ported",
                self.surfaces.len(),
                self.limit
            ));
        }
        let mut seen = BTreeSet::new();
        for surface in &self.surfaces {
            if surface.id.trim().is_empty() {
                return Err("sqlite-only surface id is empty".into());
            }
            if !seen.insert(surface.id.clone()) {
                return Err(format!("duplicate sqlite-only surface {}", surface.id));
            }
            if surface.methods.is_empty() {
                return Err(format!(
                    "sqlite-only surface {} has no evidence methods",
                    surface.id
                ));
            }
            match surface.kind {
                SqliteOnlyKind::Rpc => {
                    if !surface.id.contains('.') {
                        return Err(format!("rpc surface {} must be Service.Rpc", surface.id));
                    }
                }
                SqliteOnlyKind::Admin => {
                    if !surface.id.starts_with("admin.") {
                        return Err(format!(
                            "admin surface {} must start with admin.",
                            surface.id
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn rpc_ids(&self) -> BTreeSet<String> {
        self.surfaces
            .iter()
            .filter(|surface| surface.kind == SqliteOnlyKind::Rpc)
            .map(|surface| surface.id.clone())
            .collect()
    }

    pub fn contains_rpc(&self, service: &str, rpc: &str) -> bool {
        let id = format!("{service}.{rpc}");
        self.surfaces
            .iter()
            .any(|surface| surface.kind == SqliteOnlyKind::Rpc && surface.id == id)
    }
}

/// RuntimeDb methods whose PostgreSQL arm ignores the store (`Self::Postgres(_)`)
/// and does not call `off_runtime`. Those methods fail closed or return empty
/// on community PostgreSQL.
pub fn postgres_fail_closed_methods(runtime_db_src: &str) -> BTreeSet<String> {
    let Some(impl_at) = runtime_db_src.find("impl RuntimeDb {") else {
        return BTreeSet::new();
    };
    let src = &runtime_db_src[impl_at..];
    let mut methods = BTreeSet::new();
    let mut search_from = 0usize;
    while let Some(rel) = src[search_from..].find("\n    pub") {
        let start = search_from + rel;
        let header = &src[start..];
        let Some(name) = parse_method_name(header) else {
            search_from = start + 1;
            continue;
        };
        let Some(brace) = header.find('{') else {
            break;
        };
        let body_start = start + brace;
        let Some(body_end) = matching_brace_end(src, body_start) else {
            break;
        };
        let body = &src[body_start..body_end];
        if body.contains("Self::Postgres(_)") && !body.contains("off_runtime") {
            methods.insert(name);
        }
        search_from = body_end;
    }
    methods
}

fn parse_method_name(header: &str) -> Option<String> {
    let rest = header
        .strip_prefix("\n    pub fn ")
        .or_else(|| header.strip_prefix("\n    pub(crate) fn "))?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() { None } else { Some(name) }
}

fn matching_brace_end(src: &str, open: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    if open >= bytes.len() || bytes[open] != b'{' {
        return None;
    }
    let mut depth = 0i32;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Expected Real backend cell for one public RPC.
pub fn expected_real_backend(service: &str, rpc: &str, list: &SqliteOnlySurfaces) -> &'static str {
    if list.contains_rpc(service, rpc) {
        "sqlite only"
    } else {
        "yes"
    }
}

/// Every listed evidence method must be fail-closed on PostgreSQL.
pub fn listed_methods_are_fail_closed(
    list: &SqliteOnlySurfaces,
    runtime_db_src: &str,
) -> Result<(), String> {
    let closed = postgres_fail_closed_methods(runtime_db_src);
    let mut missing = Vec::new();
    for surface in &list.surfaces {
        for method in &surface.methods {
            if !closed.contains(method) {
                missing.push(format!("{}:{method}", surface.id));
            }
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "listed sqlite-only methods are not fail-closed on PostgreSQL: {}",
            missing.join(", ")
        ))
    }
}

/// A public RPC whose snake_case RuntimeDb method fails closed must be listed.
pub fn unlisted_fail_closed_rpcs(
    table: &RpcMaturityTable,
    list: &SqliteOnlySurfaces,
    runtime_db_src: &str,
) -> Result<(), String> {
    let closed = postgres_fail_closed_methods(runtime_db_src);
    let mut missing = Vec::new();
    for entry in &table.entries {
        let snake = pascal_to_snake(&entry.rpc);
        if closed.contains(&snake) && !list.contains_rpc(&entry.service, &entry.rpc) {
            missing.push(format!("{}.{}", entry.service, entry.rpc));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "SQLite-only RPCs missing from the shrink-only list: {}",
            missing.join(", ")
        ))
    }
}

/// Fixture and docs Real backend cells must match the list.
pub fn real_backend_matches_list(
    table: &RpcMaturityTable,
    docs: &str,
    list: &SqliteOnlySurfaces,
) -> Result<(), String> {
    let docs_rows = parse_docs_rows(docs)?;
    let docs_by_rpc: BTreeMap<_, _> = docs_rows
        .iter()
        .map(|row| (format!("{}.{}", row.service, row.rpc), row))
        .collect();
    let mut errors = Vec::new();
    for id in list.rpc_ids() {
        let Some((service, rpc)) = id.split_once('.') else {
            errors.push(format!("rpc surface {id} is not Service.Rpc"));
            continue;
        };
        if table.entry(service, rpc).is_none() {
            errors.push(format!(
                "rpc surface {id} is missing from the maturity table"
            ));
        }
    }
    for entry in &table.entries {
        let expected = expected_real_backend(&entry.service, &entry.rpc, list);
        if entry.real_backend != expected {
            errors.push(format!(
                "fixture {}.{} real_backend is {:?}, evidence says {expected}",
                entry.service, entry.rpc, entry.real_backend
            ));
        }
        let key = format!("{}.{}", entry.service, entry.rpc);
        match docs_by_rpc.get(&key) {
            None => errors.push(format!("docs table is missing {key}")),
            Some(row) if row.real_backend != expected => errors.push(format!(
                "docs {key} real_backend is {:?}, evidence says {expected}",
                row.real_backend
            )),
            Some(_) => {}
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Operator docs must name the shrink-only list instead of restating it.
pub fn parity_docs_link_the_list(sekai: &str, chisei: &str, maturity: &str) -> Result<(), String> {
    let needle = "tests/fixtures/sqlite_only_surfaces/v1.json";
    for (name, body) in [
        ("docs/postgres-sekai-parity.md", sekai),
        ("docs/postgres-chisei-parity.md", chisei),
        ("docs/rpc-maturity.md", maturity),
    ] {
        if !body.contains(needle) {
            return Err(format!("{name} must link to {needle}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_maturity::MATURITY_DOCS;

    #[test]
    fn list_loads_and_matches_runtime_evidence() {
        let list = SqliteOnlySurfaces::load().expect("sqlite-only list");
        let table = RpcMaturityTable::load().expect("maturity table");
        listed_methods_are_fail_closed(&list, RUNTIME_DB_SRC).unwrap();
        unlisted_fail_closed_rpcs(&table, &list, RUNTIME_DB_SRC).unwrap();
        real_backend_matches_list(&table, MATURITY_DOCS, &list).unwrap();
        assert_eq!(list.surfaces.len(), SQLITE_ONLY_SURFACE_LIMIT);
        assert!(list.contains_rpc("SekaiService", "PutPurposeAuthorization"));
        assert!(list.contains_rpc("SekaiService", "RegisterSourceTypeDescriptor"));
        assert!(!list.contains_rpc("SekaiService", "DecideActionInstance"));
        assert!(!list.contains_rpc("SekaiService", "AdmitGovernedDocument"));
    }

    #[test]
    fn mislabeled_docs_row_fails() {
        let list = SqliteOnlySurfaces::load().expect("list");
        let table = RpcMaturityTable::load().expect("table");
        let tampered = MATURITY_DOCS.replace(
            "| `SekaiService.PutPurposeAuthorization` | `sekai.object-security` | sqlite only |",
            "| `SekaiService.PutPurposeAuthorization` | `sekai.object-security` | yes |",
        );
        let error = real_backend_matches_list(&table, &tampered, &list)
            .expect_err("mislabeled row must fail");
        assert!(error.contains("PutPurposeAuthorization"), "{error}");
        assert!(error.contains("docs"), "{error}");
    }

    #[test]
    fn unlisted_fail_closed_rpc_fails() {
        let table = RpcMaturityTable::load().expect("table");
        let mut list = SqliteOnlySurfaces::load().expect("list");
        list.surfaces
            .retain(|surface| surface.id != "SekaiService.PutPurposeAuthorization");
        let error = unlisted_fail_closed_rpcs(&table, &list, RUNTIME_DB_SRC)
            .expect_err("unlisted sqlite-only RPC must fail");
        assert!(error.contains("PutPurposeAuthorization"), "{error}");
    }

    #[test]
    fn list_growth_fails() {
        let mut list = SqliteOnlySurfaces::load().expect("list");
        list.surfaces.push(SqliteOnlySurface {
            id: "SekaiService.InventedRpc".into(),
            kind: SqliteOnlyKind::Rpc,
            methods: vec!["invented".into()],
        });
        let error = list.validate().expect_err("growth must fail");
        assert!(
            error.contains("grew") || error.contains("only shrink"),
            "{error}"
        );
    }

    #[test]
    fn fail_closed_scanner_sees_purpose_and_skips_object_security() {
        let closed = postgres_fail_closed_methods(RUNTIME_DB_SRC);
        assert!(closed.contains("put_purpose_authorization"));
        assert!(closed.contains("put_source_type_descriptor"));
        assert!(
            !closed.contains("decide_parked_action_instance"),
            "dual-backend decide must not look sqlite-only"
        );
        assert!(
            !closed.contains("put_governed_document"),
            "dual-backend governed documents must not look sqlite-only"
        );
        assert!(
            !closed.contains("put_object_security_policy"),
            "dual-backend object security must not look sqlite-only"
        );
    }
}
