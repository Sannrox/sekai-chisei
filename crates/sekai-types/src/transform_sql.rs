//! SQL compile/validate helpers for governed transforms.
//!
//! Execution against SQLite stays in the plane `transform_engine`. These
//! helpers are value-level: they take and return strings and transform types.

use std::iter::Peekable;
use std::str::Chars;

use crate::governed_transform::{TransformError, TransformStep};

pub const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_TIME_LIMIT_MS: u64 = 5_000;
pub const BUDGET_TIME: &str = "transform_budget_time";
pub const BUDGET_MEMORY: &str = "transform_budget_memory";

const FORBIDDEN_SQL: &[&str] = &[
    "attach",
    "detach",
    "load",
    "pragma",
    "insert",
    "update",
    "delete",
    "drop",
    "create",
    "alter",
    "vacuum",
    "copy",
    "import",
    "export",
    "install",
    "uninstall",
    "reindex",
];

const FULL_SCAN_SQL: &[&str] = &[
    "join",
    "group",
    "union",
    "intersect",
    "except",
    "distinct",
    "having",
    "window",
    "over",
    "recursive",
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "total",
    "limit",
    "offset",
    "group_concat",
    "string_agg",
    "array_agg",
    "json_group_array",
    "json_group_object",
];

/// Compile `filter` / `project` steps to a single SELECT over `alias`.
pub fn compile_steps_sql(steps: &[TransformStep], alias: &str) -> Result<String, TransformError> {
    let ident = quote_ident(alias)?;
    let mut sql = format!("SELECT * FROM {ident}");
    for step in steps {
        match step.kind.trim().to_ascii_lowercase().as_str() {
            "filter" => {
                let column = quote_column(&step.column)?;
                let value = quote_string(&step.value);
                let predicate = match step.op.as_str() {
                    "eq" | "" => format!("{column} = {value}"),
                    "neq" => format!("{column} != {value}"),
                    other => {
                        return Err(TransformError::InvalidArgument(format!(
                            "unsupported transform filter op {other}"
                        )));
                    }
                };
                sql = format!("SELECT * FROM ({sql}) WHERE {predicate}");
            }
            "project" if !step.columns.is_empty() => {
                let mut columns = Vec::new();
                for column in &step.columns {
                    columns.push(quote_column(column)?);
                }
                sql = format!("SELECT {} FROM ({sql})", columns.join(", "));
            }
            "project" => {}
            other => {
                return Err(TransformError::InvalidArgument(format!(
                    "unsupported transform step {other}"
                )));
            }
        }
    }
    Ok(sql)
}

pub fn validate_analytical_sql(sql: &str) -> Result<(), TransformError> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(TransformError::InvalidArgument(
            "transform sql required".into(),
        ));
    }
    let body = trimmed.trim_end_matches(';').trim();
    if sql_has_internal_semicolon(body) {
        return Err(TransformError::InvalidArgument(
            "transform sql must be a single statement".into(),
        ));
    }
    let first = body
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if first != "select" && first != "with" {
        return Err(TransformError::InvalidArgument(
            "transform sql must be a SELECT".into(),
        ));
    }
    for token in tokenize_sql(body) {
        if FORBIDDEN_SQL.contains(&token.as_str()) {
            return Err(TransformError::InvalidArgument(format!(
                "transform sql must not use {token}"
            )));
        }
    }
    Ok(())
}

/// True when the SQL is a row-local filter/project and can reuse the
/// projection watermark. Joins, aggregates, LIMIT/OFFSET and subqueries need
/// a full recompute; any `select` after the first token fails closed.
pub fn sql_is_row_local(sql: &str) -> bool {
    let tokens = tokenize_sql(sql);
    tokens
        .iter()
        .all(|token| !FULL_SCAN_SQL.contains(&token.as_str()))
        && !tokens.iter().skip(1).any(|token| token == "select")
}

pub fn host_limit(requested: u64, max: u64) -> u64 {
    if requested == 0 {
        max
    } else {
        requested.min(max)
    }
}

pub fn quote_ident(name: &str) -> Result<String, TransformError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(TransformError::InvalidArgument(
            "identifier required".into(),
        ));
    }
    let mut chars = trimmed.chars();
    let first = chars.next().expect("non-empty");
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(TransformError::InvalidArgument(
            "identifier must start with a letter".into(),
        ));
    }
    if !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        return Err(TransformError::InvalidArgument(
            "identifier must be alphanumeric".into(),
        ));
    }
    Ok(format!("\"{trimmed}\""))
}

pub fn quote_column(name: &str) -> Result<String, TransformError> {
    if name.is_empty() || name.contains('\0') {
        return Err(TransformError::InvalidArgument(
            "identifier required".into(),
        ));
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

fn quote_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn push_sql_token(current: &mut String, tokens: &mut Vec<String>) {
    if !current.is_empty() {
        tokens.push(std::mem::take(current).to_ascii_lowercase());
    }
}

fn skip_quoted(chars: &mut Peekable<Chars<'_>>, quote: char) {
    while let Some(ch) = chars.next() {
        if ch == quote {
            if chars.peek() == Some(&quote) {
                chars.next();
                continue;
            }
            break;
        }
    }
}

fn sql_has_internal_semicolon(sql: &str) -> bool {
    let mut chars = sql.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' | '"' | '`' => skip_quoted(&mut chars, ch),
            '[' => {
                for next in chars.by_ref() {
                    if next == ']' {
                        break;
                    }
                }
            }
            '-' if chars.peek() == Some(&'-') => {
                chars.next();
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = ' ';
                for next in chars.by_ref() {
                    if prev == '*' && next == '/' {
                        break;
                    }
                    prev = next;
                }
            }
            ';' => return true,
            _ => {}
        }
    }
    false
}

fn tokenize_sql(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = sql.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' | '"' | '`' => {
                push_sql_token(&mut current, &mut tokens);
                skip_quoted(&mut chars, ch);
            }
            '[' => {
                push_sql_token(&mut current, &mut tokens);
                for next in chars.by_ref() {
                    if next == ']' {
                        break;
                    }
                }
            }
            '-' if chars.peek() == Some(&'-') => {
                push_sql_token(&mut current, &mut tokens);
                chars.next();
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                push_sql_token(&mut current, &mut tokens);
                chars.next();
                let mut prev = ' ';
                for next in chars.by_ref() {
                    if prev == '*' && next == '/' {
                        break;
                    }
                    prev = next;
                }
            }
            ch if ch.is_ascii_alphanumeric() || ch == '_' => current.push(ch),
            _ => push_sql_token(&mut current, &mut tokens),
        }
    }
    push_sql_token(&mut current, &mut tokens);
    tokens
}

#[cfg(test)]
mod row_local_tests {
    use super::sql_is_row_local;

    #[test]
    fn limits_subqueries_and_string_aggregates_are_not_row_local() {
        for sql in [
            "SELECT * FROM input LIMIT 10",
            "SELECT * FROM input LIMIT 10 OFFSET 5",
            "SELECT * FROM input WHERE id IN (SELECT id FROM input WHERE keep = 'yes')",
            "SELECT group_concat(name) FROM input",
            "SELECT json_group_array(name) FROM input",
            "SELECT json_group_object(id, name) FROM input",
        ] {
            assert!(!sql_is_row_local(sql), "{sql}");
        }
        assert!(sql_is_row_local("SELECT * FROM input WHERE keep = 'yes'"));
        assert!(sql_is_row_local("SELECT id, name FROM input"));
        assert!(sql_is_row_local(
            "SELECT * FROM input WHERE note = 'select limit'"
        ));
    }
}
