//! In-process SQL engine for the analytical governed-transform profile (#1385).
//!
//! The plane already embeds SQLite. A second engine would add a native library
//! or a large crate without changing the JobSpec, receipt, or resource
//! envelope. This host registers only caller-supplied dataset rows, rejects
//! statements other than SELECT/WITH, and bounds memory and wall time.

use super::governed_transform::{TransformError, TransformStep};
use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, InterruptHandle, params_from_iter};
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap};
use std::ffi::{c_int, c_void};
use std::iter::Peekable;
use std::ptr;
use std::str::Chars;
use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static ALLOC_INSTALL: Once = Once::new();
static ALLOC_INSTALLED: AtomicBool = AtomicBool::new(false);
static mut ORIGINAL_ALLOC: rusqlite::ffi::sqlite3_mem_methods = unsafe { std::mem::zeroed() };
static mut WRAPPED_ALLOC: rusqlite::ffi::sqlite3_mem_methods = unsafe { std::mem::zeroed() };

thread_local! {
    static ALLOC_BUDGET: Cell<AllocBudget> = const {
        Cell::new(AllocBudget {
            used: 0,
            limit: 0,
            active: false,
        })
    };
}

#[derive(Clone, Copy)]
struct AllocBudget {
    used: u64,
    limit: u64,
    active: bool,
}

struct EngineAllocGuard;

impl EngineAllocGuard {
    fn enter(limit: u64) -> Self {
        install_engine_allocator();
        ALLOC_BUDGET.with(|budget| {
            budget.set(AllocBudget {
                used: 0,
                limit,
                active: true,
            })
        });
        Self
    }
}

impl Drop for EngineAllocGuard {
    fn drop(&mut self) {
        ALLOC_BUDGET.with(|budget| {
            budget.set(AllocBudget {
                used: 0,
                limit: 0,
                active: false,
            })
        });
    }
}

/// Wrap SQLite's allocator before `sqlite3_initialize` so engine threads can
/// refuse allocations that exceed the JobSpec envelope without a process-wide
/// heap limit.
pub(crate) fn install_engine_allocator() {
    ALLOC_INSTALL.call_once(|| unsafe {
        let mut original: rusqlite::ffi::sqlite3_mem_methods = std::mem::zeroed();
        let got =
            rusqlite::ffi::sqlite3_config(rusqlite::ffi::SQLITE_CONFIG_GETMALLOC, &mut original);
        if got != rusqlite::ffi::SQLITE_OK || original.xMalloc.is_none() {
            return;
        }
        ORIGINAL_ALLOC = original;
        WRAPPED_ALLOC = rusqlite::ffi::sqlite3_mem_methods {
            xMalloc: Some(engine_malloc),
            xFree: Some(engine_free),
            xRealloc: Some(engine_realloc),
            xSize: original.xSize,
            xRoundup: original.xRoundup,
            xInit: original.xInit,
            xShutdown: original.xShutdown,
            pAppData: original.pAppData,
        };
        let set = rusqlite::ffi::sqlite3_config(
            rusqlite::ffi::SQLITE_CONFIG_MALLOC,
            ptr::addr_of_mut!(WRAPPED_ALLOC),
        );
        if set == rusqlite::ffi::SQLITE_OK {
            ALLOC_INSTALLED.store(true, Ordering::Release);
        }
    });
}

unsafe extern "C" fn install_engine_allocator_ctor() {
    install_engine_allocator();
}

#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__mod_init_func"))]
#[cfg_attr(target_os = "windows", unsafe(link_section = ".CRT$XCU"))]
static SQLITE_ENGINE_ALLOCATOR_INIT: unsafe extern "C" fn() = install_engine_allocator_ctor;

fn original_alloc() -> rusqlite::ffi::sqlite3_mem_methods {
    unsafe { ORIGINAL_ALLOC }
}

fn alloc_size(
    original: rusqlite::ffi::sqlite3_mem_methods,
    ptr: *mut c_void,
    fallback: c_int,
) -> u64 {
    if let Some(size) = original.xSize {
        let bytes = unsafe { size(ptr) };
        if bytes > 0 {
            return bytes as u64;
        }
    }
    fallback.max(0) as u64
}

fn budget_allows(additional: u64) -> bool {
    ALLOC_BUDGET.with(|budget| {
        let state = budget.get();
        !state.active || state.used.saturating_add(additional) <= state.limit
    })
}

fn budget_add(bytes: u64) {
    ALLOC_BUDGET.with(|budget| {
        let mut state = budget.get();
        if state.active {
            state.used = state.used.saturating_add(bytes);
            budget.set(state);
        }
    });
}

fn budget_sub(bytes: u64) {
    ALLOC_BUDGET.with(|budget| {
        let mut state = budget.get();
        if state.active {
            state.used = state.used.saturating_sub(bytes);
            budget.set(state);
        }
    });
}

unsafe extern "C" fn engine_malloc(requested: c_int) -> *mut c_void {
    let original = original_alloc();
    let Some(malloc) = original.xMalloc else {
        return ptr::null_mut();
    };
    if requested < 0 || !budget_allows(requested as u64) {
        return ptr::null_mut();
    }
    let allocated = unsafe { malloc(requested) };
    if !allocated.is_null() {
        budget_add(alloc_size(original, allocated, requested));
    }
    allocated
}

unsafe extern "C" fn engine_free(allocated: *mut c_void) {
    let original = original_alloc();
    if !allocated.is_null() {
        budget_sub(alloc_size(original, allocated, 0));
    }
    if let Some(free) = original.xFree {
        unsafe { free(allocated) };
    }
}

unsafe extern "C" fn engine_realloc(allocated: *mut c_void, requested: c_int) -> *mut c_void {
    if allocated.is_null() {
        return unsafe { engine_malloc(requested) };
    }
    if requested == 0 {
        unsafe { engine_free(allocated) };
        return ptr::null_mut();
    }
    let original = original_alloc();
    let Some(realloc) = original.xRealloc else {
        return ptr::null_mut();
    };
    let previous = alloc_size(original, allocated, 0);
    let allow = ALLOC_BUDGET.with(|budget| {
        let state = budget.get();
        !state.active
            || state
                .used
                .saturating_sub(previous)
                .saturating_add(requested as u64)
                <= state.limit
    });
    if !allow {
        return ptr::null_mut();
    }
    let resized = unsafe { realloc(allocated, requested) };
    if !resized.is_null() {
        budget_sub(previous);
        budget_add(alloc_size(original, resized, requested));
    }
    resized
}

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
/// projection watermark. Joins and aggregates need a full recompute.
pub fn sql_is_row_local(sql: &str) -> bool {
    tokenize_sql(sql)
        .iter()
        .all(|token| !FULL_SCAN_SQL.contains(&token.as_str()))
}

pub struct EngineTable {
    pub alias: String,
    pub rows: Vec<HashMap<String, String>>,
    pub columns: Vec<String>,
}

/// Run `sql` against in-memory tables built from governed dataset rows.
/// Declared columns keep an empty input queryable.
pub fn execute_sql(
    sql: &str,
    tables: &[EngineTable],
    memory_limit_bytes: u64,
    time_limit_ms: u64,
) -> Result<Vec<HashMap<String, String>>, TransformError> {
    execute_sql_until(sql, tables, memory_limit_bytes, time_limit_ms, None)
}

pub(crate) fn execute_sql_until(
    sql: &str,
    tables: &[EngineTable],
    memory_limit_bytes: u64,
    time_limit_ms: u64,
    deadline: Option<Instant>,
) -> Result<Vec<HashMap<String, String>>, TransformError> {
    validate_analytical_sql(sql)?;
    let memory = host_limit(memory_limit_bytes, DEFAULT_MEMORY_LIMIT_BYTES);
    let time_ms = host_limit(time_limit_ms, DEFAULT_TIME_LIMIT_MS);
    let deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_millis(time_ms));
    if Instant::now() >= deadline {
        return Err(TransformError::Quarantined(BUDGET_TIME.into()));
    }
    let conn = Connection::open_in_memory().map_err(|error| {
        TransformError::InvalidArgument(format!("analytical engine unavailable: {error}"))
    })?;
    apply_memory_bound(&conn, memory)?;
    let _alloc = EngineAllocGuard::enter(memory);
    let budget = EngineBudget {
        deadline,
        memory,
        time_exceeded: Arc::new(AtomicBool::new(false)),
    };
    conn.progress_handler(
        100,
        Some({
            let deadline = budget.deadline;
            move || Instant::now() >= deadline
        }),
    )
    .map_err(|error| TransformError::InvalidArgument(error.to_string()))?;
    let interrupt = conn.get_interrupt_handle();
    let cancel = Arc::new(AtomicBool::new(false));
    let remaining = deadline.saturating_duration_since(Instant::now());
    let watchdog = spawn_watchdog(
        interrupt,
        budget.time_exceeded.clone(),
        cancel.clone(),
        remaining,
    );
    let result = (|| {
        for table in tables {
            budget.check_time()?;
            register_table(&conn, &table.alias, &table.rows, &table.columns, &budget)?;
        }
        execute_sql_inner(&conn, sql, &budget)
    })();
    cancel.store(true, Ordering::SeqCst);
    let _ = watchdog.join();
    let _ = conn.progress_handler(0, None::<fn() -> bool>);
    if budget.time_exceeded.load(Ordering::SeqCst) {
        return Err(TransformError::Quarantined(BUDGET_TIME.into()));
    }
    result
}

fn execute_sql_inner(
    conn: &Connection,
    sql: &str,
    budget: &EngineBudget,
) -> Result<Vec<HashMap<String, String>>, TransformError> {
    let mut stmt = conn
        .prepare(sql.trim().trim_end_matches(';'))
        .map_err(map_engine_error)?;
    let names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(|name| name.to_string())
        .collect();
    let mut unique = BTreeSet::new();
    for name in &names {
        if !unique.insert(name.as_str()) {
            return Err(TransformError::InvalidArgument(
                "transform sql output columns must be unique".into(),
            ));
        }
    }
    let mut rows = stmt.query([]).map_err(map_engine_error)?;
    let mut out = Vec::new();
    let mut used = 0u64;
    while let Some(row) = rows.next().map_err(map_engine_error)? {
        used = used.saturating_add(64);
        if used > budget.memory {
            return Err(TransformError::Quarantined(BUDGET_MEMORY.into()));
        }
        let mut map = HashMap::new();
        for (index, name) in names.iter().enumerate() {
            let value: Option<String> = match row.get_ref(index).map_err(map_engine_error)? {
                rusqlite::types::ValueRef::Null => None,
                rusqlite::types::ValueRef::Integer(value) => Some(value.to_string()),
                rusqlite::types::ValueRef::Real(value) => Some(value.to_string()),
                rusqlite::types::ValueRef::Text(value) => Some(
                    std::str::from_utf8(value)
                        .map(str::to_string)
                        .map_err(|_| {
                            TransformError::InvalidArgument(
                                "transform sql output is not utf-8".into(),
                            )
                        })?,
                ),
                rusqlite::types::ValueRef::Blob(_) => {
                    return Err(TransformError::InvalidArgument(
                        "transform sql rejected blob output".into(),
                    ));
                }
            };
            if let Some(value) = value {
                used = used
                    .saturating_add(name.len() as u64)
                    .saturating_add(value.len() as u64)
                    .saturating_add(32);
                if used > budget.memory {
                    return Err(TransformError::Quarantined(BUDGET_MEMORY.into()));
                }
                map.insert(name.clone(), value);
            }
        }
        out.push(map);
    }
    Ok(out)
}

fn register_table(
    conn: &Connection,
    alias: &str,
    rows: &[HashMap<String, String>],
    declared: &[String],
    budget: &EngineBudget,
) -> Result<(), TransformError> {
    let ident = quote_ident(alias)?;
    let mut columns: BTreeSet<String> = declared.iter().cloned().collect();
    for row in rows {
        columns.extend(row.keys().cloned());
    }
    if columns.is_empty() {
        columns.insert("_row".into());
    }
    let quoted: Vec<String> = columns
        .iter()
        .map(|column| quote_column(column))
        .collect::<Result<_, _>>()?;
    let defs: Vec<String> = quoted
        .iter()
        .map(|column| format!("{column} TEXT"))
        .collect();
    conn.execute(&format!("CREATE TABLE {ident} ({})", defs.join(", ")), [])
        .map_err(map_engine_error)?;
    if rows.is_empty() {
        return Ok(());
    }
    let placeholders = vec!["?"; quoted.len()].join(", ");
    let insert = format!(
        "INSERT INTO {ident} ({}) VALUES ({placeholders})",
        quoted.join(", ")
    );
    let mut stmt = conn.prepare(&insert).map_err(map_engine_error)?;
    for row in rows {
        budget.check_time()?;
        let values: Vec<Option<&str>> = columns
            .iter()
            .map(|column| row.get(column).map(String::as_str))
            .collect();
        stmt.execute(params_from_iter(values))
            .map_err(map_engine_error)?;
    }
    Ok(())
}

pub fn host_limit(requested: u64, max: u64) -> u64 {
    if requested == 0 {
        max
    } else {
        requested.min(max)
    }
}

struct EngineBudget {
    deadline: Instant,
    memory: u64,
    time_exceeded: Arc<AtomicBool>,
}

impl EngineBudget {
    fn check_time(&self) -> Result<(), TransformError> {
        if Instant::now() >= self.deadline || self.time_exceeded.load(Ordering::SeqCst) {
            Err(TransformError::Quarantined(BUDGET_TIME.into()))
        } else {
            Ok(())
        }
    }
}

fn apply_memory_bound(conn: &Connection, memory_limit_bytes: u64) -> Result<(), TransformError> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)
        .map_err(|error| TransformError::InvalidArgument(error.to_string()))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)
        .map_err(|error| TransformError::InvalidArgument(error.to_string()))?;
    let _ = conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true);
    unsafe {
        let _ = rusqlite::ffi::sqlite3_db_config(
            conn.handle(),
            rusqlite::ffi::SQLITE_DBCONFIG_LOOKASIDE,
            ptr::null_mut::<c_void>(),
            0,
            0,
        );
    }
    let cap = i32::try_from(memory_limit_bytes.min(i32::MAX as u64)).unwrap_or(i32::MAX);
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, cap.max(1))
        .map_err(|error| TransformError::InvalidArgument(error.to_string()))?;
    let _ = conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0);
    let _ = conn.set_limit(Limit::SQLITE_LIMIT_WORKER_THREADS, 0);
    // FILE temps cap sorter PMA at cache_size. MEMORY temps leave mxPmaSize=0.
    conn.pragma_update(None, "temp_store", 1)
        .map_err(|error| TransformError::InvalidArgument(error.to_string()))?;
    let cache_kib = (memory_limit_bytes / 1024).max(1);
    conn.pragma_update(None, "cache_size", -(cache_kib as i64))
        .map_err(|error| TransformError::InvalidArgument(error.to_string()))?;
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .unwrap_or(4096);
    let page_size = page_size.max(512);
    let pages = (memory_limit_bytes / page_size as u64).max(2);
    conn.pragma_update(None, "max_page_count", pages as i64)
        .map_err(|error| TransformError::InvalidArgument(error.to_string()))?;
    conn.pragma_update(Some("temp"), "max_page_count", pages as i64)
        .map_err(|error| TransformError::InvalidArgument(error.to_string()))?;
    // hard_heap_limit is process-wide and would starve the plane database.
    Ok(())
}

fn spawn_watchdog(
    interrupt: InterruptHandle,
    expired: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    limit: Duration,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let deadline = Instant::now() + limit;
        while !cancel.load(Ordering::SeqCst) {
            if Instant::now() >= deadline {
                expired.store(true, Ordering::SeqCst);
                interrupt.interrupt();
                std::thread::sleep(Duration::from_millis(10));
            } else {
                let remaining = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(remaining.min(Duration::from_millis(10)));
            }
        }
    })
}

fn map_engine_error(error: rusqlite::Error) -> TransformError {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("interrupted") || message.contains("cancel") {
        return TransformError::Quarantined(BUDGET_TIME.into());
    }
    if message.contains("database or disk is full")
        || message.contains("out of memory")
        || message.contains("no longer valid")
        || message.contains("string or blob too big")
    {
        return TransformError::Quarantined(BUDGET_MEMORY.into());
    }
    if matches!(error, rusqlite::Error::InvalidQuery) {
        return TransformError::InvalidArgument("transform sql rejected blob output".into());
    }
    TransformError::InvalidArgument(format!("analytical query failed: {error}"))
}

fn quote_ident(name: &str) -> Result<String, TransformError> {
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

fn quote_column(name: &str) -> Result<String, TransformError> {
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
mod tests {
    use super::*;

    fn table(alias: &str, rows: Vec<HashMap<String, String>>, columns: Vec<String>) -> EngineTable {
        EngineTable {
            alias: alias.into(),
            rows,
            columns,
        }
    }

    #[test]
    fn compiled_filter_matches_row_engine() {
        let steps = [TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }];
        let sql = compile_steps_sql(&steps, "input").unwrap();
        let rows = vec![
            HashMap::from([("id".into(), "1".into()), ("keep".into(), "yes".into())]),
            HashMap::from([("id".into(), "2".into()), ("keep".into(), "no".into())]),
        ];
        let out = execute_sql(&sql, &[table("input", rows, Vec::new())], 0, 0).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].get("id").map(String::as_str), Some("1"));
    }

    #[test]
    fn join_and_aggregate_sql_returns_grouped_rows() {
        let customers = vec![
            HashMap::from([("id".into(), "c1".into()), ("region".into(), "east".into())]),
            HashMap::from([("id".into(), "c2".into()), ("region".into(), "west".into())]),
        ];
        let orders = vec![
            HashMap::from([
                ("id".into(), "o1".into()),
                ("customer_id".into(), "c1".into()),
                ("amount".into(), "10".into()),
            ]),
            HashMap::from([
                ("id".into(), "o2".into()),
                ("customer_id".into(), "c1".into()),
                ("amount".into(), "5".into()),
            ]),
            HashMap::from([
                ("id".into(), "o3".into()),
                ("customer_id".into(), "c2".into()),
                ("amount".into(), "7".into()),
            ]),
        ];
        let sql = "SELECT c.region AS region, COUNT(*) AS orders, SUM(o.amount) AS total \
                   FROM orders o JOIN customers c ON o.customer_id = c.id GROUP BY c.region";
        let out = execute_sql(
            sql,
            &[
                table("customers", customers, Vec::new()),
                table("orders", orders, Vec::new()),
            ],
            0,
            0,
        )
        .unwrap();
        let east = out
            .iter()
            .find(|row| row.get("region").map(String::as_str) == Some("east"))
            .unwrap();
        assert_eq!(east.get("orders").map(String::as_str), Some("2"));
        let total: f64 = east.get("total").unwrap().parse().unwrap();
        assert_eq!(total, 15.0);
    }

    #[test]
    fn over_budget_recursive_query_names_time() {
        let sql = "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t) SELECT n FROM t";
        let error = execute_sql(sql, &[], 0, 1).unwrap_err();
        assert_eq!(error.message(), BUDGET_TIME);
    }

    #[test]
    fn attach_is_rejected() {
        let error = validate_analytical_sql("ATTACH DATABASE 'x' AS extra").unwrap_err();
        assert!(error.message().contains("SELECT"));
    }

    #[test]
    fn semicolon_in_literal_is_a_single_statement() {
        validate_analytical_sql("SELECT ';' AS delimiter").unwrap();
        validate_analytical_sql("SELECT 1;").unwrap();
        let error = validate_analytical_sql("SELECT 1; SELECT 2").unwrap_err();
        assert!(error.message().contains("single statement"));
    }

    #[test]
    fn invalid_utf8_output_is_rejected() {
        let error = execute_sql("SELECT CAST(X'80' AS TEXT) AS value", &[], 0, 0).unwrap_err();
        assert!(error.message().contains("utf-8"), "{}", error.message());
    }

    #[test]
    fn expired_deadline_names_time() {
        let error = execute_sql_until(
            "SELECT 1 AS id",
            &[],
            0,
            5_000,
            Some(Instant::now() - Duration::from_secs(1)),
        )
        .unwrap_err();
        assert_eq!(error.message(), BUDGET_TIME);
    }

    #[test]
    fn oversized_text_result_names_memory() {
        let error =
            execute_sql("SELECT printf('%1000000s', 'x') AS blob", &[], 4096, 5_000).unwrap_err();
        assert_eq!(error.message(), BUDGET_MEMORY);
    }

    #[test]
    fn oversized_printf_width_names_memory_before_allocation() {
        let error = execute_sql(
            "SELECT printf('%1000000000s', 'x') AS blob",
            &[],
            64 * 1024,
            5_000,
        )
        .unwrap_err();
        assert_eq!(error.message(), BUDGET_MEMORY);
    }

    #[test]
    fn sql_literals_are_not_forbidden_tokens() {
        validate_analytical_sql("SELECT * FROM input WHERE action = 'update'").unwrap();
        assert!(sql_is_row_local(
            "SELECT * FROM input WHERE action = 'join'"
        ));
        let rows = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("action".into(), "update".into()),
        ])];
        let sql = compile_steps_sql(
            &[TransformStep {
                kind: "filter".into(),
                column: "action".into(),
                op: "eq".into(),
                value: "update".into(),
                columns: Vec::new(),
            }],
            "input",
        )
        .unwrap();
        let out = execute_sql(&sql, &[table("input", rows, Vec::new())], 0, 0).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn quoted_unknown_column_is_rejected() {
        let rows = vec![HashMap::from([("id".into(), "1".into())])];
        let error = execute_sql(
            "SELECT \"missing\" FROM input",
            &[table("input", rows, vec!["id".into()])],
            0,
            0,
        )
        .unwrap_err();
        assert!(
            error
                .message()
                .to_ascii_lowercase()
                .contains("no such column")
                || error.message().contains("missing"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn duplicate_output_columns_are_rejected() {
        let error = execute_sql("SELECT 1 AS id, 2 AS id", &[], 0, 0).unwrap_err();
        assert!(error.message().contains("unique"), "{}", error.message());
    }

    #[test]
    fn null_rows_still_charge_memory() {
        let sql =
            "WITH RECURSIVE t(n) AS (SELECT NULL UNION ALL SELECT NULL FROM t) SELECT n FROM t";
        let error = execute_sql(sql, &[], 2048, 5_000).unwrap_err();
        assert_eq!(error.message(), BUDGET_MEMORY);
    }

    #[test]
    fn dataset_column_names_are_quoted() {
        let rows = vec![HashMap::from([("customer-id".into(), "c1".into())])];
        let out = execute_sql(
            "SELECT \"customer-id\" AS id FROM input",
            &[table("input", rows, vec!["customer-id".into()])],
            0,
            0,
        )
        .unwrap();
        assert_eq!(out[0].get("id").map(String::as_str), Some("c1"));
    }

    #[test]
    fn over_budget_select_list_names_memory() {
        let error = execute_sql(
            "SELECT printf('%8000s','a') AS a, printf('%8000s','b') AS b, printf('%8000s','c') AS c",
            &[],
            12 * 1024,
            5_000,
        )
        .unwrap_err();
        assert_eq!(error.message(), BUDGET_MEMORY);
    }

    #[test]
    fn over_budget_sort_names_memory() {
        let rows: Vec<HashMap<String, String>> = (0..80)
            .map(|i| HashMap::from([("id".into(), format!("{i:04}"))]))
            .collect();
        let error = execute_sql(
            "SELECT a.id AS a, b.id AS b FROM input a CROSS JOIN input b ORDER BY a.id, b.id",
            &[table("input", rows, vec!["id".into()])],
            16 * 1024,
            5_000,
        )
        .unwrap_err();
        assert_eq!(error.message(), BUDGET_MEMORY);
    }

    #[test]
    fn empty_input_keeps_declared_columns() {
        let sql = compile_steps_sql(
            &[TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: "yes".into(),
                columns: Vec::new(),
            }],
            "input",
        )
        .unwrap();
        let out = execute_sql(
            &sql,
            &[table("input", Vec::new(), vec!["id".into(), "keep".into()])],
            0,
            0,
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn join_sql_is_not_row_local() {
        assert!(sql_is_row_local("SELECT * FROM input WHERE keep = 'yes'"));
        assert!(!sql_is_row_local(
            "SELECT c.region, COUNT(*) FROM orders o JOIN customers c ON o.customer_id = c.id GROUP BY c.region"
        ));
    }
}
