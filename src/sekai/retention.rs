use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const AUDIT_DATASET: &str = "audit";
pub const LLM_CALLS_DATASET: &str = "llm_calls";
pub const TASK_OBSERVATIONS_DATASET: &str = "task_observations";

const DAY_MS: i64 = 86_400_000;
const RETENTION_TOMBSTONE_CONTEXT: &str = r#"{"retention_tombstone":"true"}"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub dataset: String,
    pub namespace: String,
    pub data_class: String,
    pub retention_days: i32,
    pub updated: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionRun {
    pub audit_deleted: i32,
    pub llm_calls_deleted: i32,
    pub task_observations_deleted: i32,
    pub task_observations_redacted: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArchiveRun {
    pub batch_id: String,
    pub content_hash: String,
    pub audit_archived: i32,
    pub llm_calls_archived: i32,
    pub task_observations_archived: i32,
    pub task_observations_redacted: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArchiveVerification {
    pub ok: bool,
    pub records_checked: i64,
    pub batches_checked: i64,
    pub error: String,
}

#[derive(Debug, Clone)]
struct ArchiveRecord {
    dataset: &'static str,
    source_key: String,
    payload: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn archive_record_hash(record: &ArchiveRecord) -> String {
    archive_payload_hash(record.dataset, &record.source_key, &record.payload)
}

fn archive_payload_hash(dataset: &str, source_key: &str, payload: &str) -> String {
    sha256_hex(
        serde_json::to_string(&(dataset, source_key, payload))
            .unwrap_or_default()
            .as_bytes(),
    )
}

fn redact_retained_task_observation(tx: &Transaction<'_>, rowid: i64) -> Result<usize, String> {
    tx.execute(
        "UPDATE sekai_task_observations
         SET request_id='retention-tombstone:' || rowid,
             namespace='',data_class='unclassified',model='[redacted]',
             packages_json='[]',context_json=?1
         WHERE rowid=?2",
        params![RETENTION_TOMBSTONE_CONTEXT, rowid],
    )
    .map_err(|e| e.to_string())
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn resolved_path(path: &Path) -> Result<PathBuf, String> {
    if path.exists() {
        return path.canonicalize().map_err(|e| e.to_string());
    }
    let parent = parent_dir(path);
    let name = path
        .file_name()
        .ok_or_else(|| "archive path must name a file".to_string())?;
    Ok(parent.canonicalize().map_err(|e| e.to_string())?.join(name))
}

fn same_file(left: &Path, right: &Path) -> Result<bool, String> {
    if resolved_path(left)? == resolved_path(right)? {
        return Ok(true);
    }
    if left.exists() && right.exists() {
        return same_file::is_same_file(left, right).map_err(|e| e.to_string());
    }
    Ok(false)
}

fn belongs_to_database(database: &Path, candidate: &Path) -> Result<bool, String> {
    if same_file(database, candidate)? {
        return Ok(true);
    }
    let database = database.as_os_str().to_string_lossy();
    for suffix in ["-wal", "-shm", "-journal"] {
        if same_file(Path::new(&format!("{database}{suffix}")), candidate)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn open_archive(path: &Path) -> Result<Connection, String> {
    if path.as_os_str().is_empty() || path == Path::new(":memory:") {
        return Err("archive path must be a persistent SQLite file".into());
    }
    let parent = parent_dir(path);
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    if !path.exists() {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if let Err(error) = options.open(path)
            && error.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(error.to_string());
        }
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::from_bits_retain(rusqlite::ffi::SQLITE_OPEN_NOFOLLOW);
    let conn = Connection::open_with_flags(path, flags).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| e.to_string())?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS archive_records (
            dataset TEXT NOT NULL,
            source_key TEXT NOT NULL,
            payload TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            archived_at INTEGER NOT NULL,
            PRIMARY KEY (dataset, source_key)
         );
         CREATE TABLE IF NOT EXISTS archive_batches (
            id TEXT PRIMARY KEY,
            cutoff INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            record_count INTEGER NOT NULL,
            created INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS archive_batch_records (
            batch_id TEXT NOT NULL,
            dataset TEXT NOT NULL,
            source_key TEXT NOT NULL,
            PRIMARY KEY (batch_id, dataset, source_key),
            FOREIGN KEY (batch_id) REFERENCES archive_batches(id),
            FOREIGN KEY (dataset, source_key) REFERENCES archive_records(dataset, source_key)
         );",
    )
    .map_err(|e| e.to_string())?;
    Ok(conn)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectErasureRequest {
    pub subject_kind: String,
    pub subject: String,
    pub requested_by: String,
    pub reason: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubjectErasureResult {
    pub subject_hash: String,
    pub llm_calls_deleted: i32,
    pub audit_tombstoned: i32,
    pub attestations_deleted: i32,
    pub object_changes_tombstoned: i32,
    pub objects_deleted: i32,
    pub objects_tombstoned: i32,
    pub links_deleted: i32,
    pub work_units_deleted: i32,
    pub work_unit_references_tombstoned: i32,
    pub work_unit_text_tombstoned: i32,
    pub grants_deleted: i32,
    pub credentials_deleted: i32,
    pub object_sets_deleted: i32,
    pub contention_scopes_tombstoned: i32,
    pub coordination_references_tombstoned: i32,
    pub coordination_text_tombstoned: i32,
    pub task_observations_deleted: i32,
    pub budget_records_deleted: i32,
}

fn subject_keys(kind: &str) -> &'static [&'static str] {
    match kind {
        "agent" => &["agent"],
        "user" => &["user", "user_id"],
        "work_unit" => &["work_unit", "work_unit_id"],
        _ => &[],
    }
}

fn map_matches_subject(
    values: &std::collections::HashMap<String, String>,
    kind: &str,
    subject: &str,
) -> bool {
    values
        .iter()
        .any(|(key, value)| keyed_value_matches_subject(key, value, kind, subject))
}

fn is_identifier_char(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '-' | '.' | ':' | '@' | '/' | '#')
}

fn contains_identifier(text: &str, subject: &str) -> bool {
    text.match_indices(subject).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + subject.len()..].chars().next();
        before.is_none_or(|character| !is_identifier_char(character))
            && after.is_none_or(|character| !is_identifier_char(character))
    })
}

fn contains_delimited_identifier(text: &str, subject: &str) -> bool {
    text.match_indices(subject).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + subject.len()..].chars().next();
        before.is_none_or(|character| !character.is_alphanumeric() && character != '_')
            && after.is_none_or(|character| !character.is_alphanumeric() && character != '_')
    })
}

fn contains_key_identifier(text: &str, subject: &str) -> bool {
    text.match_indices(subject).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + subject.len()..].chars().next();
        before.is_none_or(|character| !character.is_alphanumeric())
            && after.is_none_or(|character| !character.is_alphanumeric())
    })
}

fn key_matches_subject(key: &str, kind: &str, subject: &str) -> bool {
    const GENERIC_METADATA_KEYS: &[&str] = &[
        "id",
        "user",
        "user_id",
        "agent",
        "agent_id",
        "owner",
        "subject",
        "requester",
        "requested_by",
        "work_unit",
        "work_unit_id",
    ];
    // A raw identifier that is also a schema word is not attributable from a key alone.
    // Typed keys and matching values remain authoritative for those subjects.
    contains_typed_subject(key, kind, subject)
        || (!GENERIC_METADATA_KEYS.contains(&subject) && contains_key_identifier(key, subject))
}

fn contains_typed_subject(text: &str, kind: &str, subject: &str) -> bool {
    let labels: &[&str] = match kind {
        "agent" => &["agent"],
        "user" => &["user", "user_id"],
        "work_unit" => &["work_unit", "work_unit_id", "work-unit"],
        _ => &[],
    };
    labels.iter().any(|label| {
        let pattern = format!("{label}:{subject}");
        text.match_indices(&pattern).any(|(start, _)| {
            let before = text[..start].chars().next_back();
            if before.is_some_and(|character| {
                character.is_alphanumeric() || matches!(character, '_' | '-' | '.' | '@')
            }) {
                return false;
            }
            let remainder = &text[start + pattern.len()..];
            let Some(after) = remainder.chars().next() else {
                return true;
            };
            if after.is_alphanumeric() || matches!(after, '_' | '-' | '.' | '@') {
                return false;
            }
            if after == '/' {
                return kind == "agent"
                    && (remainder.starts_with("/work_unit:")
                        || remainder.starts_with("/work_unit_id:")
                        || remainder.starts_with("/work-unit:"));
            }
            if after == ':' {
                return remainder[1..].chars().next().is_none_or(|character| {
                    character.is_whitespace()
                        || matches!(character, '"' | '\'' | ',' | ';' | ')' | ']' | '}')
                });
            }
            true
        })
    })
}

fn contains_subject_reference(text: &str, kind: &str, subject: &str) -> bool {
    text != subject
        && (contains_typed_subject(text, kind, subject)
            || if subject.chars().any(|character| !character.is_alphabetic()) {
                contains_identifier(text, subject)
            } else {
                let mut labels = subject_keys(kind).to_vec();
                labels.extend(["owner", "subject", "requester", "requested_by"]);
                let mut phrases = vec!["for", "by", "owner", "subject"];
                phrases.extend(subject_keys(kind));
                phrases
                    .iter()
                    .any(|prefix| contains_identifier(text, &format!("{prefix} {subject}")))
                    || labels.iter().any(|label| {
                        [
                            format!("{label}={subject}"),
                            format!("{label}: {subject}"),
                            format!(r#""{label}":"{subject}""#),
                            format!(r#""{label}": "{subject}""#),
                        ]
                        .iter()
                        .any(|pattern| contains_identifier(text, pattern))
                    })
            })
}

fn keyed_value_matches_subject(key: &str, value: &str, kind: &str, subject: &str) -> bool {
    let key = key.rsplit('.').next().unwrap_or(key);
    let key_base = key.strip_suffix("_id").unwrap_or(key);
    (subject_keys(kind).contains(&key)
        || subject_keys(kind).contains(&key_base)
        || matches!(
            key_base,
            "owner"
                | "owner_principal"
                | "creator_principal"
                | "principal"
                | "actor"
                | "changed_by"
                | "subject"
                | "requester"
                | "requested_by"
                | "lease_owner"
        ))
        && (value == subject || contains_subject_reference(value, kind, subject))
}

fn principal_matches_subject(principal: &str, kind: &str, subject: &str) -> bool {
    principal == subject || contains_typed_subject(principal, kind, subject)
}

fn json_matches_subject(value: &serde_json::Value, kind: &str, subject: &str) -> bool {
    match value {
        serde_json::Value::Object(values) => {
            let keyed_filter = values
                .get("key")
                .and_then(serde_json::Value::as_str)
                .zip(values.get("value").and_then(serde_json::Value::as_str))
                .is_some_and(|(key, value)| {
                    if values
                        .get("op")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|op| op == "in")
                    {
                        value.split(',').any(|candidate| {
                            keyed_value_matches_subject(key, candidate.trim(), kind, subject)
                        })
                    } else {
                        keyed_value_matches_subject(key, value, kind, subject)
                    }
                });
            let typed_object = values
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value_kind| value_kind == kind)
                && ["name", "id", "external_id", "subject"].iter().any(|key| {
                    values
                        .get(*key)
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| value == subject)
                });
            keyed_filter
                || typed_object
                || values.iter().any(|(key, value)| {
                    value
                        .as_str()
                        .is_some_and(|value| keyed_value_matches_subject(key, value, kind, subject))
                        || json_matches_subject(value, kind, subject)
                })
        }
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| json_matches_subject(value, kind, subject)),
        serde_json::Value::String(value) => contains_subject_reference(value, kind, subject),
        _ => false,
    }
}

fn matching_principal_rows(
    tx: &Transaction<'_>,
    table: &str,
    column: &str,
    kind: &str,
    subject: &str,
) -> Result<Vec<i64>, String> {
    let mut stmt = tx
        .prepare(&format!("SELECT rowid, {column} FROM {table}"))
        .map_err(|e| e.to_string())?;
    stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })
    .map_err(|e| e.to_string())?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| e.to_string())
    .map(|rows| {
        rows.into_iter()
            .filter_map(|(rowid, principal)| {
                principal_matches_subject(&principal, kind, subject).then_some(rowid)
            })
            .collect()
    })
}

fn find_subject_object_ids(
    tx: &Transaction<'_>,
    kind: &str,
    subject: &str,
) -> Result<Vec<String>, String> {
    let mut stmt = tx
        .prepare("SELECT id, kind, name, external_id FROM sekai_objects")
        .map_err(|e| e.to_string())?;
    stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })
    .map_err(|e| e.to_string())?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| e.to_string())
    .map(|objects| {
        objects
            .into_iter()
            .filter_map(|(id, object_kind, name, external_id)| {
                let id_matches = id == subject || contains_typed_subject(&id, kind, subject);
                let external_id_matches =
                    external_id == subject || contains_typed_subject(&external_id, kind, subject);
                (id == subject
                    || (object_kind == kind
                        && (id_matches
                            || name == subject
                            || name == format!("{kind}:{subject}")
                            || external_id_matches)))
                    .then_some(id)
            })
            .collect()
    })
}

fn find_subject_related_object_ids(
    tx: &Transaction<'_>,
    kind: &str,
    subject: &str,
    subject_object_ids: &[String],
) -> Result<Vec<String>, String> {
    let mut stmt = tx
        .prepare("SELECT id, kind, properties FROM sekai_objects")
        .map_err(|e| e.to_string())?;
    stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })
    .map_err(|e| e.to_string())?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| e.to_string())
    .map(|objects| {
        let mut related_ids = subject_object_ids.to_vec();
        for (id, object_kind, _) in &objects {
            let id_matches = id == subject
                || contains_typed_subject(id, kind, subject)
                || (object_kind != kind && contains_delimited_identifier(id, subject));
            if id_matches && !related_ids.contains(id) {
                related_ids.push(id.clone());
            }
        }
        loop {
            let mut discovered = Vec::new();
            for (id, object_kind, properties_json) in &objects {
                if related_ids.contains(id)
                    || object_kind != crate::sekai::action_approval::ACTION_APPROVAL_KIND
                {
                    continue;
                }
                let approval_matches = serde_json::from_str::<
                    std::collections::HashMap<String, String>,
                >(properties_json)
                .unwrap_or_default()
                .iter()
                .any(|(key, value)| {
                    keyed_value_matches_subject(key, value, kind, subject)
                        || contains_subject_reference(value, kind, subject)
                        || serde_json::from_str::<serde_json::Value>(value)
                            .ok()
                            .is_some_and(|json| json_matches_subject(&json, kind, subject))
                        || related_ids.iter().any(|object_id| {
                            contains_identifier(value, object_id)
                                || serde_json::from_str::<serde_json::Value>(value)
                                    .ok()
                                    .is_some_and(|json| {
                                        json_matches_subject(&json, kind, object_id)
                                    })
                        })
                });
                if approval_matches {
                    discovered.push(id.clone());
                }
            }
            if discovered.is_empty() {
                return related_ids;
            }
            related_ids.extend(discovered);
        }
    })
}

fn opaque_erasure_id() -> String {
    format!("erasure:{}", uuid::Uuid::new_v4().simple())
}

fn audit_matches_subject(decision: &Decision, kind: &str, subject: &str) -> bool {
    (matches!(kind, "agent" | "user")
        && (decision.actor == subject || decision.actor == format!("{kind}:{subject}")))
        || contains_subject_reference(&decision.actor, kind, subject)
        || (kind == "work_unit" && decision.target_id == subject)
        || map_matches_subject(&decision.evidence, kind, subject)
        || contains_subject_reference(&decision.action, kind, subject)
        || contains_subject_reference(&decision.reason, kind, subject)
        || contains_subject_reference(&decision.outcome, kind, subject)
        || contains_subject_reference(&decision.target_id, kind, subject)
        || decision
            .evidence
            .values()
            .any(|value| contains_subject_reference(value, kind, subject))
}

fn audit_contains_identifier(decision: &Decision, identifier: &str) -> bool {
    [
        decision.actor.as_str(),
        decision.action.as_str(),
        decision.reason.as_str(),
        decision.target_id.as_str(),
        decision.outcome.as_str(),
    ]
    .iter()
    .any(|value| contains_identifier(value, identifier))
        || decision.evidence.iter().any(|(key, value)| {
            contains_identifier(key, identifier) || contains_identifier(value, identifier)
        })
}

fn verify_decisions_in_transaction(tx: &Transaction<'_>) -> Result<(), String> {
    let (anchor_seq, anchor_hash) = tx
        .query_row(
            "SELECT seq, entry_hash FROM sekai_ledger_anchors ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .unwrap_or((0, String::new()));
    let forged: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM sekai_decisions WHERE seq <= ?1",
            params![anchor_seq],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if forged > 0 {
        return Err("audit ledger contains rows below its purge anchor".into());
    }
    let incomplete: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM sekai_decisions
             WHERE seq IS NULL OR prev_hash IS NULL OR entry_hash IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if incomplete > 0 {
        return Err("audit ledger contains incomplete chain metadata".into());
    }
    let rows = {
        let mut stmt = tx
            .prepare(
                "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome,
                        seq,prev_hash,entry_hash,namespace,data_class
                 FROM sekai_decisions WHERE seq > ?1 ORDER BY seq",
            )
            .map_err(|e| e.to_string())?;
        stmt.query_map(params![anchor_seq], |row| {
            let evidence_json: String = row.get(5)?;
            Ok((
                Decision {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    reason: row.get(4)?,
                    evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
                    target_id: row.get(6)?,
                    outcome: row.get(7)?,
                },
                evidence_json,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?
    };
    let mut expected_seq = anchor_seq;
    let mut expected_prev = anchor_hash;
    for (decision, evidence_json, seq, prev_hash, stored_hash, namespace, data_class) in rows {
        if seq != expected_seq + 1 || prev_hash != expected_prev {
            return Err(format!("audit ledger linkage invalid at seq {seq}"));
        }
        let expected_hash =
            crate::sekai::ledger::entry_hash(seq, &prev_hash, &decision, &evidence_json);
        if stored_hash != expected_hash {
            return Err(format!("audit ledger hash invalid at seq {seq}"));
        }
        let expected = crate::sekai::ledger::lifecycle_scope_from_evidence(&decision.evidence);
        if (namespace, data_class) != expected {
            return Err(format!(
                "audit lifecycle classification invalid at seq {seq}"
            ));
        }
        expected_seq = seq;
        expected_prev = stored_hash;
    }
    Ok(())
}

fn rechain_decisions(tx: &Transaction<'_>) -> Result<(i64, String), String> {
    let (anchor_seq, anchor_hash) = tx
        .query_row(
            "SELECT seq, entry_hash FROM sekai_ledger_anchors ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .unwrap_or((0, String::new()));
    let decisions = {
        let mut stmt = tx
            .prepare(
                "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome,seq
                 FROM sekai_decisions WHERE seq > ?1 ORDER BY seq",
            )
            .map_err(|e| e.to_string())?;
        stmt.query_map(params![anchor_seq], |row| {
            let evidence_json: String = row.get(5)?;
            Ok((
                Decision {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    reason: row.get(4)?,
                    evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
                    target_id: row.get(6)?,
                    outcome: row.get(7)?,
                },
                evidence_json,
                row.get::<_, i64>(8)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?
    };
    let mut prev_hash = anchor_hash;
    let mut head_seq = anchor_seq;
    for (decision, evidence_json, seq) in decisions {
        let hash = crate::sekai::ledger::entry_hash(seq, &prev_hash, &decision, &evidence_json);
        tx.execute(
            "UPDATE sekai_decisions SET prev_hash = ?1, entry_hash = ?2 WHERE seq = ?3",
            params![prev_hash, hash, seq],
        )
        .map_err(|e| e.to_string())?;
        prev_hash = hash;
        head_seq = seq;
    }
    Ok((head_seq, prev_hash))
}

fn expired_audit_prefix(
    tx: &Transaction<'_>,
    policies: &[RetentionPolicy],
    now: i64,
) -> Result<Option<i64>, String> {
    let rows = {
        let mut stmt = tx
            .prepare("SELECT seq,timestamp,namespace,data_class FROM sekai_decisions ORDER BY seq")
            .map_err(|e| e.to_string())?;
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?
    };
    let mut prefix_end = None;
    for (seq, timestamp, namespace, data_class) in rows {
        let Some(policy) = effective_policy(policies, AUDIT_DATASET, &namespace, &data_class)
        else {
            break;
        };
        if timestamp >= now - i64::from(policy.retention_days) * DAY_MS {
            break;
        }
        prefix_end = Some(seq);
    }
    Ok(prefix_end)
}

fn validate_policy(policy: &RetentionPolicy) -> Result<(), String> {
    if !matches!(
        policy.dataset.as_str(),
        AUDIT_DATASET | LLM_CALLS_DATASET | TASK_OBSERVATIONS_DATASET
    ) {
        return Err("dataset must be audit, llm_calls, or task_observations".into());
    }
    if policy.retention_days <= 0 {
        return Err("retention_days must be positive".into());
    }
    Ok(())
}

fn effective_policy<'a>(
    policies: &'a [RetentionPolicy],
    dataset: &str,
    namespace: &str,
    data_class: &str,
) -> Option<&'a RetentionPolicy> {
    policies
        .iter()
        .filter(|policy| {
            policy.dataset == dataset
                && (policy.namespace.is_empty() || policy.namespace == namespace)
                && (policy.data_class.is_empty() || policy.data_class == data_class)
        })
        .max_by_key(|policy| {
            (
                u8::from(!policy.namespace.is_empty()) + u8::from(!policy.data_class.is_empty()),
                std::cmp::Reverse(policy.retention_days),
            )
        })
}

impl SekaiDb {
    pub(crate) fn migrate_retention(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_retention_policies (
                dataset TEXT NOT NULL,
                namespace TEXT NOT NULL DEFAULT '',
                data_class TEXT NOT NULL DEFAULT '',
                retention_days INTEGER NOT NULL,
                updated INTEGER NOT NULL,
                PRIMARY KEY (dataset, namespace, data_class)
            );",
        )
        .map_err(|e| e.to_string())?;
        let now = chrono::Utc::now().timestamp_millis();
        for (dataset, days) in [
            (AUDIT_DATASET, 365),
            (LLM_CALLS_DATASET, 90),
            (TASK_OBSERVATIONS_DATASET, 90),
        ] {
            conn.execute(
                "INSERT OR IGNORE INTO sekai_retention_policies
                 (dataset, namespace, data_class, retention_days, updated)
                 VALUES (?1, '', '', ?2, ?3)",
                params![dataset, days, now],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String> {
        validate_policy(policy)?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_retention_policies
             (dataset, namespace, data_class, retention_days, updated)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(dataset, namespace, data_class) DO UPDATE SET
               retention_days=excluded.retention_days, updated=excluded.updated",
            params![
                policy.dataset,
                policy.namespace,
                policy.data_class,
                policy.retention_days,
                policy.updated
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT dataset, namespace, data_class, retention_days, updated
                 FROM sekai_retention_policies
                 ORDER BY dataset, namespace, data_class",
            )
            .map_err(|e| e.to_string())?;
        stmt.query_map([], |row| {
            Ok(RetentionPolicy {
                dataset: row.get(0)?,
                namespace: row.get(1)?,
                data_class: row.get(2)?,
                retention_days: row.get(3)?,
                updated: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
    }

    pub fn erase_subject(
        &self,
        request: &SubjectErasureRequest,
    ) -> Result<SubjectErasureResult, String> {
        if !matches!(
            request.subject_kind.as_str(),
            "agent" | "user" | "work_unit"
        ) {
            return Err("subject_kind must be agent, user, or work_unit".into());
        }
        if request.subject.trim().is_empty() {
            return Err("subject must not be empty".into());
        }
        if request.requested_by.trim().is_empty() {
            return Err("requested_by must not be empty".into());
        }
        let subject_hash = opaque_erasure_id();
        let mut result = SubjectErasureResult {
            subject_hash: subject_hash.clone(),
            ..Default::default()
        };
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        verify_decisions_in_transaction(&tx)?;
        let known_subject_object_ids =
            find_subject_object_ids(&tx, &request.subject_kind, &request.subject)?;
        let subject_object_ids = find_subject_related_object_ids(
            &tx,
            &request.subject_kind,
            &request.subject,
            &known_subject_object_ids,
        )?;

        let usage_rows = {
            let mut stmt = tx
                .prepare("SELECT id, data FROM sekai_dataset_rows WHERE dataset_id = 'llm_calls'")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (id, data) in usage_rows {
            let values: std::collections::HashMap<String, String> =
                serde_json::from_str(&data).unwrap_or_default();
            if map_matches_subject(&values, &request.subject_kind, &request.subject)
                || values.iter().any(|(key, value)| {
                    key_matches_subject(key, &request.subject_kind, &request.subject)
                        || contains_subject_reference(
                            value,
                            &request.subject_kind,
                            &request.subject,
                        )
                        || subject_object_ids.iter().any(|object_id| {
                            contains_identifier(value, object_id)
                                || contains_key_identifier(key, object_id)
                        })
                })
            {
                result.llm_calls_deleted += tx
                    .execute("DELETE FROM sekai_dataset_rows WHERE id = ?1", params![id])
                    .map_err(|e| e.to_string())? as i32;
            }
        }

        let matching_virtual_tables = {
            let mut stmt = tx
                .prepare(
                    "SELECT rowid,id,name,dataset_id,filters,columns
                     FROM sekai_virtual_tables",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(
                |(rowid, id, name, dataset_id, filters_json, columns_json)| {
                    let filters =
                        serde_json::from_str::<Vec<(String, String, String)>>(&filters_json)
                            .unwrap_or_default();
                    let filter_matches = filters.iter().any(|(column, op, value)| {
                        let candidate_matches = |candidate: &str| {
                            keyed_value_matches_subject(
                                column,
                                candidate,
                                &request.subject_kind,
                                &request.subject,
                            ) || subject_object_ids.iter().any(|object_id| {
                                candidate == object_id || contains_identifier(candidate, object_id)
                            })
                        };
                        if op == "in" {
                            value
                                .split(',')
                                .any(|candidate| candidate_matches(candidate.trim()))
                        } else {
                            candidate_matches(value)
                        }
                    });
                    let metadata_matches =
                        [id, name, dataset_id, columns_json].iter().any(|value| {
                            value == &request.subject
                                || contains_subject_reference(
                                    value,
                                    &request.subject_kind,
                                    &request.subject,
                                )
                                || subject_object_ids.iter().any(|object_id| {
                                    value == object_id || contains_identifier(value, object_id)
                                })
                        });
                    (filter_matches || metadata_matches).then_some(rowid)
                },
            )
            .collect::<Vec<_>>()
        };
        for rowid in matching_virtual_tables {
            tx.execute(
                "DELETE FROM sekai_virtual_tables WHERE rowid=?1",
                params![rowid],
            )
            .map_err(|e| e.to_string())?;
        }

        let observations = {
            let mut stmt = tx
                .prepare(
                    "SELECT rowid, request_id, namespace, component_id, model, status,
                            packages_json, context_json
                     FROM sekai_task_observations",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (
            rowid,
            request_id,
            namespace,
            component_id,
            model,
            status,
            packages_json,
            context_json,
        ) in observations
        {
            let context: std::collections::HashMap<String, String> =
                serde_json::from_str(&context_json).unwrap_or_default();
            let metadata_matches = [
                request_id.as_str(),
                namespace.as_str(),
                component_id.as_str(),
                model.as_str(),
                status.as_str(),
                packages_json.as_str(),
            ]
            .iter()
            .any(|value| {
                contains_subject_reference(value, &request.subject_kind, &request.subject)
                    || subject_object_ids
                        .iter()
                        .any(|object_id| contains_identifier(value, object_id))
            }) || serde_json::from_str::<serde_json::Value>(&packages_json)
                .ok()
                .is_some_and(|json| {
                    json_matches_subject(&json, &request.subject_kind, &request.subject)
                        || subject_object_ids.iter().any(|object_id| {
                            json_matches_subject(&json, &request.subject_kind, object_id)
                        })
                });
            if metadata_matches
                || map_matches_subject(&context, &request.subject_kind, &request.subject)
                || context.iter().any(|(key, value)| {
                    key_matches_subject(key, &request.subject_kind, &request.subject)
                        || contains_subject_reference(
                            value,
                            &request.subject_kind,
                            &request.subject,
                        )
                        || subject_object_ids.iter().any(|object_id| {
                            contains_identifier(value, object_id)
                                || contains_key_identifier(key, object_id)
                        })
                })
                || (request.subject_kind == "work_unit" && request_id == request.subject)
            {
                result.task_observations_deleted +=
                    tx.execute(
                        "DELETE FROM sekai_task_observations WHERE rowid = ?1",
                        params![rowid],
                    )
                    .map_err(|e| e.to_string())? as i32;
            }
        }

        let matching_budget_attributions = {
            let mut stmt = tx
                .prepare(
                    "SELECT rowid, source_scope_id, applied_scope_id, metric,
                            period_start, amount_used
                     FROM chisei_budget_attributions",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|(_, source_scope_id, _, _, _, _)| {
                principal_matches_subject(source_scope_id, &request.subject_kind, &request.subject)
            })
            .collect::<Vec<_>>()
        };
        for (_, _, applied_scope, metric, period_start, amount_used) in
            &matching_budget_attributions
        {
            tx.execute(
                "UPDATE chisei_budget_usage
                 SET amount_used=MAX(0, amount_used-?1)
                 WHERE scope_id=?2 AND metric=?3 AND period_start=?4",
                params![amount_used, applied_scope, metric, period_start],
            )
            .map_err(|e| e.to_string())?;
        }
        for (rowid, _, _, _, _, _) in &matching_budget_attributions {
            result.budget_records_deleted += tx
                .execute(
                    "DELETE FROM chisei_budget_attributions WHERE rowid=?1",
                    params![rowid],
                )
                .map_err(|e| e.to_string())? as i32;
        }

        let matching_usage_rows = {
            let mut stmt = tx
                .prepare(
                    "SELECT rowid, scope_id, metric, period_start, amount_used
                     FROM chisei_budget_usage",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|(_, scope_id, _, _, _)| {
                principal_matches_subject(scope_id, &request.subject_kind, &request.subject)
            })
            .collect::<Vec<_>>()
        };
        let legacy_usage_rows = matching_usage_rows
            .iter()
            .filter(|(_, _, _, _, amount_used)| *amount_used > 0)
            .collect::<Vec<_>>();
        for (_, scope_id, metric, period_start, amount_used) in &legacy_usage_rows {
            let scoped_peer_total = legacy_usage_rows
                .iter()
                .filter(|(_, peer_scope, peer_metric, peer_period, _)| {
                    peer_metric == metric
                        && peer_period == period_start
                        && peer_scope.contains('/')
                        && crate::db::chisei_budget::scope_chain(peer_scope).contains(scope_id)
                })
                .map(|(_, _, _, _, peer_amount)| *peer_amount)
                .sum::<i64>();
            let reconciled_amount = if scope_id.contains('/') {
                *amount_used
            } else {
                (*amount_used - scoped_peer_total).max(0)
            };
            if reconciled_amount == 0 {
                continue;
            }
            let has_matching_parent = legacy_usage_rows.iter().any(
                |(_, parent_scope, parent_metric, parent_period, _)| {
                    parent_metric == metric
                        && parent_period == period_start
                        && parent_scope != scope_id
                        && scope_id.starts_with(&format!("{parent_scope}/"))
                },
            );
            if has_matching_parent {
                continue;
            }
            for ancestor in crate::db::chisei_budget::scope_chain(scope_id) {
                if ancestor == *scope_id
                    || matching_usage_rows
                        .iter()
                        .any(|(_, matching_scope, _, _, _)| matching_scope == &ancestor)
                {
                    continue;
                }
                tx.execute(
                    "UPDATE chisei_budget_usage
                     SET amount_used=MAX(0, amount_used-?1)
                     WHERE scope_id=?2 AND metric=?3 AND period_start=(
                       SELECT MAX(period_start) FROM chisei_budget_usage
                       WHERE scope_id=?2 AND metric=?3 AND period_start<=?4
                     )",
                    params![reconciled_amount, ancestor, metric, period_start],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        for (rowid, _, _, _, _) in matching_usage_rows {
            result.budget_records_deleted += tx
                .execute(
                    "DELETE FROM chisei_budget_usage WHERE rowid=?1",
                    params![rowid],
                )
                .map_err(|e| e.to_string())? as i32;
        }

        let matching_usage_events = {
            let mut stmt = tx
                .prepare("SELECT rowid,scope_id FROM chisei_budget_usage_events")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(|(rowid, scope_id)| {
                principal_matches_subject(&scope_id, &request.subject_kind, &request.subject)
                    .then_some(rowid)
            })
            .collect::<Vec<_>>()
        };
        for rowid in matching_usage_events {
            result.budget_records_deleted += tx
                .execute(
                    "DELETE FROM chisei_budget_usage_events WHERE rowid=?1",
                    params![rowid],
                )
                .map_err(|e| e.to_string())? as i32;
        }

        let matching_limit_rows = {
            let mut stmt = tx
                .prepare("SELECT rowid, scope_id FROM chisei_budget_limits")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(|(rowid, scope_id)| {
                principal_matches_subject(&scope_id, &request.subject_kind, &request.subject)
                    .then_some(rowid)
            })
            .collect::<Vec<_>>()
        };
        for rowid in matching_limit_rows {
            result.budget_records_deleted += tx
                .execute(
                    "DELETE FROM chisei_budget_limits WHERE rowid=?1",
                    params![rowid],
                )
                .map_err(|e| e.to_string())? as i32;
        }

        let work_unit_text = {
            let mut stmt = tx
                .prepare(
                    "SELECT id, requested_spec, failure_reason, cancel_reason
                     FROM sekai_work_units",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (id, requested_spec, failure_reason, cancel_reason) in work_unit_text {
            let matches_text = |text: &str| {
                contains_subject_reference(text, &request.subject_kind, &request.subject)
                    || subject_object_ids
                        .iter()
                        .any(|object_id| contains_identifier(text, object_id))
            };
            let requested_matches = matches_text(&requested_spec);
            let failure_matches = matches_text(&failure_reason);
            let cancel_matches = matches_text(&cancel_reason);
            if requested_matches || failure_matches || cancel_matches {
                result.work_unit_text_tombstoned +=
                    tx.execute(
                        "UPDATE sekai_work_units SET requested_spec=?1, failure_reason=?2,
                         cancel_reason=?3, updated_at=?4 WHERE id=?5",
                        params![
                            if requested_matches {
                                "[erased]"
                            } else {
                                &requested_spec
                            },
                            if failure_matches {
                                "[erased]"
                            } else {
                                &failure_reason
                            },
                            if cancel_matches {
                                "[erased]"
                            } else {
                                &cancel_reason
                            },
                            request.timestamp,
                            id
                        ],
                    )
                    .map_err(|e| e.to_string())? as i32;
            }
        }

        let work_unit_ids = {
            let mut stmt = tx
                .prepare(
                    "SELECT id, actor, owner_principal, creator_principal, target_object_id,
                            scope_id
                     FROM sekai_work_units",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(|(id, actor, owner, creator, target, scope_id)| {
                let matches = match request.subject_kind.as_str() {
                    "work_unit" => id == request.subject,
                    "agent" | "user" => {
                        [actor, owner, creator, target, scope_id]
                            .iter()
                            .any(|principal| {
                                principal_matches_subject(
                                    principal,
                                    &request.subject_kind,
                                    &request.subject,
                                )
                            })
                    }
                    _ => false,
                };
                matches.then_some(id)
            })
            .collect::<Vec<_>>()
        };
        for work_unit_id in work_unit_ids {
            let reservation_ids = {
                let mut stmt = tx
                    .prepare("SELECT id FROM sekai_reservations WHERE work_unit_id=?1")
                    .map_err(|e| e.to_string())?;
                stmt.query_map(params![work_unit_id], |row| row.get::<_, String>(0))
                    .map_err(|e| e.to_string())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?
            };
            tx.execute(
                "DELETE FROM sekai_coordination_requests WHERE work_unit_id=?1",
                params![work_unit_id],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "DELETE FROM sekai_reconciliations WHERE work_unit_id=?1",
                params![work_unit_id],
            )
            .map_err(|e| e.to_string())?;
            for reservation_id in reservation_ids {
                tx.execute(
                    "DELETE FROM sekai_reconciliations WHERE reservation_id=?1",
                    params![reservation_id],
                )
                .map_err(|e| e.to_string())?;
            }
            tx.execute(
                "DELETE FROM sekai_run_events WHERE work_unit_id=?1",
                params![work_unit_id],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "DELETE FROM sekai_reservations WHERE work_unit_id=?1",
                params![work_unit_id],
            )
            .map_err(|e| e.to_string())?;
            result.work_units_deleted += tx
                .execute(
                    "DELETE FROM sekai_work_units WHERE id=?1",
                    params![work_unit_id],
                )
                .map_err(|e| e.to_string())? as i32;
        }

        let matching_object_sets = {
            let mut stmt = tx
                .prepare(
                    "SELECT rowid, id, name, description, filter, owner_principal
                     FROM sekai_object_sets",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(|(rowid, id, name, description, filter, owner)| {
                let text_matches = [id, name, description].iter().any(|value| {
                    contains_subject_reference(value, &request.subject_kind, &request.subject)
                        || subject_object_ids
                            .iter()
                            .any(|object_id| contains_identifier(value, object_id))
                });
                let filter_matches = serde_json::from_str::<serde_json::Value>(&filter)
                    .ok()
                    .is_some_and(|json| {
                        json_matches_subject(&json, &request.subject_kind, &request.subject)
                            || subject_object_ids.iter().any(|object_id| {
                                json_matches_subject(&json, &request.subject_kind, object_id)
                            })
                    });
                ((matches!(request.subject_kind.as_str(), "agent" | "user")
                    && principal_matches_subject(&owner, &request.subject_kind, &request.subject))
                    || text_matches
                    || filter_matches)
                    .then_some(rowid)
            })
            .collect::<Vec<_>>()
        };
        for rowid in matching_object_sets {
            result.object_sets_deleted += tx
                .execute(
                    "DELETE FROM sekai_object_sets WHERE rowid=?1",
                    params![rowid],
                )
                .map_err(|e| e.to_string())? as i32;
        }

        if matches!(request.subject_kind.as_str(), "user" | "agent") {
            for (table, column) in [
                ("sekai_coordination_requests", "principal"),
                ("sekai_coordination_requests", "scope_id"),
                ("sekai_reservations", "lease_owner"),
            ] {
                for rowid in matching_principal_rows(
                    &tx,
                    table,
                    column,
                    &request.subject_kind,
                    &request.subject,
                )? {
                    result.coordination_references_tombstoned +=
                        tx.execute(
                            &format!("UPDATE {table} SET {column}='[erased]' WHERE rowid=?1"),
                            params![rowid],
                        )
                        .map_err(|e| e.to_string())? as i32;
                }
            }
            let scoped_reservations = {
                let mut stmt = tx
                    .prepare("SELECT rowid, id, scope_id FROM sekai_reservations")
                    .map_err(|e| e.to_string())?;
                stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|(_, _, scope_id)| {
                    principal_matches_subject(scope_id, &request.subject_kind, &request.subject)
                })
                .collect::<Vec<_>>()
            };
            for (rowid, reservation_id, _) in scoped_reservations {
                let replacement_id =
                    format!("erased-reservation:{}", uuid::Uuid::new_v4().simple());
                tx.execute(
                    "UPDATE sekai_reconciliations SET reservation_id=?1 WHERE reservation_id=?2",
                    params![replacement_id, reservation_id],
                )
                .map_err(|e| e.to_string())?;
                result.coordination_references_tombstoned +=
                    tx.execute(
                        "UPDATE sekai_reservations SET id=?1, scope_id='[erased]' WHERE rowid=?2",
                        params![replacement_id, rowid],
                    )
                    .map_err(|e| e.to_string())? as i32;
            }
            let previous_activity_epoch: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(value), 0) FROM (
                       SELECT created AS value FROM sekai_principal_credentials
                       UNION ALL SELECT rotated_at FROM sekai_principal_credentials
                       UNION ALL SELECT revoked_at FROM sekai_principal_credentials
                     )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            for rowid in matching_principal_rows(
                &tx,
                "sekai_grants",
                "principal",
                &request.subject_kind,
                &request.subject,
            )? {
                result.grants_deleted += tx
                    .execute("DELETE FROM sekai_grants WHERE rowid=?1", params![rowid])
                    .map_err(|e| e.to_string())? as i32;
            }
            for rowid in matching_principal_rows(
                &tx,
                "sekai_contention_scopes",
                "owner_principal",
                &request.subject_kind,
                &request.subject,
            )? {
                result.contention_scopes_tombstoned += tx.execute(
                    "UPDATE sekai_contention_scopes SET owner_principal='', updated=?2 WHERE rowid=?1",
                    params![rowid, request.timestamp],
                ).map_err(|e| e.to_string())? as i32;
            }
            for rowid in matching_principal_rows(
                &tx,
                "sekai_principal_credentials",
                "principal",
                &request.subject_kind,
                &request.subject,
            )? {
                result.credentials_deleted +=
                    tx.execute(
                        "DELETE FROM sekai_principal_credentials WHERE rowid=?1",
                        params![rowid],
                    )
                    .map_err(|e| e.to_string())? as i32;
            }
            if result.credentials_deleted > 0 {
                let marker_id = format!("credential-erasure-{}", uuid::Uuid::new_v4().simple());
                let marker_hash = format!("erasure-{}", uuid::Uuid::new_v4().simple());
                let activity_time = chrono::Utc::now()
                    .timestamp_millis()
                    .max(request.timestamp)
                    .max(previous_activity_epoch.saturating_add(1));
                tx.execute(
                    "INSERT INTO sekai_principal_credentials
                     (id,principal,token_hash,status,created,rotated_at,revoked_at)
                     VALUES (?1,'[erased]',?2,'revoked',?3,?3,?3)",
                    params![marker_id, marker_hash, activity_time],
                )
                .map_err(|e| e.to_string())?;
            }
        }

        let matches_coordination_text = |value: &str| {
            contains_subject_reference(value, &request.subject_kind, &request.subject)
                || subject_object_ids
                    .iter()
                    .any(|object_id| contains_identifier(value, object_id))
                || serde_json::from_str::<serde_json::Value>(value)
                    .ok()
                    .is_some_and(|json| {
                        json_matches_subject(&json, &request.subject_kind, &request.subject)
                            || subject_object_ids.iter().any(|object_id| {
                                json_matches_subject(&json, &request.subject_kind, object_id)
                            })
                    })
        };
        let run_event_text = {
            let mut stmt = tx
                .prepare("SELECT id, message, evidence_json FROM sekai_run_events")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (id, message, evidence_json) in run_event_text {
            let message_matches = matches_coordination_text(&message);
            let evidence_matches = matches_coordination_text(&evidence_json);
            if message_matches || evidence_matches {
                result.coordination_text_tombstoned +=
                    tx.execute(
                        "UPDATE sekai_run_events SET message=?1, evidence_json=?2 WHERE id=?3",
                        params![
                            if message_matches {
                                "[erased]"
                            } else {
                                &message
                            },
                            if evidence_matches {
                                r#"{"erasure_tombstone":true}"#
                            } else {
                                &evidence_json
                            },
                            id
                        ],
                    )
                    .map_err(|e| e.to_string())? as i32;
            }
        }
        let reconciliation_text = {
            let mut stmt = tx
                .prepare("SELECT id, reason, action FROM sekai_reconciliations")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (id, reason, action) in reconciliation_text {
            let reason_matches = matches_coordination_text(&reason);
            let action_matches = matches_coordination_text(&action);
            if reason_matches || action_matches {
                result.coordination_text_tombstoned +=
                    tx.execute(
                        "UPDATE sekai_reconciliations SET reason=?1, action=?2 WHERE id=?3",
                        params![
                            if reason_matches { "[erased]" } else { &reason },
                            if action_matches { "[erased]" } else { &action },
                            id
                        ],
                    )
                    .map_err(|e| e.to_string())? as i32;
            }
        }

        let objects = {
            let mut stmt = tx
                .prepare(
                    "SELECT id, kind, name, namespace, external_id, properties
                     FROM sekai_objects",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (id, kind, name, namespace, external_id, properties_json) in objects {
            let mut properties: std::collections::HashMap<String, String> =
                serde_json::from_str(&properties_json).unwrap_or_default();
            let id_matches = id == request.subject
                || contains_typed_subject(&id, &request.subject_kind, &request.subject)
                || (kind != request.subject_kind
                    && contains_delimited_identifier(&id, &request.subject));
            let external_id_matches = external_id == request.subject
                || contains_typed_subject(&external_id, &request.subject_kind, &request.subject)
                || (kind != request.subject_kind
                    && contains_delimited_identifier(&external_id, &request.subject));
            let approval_matches = kind == crate::sekai::action_approval::ACTION_APPROVAL_KIND
                && subject_object_ids.contains(&id);
            let represents_subject = approval_matches || known_subject_object_ids.contains(&id);
            if represents_subject {
                continue;
            }
            let mut object_id = id;
            if id_matches {
                let replacement_id = format!("erased-object:{}", uuid::Uuid::new_v4().simple());
                let link_ids = {
                    let mut stmt = tx
                        .prepare("SELECT id FROM sekai_links WHERE from_id=?1 OR to_id=?1")
                        .map_err(|e| e.to_string())?;
                    stmt.query_map(params![object_id], |row| row.get::<_, String>(0))
                        .map_err(|e| e.to_string())?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| e.to_string())?
                };
                for link_id in link_ids {
                    tx.execute(
                        "UPDATE sekai_links SET id=?1 WHERE id=?2",
                        params![
                            format!("erased-link:{}", uuid::Uuid::new_v4().simple()),
                            link_id
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                }
                for (table, column) in [
                    ("sekai_links", "from_id"),
                    ("sekai_links", "to_id"),
                    ("sekai_grants", "object_id"),
                    ("sekai_object_changes", "object_id"),
                    ("sekai_work_units", "target_object_id"),
                    ("sekai_datasets", "object_id"),
                ] {
                    tx.execute(
                        &format!("UPDATE {table} SET {column}=?1 WHERE {column}=?2"),
                        params![replacement_id, object_id],
                    )
                    .map_err(|e| e.to_string())?;
                }
                tx.execute(
                    "UPDATE sekai_objects SET id=?1 WHERE id=?2",
                    params![replacement_id, object_id],
                )
                .map_err(|e| e.to_string())?;
                object_id = replacement_id;
            }
            let mut changed = false;
            let mut redacted_properties = std::collections::HashMap::new();
            for (key, mut value) in properties {
                let key_matches =
                    key_matches_subject(&key, &request.subject_kind, &request.subject)
                        || subject_object_ids
                            .iter()
                            .any(|object_id| contains_key_identifier(&key, object_id));
                let value_matches = keyed_value_matches_subject(
                    &key,
                    &value,
                    &request.subject_kind,
                    &request.subject,
                ) || contains_subject_reference(
                    &value,
                    &request.subject_kind,
                    &request.subject,
                ) || subject_object_ids
                    .iter()
                    .any(|object_id| contains_identifier(&value, object_id));
                if value_matches {
                    value = "[erased]".into();
                    changed = true;
                }
                if key_matches {
                    redacted_properties.insert("[erased]".to_string(), value);
                    changed = true;
                } else {
                    redacted_properties.insert(key, value);
                }
            }
            properties = redacted_properties;
            let redacted_name =
                if contains_subject_reference(&name, &request.subject_kind, &request.subject) {
                    changed = true;
                    "[erased]"
                } else {
                    &name
                };
            let redacted_namespace = if contains_subject_reference(
                &namespace,
                &request.subject_kind,
                &request.subject,
            ) {
                changed = true;
                "[erased]"
            } else {
                &namespace
            };
            if external_id_matches {
                changed = true;
            }
            if changed {
                tx.execute(
                    "UPDATE sekai_objects SET name=?1, namespace=?2, external_id=?3,
                     properties=?4, updated=?5 WHERE id=?6",
                    params![
                        redacted_name,
                        redacted_namespace,
                        if external_id_matches {
                            "[erased]"
                        } else {
                            &external_id
                        },
                        serde_json::to_string(&properties).map_err(|e| e.to_string())?,
                        request.timestamp,
                        object_id
                    ],
                )
                .map_err(|e| e.to_string())?;
                result.objects_tombstoned += 1;
            } else if id_matches {
                result.objects_tombstoned += 1;
            }
        }
        let subject_link_ids = {
            let mut stmt = tx
                .prepare("SELECT id FROM sekai_links")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|link_id| {
                    contains_typed_subject(link_id, &request.subject_kind, &request.subject)
                        || contains_delimited_identifier(link_id, &request.subject)
                })
                .collect::<Vec<_>>()
        };
        for link_id in subject_link_ids {
            tx.execute(
                "UPDATE sekai_links SET id=?1 WHERE id=?2",
                params![
                    format!("erased-link:{}", uuid::Uuid::new_v4().simple()),
                    link_id
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        let deleted_subject_object_ids = subject_object_ids
            .iter()
            .filter(|object_id| {
                tx.query_row(
                    "SELECT 1 FROM sekai_objects WHERE id=?1",
                    params![object_id],
                    |_| Ok(()),
                )
                .optional()
                .ok()
                .flatten()
                .is_some()
            })
            .cloned()
            .collect::<Vec<_>>();
        for object_id in &deleted_subject_object_ids {
            tx.execute(
                "UPDATE sekai_datasets SET object_id='[erased]' WHERE object_id=?1",
                params![object_id],
            )
            .map_err(|e| e.to_string())?;
            result.work_unit_references_tombstoned +=
                tx.execute(
                    "UPDATE sekai_work_units SET target_object_id='[erased]',
                     updated_at=?2 WHERE target_object_id=?1",
                    params![object_id, request.timestamp],
                )
                .map_err(|e| e.to_string())? as i32;
            result.links_deleted += tx
                .execute(
                    "DELETE FROM sekai_links WHERE from_id=?1 OR to_id=?1",
                    params![object_id],
                )
                .map_err(|e| e.to_string())? as i32;
            result.grants_deleted += tx
                .execute(
                    "DELETE FROM sekai_grants WHERE object_id=?1",
                    params![object_id],
                )
                .map_err(|e| e.to_string())? as i32;
            result.objects_deleted += tx
                .execute("DELETE FROM sekai_objects WHERE id=?1", params![object_id])
                .map_err(|e| e.to_string())? as i32;
        }

        let decisions = {
            let mut stmt = tx
                .prepare(
                    "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome
                     FROM sekai_decisions ORDER BY seq",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                let evidence_json: String = row.get(5)?;
                Ok(Decision {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    reason: row.get(4)?,
                    evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
                    target_id: row.get(6)?,
                    outcome: row.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        let mut erased_decision_ids = Vec::new();
        for decision in decisions {
            let decision_id_matches = decision.id == request.subject
                || contains_typed_subject(&decision.id, &request.subject_kind, &request.subject)
                || contains_delimited_identifier(&decision.id, &request.subject)
                || subject_object_ids
                    .iter()
                    .any(|object_id| contains_key_identifier(&decision.id, object_id));
            if !audit_matches_subject(&decision, &request.subject_kind, &request.subject)
                && !decision_id_matches
                && !subject_object_ids.contains(&decision.target_id)
                && !subject_object_ids
                    .iter()
                    .any(|object_id| audit_contains_identifier(&decision, object_id))
            {
                continue;
            }
            let tombstone = std::collections::HashMap::from([
                ("erasure_tombstone".to_string(), "true".to_string()),
                ("subject_kind".to_string(), request.subject_kind.clone()),
                ("subject_hash".to_string(), subject_hash.clone()),
                ("erased_at".to_string(), request.timestamp.to_string()),
            ]);
            let original_id = decision.id;
            let replacement_id = if decision_id_matches {
                format!("erased-decision:{}", uuid::Uuid::new_v4().simple())
            } else {
                original_id.clone()
            };
            tx.execute(
                "UPDATE sekai_decisions SET id=?1, actor='[erased]', action='[erased]',
                 reason='subject content erased', evidence=?2,
                 target_id='[erased]', outcome='[erased]', namespace='',
                 data_class='unclassified' WHERE id=?3",
                params![
                    replacement_id,
                    serde_json::to_string(&tombstone).map_err(|e| e.to_string())?,
                    original_id
                ],
            )
            .map_err(|e| e.to_string())?;
            erased_decision_ids.push(original_id);
            result.audit_tombstoned += 1;
        }
        for decision_id in erased_decision_ids {
            result.attestations_deleted += tx
                .execute(
                    "DELETE FROM sekai_attestations WHERE decision_id = ?1",
                    params![decision_id],
                )
                .map_err(|e| e.to_string())? as i32;
        }

        let object_changes = {
            let mut stmt = tx
                .prepare(
                    "SELECT id, object_id, field, changed_by, old_value, new_value
                     FROM sekai_object_changes",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (id, object_id, field, changed_by, old_value, new_value) in object_changes {
            let object_matches =
                object_id == request.subject || subject_object_ids.contains(&object_id);
            let actor_matches =
                principal_matches_subject(&changed_by, &request.subject_kind, &request.subject);
            let field_matches =
                contains_typed_subject(&field, &request.subject_kind, &request.subject)
                    || contains_delimited_identifier(&field, &request.subject)
                    || subject_object_ids
                        .iter()
                        .any(|object_id| contains_delimited_identifier(&field, object_id));
            let identity_value_matches = |value: &str| match field.as_str() {
                "id" | "object_id" | "external_id" => {
                    contains_delimited_identifier(value, &request.subject)
                }
                "_created" | "_deleted" => value
                    .split_once('/')
                    .is_some_and(|(_, name)| contains_delimited_identifier(name, &request.subject)),
                _ => false,
            };
            let old_matches = object_matches
                || keyed_value_matches_subject(
                    &field,
                    &old_value,
                    &request.subject_kind,
                    &request.subject,
                )
                || contains_subject_reference(&old_value, &request.subject_kind, &request.subject)
                || identity_value_matches(&old_value)
                || subject_object_ids
                    .iter()
                    .any(|object_id| contains_identifier(&old_value, object_id));
            let new_matches = object_matches
                || keyed_value_matches_subject(
                    &field,
                    &new_value,
                    &request.subject_kind,
                    &request.subject,
                )
                || contains_subject_reference(&new_value, &request.subject_kind, &request.subject)
                || identity_value_matches(&new_value)
                || subject_object_ids
                    .iter()
                    .any(|object_id| contains_identifier(&new_value, object_id));
            if !(object_matches || actor_matches || field_matches || old_matches || new_matches) {
                continue;
            }
            tx.execute(
                "UPDATE sekai_object_changes SET object_id=?1, field=?2, changed_by=?3,
                 old_value=?4, new_value=?5 WHERE id=?6",
                params![
                    if object_matches {
                        "[erased]"
                    } else {
                        &object_id
                    },
                    if field_matches { "[erased]" } else { &field },
                    if actor_matches {
                        "[erased]"
                    } else {
                        &changed_by
                    },
                    if old_matches { "[erased]" } else { &old_value },
                    if new_matches { "[erased]" } else { &new_value },
                    id
                ],
            )
            .map_err(|e| e.to_string())?;
            result.object_changes_tombstoned += 1;
        }

        let (head_seq, head_hash) = if result.audit_tombstoned > 0 {
            rechain_decisions(&tx)?
        } else {
            crate::sekai::ledger::chain_head(&tx)?
        };
        let requester_hash = opaque_erasure_id();
        let event_evidence = std::collections::HashMap::from([
            ("subject_kind".to_string(), request.subject_kind.clone()),
            ("subject_hash".to_string(), subject_hash),
            (
                "llm_calls_deleted".to_string(),
                result.llm_calls_deleted.to_string(),
            ),
            (
                "audit_tombstoned".to_string(),
                result.audit_tombstoned.to_string(),
            ),
            (
                "object_changes_tombstoned".to_string(),
                result.object_changes_tombstoned.to_string(),
            ),
            (
                "objects_deleted".to_string(),
                result.objects_deleted.to_string(),
            ),
            (
                "objects_tombstoned".to_string(),
                result.objects_tombstoned.to_string(),
            ),
            (
                "links_deleted".to_string(),
                result.links_deleted.to_string(),
            ),
            (
                "work_units_deleted".to_string(),
                result.work_units_deleted.to_string(),
            ),
            (
                "work_unit_references_tombstoned".to_string(),
                result.work_unit_references_tombstoned.to_string(),
            ),
            (
                "work_unit_text_tombstoned".to_string(),
                result.work_unit_text_tombstoned.to_string(),
            ),
            (
                "grants_deleted".to_string(),
                result.grants_deleted.to_string(),
            ),
            (
                "credentials_deleted".to_string(),
                result.credentials_deleted.to_string(),
            ),
            (
                "object_sets_deleted".to_string(),
                result.object_sets_deleted.to_string(),
            ),
            (
                "contention_scopes_tombstoned".to_string(),
                result.contention_scopes_tombstoned.to_string(),
            ),
            (
                "coordination_references_tombstoned".to_string(),
                result.coordination_references_tombstoned.to_string(),
            ),
            (
                "coordination_text_tombstoned".to_string(),
                result.coordination_text_tombstoned.to_string(),
            ),
            (
                "task_observations_deleted".to_string(),
                result.task_observations_deleted.to_string(),
            ),
            (
                "budget_records_deleted".to_string(),
                result.budget_records_deleted.to_string(),
            ),
            ("requester_hash".to_string(), requester_hash),
        ]);
        let event = Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: request.timestamp,
            actor: "privacy.erasure".into(),
            action: "privacy.subject_erased".into(),
            reason: "subject erasure completed".into(),
            evidence: event_evidence,
            target_id: String::new(),
            outcome: "erased".into(),
        };
        let event_json = serde_json::to_string(&event.evidence).map_err(|e| e.to_string())?;
        let event_seq = head_seq + 1;
        let event_hash =
            crate::sekai::ledger::entry_hash(event_seq, &head_hash, &event, &event_json);
        tx.execute(
            "INSERT INTO sekai_decisions
             (id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                event.id,
                event.timestamp,
                event.actor,
                event.action,
                event.reason,
                event_json,
                event.target_id,
                event.outcome,
                event_seq,
                head_hash,
                event_hash
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(result)
    }

    fn purge_classified_audit_records(
        &self,
        policies: &[RetentionPolicy],
        now: i64,
    ) -> Result<i32, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        verify_decisions_in_transaction(&tx)?;
        let prefix_end = expired_audit_prefix(&tx, policies, now)?;
        let mut deleted = 0;
        if let Some(prefix_end) = prefix_end {
            let anchor_hash: String = tx
                .query_row(
                    "SELECT entry_hash FROM sekai_decisions WHERE seq=?1",
                    params![prefix_end],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            deleted += tx
                .execute(
                    "DELETE FROM sekai_attestations WHERE decision_id IN
                     (SELECT id FROM sekai_decisions WHERE seq <= ?1)",
                    params![prefix_end],
                )
                .map_err(|e| e.to_string())? as i32;
            deleted += tx
                .execute(
                    "DELETE FROM sekai_decisions WHERE seq <= ?1",
                    params![prefix_end],
                )
                .map_err(|e| e.to_string())? as i32;
            tx.execute(
                "INSERT OR REPLACE INTO sekai_ledger_anchors (seq,entry_hash,reason,created)
                 VALUES (?1,?2,?3,?4)",
                params![prefix_end, anchor_hash, "classified retention purge", now],
            )
            .map_err(|e| e.to_string())?;
        }
        if let Some(policy) = policies.iter().find(|policy| {
            policy.dataset == AUDIT_DATASET
                && policy.namespace.is_empty()
                && policy.data_class.is_empty()
        }) {
            deleted += tx
                .execute(
                    "DELETE FROM sekai_object_changes WHERE timestamp < ?1",
                    params![now - i64::from(policy.retention_days) * DAY_MS],
                )
                .map_err(|e| e.to_string())? as i32;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(deleted)
    }

    pub fn verify_archive(archive_path: impl AsRef<Path>) -> Result<ArchiveVerification, String> {
        let archive_path = archive_path.as_ref();
        if !archive_path.is_file() {
            return Err("archive file does not exist".into());
        }
        let archive = Connection::open(archive_path).map_err(|e| e.to_string())?;
        let mut verification = ArchiveVerification {
            ok: true,
            ..Default::default()
        };
        let records = {
            let mut stmt = archive
                .prepare(
                    "SELECT dataset,source_key,payload,payload_hash
                     FROM archive_records ORDER BY dataset,source_key",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (dataset, source_key, payload, stored_hash) in records {
            verification.records_checked += 1;
            if archive_payload_hash(&dataset, &source_key, &payload) != stored_hash {
                verification.ok = false;
                verification.error = format!("archive record {dataset}:{source_key} was altered");
                return Ok(verification);
            }
        }

        let broken_references: i64 = archive
            .query_row(
                "SELECT COUNT(*) FROM archive_batch_records link
                 LEFT JOIN archive_batches batch ON batch.id=link.batch_id
                 LEFT JOIN archive_records record
                   ON record.dataset=link.dataset AND record.source_key=link.source_key
                 WHERE batch.id IS NULL OR record.dataset IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if broken_references > 0 {
            verification.ok = false;
            verification.error = "archive contains broken manifest references".into();
            return Ok(verification);
        }
        let unbatched_records: i64 = archive
            .query_row(
                "SELECT COUNT(*) FROM archive_records r
                 WHERE NOT EXISTS (
                    SELECT 1 FROM archive_batch_records link
                    JOIN archive_batches batch ON batch.id=link.batch_id
                    WHERE link.dataset=r.dataset AND link.source_key=r.source_key
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if unbatched_records > 0 {
            verification.ok = false;
            verification.error = "archive contains records without a batch manifest".into();
            return Ok(verification);
        }

        let batches = {
            let mut stmt = archive
                .prepare("SELECT id,content_hash,record_count FROM archive_batches ORDER BY id")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        if batches.is_empty() {
            verification.ok = false;
            verification.error = "archive contains no batch manifests".into();
            return Ok(verification);
        }
        for (batch_id, stored_hash, record_count) in batches {
            verification.batches_checked += 1;
            let hashes = {
                let mut stmt = archive
                    .prepare(
                        "SELECT r.payload_hash FROM archive_batch_records b
                         JOIN archive_records r ON r.dataset=b.dataset AND r.source_key=b.source_key
                         WHERE b.batch_id=?1 ORDER BY b.dataset,b.source_key",
                    )
                    .map_err(|e| e.to_string())?;
                stmt.query_map(params![batch_id], |row| row.get::<_, String>(0))
                    .map_err(|e| e.to_string())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?
            };
            let computed_hash = sha256_hex(
                serde_json::to_string(&hashes)
                    .unwrap_or_default()
                    .as_bytes(),
            );
            if hashes.len() as i64 != record_count || computed_hash != stored_hash {
                verification.ok = false;
                verification.error = format!("archive batch {batch_id} manifest does not match");
                return Ok(verification);
            }
        }
        Ok(verification)
    }

    /// Move records outside their hot-store retention windows into a separate
    /// SQLite archive before deleting them from the operational database.
    /// Archive records are content-hashed and keyed by their stable source
    /// identity, making a retry after an interrupted hot-store commit safe.
    pub fn archive_retained_records(
        &self,
        archive_path: impl AsRef<Path>,
        now: i64,
    ) -> Result<ArchiveRun, String> {
        let archive_path = archive_path.as_ref();
        if archive_path.as_os_str().is_empty() || archive_path == Path::new(":memory:") {
            return Err("archive path must be a persistent SQLite file".into());
        }
        if std::fs::symlink_metadata(archive_path)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err("archive path must not be a symbolic link".into());
        }
        std::fs::create_dir_all(parent_dir(archive_path)).map_err(|e| e.to_string())?;
        let archive_resolved = resolved_path(archive_path)?;
        let policies = self.list_retention_policies()?;
        let mut conn = self.conn();
        let hot_path: String = conn
            .query_row(
                "SELECT file FROM pragma_database_list WHERE name = 'main'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !hot_path.is_empty() && belongs_to_database(Path::new(&hot_path), &archive_resolved)? {
            return Err("archive path must differ from the operational database".into());
        }

        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let audit_cutoff = policies
            .iter()
            .find(|policy| {
                policy.dataset == AUDIT_DATASET
                    && policy.namespace.is_empty()
                    && policy.data_class.is_empty()
            })
            .map(|policy| now - i64::from(policy.retention_days) * DAY_MS);
        if policies
            .iter()
            .any(|policy| policy.dataset == AUDIT_DATASET)
        {
            verify_decisions_in_transaction(&tx)?;
        }
        let prefix_end = expired_audit_prefix(&tx, &policies, now)?;

        let mut records = Vec::<ArchiveRecord>::new();
        if let Some(prefix_end) = prefix_end {
            let mut stmt = tx
                .prepare(
                    "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash,namespace,data_class
                     FROM sekai_decisions WHERE seq <= ?1 ORDER BY seq",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![prefix_end], |row| {
                    let id: String = row.get(0)?;
                    let payload = serde_json::json!({
                        "id": id, "timestamp": row.get::<_, i64>(1)?,
                        "actor": row.get::<_, String>(2)?, "action": row.get::<_, String>(3)?,
                        "reason": row.get::<_, String>(4)?, "evidence": row.get::<_, String>(5)?,
                        "target_id": row.get::<_, String>(6)?, "outcome": row.get::<_, String>(7)?,
                        "seq": row.get::<_, i64>(8)?, "prev_hash": row.get::<_, String>(9)?,
                        "entry_hash": row.get::<_, String>(10)?,
                        "namespace": row.get::<_, String>(11)?, "data_class": row.get::<_, String>(12)?,
                    });
                    Ok(ArchiveRecord {
                        dataset: "audit.decisions",
                        source_key: id,
                        payload: payload.to_string(),
                    })
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            records.extend(rows);

            let mut stmt = tx
                .prepare(
                    "SELECT a.id,a.decision_id,a.policy_kind,a.policy_scope,a.policy_version,
                            a.policy_snapshot,a.inputs,a.decision,a.content_hash,a.created
                     FROM sekai_attestations a JOIN sekai_decisions d ON d.id=a.decision_id
                     WHERE d.seq <= ?1 ORDER BY a.id",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![prefix_end], |row| {
                    let id: String = row.get(0)?;
                    let payload = serde_json::json!({
                        "id": id, "decision_id": row.get::<_, String>(1)?,
                        "policy_kind": row.get::<_, String>(2)?, "policy_scope": row.get::<_, String>(3)?,
                        "policy_version": row.get::<_, String>(4)?, "policy_snapshot": row.get::<_, String>(5)?,
                        "inputs": row.get::<_, String>(6)?, "decision": row.get::<_, String>(7)?,
                        "content_hash": row.get::<_, String>(8)?, "created": row.get::<_, i64>(9)?,
                    });
                    Ok(ArchiveRecord {
                        dataset: "audit.attestations",
                        source_key: id,
                        payload: payload.to_string(),
                    })
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            records.extend(rows);
        }
        if let Some(cutoff) = audit_cutoff {
            let mut stmt = tx
                .prepare(
                    "SELECT id,object_id,field,old_value,new_value,changed_by,timestamp
                     FROM sekai_object_changes WHERE timestamp < ?1 ORDER BY timestamp,id",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![cutoff], |row| {
                    let id: String = row.get(0)?;
                    let payload = serde_json::json!({
                        "id": id, "object_id": row.get::<_, String>(1)?, "field": row.get::<_, String>(2)?,
                        "old_value": row.get::<_, String>(3)?, "new_value": row.get::<_, String>(4)?,
                        "changed_by": row.get::<_, String>(5)?, "timestamp": row.get::<_, i64>(6)?,
                    });
                    Ok(ArchiveRecord {
                        dataset: "audit.object_changes",
                        source_key: id,
                        payload: payload.to_string(),
                    })
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            records.extend(rows);
        }

        let llm_rows = {
            let mut stmt = tx
                .prepare("SELECT id,data FROM sekai_dataset_rows WHERE dataset_id=?1 ORDER BY id")
                .map_err(|e| e.to_string())?;
            stmt.query_map(params![LLM_CALLS_DATASET], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        let mut llm_ids = Vec::new();
        for (id, data) in llm_rows {
            let row: std::collections::HashMap<String, String> =
                serde_json::from_str(&data).unwrap_or_default();
            let namespace = row.get("project").map(String::as_str).unwrap_or_default();
            let data_class = row
                .get("data_class")
                .map(String::as_str)
                .unwrap_or_default();
            let timestamp = row
                .get("timestamp_ms")
                .and_then(|value| value.parse::<i64>().ok());
            if let (Some(timestamp), Some(policy)) = (
                timestamp,
                effective_policy(&policies, LLM_CALLS_DATASET, namespace, data_class),
            ) && timestamp < now - i64::from(policy.retention_days) * DAY_MS
            {
                llm_ids.push(id);
                records.push(ArchiveRecord {
                    dataset: "llm_calls",
                    source_key: id.to_string(),
                    payload: data,
                });
            }
        }

        let observation_rows = {
            let mut stmt = tx
                .prepare(
                    "SELECT rowid,request_id,namespace,data_class,component_id,model,status,timestamp,packages_json,context_json
                     FROM sekai_task_observations ORDER BY component_id,timestamp,rowid",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        let mut expired_observations =
            std::collections::BTreeMap::<String, (String, Vec<(i64, String)>)>::new();
        let mut redacted_observation_ids = Vec::new();
        let mut retained_components = std::collections::BTreeSet::new();
        for (
            rowid,
            request_id,
            namespace,
            data_class,
            component_id,
            model,
            status,
            timestamp,
            packages,
            context,
        ) in observation_rows
        {
            if context == RETENTION_TOMBSTONE_CONTEXT {
                retained_components.insert(component_id);
                continue;
            }
            let expired = effective_policy(
                &policies,
                TASK_OBSERVATIONS_DATASET,
                &namespace,
                &data_class,
            )
            .is_some_and(|policy| {
                timestamp < (now - i64::from(policy.retention_days) * DAY_MS) / 1000
            });
            if expired {
                records.push(ArchiveRecord {
                    dataset: "task_observations",
                    source_key: serde_json::to_string(&(&request_id, &component_id))
                        .unwrap_or_default(),
                    payload: serde_json::json!({
                        "request_id": request_id, "namespace": namespace, "component_id": component_id,
                        "data_class": data_class, "model": model, "status": status, "timestamp": timestamp,
                        "packages_json": packages, "context_json": context,
                    })
                    .to_string(),
                });
                if retained_components.contains(&component_id) {
                    redacted_observation_ids.push(rowid);
                } else {
                    expired_observations
                        .entry(component_id.clone())
                        .or_insert_with(|| (namespace.clone(), Vec::new()))
                        .1
                        .push((rowid, status.clone()));
                }
            } else {
                retained_components.insert(component_id);
            }
        }

        records.sort_by(|left, right| {
            (&left.dataset, &left.source_key).cmp(&(&right.dataset, &right.source_key))
        });
        let record_hashes: Vec<String> = records.iter().map(archive_record_hash).collect();
        let content_hash = sha256_hex(
            serde_json::to_string(&record_hashes)
                .unwrap_or_default()
                .as_bytes(),
        );
        let batch_id = sha256_hex(
            serde_json::to_string(&(now, &content_hash))
                .unwrap_or_default()
                .as_bytes(),
        );
        let mut run = ArchiveRun {
            batch_id: batch_id.clone(),
            content_hash: content_hash.clone(),
            audit_archived: records
                .iter()
                .filter(|record| record.dataset.starts_with("audit."))
                .count() as i32,
            llm_calls_archived: llm_ids.len() as i32,
            task_observations_archived: records
                .iter()
                .filter(|record| record.dataset == "task_observations")
                .count() as i32,
            task_observations_redacted: redacted_observation_ids.len() as i32,
        };
        if records.is_empty() {
            run.batch_id.clear();
            run.content_hash.clear();
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(run);
        }

        let mut archive = open_archive(&archive_resolved)?;
        let archive_tx = archive.transaction().map_err(|e| e.to_string())?;
        archive_tx
            .execute(
                "INSERT OR IGNORE INTO archive_batches (id,cutoff,content_hash,record_count,created)
                 VALUES (?1,?2,?3,?4,?5)",
                params![batch_id, now, content_hash, records.len() as i64, now],
            )
            .map_err(|e| e.to_string())?;
        let batch_matches: bool = archive_tx
            .query_row(
                "SELECT cutoff=?2 AND content_hash=?3 AND record_count=?4 FROM archive_batches WHERE id=?1",
                params![batch_id, now, content_hash, records.len() as i64],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !batch_matches {
            return Err("archive batch identity conflicts with existing content".into());
        }
        for (record, payload_hash) in records.iter().zip(&record_hashes) {
            archive_tx
                .execute(
                    "INSERT OR IGNORE INTO archive_records
                     (dataset,source_key,payload,payload_hash,archived_at) VALUES (?1,?2,?3,?4,?5)",
                    params![
                        record.dataset,
                        record.source_key,
                        record.payload,
                        payload_hash,
                        now
                    ],
                )
                .map_err(|e| e.to_string())?;
            let stored_hash: String = archive_tx
                .query_row(
                    "SELECT payload_hash FROM archive_records WHERE dataset=?1 AND source_key=?2",
                    params![record.dataset, record.source_key],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if stored_hash != *payload_hash {
                return Err(format!(
                    "archive record {}:{} conflicts with existing content",
                    record.dataset, record.source_key
                ));
            }
            archive_tx
                .execute(
                    "INSERT OR IGNORE INTO archive_batch_records (batch_id,dataset,source_key)
                     VALUES (?1,?2,?3)",
                    params![batch_id, record.dataset, record.source_key],
                )
                .map_err(|e| e.to_string())?;
        }
        archive_tx.commit().map_err(|e| e.to_string())?;

        if let Some(prefix_end) = prefix_end {
            let anchor_hash: String = tx
                .query_row(
                    "SELECT entry_hash FROM sekai_decisions WHERE seq=?1",
                    params![prefix_end],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            tx.execute(
                "DELETE FROM sekai_attestations WHERE decision_id IN
                 (SELECT id FROM sekai_decisions WHERE seq <= ?1)",
                params![prefix_end],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "DELETE FROM sekai_decisions WHERE seq <= ?1",
                params![prefix_end],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT OR REPLACE INTO sekai_ledger_anchors (seq,entry_hash,reason,created)
                 VALUES (?1,?2,?3,?4)",
                params![
                    prefix_end,
                    anchor_hash,
                    format!("archived before {}", audit_cutoff.unwrap_or(now)),
                    now
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        if let Some(cutoff) = audit_cutoff {
            tx.execute(
                "DELETE FROM sekai_object_changes WHERE timestamp < ?1",
                params![cutoff],
            )
            .map_err(|e| e.to_string())?;
        }
        for id in llm_ids {
            tx.execute("DELETE FROM sekai_dataset_rows WHERE id=?1", params![id])
                .map_err(|e| e.to_string())?;
        }
        for (component_id, (namespace, rows)) in expired_observations {
            let baseline = tx
                .query_row(
                    "SELECT task_total,task_succeeded,consecutive_failures
                     FROM sekai_task_observation_baselines WHERE component_id=?1",
                    params![component_id],
                    |row| {
                        Ok((
                            row.get::<_, i32>(0)?,
                            row.get::<_, i32>(1)?,
                            row.get::<_, i32>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or((0, 0, 0));
            let succeeded = rows.iter().filter(|(_, status)| status == "done").count() as i32;
            let trailing_failures = rows
                .iter()
                .rev()
                .take_while(|(_, status)| status != "done")
                .count() as i32;
            let consecutive_failures = if trailing_failures == rows.len() as i32 {
                baseline.2 + trailing_failures
            } else {
                trailing_failures
            };
            tx.execute(
                "INSERT INTO sekai_task_observation_baselines
                 (component_id,namespace,task_total,task_succeeded,consecutive_failures,created)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(component_id) DO UPDATE SET namespace=excluded.namespace,
                   task_total=excluded.task_total,task_succeeded=excluded.task_succeeded,
                   consecutive_failures=excluded.consecutive_failures,created=excluded.created",
                params![
                    component_id,
                    namespace,
                    baseline.0 + rows.len() as i32,
                    baseline.1 + succeeded,
                    consecutive_failures,
                    now / 1000
                ],
            )
            .map_err(|e| e.to_string())?;
            for (rowid, _) in rows {
                tx.execute(
                    "DELETE FROM sekai_task_observations WHERE rowid=?1",
                    params![rowid],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        for rowid in redacted_observation_ids {
            redact_retained_task_observation(&tx, rowid)?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(run)
    }

    pub fn run_retention(&self, now: i64) -> Result<RetentionRun, String> {
        let policies = self.list_retention_policies()?;
        let mut run = RetentionRun::default();

        if policies
            .iter()
            .any(|policy| policy.dataset == AUDIT_DATASET)
        {
            let verification = self.verify_ledger()?;
            if !verification.ok {
                return Err(format!(
                    "audit ledger verification failed before retention: {}",
                    verification.error
                ));
            }
            run.audit_deleted = self.purge_classified_audit_records(&policies, now)?;
        }

        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let llm_rows = {
            let mut stmt = tx
                .prepare("SELECT id, data FROM sekai_dataset_rows WHERE dataset_id = 'llm_calls'")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        for (id, data) in llm_rows {
            let row: std::collections::HashMap<String, String> =
                serde_json::from_str(&data).unwrap_or_default();
            let namespace = row.get("project").map(String::as_str).unwrap_or_default();
            let data_class = row
                .get("data_class")
                .map(String::as_str)
                .unwrap_or_default();
            let timestamp = row
                .get("timestamp_ms")
                .and_then(|value| value.parse::<i64>().ok());
            if let (Some(timestamp), Some(policy)) = (
                timestamp,
                effective_policy(&policies, LLM_CALLS_DATASET, namespace, data_class),
            ) && timestamp < now - i64::from(policy.retention_days) * DAY_MS
            {
                run.llm_calls_deleted += tx
                    .execute("DELETE FROM sekai_dataset_rows WHERE id = ?1", params![id])
                    .map_err(|e| e.to_string())? as i32;
            }
        }

        let observation_rows = {
            let mut stmt = tx
                .prepare(
                    "SELECT rowid, namespace, data_class, component_id, status, timestamp,
                            context_json
                     FROM sekai_task_observations
                     ORDER BY component_id, timestamp, rowid",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        let mut expired = std::collections::BTreeMap::<String, (String, Vec<(i64, String)>)>::new();
        let mut redacted_observation_ids = Vec::new();
        let mut retained_components = std::collections::BTreeSet::new();
        for (rowid, namespace, data_class, component_id, status, timestamp_seconds, context) in
            observation_rows
        {
            if context == RETENTION_TOMBSTONE_CONTEXT {
                retained_components.insert(component_id);
                continue;
            }
            let expired_by_policy = effective_policy(
                &policies,
                TASK_OBSERVATIONS_DATASET,
                &namespace,
                &data_class,
            )
            .is_some_and(|policy| {
                timestamp_seconds < (now - i64::from(policy.retention_days) * DAY_MS) / 1000
            });
            if expired_by_policy {
                if retained_components.contains(&component_id) {
                    redacted_observation_ids.push(rowid);
                } else {
                    let entry = expired
                        .entry(component_id)
                        .or_insert_with(|| (namespace, Vec::new()));
                    entry.1.push((rowid, status));
                }
            } else {
                retained_components.insert(component_id);
            }
        }
        for (component_id, (namespace, rows)) in expired {
            let baseline = tx
                .query_row(
                    "SELECT task_total, task_succeeded, consecutive_failures
                     FROM sekai_task_observation_baselines WHERE component_id = ?1",
                    params![component_id],
                    |row| {
                        Ok((
                            row.get::<_, i32>(0)?,
                            row.get::<_, i32>(1)?,
                            row.get::<_, i32>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or((0, 0, 0));
            let succeeded = rows.iter().filter(|(_, status)| status == "done").count() as i32;
            let trailing_failures = rows
                .iter()
                .rev()
                .take_while(|(_, status)| status != "done")
                .count() as i32;
            let consecutive_failures = if trailing_failures == rows.len() as i32 {
                baseline.2 + trailing_failures
            } else {
                trailing_failures
            };
            tx.execute(
                "INSERT INTO sekai_task_observation_baselines
                 (component_id, namespace, task_total, task_succeeded, consecutive_failures, created)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(component_id) DO UPDATE SET
                   namespace=excluded.namespace,
                   task_total=excluded.task_total,
                   task_succeeded=excluded.task_succeeded,
                   consecutive_failures=excluded.consecutive_failures,
                   created=excluded.created",
                params![
                    component_id,
                    namespace,
                    baseline.0 + rows.len() as i32,
                    baseline.1 + succeeded,
                    consecutive_failures,
                    now / 1000
                ],
            )
            .map_err(|e| e.to_string())?;
            for (rowid, _) in rows {
                run.task_observations_deleted +=
                    tx.execute(
                        "DELETE FROM sekai_task_observations WHERE rowid = ?1",
                        params![rowid],
                    )
                    .map_err(|e| e.to_string())? as i32;
            }
        }
        for rowid in redacted_observation_ids {
            run.task_observations_redacted += redact_retained_task_observation(&tx, rowid)? as i32;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::audit::Decision;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use std::collections::HashMap;

    fn archive_path() -> PathBuf {
        std::env::temp_dir().join(format!("sekai-archive-{}.db", uuid::Uuid::new_v4()))
    }

    #[test]
    fn resolves_relative_archive_filename_against_current_directory() {
        let resolved = resolved_path(Path::new("archive.db")).unwrap();
        assert_eq!(
            resolved,
            std::env::current_dir().unwrap().join("archive.db")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_hard_link_to_operational_database_as_archive() {
        let directory =
            std::env::temp_dir().join(format!("sekai-archive-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let hot_path = directory.join("hot.db");
        let archive_path = directory.join("archive.db");
        let db = SekaiDb::new(hot_path.to_str().unwrap()).unwrap();
        std::fs::hard_link(&hot_path, &archive_path).unwrap();

        let error = db
            .archive_retained_records(&archive_path, 2 * DAY_MS)
            .unwrap_err();
        assert!(error.contains("must differ"));
        drop(db);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_operational_database_sidecars_as_archives() {
        let directory =
            std::env::temp_dir().join(format!("sekai-sidecar-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let hot_path = directory.join("hot.db");
        let db = SekaiDb::new(hot_path.to_str().unwrap()).unwrap();

        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", hot_path.display()));
            let error = db
                .archive_retained_records(&sidecar, 2 * DAY_MS)
                .unwrap_err();
            assert!(error.contains("must differ"));
        }
        db.ping().unwrap();
        drop(db);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_dangling_archive_symlink_to_database_sidecar() {
        use std::os::unix::fs::symlink;

        let directory =
            std::env::temp_dir().join(format!("sekai-symlink-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let hot_path = directory.join("hot.db");
        let archive_path = directory.join("archive.db");
        let db = SekaiDb::new(hot_path.to_str().unwrap()).unwrap();
        let sidecar = PathBuf::from(format!("{}-journal", hot_path.display()));
        symlink(&sidecar, &archive_path).unwrap();

        let error = db
            .archive_retained_records(&archive_path, 2 * DAY_MS)
            .unwrap_err();
        assert!(error.contains("symbolic link"));
        assert!(!sidecar.exists());
        drop(db);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn typed_subject_matching_preserves_kind_and_full_scoped_values() {
        assert!(contains_typed_subject(
            "project:p/agent:a/work_unit_id:wu-1",
            "work_unit",
            "wu-1"
        ));
        assert!(contains_typed_subject(
            "user_id:project:default/agent:codex-app",
            "user",
            "project:default/agent:codex-app"
        ));
        assert!(!contains_typed_subject(
            "project:default/agent:codex-app",
            "agent",
            "default"
        ));
        assert!(!contains_typed_subject("agent:agent10", "agent", "agent1"));
        assert!(!contains_typed_subject(
            "user_id:project:p/agent:a/work_unit:w",
            "user",
            "project:p/agent:a"
        ));
        assert!(!contains_typed_subject(
            "work_unit_id:wu-1/child:two",
            "work_unit",
            "wu-1"
        ));
        for text in [
            "budget exceeded for agent:codex-app: used limit",
            "\"agent:codex-app\"",
            "subject=agent:codex-app",
        ] {
            assert!(contains_typed_subject(text, "agent", "codex-app"));
        }
        assert!(!contains_typed_subject(
            "agent:codex-app:v2",
            "agent",
            "codex-app"
        ));
        assert!(!contains_subject_reference(
            "operation done successfully",
            "agent",
            "done"
        ));
        assert!(!contains_subject_reference("done", "agent", "done"));
        assert!(contains_subject_reference(
            "approved for alice after review",
            "user",
            "alice"
        ));
        assert!(contains_subject_reference("owned by bot", "agent", "bot"));
        for text in ["owner=alice", "subject: alice", r#"{"user":"alice"}"#] {
            assert!(contains_subject_reference(text, "user", "alice"));
        }
        assert!(!contains_subject_reference(
            r#"{"user":"alice"}"#,
            "agent",
            "alice"
        ));
    }

    #[test]
    fn installs_bounded_defaults_and_validates_overrides() {
        let db = SekaiDb::new(":memory:").unwrap();
        let policies = db.list_retention_policies().unwrap();
        assert_eq!(policies.len(), 3);
        assert!(
            policies
                .iter()
                .any(|p| p.dataset == AUDIT_DATASET && p.retention_days == 365)
        );
        let mut invalid = policies[0].clone();
        invalid.retention_days = 0;
        assert!(db.set_retention_policy(&invalid).is_err());
    }

    #[test]
    fn prunes_scoped_usage_and_preserves_other_namespaces() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: vec![ColumnDef {
                name: "timestamp_ms".into(),
                col_type: "string".into(),
                classification: "public".into(),
            }],
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        let rows = [
            HashMap::from([
                ("timestamp_ms".into(), "1".into()),
                ("project".into(), "erase".into()),
            ]),
            HashMap::from([
                ("timestamp_ms".into(), "1".into()),
                ("project".into(), "keep".into()),
            ]),
        ];
        db.append_rows(LLM_CALLS_DATASET, &rows).unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: LLM_CALLS_DATASET.into(),
            namespace: "erase".into(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        // Keep the global default from matching either row in this synthetic clock.
        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.llm_calls_deleted, 1);
        let rows = db
            .query_rows(LLM_CALLS_DATASET, &Default::default())
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["project"], "keep");
    }

    #[test]
    fn specific_policy_can_retain_rows_longer_than_default() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[HashMap::from([
                ("timestamp_ms".into(), "1".into()),
                ("project".into(), "legal".into()),
            ])],
        )
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: LLM_CALLS_DATASET.into(),
            namespace: "legal".into(),
            data_class: String::new(),
            retention_days: 365,
            updated: 1,
        })
        .unwrap();

        let run = db.run_retention(120 * DAY_MS).unwrap();
        assert_eq!(run.llm_calls_deleted, 0);
        assert_eq!(
            db.query_rows(LLM_CALLS_DATASET, &Default::default())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn class_policy_uses_shorter_window_than_equal_scope_namespace_policy() {
        let policies = vec![
            RetentionPolicy {
                dataset: LLM_CALLS_DATASET.into(),
                namespace: "legal".into(),
                data_class: String::new(),
                retention_days: 365,
                updated: 1,
            },
            RetentionPolicy {
                dataset: LLM_CALLS_DATASET.into(),
                namespace: String::new(),
                data_class: "sensitive".into(),
                retention_days: 7,
                updated: 1,
            },
        ];

        let selected =
            effective_policy(&policies, LLM_CALLS_DATASET, "legal", "sensitive").unwrap();
        assert_eq!(selected.retention_days, 7);
    }

    #[test]
    fn scoped_audit_policy_expires_classified_prefix() {
        let db = SekaiDb::new(":memory:").unwrap();
        for (id, data_class) in [("sensitive", "sensitive"), ("public", "public")] {
            db.record_decision(&Decision {
                id: id.into(),
                timestamp: 1,
                actor: "actor".into(),
                action: "test".into(),
                reason: String::new(),
                evidence: HashMap::from([
                    ("project".into(), "legal".into()),
                    ("data_class".into(), data_class.into()),
                ]),
                target_id: String::new(),
                outcome: "ok".into(),
            })
            .unwrap();
        }
        db.set_retention_policy(&RetentionPolicy {
            dataset: AUDIT_DATASET.into(),
            namespace: "legal".into(),
            data_class: "sensitive".into(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();

        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.audit_deleted, 1);
        assert!(db.get_decision("sensitive").unwrap().is_none());
        assert!(db.get_decision("public").unwrap().is_some());
        assert!(db.verify_ledger().unwrap().ok);
    }

    #[test]
    fn class_scoped_task_policy_preserves_other_classes() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            for (request_id, data_class) in [("remove", "sensitive"), ("keep", "public")] {
                conn.execute(
                    "INSERT INTO sekai_task_observations
                     (request_id,namespace,data_class,component_id,model,status,timestamp)
                     VALUES (?1,'ns',?2,'component','','done',1)",
                    params![request_id, data_class],
                )
                .unwrap();
            }
        }
        db.set_retention_policy(&RetentionPolicy {
            dataset: TASK_OBSERVATIONS_DATASET.into(),
            namespace: String::new(),
            data_class: "sensitive".into(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();

        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.task_observations_deleted, 1);
        let remaining = db
            .list_task_observations_for_component("component")
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].data_class, "public");
    }

    #[test]
    fn class_scoped_task_retention_only_folds_contiguous_prefix() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            for (request_id, data_class, status, timestamp) in [
                ("sensitive-first", "sensitive", "failed", 1),
                ("public-success", "public", "done", 2),
                ("sensitive-later", "sensitive", "failed", 3),
                ("public-failure", "public", "failed", 4),
            ] {
                conn.execute(
                    "INSERT INTO sekai_task_observations
                     (request_id,namespace,data_class,component_id,model,status,timestamp)
                     VALUES (?1,'ns',?2,'component','',?3,?4)",
                    params![request_id, data_class, status, timestamp],
                )
                .unwrap();
            }
        }
        db.set_retention_policy(&RetentionPolicy {
            dataset: TASK_OBSERVATIONS_DATASET.into(),
            namespace: String::new(),
            data_class: "sensitive".into(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        let before = crate::sekai::observation::task_observation_stats(&db, "component").unwrap();

        let run = db.run_retention(2 * DAY_MS).unwrap();

        assert_eq!(run.task_observations_deleted, 1);
        assert_eq!(run.task_observations_redacted, 1);
        let after = crate::sekai::observation::task_observation_stats(&db, "component").unwrap();
        assert_eq!(after, before);
        let remaining = db
            .list_task_observations_for_component("component")
            .unwrap();
        assert!(
            remaining
                .iter()
                .any(|row| row.request_id.starts_with("retention-tombstone:"))
        );
        assert!(!remaining.iter().any(|row| {
            row.request_id == "sensitive-later"
                || row.namespace == "ns" && row.data_class == "sensitive"
        }));
    }

    #[test]
    fn class_scoped_task_archive_redacts_expired_non_prefix_payloads() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            for (request_id, data_class, status, timestamp) in [
                ("sensitive-first", "sensitive", "failed", 1),
                ("public-success", "public", "done", 2),
                ("sensitive-later", "sensitive", "failed", 3),
                ("public-failure", "public", "failed", 4),
            ] {
                conn.execute(
                    "INSERT INTO sekai_task_observations
                     (request_id,namespace,data_class,component_id,model,status,timestamp,context_json)
                     VALUES (?1,'ns',?2,'component','private-model',?3,?4,
                             '{\"subject\":\"private\"}')",
                    params![request_id, data_class, status, timestamp],
                )
                .unwrap();
            }
        }
        db.set_retention_policy(&RetentionPolicy {
            dataset: TASK_OBSERVATIONS_DATASET.into(),
            namespace: String::new(),
            data_class: "sensitive".into(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        let before = crate::sekai::observation::task_observation_stats(&db, "component").unwrap();

        let path = archive_path();
        let run = db.archive_retained_records(&path, 2 * DAY_MS).unwrap();

        assert_eq!(run.task_observations_archived, 2);
        assert_eq!(run.task_observations_redacted, 1);
        assert_eq!(
            crate::sekai::observation::task_observation_stats(&db, "component").unwrap(),
            before
        );
        let remaining = db
            .list_task_observations_for_component("component")
            .unwrap();
        assert!(
            remaining
                .iter()
                .any(|row| row.request_id.starts_with("retention-tombstone:"))
        );
        let archive = Connection::open(path).unwrap();
        let archived_payload: String = archive
            .query_row(
                "SELECT payload FROM archive_records
                 WHERE dataset='task_observations' AND payload LIKE '%sensitive-later%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(archived_payload.contains("private-model"));
    }

    #[test]
    fn audit_retention_records_a_verifiable_anchor() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.record_decision(&Decision {
            id: "old".into(),
            timestamp: 1,
            actor: "a".into(),
            action: "x".into(),
            reason: String::new(),
            evidence: HashMap::new(),
            target_id: "target".into(),
            outcome: String::new(),
        })
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: AUDIT_DATASET.into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.audit_deleted, 1);
        let verification = db.verify_ledger().unwrap();
        assert!(verification.ok);
        assert_eq!(verification.anchor_seq, 1);
    }

    #[test]
    fn audit_retention_refuses_to_anchor_tampered_history() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.record_decision(&Decision {
            id: "old".into(),
            timestamp: 1,
            actor: "a".into(),
            action: "x".into(),
            reason: String::new(),
            evidence: HashMap::new(),
            target_id: "target".into(),
            outcome: String::new(),
        })
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: AUDIT_DATASET.into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        db.conn()
            .execute(
                "UPDATE sekai_decisions SET outcome='tampered' WHERE id='old'",
                [],
            )
            .unwrap();

        let error = db.run_retention(2 * DAY_MS).unwrap_err();

        assert!(error.contains("audit ledger verification failed"));
        assert!(db.get_decision("old").unwrap().is_some());
    }

    #[test]
    fn task_observation_retention_converts_millisecond_clock_to_seconds() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            for (request_id, timestamp) in [("old", 1), ("fresh", 100_000)] {
                conn.execute(
                    "INSERT INTO sekai_task_observations
                     (request_id, namespace, component_id, model, status, timestamp)
                     VALUES (?1, 'ns', 'component', '', 'succeeded', ?2)",
                    params![request_id, timestamp],
                )
                .unwrap();
            }
        }
        db.set_retention_policy(&RetentionPolicy {
            dataset: TASK_OBSERVATIONS_DATASET.into(),
            namespace: "ns".into(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();

        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.task_observations_deleted, 1);
        let remaining: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_task_observations WHERE request_id = 'fresh'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn task_observation_retention_preserves_lifetime_statistics() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            for (request_id, status, timestamp) in [
                ("old-success", "done", 1),
                ("old-failure", "failed", 2),
                ("fresh-success", "done", 200_000),
            ] {
                conn.execute(
                    "INSERT INTO sekai_task_observations
                     (request_id, namespace, component_id, model, status, timestamp)
                     VALUES (?1, 'ns', 'component', '', ?2, ?3)",
                    params![request_id, status, timestamp],
                )
                .unwrap();
            }
        }
        db.set_retention_policy(&RetentionPolicy {
            dataset: TASK_OBSERVATIONS_DATASET.into(),
            namespace: "ns".into(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        let before = crate::sekai::observation::task_observation_stats(&db, "component").unwrap();

        let run = db.run_retention(3 * DAY_MS).unwrap();

        assert_eq!(run.task_observations_deleted, 2);
        let after = crate::sekai::observation::task_observation_stats(&db, "component").unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn audit_retention_removes_related_object_changes() {
        use crate::sekai::audit::ObjectChange;

        let db = SekaiDb::new(":memory:").unwrap();
        db.record_object_change(&ObjectChange {
            id: "old-change".into(),
            object_id: "target".into(),
            field: "name".into(),
            old_value: "old".into(),
            new_value: "new".into(),
            changed_by: "actor".into(),
            timestamp: 1,
        })
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: AUDIT_DATASET.into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();

        let run = db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(run.audit_deleted, 1);
        assert!(db.list_object_changes("target", 10, 0).unwrap().is_empty());
    }

    #[test]
    fn archives_aged_records_before_removing_them_from_the_hot_store() {
        use crate::sekai::audit::ObjectChange;

        let db = SekaiDb::new(":memory:").unwrap();
        for dataset in [AUDIT_DATASET, LLM_CALLS_DATASET, TASK_OBSERVATIONS_DATASET] {
            db.set_retention_policy(&RetentionPolicy {
                dataset: dataset.into(),
                namespace: String::new(),
                data_class: String::new(),
                retention_days: 1,
                updated: 1,
            })
            .unwrap();
        }
        for (id, timestamp) in [("old-decision", 1), ("fresh-decision", 2 * DAY_MS)] {
            db.record_decision(&Decision {
                id: id.into(),
                timestamp,
                actor: "actor".into(),
                action: "test".into(),
                reason: String::new(),
                evidence: HashMap::new(),
                target_id: String::new(),
                outcome: "ok".into(),
            })
            .unwrap();
        }
        db.record_object_change(&ObjectChange {
            id: "old-change".into(),
            object_id: "object".into(),
            field: "name".into(),
            old_value: "old".into(),
            new_value: "new".into(),
            changed_by: "actor".into(),
            timestamp: 1,
        })
        .unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[
                HashMap::from([("timestamp_ms".into(), "1".into())]),
                HashMap::from([("timestamp_ms".into(), (2 * DAY_MS).to_string())]),
            ],
        )
        .unwrap();
        {
            let conn = db.conn();
            for (request_id, timestamp) in [("old-observation", 1), ("fresh-observation", 200_000)]
            {
                conn.execute(
                    "INSERT INTO sekai_task_observations
                     (request_id,namespace,component_id,model,status,timestamp)
                     VALUES (?1,'','component','','done',?2)",
                    params![request_id, timestamp],
                )
                .unwrap();
            }
        }

        let path = archive_path();
        let run = db.archive_retained_records(&path, 2 * DAY_MS).unwrap();

        assert_eq!(run.audit_archived, 2);
        assert_eq!(run.llm_calls_archived, 1);
        assert_eq!(run.task_observations_archived, 1);
        assert!(!run.batch_id.is_empty());
        assert_eq!(db.list_decisions(&Default::default()).unwrap().len(), 1);
        assert_eq!(
            db.query_rows(LLM_CALLS_DATASET, &Default::default())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            db.list_task_observations_for_component("component")
                .unwrap()
                .len(),
            1
        );
        let verification = db.verify_ledger().unwrap();
        assert!(verification.ok, "{}", verification.error);
        assert_eq!(verification.anchor_seq, 1);

        let archive = Connection::open(&path).unwrap();
        let archived: i64 = archive
            .query_row("SELECT COUNT(*) FROM archive_records", [], |row| row.get(0))
            .unwrap();
        assert_eq!(archived, 4);
        let manifest: (String, i64) = archive
            .query_row(
                "SELECT content_hash,record_count FROM archive_batches WHERE id=?1",
                params![run.batch_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(manifest, (run.content_hash, 4));
        drop(archive);
        let verification = SekaiDb::verify_archive(&path).unwrap();
        assert!(verification.ok, "{}", verification.error);
        assert_eq!(verification.records_checked, 4);
        assert_eq!(verification.batches_checked, 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn archive_verification_detects_payload_tampering() {
        let path = archive_path();
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[HashMap::from([("timestamp_ms".into(), "1".into())])],
        )
        .unwrap();
        db.archive_retained_records(&path, 100 * DAY_MS).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute("UPDATE archive_records SET payload='forged'", [])
            .unwrap();

        let verification = SekaiDb::verify_archive(&path).unwrap();
        assert!(!verification.ok);
        assert!(verification.error.contains("was altered"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn archive_verification_detects_removed_batch_manifest() {
        let path = archive_path();
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[HashMap::from([("timestamp_ms".into(), "1".into())])],
        )
        .unwrap();
        db.archive_retained_records(&path, 100 * DAY_MS).unwrap();
        let archive = Connection::open(&path).unwrap();
        archive
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DELETE FROM archive_batches;",
            )
            .unwrap();
        drop(archive);

        let verification = SekaiDb::verify_archive(&path).unwrap();
        assert!(!verification.ok);
        assert!(verification.error.contains("broken manifest references"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn archive_verification_rejects_total_content_loss() {
        let path = archive_path();
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[HashMap::from([("timestamp_ms".into(), "1".into())])],
        )
        .unwrap();
        db.archive_retained_records(&path, 100 * DAY_MS).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DELETE FROM archive_batch_records;
                 DELETE FROM archive_records;
                 DELETE FROM archive_batches;",
            )
            .unwrap();

        let verification = SekaiDb::verify_archive(&path).unwrap();
        assert!(!verification.ok);
        assert!(verification.error.contains("no batch manifests"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn refuses_to_archive_tampered_audit_history() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.record_decision(&Decision {
            id: "tampered".into(),
            timestamp: 1,
            actor: "actor".into(),
            action: "test".into(),
            reason: String::new(),
            evidence: HashMap::new(),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();
        db.conn()
            .execute(
                "UPDATE sekai_decisions SET outcome='forged' WHERE id='tampered'",
                [],
            )
            .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: AUDIT_DATASET.into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();

        let path = archive_path();
        let error = db.archive_retained_records(&path, 2 * DAY_MS).unwrap_err();
        assert!(error.contains("audit ledger hash invalid"), "{error}");
        assert!(db.get_decision("tampered").unwrap().is_some());
        assert!(!path.exists());
    }

    #[test]
    fn archive_conflicts_leave_hot_records_untouched() {
        let path = archive_path();
        for (index, model) in ["first", "changed"].into_iter().enumerate() {
            let db = SekaiDb::new(":memory:").unwrap();
            db.create_dataset(&Dataset {
                id: LLM_CALLS_DATASET.into(),
                name: "calls".into(),
                columns: Vec::new(),
                object_id: String::new(),
                created: 0,
            })
            .unwrap();
            db.append_rows(
                LLM_CALLS_DATASET,
                &[HashMap::from([
                    ("timestamp_ms".into(), "1".into()),
                    ("model".into(), model.into()),
                ])],
            )
            .unwrap();
            db.set_retention_policy(&RetentionPolicy {
                dataset: LLM_CALLS_DATASET.into(),
                namespace: String::new(),
                data_class: String::new(),
                retention_days: 1,
                updated: 1,
            })
            .unwrap();
            let result = db.archive_retained_records(&path, 2 * DAY_MS);
            if index == 0 {
                assert!(result.is_ok());
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .contains("conflicts with existing content")
                );
                assert_eq!(
                    db.query_rows(LLM_CALLS_DATASET, &Default::default())
                        .unwrap()
                        .len(),
                    1
                );
            }
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn archives_non_audit_records_after_ledger_anchor_advances() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.record_decision(&Decision {
            id: "purged".into(),
            timestamp: 1,
            actor: "actor".into(),
            action: "test".into(),
            reason: String::new(),
            evidence: HashMap::new(),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: AUDIT_DATASET.into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();
        db.run_retention(2 * DAY_MS).unwrap();
        assert_eq!(db.verify_ledger().unwrap().anchor_seq, 1);
        db.record_decision(&Decision {
            id: "fresh".into(),
            timestamp: 2 * DAY_MS,
            actor: "actor".into(),
            action: "test".into(),
            reason: String::new(),
            evidence: HashMap::new(),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();

        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[HashMap::from([("timestamp_ms".into(), "1".into())])],
        )
        .unwrap();
        db.set_retention_policy(&RetentionPolicy {
            dataset: LLM_CALLS_DATASET.into(),
            namespace: String::new(),
            data_class: String::new(),
            retention_days: 1,
            updated: 1,
        })
        .unwrap();

        let path = archive_path();
        let run = db.archive_retained_records(&path, 2 * DAY_MS).unwrap();
        assert_eq!(run.audit_archived, 0);
        assert_eq!(run.llm_calls_archived, 1);
        assert!(
            db.query_rows(LLM_CALLS_DATASET, &Default::default())
                .unwrap()
                .is_empty()
        );
        assert!(db.verify_ledger().unwrap().ok);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn subject_erasure_removes_saved_filters_and_budget_events() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&crate::domain::Object {
            id: "agent-object".into(),
            kind: "agent".into(),
            name: "erase-agent".into(),
            namespace: "ns".into(),
            external_id: "agent:erase-agent".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.conn()
            .execute(
                "INSERT INTO chisei_budget_usage_events
                 (idempotency_key,scope_id,metric,amount,created_at)
                 VALUES ('event','project:p/agent:erase-agent','tokens',1,1)",
                [],
            )
            .unwrap();
        let object_filters =
            serde_json::to_string(&vec![("owner_id", "in", "keep-object,agent-object")]).unwrap();
        db.conn()
            .execute(
                "INSERT INTO sekai_virtual_tables
                 (id,name,dataset_id,filters,columns,created)
                 VALUES ('saved-object','saved-object','llm_calls',?1,'[]',1)",
                params![object_filters],
            )
            .unwrap();
        let filters = serde_json::to_string(&vec![("agent", "eq", "erase-agent")]).unwrap();
        db.conn()
            .execute(
                "INSERT INTO sekai_virtual_tables
                 (id,name,dataset_id,filters,columns,created)
                 VALUES ('saved','saved','llm_calls',?1,'[]',1)",
                params![filters],
            )
            .unwrap();

        let result = db
            .erase_subject(&SubjectErasureRequest {
                subject_kind: "agent".into(),
                subject: "erase-agent".into(),
                requested_by: "admin".into(),
                reason: "privacy request".into(),
                timestamp: 2,
            })
            .unwrap();

        assert_eq!(result.budget_records_deleted, 1);
        let budget_events: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM chisei_budget_usage_events",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(budget_events, 0);
        assert!(db.list_virtual_tables().unwrap().is_empty());
    }

    #[test]
    fn subject_erasure_spans_stores_and_preserves_verifiable_tombstones() {
        let db = SekaiDb::new(":memory:").unwrap();
        for (id, external_id) in [
            ("agent-object", "agent:erase-agent"),
            ("keep-object", "agent:keep-agent"),
        ] {
            db.create_object(&crate::domain::Object {
                id: id.into(),
                kind: "agent".into(),
                name: external_id.into(),
                namespace: "ns".into(),
                external_id: external_id.into(),
                properties: HashMap::from([("profile".into(), external_id.into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        }
        db.create_object(&crate::domain::Object {
            id: "named-agent-object".into(),
            kind: "agent".into(),
            name: "erase-agent".into(),
            namespace: "ns".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.conn()
            .execute(
                "INSERT INTO sekai_grants (id,object_id,principal,role,created)
                 VALUES ('subject-object-grant','agent-object','agent:other','reader',1)",
                [],
            )
            .unwrap();
        db.create_object(&crate::domain::Object {
            id: "referencing-object".into(),
            kind: "project".into(),
            name: "project".into(),
            namespace: "ns".into(),
            external_id: "budget:erase-agent:daily".into(),
            properties: HashMap::from([
                ("owner".into(), "agent:erase-agent".into()),
                ("owner_id".into(), "agent-object".into()),
                ("owner_erase-agent".into(), "public".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_object(&crate::domain::Object {
            id: "budget-erase-agent-daily".into(),
            kind: "budget".into(),
            name: "daily budget".into(),
            namespace: "ns".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_object(&crate::domain::Object {
            id: "namespace-reference".into(),
            kind: "project".into(),
            name: "unrelated".into(),
            namespace: "agent:erase-agent".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_object(&crate::domain::Object {
            id: "pending-approval".into(),
            kind: crate::sekai::action_approval::ACTION_APPROVAL_KIND.into(),
            name: "pending approval".into(),
            namespace: "ns".into(),
            external_id: "action-approval:pending".into(),
            properties: HashMap::from([
                ("status".into(), "pending".into()),
                (
                    "params_json".into(),
                    serde_json::json!({"id": "agent-object"}).to_string(),
                ),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_object(&crate::domain::Object {
            id: "related-approval".into(),
            kind: crate::sekai::action_approval::ACTION_APPROVAL_KIND.into(),
            name: "related approval".into(),
            namespace: "ns".into(),
            external_id: "action-approval:related".into(),
            properties: HashMap::from([
                ("status".into(), "pending".into()),
                (
                    "params_json".into(),
                    serde_json::json!({"id": "budget-erase-agent-daily"}).to_string(),
                ),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_link(&crate::domain::Link {
            id: "agent-link".into(),
            from_id: "agent-object".into(),
            to_id: "keep-object".into(),
            relation: "owns".into(),
            created: 1,
        })
        .unwrap();
        db.create_link(&crate::domain::Link {
            id: "budget-erase-agent-daily->keep-object".into(),
            from_id: "budget-erase-agent-daily".into(),
            to_id: "keep-object".into(),
            relation: "limits".into(),
            created: 1,
        })
        .unwrap();
        db.create_link(&crate::domain::Link {
            id: "review-erase-agent-note".into(),
            from_id: "keep-object".into(),
            to_id: "referencing-object".into(),
            relation: "reviews".into(),
            created: 1,
        })
        .unwrap();
        for (id, object_id) in [
            ("subject-backed", "agent-object"),
            ("rekey-backed", "budget-erase-agent-daily"),
        ] {
            db.create_dataset(&Dataset {
                id: id.into(),
                name: id.into(),
                columns: Vec::new(),
                object_id: object_id.into(),
                created: 0,
            })
            .unwrap();
        }
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[
                HashMap::from([("agent".into(), "erase-agent".into())]),
                HashMap::from([("agent".into(), "keep-agent".into())]),
                HashMap::from([
                    ("agent".into(), "keep-agent".into()),
                    ("policy_scope".into(), "agent:erase-agent".into()),
                ]),
                HashMap::from([
                    ("agent".into(), "keep-agent".into()),
                    ("object_id".into(), "budget-erase-agent-daily".into()),
                ]),
                HashMap::from([
                    ("agent".into(), "keep-agent".into()),
                    ("approval_id".into(), "related-approval".into()),
                ]),
                HashMap::from([
                    ("agent".into(), "keep-agent".into()),
                    ("owner_erase-agent".into(), "public".into()),
                ]),
                HashMap::from([
                    ("agent".into(), "keep-agent".into()),
                    ("agent_id".into(), "erase-agent".into()),
                ]),
            ],
        )
        .unwrap();
        {
            let conn = db.conn();
            for (request_id, context) in [
                (
                    "erase-observation",
                    serde_json::json!({"agent": "erase-agent"}),
                ),
                (
                    "scoped-observation",
                    serde_json::json!({
                        "agent": "keep-agent",
                        "policy_scope": "agent:erase-agent"
                    }),
                ),
                (
                    "keyed-observation",
                    serde_json::json!({
                        "agent": "keep-agent",
                        "owner_erase-agent": "public"
                    }),
                ),
                (
                    "owner-id-observation",
                    serde_json::json!({
                        "agent": "keep-agent",
                        "owner_id": "erase-agent"
                    }),
                ),
                (
                    "keep-observation",
                    serde_json::json!({"agent": "keep-agent"}),
                ),
            ] {
                conn.execute(
                    "INSERT INTO sekai_task_observations
                     (request_id, namespace, component_id, model, status, timestamp, context_json)
                     VALUES (?1, 'ns', 'component', '', 'done', 1, ?2)",
                    params![request_id, context.to_string()],
                )
                .unwrap();
            }
            conn.execute_batch(
                "INSERT INTO sekai_task_observations
                   (request_id,namespace,component_id,model,status,timestamp,context_json)
                 VALUES
                   ('namespace-observation','agent:erase-agent','component','',
                    'done',1,'{\"agent\":\"keep-agent\"}');
                 INSERT INTO sekai_work_units
                   (id,kind,actor,status,scope_id,owner_principal,creator_principal,
                    target_object_id,requested_spec,created_at)
                 VALUES
                   ('subject-target-work','task','service','queued','scope',
                    'agent:other','agent:other','agent-object',
                    'review budget-erase-agent-daily',1);
                 INSERT INTO sekai_run_events
                   (id,work_unit_id,event_type,message,evidence_json,created_at)
                 VALUES
                   ('subject-related-event','subject-target-work','note',
                    'review budget-erase-agent-daily','{}',1);
                 INSERT INTO chisei_budget_limits
                   (scope_id,metric,parent_scope_id,max_amount,period_type)
                 VALUES
                   ('project:p/agent:erase-agent','tokens','project:p',100,'daily'),
                   ('project:p/agent:keep-agent','tokens','project:p',100,'daily'),
                   ('project:p','tokens','global',1000,'weekly'),
                   ('global','tokens','',10000,'monthly');",
            )
            .unwrap();
        }
        let budget_time = 10 * DAY_MS;
        db.budget_adjust_chain("project:p/agent:erase-agent", "tokens", 10, budget_time)
            .unwrap();
        db.budget_adjust_chain("agent:erase-agent", "tokens", 5, budget_time)
            .unwrap();
        db.budget_adjust_chain("project:p/agent:keep-agent", "tokens", 10, budget_time)
            .unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO chisei_budget_usage
                   (scope_id,metric,period_start,amount_used)
                 VALUES
                   ('project:legacy/agent:erase-agent','tokens',864000000,4),
                   ('project:legacy','tokens',604800000,4),
                   ('erase-agent','tokens',864000000,6)
                 ON CONFLICT(scope_id,metric,period_start)
                 DO UPDATE SET amount_used=amount_used+excluded.amount_used;
                 UPDATE chisei_budget_usage SET amount_used=amount_used+4
                 WHERE scope_id='global' AND metric='tokens';
                 UPDATE chisei_budget_usage SET amount_used=amount_used+4
                 WHERE scope_id='agent:erase-agent' AND metric='tokens';
                 UPDATE chisei_budget_usage SET amount_used=amount_used+3
                 WHERE scope_id='project:p/agent:erase-agent' AND metric='tokens';
                 UPDATE chisei_budget_usage SET amount_used=amount_used+5
                 WHERE scope_id='agent:erase-agent' AND metric='tokens';
                 UPDATE chisei_budget_usage SET amount_used=amount_used+3
                 WHERE scope_id='project:p' AND metric='tokens';
                 UPDATE chisei_budget_usage SET amount_used=amount_used+5
                 WHERE scope_id='global' AND metric='tokens';
                 UPDATE chisei_budget_usage SET amount_used=amount_used+6
                 WHERE scope_id='global' AND metric='tokens';",
            )
            .unwrap();
        for (id, actor) in [
            ("erase-decision", "erase-agent"),
            ("keep-decision", "keep-agent"),
        ] {
            db.record_decision(&Decision {
                id: id.into(),
                timestamp: 1,
                actor: actor.into(),
                action: "call".into(),
                reason: actor.into(),
                evidence: HashMap::from([("agent".into(), actor.into())]),
                target_id: actor.into(),
                outcome: actor.into(),
            })
            .unwrap();
        }
        db.record_decision(&Decision {
            id: "free-text-decision".into(),
            timestamp: 1,
            actor: "privacy-admin".into(),
            action: "request".into(),
            reason: "approved for erase-agent after review".into(),
            evidence: HashMap::from([("requester".into(), "erase-agent".into())]),
            target_id: String::new(),
            outcome: "approved".into(),
        })
        .unwrap();
        db.record_decision(&Decision {
            id: "scoped-decision".into(),
            timestamp: 1,
            actor: "project:default/agent:erase-agent".into(),
            action: "check".into(),
            reason: "scope checked".into(),
            evidence: HashMap::new(),
            target_id: String::new(),
            outcome: "allowed".into(),
        })
        .unwrap();
        db.record_decision(&Decision {
            id: "subject-object-decision".into(),
            timestamp: 1,
            actor: "privacy-admin".into(),
            action: "inspect".into(),
            reason: "request".into(),
            evidence: HashMap::new(),
            target_id: "agent-object".into(),
            outcome: "allowed".into(),
        })
        .unwrap();
        db.record_decision(&Decision {
            id: "subject-object-evidence".into(),
            timestamp: 1,
            actor: "privacy-admin".into(),
            action: "inspect".into(),
            reason: "request".into(),
            evidence: HashMap::from([("object_id".into(), "agent-object".into())]),
            target_id: "unrelated-object".into(),
            outcome: "allowed".into(),
        })
        .unwrap();
        db.record_decision(&Decision {
            id: "erase-agent-login".into(),
            timestamp: 1,
            actor: "privacy-admin".into(),
            action: "inspect".into(),
            reason: "request".into(),
            evidence: HashMap::new(),
            target_id: "unrelated-object".into(),
            outcome: "allowed".into(),
        })
        .unwrap();
        db.record_object_change(&crate::sekai::audit::ObjectChange {
            id: "change".into(),
            object_id: "agent-object".into(),
            field: "owner".into(),
            old_value: "private profile".into(),
            new_value: "released".into(),
            changed_by: "erase-agent".into(),
            timestamp: 1,
        })
        .unwrap();
        db.record_object_change(&crate::sekai::audit::ObjectChange {
            id: "external-id-change".into(),
            object_id: "referencing-object".into(),
            field: "external_id".into(),
            old_value: "budget:erase-agent:daily".into(),
            new_value: "budget:keep-agent:daily".into(),
            changed_by: "privacy-admin".into(),
            timestamp: 1,
        })
        .unwrap();
        db.record_object_change(&crate::sekai::audit::ObjectChange {
            id: "creation-change".into(),
            object_id: "referencing-object".into(),
            field: "_created".into(),
            old_value: String::new(),
            new_value: "project/erase-agent".into(),
            changed_by: "privacy-admin".into(),
            timestamp: 1,
        })
        .unwrap();
        db.record_object_change(&crate::sekai::audit::ObjectChange {
            id: "canonical-id-change".into(),
            object_id: "referencing-object".into(),
            field: "properties.agent-object".into(),
            old_value: "agent-object".into(),
            new_value: "unrelated-object".into(),
            changed_by: "privacy-admin".into(),
            timestamp: 1,
        })
        .unwrap();
        db.record_object_change(&crate::sekai::audit::ObjectChange {
            id: "subject-field-change".into(),
            object_id: "referencing-object".into(),
            field: "properties.agent:erase-agent".into(),
            old_value: "public".into(),
            new_value: "public".into(),
            changed_by: "privacy-admin".into(),
            timestamp: 1,
        })
        .unwrap();

        let result = db
            .erase_subject(&SubjectErasureRequest {
                subject_kind: "agent".into(),
                subject: "erase-agent".into(),
                requested_by: "erase-agent".into(),
                reason: "erase erase-agent by request".into(),
                timestamp: 10,
            })
            .unwrap();

        assert_eq!(result.llm_calls_deleted, 6);
        assert_eq!(result.task_observations_deleted, 5);
        assert_eq!(result.budget_records_deleted, 11);
        assert_eq!(result.audit_tombstoned, 6);
        assert_eq!(result.object_changes_tombstoned, 5);
        assert_eq!(result.objects_deleted, 4);
        assert_eq!(result.objects_tombstoned, 3);
        assert_eq!(result.work_unit_references_tombstoned, 1);
        assert_eq!(result.work_unit_text_tombstoned, 1);
        assert_eq!(result.coordination_text_tombstoned, 1);
        assert_eq!(result.links_deleted, 1);
        assert_eq!(result.grants_deleted, 1);
        assert!(db.get_object("agent-object").unwrap().is_none());
        assert!(db.get_decision("erase-agent-login").unwrap().is_none());
        let leaked_decision_ids: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_decisions WHERE id LIKE '%erase-agent%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(leaked_decision_ids, 0);
        assert!(db.get_object("related-approval").unwrap().is_none());
        let subject_dataset = db.get_dataset("subject-backed").unwrap().unwrap();
        assert_eq!(subject_dataset.object_id, "[erased]");
        let rekeyed_dataset = db.get_dataset("rekey-backed").unwrap().unwrap();
        assert_ne!(rekeyed_dataset.object_id, "budget-erase-agent-daily");
        assert!(db.get_object(&rekeyed_dataset.object_id).unwrap().is_some());
        assert!(db.get_object("keep-object").unwrap().is_some());
        let referencing = db.get_object("referencing-object").unwrap().unwrap();
        assert_eq!(referencing.properties["owner"], "[erased]");
        assert_eq!(referencing.properties["owner_id"], "[erased]");
        assert!(!referencing.properties.contains_key("owner_erase-agent"));
        assert_eq!(referencing.properties["[erased]"], "public");
        let canonical_change_field: String = db
            .conn()
            .query_row(
                "SELECT field FROM sekai_object_changes
                 WHERE id='canonical-id-change'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(canonical_change_field, "[erased]");
        let subject_change_field: String = db
            .conn()
            .query_row(
                "SELECT field FROM sekai_object_changes
                 WHERE id='subject-field-change'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(subject_change_field, "[erased]");
        let subject_related_event: String = db
            .conn()
            .query_row(
                "SELECT message FROM sekai_run_events WHERE id='subject-related-event'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(subject_related_event, "[erased]");
        assert_eq!(referencing.external_id, "[erased]");
        assert_eq!(
            db.get_object("namespace-reference")
                .unwrap()
                .unwrap()
                .namespace,
            "[erased]"
        );
        assert!(db.get_object("budget-erase-agent-daily").unwrap().is_none());
        assert!(db.get_object("pending-approval").unwrap().is_none());
        let rekeyed_budget_count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_objects
                 WHERE kind='budget' AND id LIKE 'erased-object:%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rekeyed_budget_count, 1);
        let leaked_links: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_links
                 WHERE id LIKE '%erase-agent%' OR from_id LIKE '%erase-agent%'
                    OR to_id LIKE '%erase-agent%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(leaked_links, 0);
        let remaining_budget_records: i64 = db
            .conn()
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM chisei_budget_limits) +
                   (SELECT COUNT(*) FROM chisei_budget_usage)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining_budget_records, 8);
        let ancestor_budget_usage: i64 = db
            .conn()
            .query_row(
                "SELECT SUM(amount_used) FROM chisei_budget_usage
                 WHERE scope_id IN ('global','project:p')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ancestor_budget_usage, 20);
        let legacy_project_usage: i64 = db
            .conn()
            .query_row(
                "SELECT amount_used FROM chisei_budget_usage
                 WHERE scope_id='project:legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_project_usage, 0);
        let target_object_id: String = db
            .conn()
            .query_row(
                "SELECT target_object_id FROM sekai_work_units
                 WHERE id='subject-target-work'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(target_object_id, "[erased]");
        let requested_spec: String = db
            .conn()
            .query_row(
                "SELECT requested_spec FROM sekai_work_units
                 WHERE id='subject-target-work'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(requested_spec, "[erased]");
        assert_ne!(result.subject_hash, "erase-agent");
        assert!(db.verify_ledger().unwrap().ok);
        let erased = db.get_decision("erase-decision").unwrap().unwrap();
        assert_eq!(erased.actor, "[erased]");
        assert_eq!(erased.evidence["erasure_tombstone"], "true");
        assert_eq!(erased.evidence["subject_hash"], result.subject_hash);
        let events = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("privacy.subject_erased".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].evidence["subject_hash"], result.subject_hash);

        let conn = db.conn();
        let usage: String = conn
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(data), '') FROM sekai_dataset_rows WHERE dataset_id='llm_calls'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let audit: String = conn
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(actor || action || reason || evidence || target_id || outcome), '') FROM sekai_decisions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let observations: String = conn
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(context_json), '') FROM sekai_task_observations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let changes: String = conn
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(object_id || changed_by || old_value || new_value), '') FROM sekai_object_changes",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!format!("{usage}{audit}{observations}{changes}").contains("erase-agent"));
    }

    #[test]
    fn subject_erasure_refuses_to_launder_invalid_ledger() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.record_decision(&Decision {
            id: "tampered".into(),
            timestamp: 1,
            actor: "agent".into(),
            action: "call".into(),
            reason: "original".into(),
            evidence: HashMap::new(),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();
        db.conn()
            .execute(
                "UPDATE sekai_decisions SET seq=NULL WHERE id='tampered'",
                [],
            )
            .unwrap();

        let error = db
            .erase_subject(&SubjectErasureRequest {
                subject_kind: "agent".into(),
                subject: "absent".into(),
                requested_by: "privacy-admin".into(),
                reason: "request".into(),
                timestamp: 10,
            })
            .unwrap_err();
        assert!(error.contains("incomplete chain metadata"));
        assert!(!db.verify_ledger().unwrap().ok);
    }

    #[test]
    fn subject_erasure_does_not_match_identifier_prefixes() {
        let db = SekaiDb::new(":memory:").unwrap();
        for (id, agent) in [("exact", "agent1"), ("prefix", "agent10")] {
            db.record_decision(&Decision {
                id: id.into(),
                timestamp: 1,
                actor: agent.into(),
                action: "call".into(),
                reason: agent.into(),
                evidence: HashMap::from([("agent".into(), agent.into())]),
                target_id: String::new(),
                outcome: "ok".into(),
            })
            .unwrap();
        }
        db.record_decision(&Decision {
            id: "other-scope".into(),
            timestamp: 1,
            actor: "budget".into(),
            action: "check".into(),
            reason: "project scope".into(),
            evidence: HashMap::from([("budget_subject".into(), "project:agent1".into())]),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();
        db.record_object_change(&crate::sekai::audit::ObjectChange {
            id: "prefix-change".into(),
            object_id: "object".into(),
            field: "owner".into(),
            old_value: "owned by agent10".into(),
            new_value: "unchanged".into(),
            changed_by: "agent10".into(),
            timestamp: 1,
        })
        .unwrap();
        db.create_object(&crate::domain::Object {
            id: "agent1-smith".into(),
            kind: "agent".into(),
            name: "Agent Smith".into(),
            namespace: "ns".into(),
            external_id: "agent1-smith".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();

        db.erase_subject(&SubjectErasureRequest {
            subject_kind: "agent".into(),
            subject: "agent1".into(),
            requested_by: "privacy-admin".into(),
            reason: "request".into(),
            timestamp: 10,
        })
        .unwrap();

        assert_eq!(db.get_decision("exact").unwrap().unwrap().actor, "[erased]");
        assert_eq!(db.get_decision("prefix").unwrap().unwrap().actor, "agent10");
        assert_eq!(
            db.get_decision("other-scope").unwrap().unwrap().actor,
            "budget"
        );
        let prefix_change: (String, String) = db
            .conn()
            .query_row(
                "SELECT changed_by, old_value FROM sekai_object_changes WHERE id='prefix-change'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(prefix_change.0, "agent10");
        assert_eq!(prefix_change.1, "owned by agent10");
        assert!(db.get_object("agent1-smith").unwrap().is_some());
        assert!(db.verify_ledger().unwrap().ok);
    }

    #[test]
    fn work_unit_erasure_removes_coordination_state() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO sekai_work_units
                   (id,kind,actor,status,scope_id,created_at)
                 VALUES ('wu-1','task','agent','queued','scope',1);
                 INSERT INTO sekai_reservations
                   (id,work_unit_id,scope_id,status,leased_at,expires_at,created_at)
                 VALUES ('reservation','wu-1','scope','active',1,2,1);
                 INSERT INTO sekai_run_events
                   (id,work_unit_id,event_type,message,created_at)
                 VALUES ('event','wu-1','created','private',1);
                 INSERT INTO sekai_reconciliations
                   (id,work_unit_id,reservation_id,reason,action,created_at)
                 VALUES ('reconcile','wu-1','reservation','private','release',1);
                 INSERT INTO sekai_coordination_requests
                   (request_id,operation,work_unit_id,created_at)
                 VALUES ('request','create','wu-1',1);
                 INSERT INTO sekai_object_sets
                   (id,name,description,filter,owner_principal,created)
                 VALUES ('unrelated-set','saved','saved','{}','wu-1',1);",
            )
            .unwrap();

        let result = db
            .erase_subject(&SubjectErasureRequest {
                subject_kind: "work_unit".into(),
                subject: "wu-1".into(),
                requested_by: "privacy-admin".into(),
                reason: "request".into(),
                timestamp: 10,
            })
            .unwrap();

        assert_eq!(result.work_units_deleted, 1);
        let conn = db.conn();
        for table in [
            "sekai_work_units",
            "sekai_reservations",
            "sekai_run_events",
            "sekai_reconciliations",
            "sekai_coordination_requests",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
        let object_sets: i64 = conn
            .query_row("SELECT COUNT(*) FROM sekai_object_sets", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(object_sets, 1);
    }

    #[test]
    fn user_erasure_removes_grants_and_credentials() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO sekai_grants (id,object_id,principal,role,created)
                 VALUES ('grant','object','user:alice','reader',1);
                 INSERT INTO sekai_object_sets
                   (id,name,description,filter,owner_principal,created)
                 VALUES
                   ('set','private','private','{}','alice',1),
                   ('admin-set','review','review',
                    '{\"property_filters\":[{\"key\":\"owner\",\"value\":\"alice\"}]}',
                    'privacy-admin',1),
                   ('admin-in-set','review-in','review',
                    '{\"property_filters\":[{\"key\":\"owner\",\"op\":\"in\",\"value\":\"bob,alice\"}]}',
                    'privacy-admin',1);
                 INSERT INTO sekai_contention_scopes
                   (id,name,max_concurrency,owner_principal,created,updated)
                 VALUES ('scope','private',1,'user:alice',1,1);",
            )
            .unwrap();
        db.create_principal_credential(
            "alice",
            &crate::gateway_keys::hash_gateway_key("secret"),
            1,
        )
        .unwrap();
        let store = crate::sekai::credentials::PrincipalCredentialStore::new();
        assert!(store.maybe_reload(&db));
        assert_eq!(store.resolve("secret").as_deref(), Some("alice"));
        db.record_decision(&Decision {
            id: "typed-user".into(),
            timestamp: 1,
            actor: "user:alice".into(),
            action: "read".into(),
            reason: "request".into(),
            evidence: HashMap::new(),
            target_id: String::new(),
            outcome: "ok".into(),
        })
        .unwrap();

        let result = db
            .erase_subject(&SubjectErasureRequest {
                subject_kind: "user".into(),
                subject: "alice".into(),
                requested_by: "privacy-admin".into(),
                reason: "request".into(),
                timestamp: 10,
            })
            .unwrap();

        assert_eq!(result.grants_deleted, 1);
        assert_eq!(result.credentials_deleted, 1);
        assert_eq!(result.object_sets_deleted, 3);
        assert_eq!(result.contention_scopes_tombstoned, 1);
        assert_eq!(result.audit_tombstoned, 1);
        assert!(store.maybe_reload(&db));
        assert!(store.resolve("secret").is_none());
        let conn = db.conn();
        let grants: i64 = conn
            .query_row("SELECT COUNT(*) FROM sekai_grants", [], |row| row.get(0))
            .unwrap();
        let active_credentials: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sekai_principal_credentials WHERE status='active' OR principal='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((grants, active_credentials), (0, 0));
        let object_sets: i64 = conn
            .query_row("SELECT COUNT(*) FROM sekai_object_sets", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(object_sets, 0);
        let scope_owner: String = conn
            .query_row(
                "SELECT owner_principal FROM sekai_contention_scopes WHERE id='scope'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(scope_owner.is_empty());
    }

    #[test]
    fn common_literal_subjects_require_attributable_value_context() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[
                HashMap::from([("status".into(), "done".into())]),
                HashMap::from([("agent".into(), "done".into())]),
            ],
        )
        .unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO sekai_task_observations
                 (request_id,namespace,component_id,model,status,timestamp,context_json)
                 VALUES
                   ('status','ns','component','','done',1,'{\"status\":\"done\"}'),
                   ('owner','ns','component','','done',1,'{\"owner\":\"done\"}');",
            )
            .unwrap();
        db.create_object(&crate::domain::Object {
            id: "literal-object".into(),
            kind: "project".into(),
            name: "literal".into(),
            namespace: "ns".into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("status".into(), "done".into()),
                ("owner".into(), "done".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();

        let result = db
            .erase_subject(&SubjectErasureRequest {
                subject_kind: "agent".into(),
                subject: "done".into(),
                requested_by: "privacy-admin".into(),
                reason: "request".into(),
                timestamp: 10,
            })
            .unwrap();

        assert_eq!(result.llm_calls_deleted, 1);
        assert_eq!(result.task_observations_deleted, 1);
        let object = db.get_object("literal-object").unwrap().unwrap();
        assert_eq!(object.properties["status"], "done");
        assert_eq!(object.properties["owner"], "[erased]");
    }

    #[test]
    fn generic_subject_ids_do_not_match_unrelated_schema_keys() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: LLM_CALLS_DATASET.into(),
            name: "calls".into(),
            columns: Vec::new(),
            object_id: String::new(),
            created: 0,
        })
        .unwrap();
        db.append_rows(
            LLM_CALLS_DATASET,
            &[
                HashMap::from([("user_id".into(), "other".into())]),
                HashMap::from([("user_notes".into(), "private".into())]),
            ],
        )
        .unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO sekai_task_observations
                 (request_id,namespace,component_id,model,status,timestamp,context_json)
                 VALUES
                   ('request','ns','component','','done',1,'{\"user_id\":\"other\"}'),
                   ('private','ns','component','','done',1,'{\"owner_user\":\"private\"}');",
            )
            .unwrap();
        db.create_object(&crate::domain::Object {
            id: "schema-object".into(),
            kind: "project".into(),
            name: "schema".into(),
            namespace: "ns".into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("user_id".into(), "other".into()),
                ("user_notes".into(), "private".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();

        let result = db
            .erase_subject(&SubjectErasureRequest {
                subject_kind: "user".into(),
                subject: "user".into(),
                requested_by: "privacy-admin".into(),
                reason: "request".into(),
                timestamp: 10,
            })
            .unwrap();

        assert_eq!(result.llm_calls_deleted, 0);
        assert_eq!(result.task_observations_deleted, 0);
        let llm_rows: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_dataset_rows WHERE dataset_id='llm_calls'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(llm_rows, 2);
        let object = db.get_object("schema-object").unwrap().unwrap();
        assert_eq!(object.properties["user_id"], "other");
        assert_eq!(object.properties["user_notes"], "private");
    }

    #[test]
    fn agent_erasure_removes_agent_principal_state() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO sekai_grants (id,object_id,principal,role,created)
                 VALUES ('grant','object','project:default/agent:bot','writer',1);
                 INSERT INTO sekai_principal_credentials
                   (id,principal,token_hash,status,created)
                 VALUES ('credential','project:default/agent:bot','hash','active',1);
                 INSERT INTO sekai_work_units
                   (id,kind,actor,status,scope_id,owner_principal,creator_principal,created_at)
                 VALUES ('owned-work','task','service','queued','scope','agent:bot','agent:bot',1);
                 INSERT INTO sekai_run_events
                   (id,work_unit_id,event_type,message,created_at)
                 VALUES ('owned-event','owned-work','created','private',1);
                 INSERT INTO sekai_work_units
                   (id,kind,actor,status,scope_id,owner_principal,creator_principal,created_at)
                 VALUES ('other-work','task','service','queued','scope','agent:other','agent:other',1);
                 INSERT INTO sekai_work_units
                   (id,kind,actor,status,scope_id,owner_principal,creator_principal,created_at)
                 VALUES
                   ('scoped-work','task','service','queued','project:p/agent:bot',
                    'agent:other','agent:other',1);
                 INSERT INTO sekai_work_units
                   (id,kind,actor,status,scope_id,owner_principal,creator_principal,target_object_id,created_at)
                 VALUES ('target-work','task','service','queued','scope','agent:other','agent:other','agent:bot',1);
                 INSERT INTO sekai_reservations
                   (id,work_unit_id,scope_id,status,lease_owner,leased_at,expires_at,created_at)
                 VALUES
                   ('res:other-work:project:p/agent:bot','other-work',
                    'project:p/agent:bot','active',
                    'agent:bot',1,2,1);
                 INSERT INTO sekai_coordination_requests
                   (request_id,operation,principal,scope_id,work_unit_id,created_at)
                 VALUES
                   ('other-request','reserve','bot','project:p/agent:bot','other-work',1);
                 INSERT INTO sekai_run_events
                   (id,work_unit_id,event_type,message,evidence_json,created_at)
                 VALUES
                   ('other-event','other-work','note','agent:bot reviewed','{}',1);
                 INSERT INTO sekai_reconciliations
                   (id,work_unit_id,reservation_id,reason,action,created_at)
                 VALUES
                   ('other-reconcile','other-work','','review agent bot','release',1),
                   ('reservation-reconcile','other-work',
                    'res:other-work:project:p/agent:bot','lease held','hold',1);",
            )
            .unwrap();
        db.record_object_change(&crate::sekai::audit::ObjectChange {
            id: "typed-agent-change".into(),
            object_id: "unrelated-object".into(),
            field: "name".into(),
            old_value: "public".into(),
            new_value: "public".into(),
            changed_by: "project:default/agent:bot".into(),
            timestamp: 1,
        })
        .unwrap();

        let result = db
            .erase_subject(&SubjectErasureRequest {
                subject_kind: "agent".into(),
                subject: "bot".into(),
                requested_by: "privacy-admin".into(),
                reason: "Keep AGENT:BOT out of logs".into(),
                timestamp: 10,
            })
            .unwrap();

        assert_eq!(result.grants_deleted, 1);
        assert_eq!(result.credentials_deleted, 1);
        assert_eq!(result.work_units_deleted, 3);
        assert_eq!(result.object_changes_tombstoned, 1);
        assert_eq!(result.coordination_references_tombstoned, 4);
        assert_eq!(result.coordination_text_tombstoned, 2);
        let erased_principals: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_principal_credentials
                 WHERE principal='bot' OR principal LIKE '%/agent:bot'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(erased_principals, 0);
        let work_units: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM sekai_work_units", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(work_units, 1);
        let coordination_references: (String, String, String, String) = db
            .conn()
            .query_row(
                "SELECT r.lease_owner, c.principal, r.scope_id, c.scope_id
                 FROM sekai_reservations r
                 JOIN sekai_coordination_requests c ON c.work_unit_id=r.work_unit_id
                 WHERE r.work_unit_id='other-work'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            coordination_references,
            (
                "[erased]".into(),
                "[erased]".into(),
                "[erased]".into(),
                "[erased]".into()
            )
        );
        let reservation_reference: (String, String) = db
            .conn()
            .query_row(
                "SELECT r.id, c.reservation_id
                 FROM sekai_reservations r
                 JOIN sekai_reconciliations c ON c.work_unit_id=r.work_unit_id
                 WHERE c.id='reservation-reconcile'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(reservation_reference.0, reservation_reference.1);
        assert!(reservation_reference.0.starts_with("erased-reservation:"));
        assert!(!reservation_reference.0.contains("bot"));
        let coordination_text: (String, String) = db
            .conn()
            .query_row(
                "SELECT e.message, r.reason FROM sekai_run_events e
                 JOIN sekai_reconciliations r ON r.work_unit_id=e.work_unit_id
                 WHERE e.id='other-event'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(coordination_text, ("[erased]".into(), "[erased]".into()));
        let events = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("privacy.subject_erased".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            events[0].evidence["coordination_references_tombstoned"],
            "4"
        );
        assert_eq!(events[0].reason, "subject erasure completed");
        let changed_by: String = db
            .conn()
            .query_row(
                "SELECT changed_by FROM sekai_object_changes WHERE id='typed-agent-change'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(changed_by, "[erased]");
    }
}
