//! What an agent turn did (#3045): the model route and token counts the
//! worker reports, the prompt as a reference under a marking, and an ordered
//! list of steps. A console reads this from the plane instead of keeping its
//! own copy of every turn.
//!
//! The worker appends under the turn's live claim. The fence is checked in
//! the same transaction as the write, so a lapsed or superseded claim
//! cannot append. Appends are idempotent: usage is the worker's latest
//! report, the prompt is recorded once, and a step is keyed by the worker's
//! `step_id`. Repeating a step or prompt with the same content is a no-op;
//! the same key with different content is refused. Past a bound an append
//! is refused, never truncated.
//!
//! An `action` step stores only the ActionInstance id. Its decision and
//! receipt are read from the Action, so the transcript never disagrees
//! with it. Subject erasure removes prompt text and marks the transcript
//! erased; an erased transcript refuses every further append.
//!
//! The transcript lives in its own tables, so acknowledging a turn never
//! rewrites it and an older plane instance during a rolling deploy cannot
//! drop it.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{AgentTurn, COLUMNS, TurnError, load, pg_turn};
use crate::db::postgres::{PostgresDb, off_runtime};
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;

/// Steps one turn may hold.
pub const MAX_TRANSCRIPT_STEPS: usize = 256;
/// UTF-8 bytes of prompt text.
pub const MAX_PROMPT_TEXT_BYTES: usize = 65_536;
/// UTF-8 bytes of a step id, name, target, route or prompt reference.
pub const MAX_TRANSCRIPT_FIELD_BYTES: usize = 512;

/// A step's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StepKind {
    ToolCall,
    Action,
}

impl StepKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tool_call" => Some(Self::ToolCall),
            "action" => Some(Self::Action),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToolCall => "tool_call",
            Self::Action => "action",
        }
    }
}

/// Model route and token counts, as the worker reports them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TurnUsage {
    pub model_route: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

/// The prompt a worker records: a reference, the marking of the data it was
/// built from, and optionally its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptRecord {
    pub reference: String,
    pub marking: String,
    pub text: Option<String>,
}

/// One appended step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    pub step_id: String,
    pub kind: StepKind,
    pub name: String,
    pub target: String,
    /// The ActionInstance an `action` step submitted; empty for a tool call.
    pub action_instance_id: String,
}

/// A stored step, in append order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptStep {
    pub sequence: i64,
    pub record: StepRecord,
    pub recorded_at_ms: i64,
}

/// One append; each part is optional and applied together.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TranscriptAppend {
    pub usage: Option<TurnUsage>,
    pub prompt: Option<PromptRecord>,
    pub step: Option<StepRecord>,
}

/// A turn's transcript. Prompt text is never part of it; read it with
/// [`prompt_text`] after a clearance check.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TurnTranscript {
    pub usage: Option<TurnUsage>,
    pub prompt_reference: String,
    pub prompt_marking: String,
    /// Prompt text is stored and has not been erased.
    pub prompt_text_stored: bool,
    /// Subject erasure removed prompt text; appends are refused.
    pub erased_at_ms: i64,
    pub steps: Vec<TranscriptStep>,
}

/// The stored transcript row, as both stores keep it.
#[derive(Debug, Clone, Default)]
struct Row {
    usage: Option<TurnUsage>,
    prompt_reference: String,
    prompt_marking: String,
    prompt_text: Option<String>,
    erased_at_ms: i64,
}

/// What an append writes once it is admitted.
struct Plan {
    row: Row,
    new_step: Option<StepRecord>,
}

/// Checks `append` against the stored transcript and decides what to write.
fn plan(row: Row, steps: &[TranscriptStep], append: TranscriptAppend) -> Result<Plan, TurnError> {
    if row.erased_at_ms > 0 {
        return Err(TurnError::Invalid(
            "agent turn transcript was erased; appends are refused".into(),
        ));
    }
    if append.usage.is_none() && append.prompt.is_none() && append.step.is_none() {
        return Err(TurnError::Invalid(
            "an append needs usage, a prompt or a step".into(),
        ));
    }
    let mut row = row;
    if let Some(usage) = append.usage {
        bounded("model_route", &usage.model_route, true)?;
        if usage.input_tokens < 0 || usage.output_tokens < 0 {
            return Err(TurnError::Invalid(
                "token counts must not be negative".into(),
            ));
        }
        row.usage = Some(usage);
    }
    if let Some(prompt) = append.prompt {
        bounded("prompt reference", &prompt.reference, true)?;
        if prompt.marking.trim().is_empty() {
            return Err(TurnError::Invalid("a prompt needs a marking".into()));
        }
        if let Some(text) = &prompt.text
            && text.len() > MAX_PROMPT_TEXT_BYTES
        {
            return Err(TurnError::Invalid(format!(
                "prompt text exceeds {MAX_PROMPT_TEXT_BYTES} bytes"
            )));
        }
        if row.prompt_reference.is_empty() {
            row.prompt_reference = prompt.reference;
            row.prompt_marking = prompt.marking;
            row.prompt_text = prompt.text;
        } else if row.prompt_reference != prompt.reference
            || row.prompt_marking != prompt.marking
            || row.prompt_text != prompt.text
        {
            return Err(TurnError::Invalid(
                "agent turn already recorded a different prompt".into(),
            ));
        }
    }
    let mut new_step = None;
    if let Some(step) = append.step {
        bounded("step_id", &step.step_id, true)?;
        bounded("step name", &step.name, true)?;
        bounded("step target", &step.target, false)?;
        match step.kind {
            StepKind::Action if step.action_instance_id.trim().is_empty() => {
                return Err(TurnError::Invalid(
                    "an action step needs its action_instance_id".into(),
                ));
            }
            StepKind::ToolCall if !step.action_instance_id.is_empty() => {
                return Err(TurnError::Invalid(
                    "a tool_call step carries no action_instance_id".into(),
                ));
            }
            _ => {}
        }
        match steps
            .iter()
            .find(|stored| stored.record.step_id == step.step_id)
        {
            Some(stored) if stored.record == step => {}
            Some(_) => {
                return Err(TurnError::Invalid(
                    "step_id was already recorded with different content".into(),
                ));
            }
            None if steps.len() >= MAX_TRANSCRIPT_STEPS => {
                return Err(TurnError::Invalid(format!(
                    "agent turn holds at most {MAX_TRANSCRIPT_STEPS} steps"
                )));
            }
            None => new_step = Some(step),
        }
    }
    Ok(Plan { row, new_step })
}

fn bounded(field: &str, value: &str, required: bool) -> Result<(), TurnError> {
    if required && value.trim().is_empty() {
        return Err(TurnError::Invalid(format!("{field} is required")));
    }
    if value.len() > MAX_TRANSCRIPT_FIELD_BYTES {
        return Err(TurnError::Invalid(format!(
            "{field} exceeds {MAX_TRANSCRIPT_FIELD_BYTES} bytes"
        )));
    }
    Ok(())
}

fn transcript(row: Row, steps: Vec<TranscriptStep>) -> TurnTranscript {
    TurnTranscript {
        usage: row.usage,
        prompt_reference: row.prompt_reference,
        prompt_marking: row.prompt_marking,
        prompt_text_stored: row.prompt_text.is_some(),
        erased_at_ms: row.erased_at_ms,
        steps,
    }
}

/// Appends to the transcript of `turn_id` under its live claim, checked in
/// the same transaction as the write. Returns the transcript as stored after
/// the append. Callers check the prompt marking against the turn's principal
/// first.
pub fn append(
    db: &RuntimeDb,
    turn_id: &str,
    runtime_id: &str,
    claim_generation: i64,
    fencing_token: &str,
    append: TranscriptAppend,
    now_ms: i64,
) -> Result<TurnTranscript, TurnError> {
    let live =
        |turn: &AgentTurn| turn.require_live(runtime_id, claim_generation, fencing_token, now_ms);
    match db {
        RuntimeDb::Sqlite(store) => store.append_turn_transcript(turn_id, live, append, now_ms),
        RuntimeDb::Postgres(store) => {
            off_runtime(|| store.append_turn_transcript(turn_id, live, append, now_ms))
        }
    }
}

/// The transcript of `turn_id`; empty when nothing was appended.
pub fn get(db: &RuntimeDb, turn_id: &str) -> Result<TurnTranscript, TurnError> {
    let (row, steps) = match db {
        RuntimeDb::Sqlite(store) => {
            let conn = store.conn();
            (sqlite_row(&conn, turn_id)?, sqlite_steps(&conn, turn_id)?)
        }
        RuntimeDb::Postgres(store) => off_runtime(|| {
            let mut connection = store.connection()?;
            let row = pg_row(&mut *connection, turn_id, false)?;
            let steps = pg_steps(&mut *connection, turn_id)?;
            Ok::<_, TurnError>((row, steps))
        })?,
    };
    Ok(transcript(row.unwrap_or_default(), steps))
}

/// The prompt text of `turn_id`, when stored and not erased. Callers check
/// the reader's clearance for the prompt marking first.
pub fn prompt_text(db: &RuntimeDb, turn_id: &str) -> Result<Option<String>, TurnError> {
    let row = match db {
        RuntimeDb::Sqlite(store) => sqlite_row(&store.conn(), turn_id)?,
        RuntimeDb::Postgres(store) => off_runtime(|| {
            let mut connection = store.connection()?;
            pg_row(&mut *connection, turn_id, false)
        })?,
    };
    Ok(row.and_then(|row| row.prompt_text))
}

/// Which turns a subject erasure reaches: the instance principal for an
/// `agent`, the requester of a manual turn for a `user`, and any turn whose
/// prompt text references the subject.
pub(crate) fn turn_matches_subject(
    principal_id: &str,
    cause: &str,
    admitted_by: &str,
    prompt_text: Option<&str>,
    kind: &str,
    subject: &str,
    references: impl Fn(&str) -> bool,
) -> bool {
    let by_identity = match kind {
        "agent" => principal_id == subject,
        "user" => cause == "manual" && admitted_by == subject,
        _ => false,
    };
    by_identity || prompt_text.is_some_and(references)
}

pub(crate) const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_agent_turn_transcript (
    turn_id TEXT PRIMARY KEY,
    usage_reported INTEGER NOT NULL DEFAULT 0,
    model_route TEXT NOT NULL DEFAULT '',
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    prompt_reference TEXT NOT NULL DEFAULT '',
    prompt_marking TEXT NOT NULL DEFAULT '',
    prompt_text TEXT,
    erased_at_ms INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_agent_turn_step (
    turn_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    step_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    action_instance_id TEXT NOT NULL DEFAULT '',
    recorded_at_ms INTEGER NOT NULL,
    PRIMARY KEY (turn_id, sequence),
    UNIQUE (turn_id, step_id)
);
";

const ROW_COLUMNS: &str = "usage_reported, model_route, input_tokens, output_tokens,
    prompt_reference, prompt_marking, prompt_text, erased_at_ms";

const STEP_COLUMNS: &str =
    "sequence, step_id, kind, name, target, action_instance_id, recorded_at_ms";

/// Usage as stored: kept only once the worker reported it.
fn usage_from(
    reported: bool,
    model_route: String,
    input_tokens: i64,
    output_tokens: i64,
) -> Option<TurnUsage> {
    reported.then_some(TurnUsage {
        model_route,
        input_tokens,
        output_tokens,
    })
}

fn row_from(
    usage: Option<TurnUsage>,
    prompt_reference: String,
    prompt_marking: String,
    prompt_text: Option<String>,
    erased_at_ms: i64,
) -> Row {
    Row {
        usage,
        prompt_reference,
        prompt_marking,
        prompt_text,
        erased_at_ms,
    }
}

fn step_from(
    sequence: i64,
    step_id: String,
    kind: &str,
    name: String,
    target: String,
    action_instance_id: String,
    recorded_at_ms: i64,
) -> Result<TranscriptStep, TurnError> {
    Ok(TranscriptStep {
        sequence,
        record: StepRecord {
            step_id,
            kind: StepKind::parse(kind)
                .ok_or_else(|| TurnError::Internal(format!("stored step kind {kind}")))?,
            name,
            target,
            action_instance_id,
        },
        recorded_at_ms,
    })
}

fn sqlite_row(conn: &rusqlite::Connection, turn_id: &str) -> Result<Option<Row>, TurnError> {
    Ok(conn
        .query_row(
            &format!("SELECT {ROW_COLUMNS} FROM sekai_agent_turn_transcript WHERE turn_id = ?1"),
            params![turn_id],
            |row| {
                Ok(row_from(
                    usage_from(
                        row.get::<_, i64>(0)? != 0,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                    ),
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?)
}

fn sqlite_steps(
    conn: &rusqlite::Connection,
    turn_id: &str,
) -> Result<Vec<TranscriptStep>, TurnError> {
    let mut statement = conn.prepare(&format!(
        "SELECT {STEP_COLUMNS} FROM sekai_agent_turn_step WHERE turn_id = ?1 ORDER BY sequence"
    ))?;
    let rows = statement
        .query_map(params![turn_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(sequence, step_id, kind, name, target, action, at)| {
            step_from(sequence, step_id, &kind, name, target, action, at)
        })
        .collect()
}

fn pg_row(
    client: &mut impl postgres::GenericClient,
    turn_id: &str,
    lock: bool,
) -> Result<Option<Row>, TurnError> {
    let lock = if lock { " FOR UPDATE" } else { "" };
    let row = client.query_opt(
        &format!("SELECT {ROW_COLUMNS} FROM sekai_agent_turn_transcript WHERE turn_id = $1{lock}"),
        &[&turn_id],
    )?;
    Ok(row.map(|row| {
        row_from(
            usage_from(row.get(0), row.get(1), row.get(2), row.get(3)),
            row.get(4),
            row.get(5),
            row.get(6),
            row.get(7),
        )
    }))
}

fn pg_steps(
    client: &mut impl postgres::GenericClient,
    turn_id: &str,
) -> Result<Vec<TranscriptStep>, TurnError> {
    client
        .query(
            &format!(
                "SELECT {STEP_COLUMNS} FROM sekai_agent_turn_step WHERE turn_id = $1
                 ORDER BY sequence"
            ),
            &[&turn_id],
        )?
        .iter()
        .map(|row| {
            step_from(
                row.get(0),
                row.get(1),
                row.get::<_, &str>(2),
                row.get(3),
                row.get(4),
                row.get(5),
                row.get(6),
            )
        })
        .collect()
}

impl SekaiDb {
    pub(crate) fn migrate_agent_turn_transcripts(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    fn append_turn_transcript(
        &self,
        turn_id: &str,
        live: impl FnOnce(&AgentTurn) -> Result<(), TurnError>,
        append: TranscriptAppend,
        now_ms: i64,
    ) -> Result<TurnTranscript, TurnError> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let turn = load(&tx, turn_id)?.ok_or(TurnError::NotFound)?;
        live(&turn)?;
        let mut steps = sqlite_steps(&tx, turn_id)?;
        let plan = plan(
            sqlite_row(&tx, turn_id)?.unwrap_or_default(),
            &steps,
            append,
        )?;
        let usage = plan.row.usage.clone().unwrap_or_default();
        tx.execute(
            "INSERT INTO sekai_agent_turn_transcript (turn_id, usage_reported, model_route,
                 input_tokens, output_tokens, prompt_reference, prompt_marking, prompt_text,
                 erased_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)
             ON CONFLICT (turn_id) DO UPDATE SET usage_reported = excluded.usage_reported,
                 model_route = excluded.model_route, input_tokens = excluded.input_tokens,
                 output_tokens = excluded.output_tokens,
                 prompt_reference = excluded.prompt_reference,
                 prompt_marking = excluded.prompt_marking, prompt_text = excluded.prompt_text,
                 updated_at_ms = excluded.updated_at_ms",
            params![
                turn_id,
                i64::from(plan.row.usage.is_some()),
                usage.model_route,
                usage.input_tokens,
                usage.output_tokens,
                plan.row.prompt_reference,
                plan.row.prompt_marking,
                plan.row.prompt_text,
                now_ms,
            ],
        )?;
        if let Some(step) = plan.new_step {
            let sequence = steps.len() as i64;
            tx.execute(
                "INSERT INTO sekai_agent_turn_step (turn_id, sequence, step_id, kind, name,
                     target, action_instance_id, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    turn_id,
                    sequence,
                    step.step_id,
                    step.kind.as_str(),
                    step.name,
                    step.target,
                    step.action_instance_id,
                    now_ms,
                ],
            )?;
            steps.push(TranscriptStep {
                sequence,
                record: step,
                recorded_at_ms: now_ms,
            });
        }
        tx.commit()?;
        Ok(transcript(plan.row, steps))
    }
}

impl PostgresDb {
    fn append_turn_transcript(
        &self,
        turn_id: &str,
        live: impl FnOnce(&AgentTurn) -> Result<(), TurnError>,
        append: TranscriptAppend,
        now_ms: i64,
    ) -> Result<TurnTranscript, TurnError> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction()?;
        // The turn row lock serializes appends with claim changes, so the
        // fence read here is the fence at commit.
        let turn = tx
            .query_opt(
                &format!("SELECT {COLUMNS} FROM sekai_agent_turn WHERE turn_id = $1 FOR UPDATE"),
                &[&turn_id],
            )?
            .ok_or(TurnError::NotFound)?;
        live(&pg_turn(&turn)?)?;
        let mut steps = pg_steps(&mut tx, turn_id)?;
        let plan = plan(
            pg_row(&mut tx, turn_id, true)?.unwrap_or_default(),
            &steps,
            append,
        )?;
        let usage = plan.row.usage.clone().unwrap_or_default();
        tx.execute(
            "INSERT INTO sekai_agent_turn_transcript (turn_id, usage_reported, model_route,
                 input_tokens, output_tokens, prompt_reference, prompt_marking, prompt_text,
                 erased_at_ms, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9)
             ON CONFLICT (turn_id) DO UPDATE SET usage_reported = EXCLUDED.usage_reported,
                 model_route = EXCLUDED.model_route, input_tokens = EXCLUDED.input_tokens,
                 output_tokens = EXCLUDED.output_tokens,
                 prompt_reference = EXCLUDED.prompt_reference,
                 prompt_marking = EXCLUDED.prompt_marking, prompt_text = EXCLUDED.prompt_text,
                 updated_at_ms = EXCLUDED.updated_at_ms",
            &[
                &turn_id,
                &plan.row.usage.is_some(),
                &usage.model_route,
                &usage.input_tokens,
                &usage.output_tokens,
                &plan.row.prompt_reference,
                &plan.row.prompt_marking,
                &plan.row.prompt_text,
                &now_ms,
            ],
        )?;
        if let Some(step) = plan.new_step {
            let sequence = steps.len() as i64;
            tx.execute(
                "INSERT INTO sekai_agent_turn_step (turn_id, sequence, step_id, kind, name,
                     target, action_instance_id, recorded_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &turn_id,
                    &sequence,
                    &step.step_id,
                    &step.kind.as_str(),
                    &step.name,
                    &step.target,
                    &step.action_instance_id,
                    &now_ms,
                ],
            )?;
            steps.push(TranscriptStep {
                sequence,
                record: step,
                recorded_at_ms: now_ms,
            });
        }
        tx.commit()?;
        Ok(transcript(plan.row, steps))
    }
}

/// Erases prompt text of every turn the subject reaches, inside an erasure
/// transaction on SQLite, and marks each such transcript erased so later
/// appends are refused. Returns how many transcripts it marked.
pub(crate) fn erase_subject_sqlite(
    tx: &rusqlite::Transaction<'_>,
    kind: &str,
    subject: &str,
    references: impl Fn(&str) -> bool,
    now_ms: i64,
) -> Result<usize, String> {
    let candidates = {
        let mut statement = tx
            .prepare(
                "SELECT t.turn_id, t.principal_id, t.cause, t.admitted_by, x.prompt_text
                 FROM sekai_agent_turn t
                 LEFT JOIN sekai_agent_turn_transcript x ON x.turn_id = t.turn_id
                 WHERE COALESCE(x.erased_at_ms, 0) = 0",
            )
            .map_err(|error| error.to_string())?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    let mut erased = 0;
    for (turn_id, principal_id, cause, admitted_by, text) in candidates {
        if !turn_matches_subject(
            &principal_id,
            &cause,
            &admitted_by,
            text.as_deref(),
            kind,
            subject,
            &references,
        ) {
            continue;
        }
        tx.execute(
            "INSERT INTO sekai_agent_turn_transcript (turn_id, erased_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?2)
             ON CONFLICT (turn_id) DO UPDATE SET prompt_text = NULL,
                 erased_at_ms = excluded.erased_at_ms, updated_at_ms = excluded.updated_at_ms",
            params![turn_id, now_ms.max(1)],
        )
        .map_err(|error| error.to_string())?;
        erased += 1;
    }
    Ok(erased)
}

/// [`erase_subject_sqlite`] inside a PostgreSQL erasure transaction.
pub(crate) fn erase_subject_pg(
    tx: &mut impl postgres::GenericClient,
    kind: &str,
    subject: &str,
    references: impl Fn(&str) -> bool,
    now_ms: i64,
) -> Result<usize, String> {
    let candidates = tx
        .query(
            "SELECT t.turn_id, t.principal_id, t.cause, t.admitted_by, x.prompt_text
             FROM sekai_agent_turn t
             LEFT JOIN sekai_agent_turn_transcript x ON x.turn_id = t.turn_id
             WHERE COALESCE(x.erased_at_ms, 0) = 0",
            &[],
        )
        .map_err(|error| error.to_string())?;
    let mut erased = 0;
    for row in candidates {
        let turn_id: String = row.get(0);
        let text: Option<String> = row.get(4);
        if !turn_matches_subject(
            row.get(1),
            row.get(2),
            row.get(3),
            text.as_deref(),
            kind,
            subject,
            &references,
        ) {
            continue;
        }
        tx.execute(
            "INSERT INTO sekai_agent_turn_transcript (turn_id, erased_at_ms, updated_at_ms)
             VALUES ($1, $2, $2)
             ON CONFLICT (turn_id) DO UPDATE SET prompt_text = NULL,
                 erased_at_ms = EXCLUDED.erased_at_ms, updated_at_ms = EXCLUDED.updated_at_ms",
            &[&turn_id, &now_ms.max(1)],
        )
        .map_err(|error| error.to_string())?;
        erased += 1;
    }
    Ok(erased)
}

#[cfg(test)]
#[path = "agent_turn_transcript_tests.rs"]
mod tests;
