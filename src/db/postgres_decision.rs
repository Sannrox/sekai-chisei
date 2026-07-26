use crate::db::postgres::PostgresDb;
use crate::sekai::audit::{Decision, DecisionFilter};
use crate::sekai::ledger;
use std::collections::HashMap;

impl PostgresDb {
    pub fn record_decision(&self, decision: &Decision) -> Result<(), String> {
        validate_decision(decision)?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        insert_chained_decision(&mut tx, decision)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn record_decisions(&self, decisions: &[Decision]) -> Result<(), String> {
        if decisions.is_empty() {
            return Ok(());
        }
        for decision in decisions {
            validate_decision(decision)?;
        }
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for decision in decisions {
            insert_chained_decision(&mut tx, decision)?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn record_decisions_idempotently(&self, decisions: &[Decision]) -> Result<(), String> {
        if decisions.is_empty() {
            return Ok(());
        }
        for decision in decisions {
            validate_decision(decision)?;
        }
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for decision in decisions {
            let existing = tx
                .query_opt(
                    "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome
                     FROM sekai_decisions WHERE id=$1 FOR UPDATE",
                    &[&decision.id.as_str()],
                )
                .map_err(|error| error.to_string())?
                .map(row_to_decision)
                .transpose()?;
            match existing {
                Some(existing) if existing == *decision => continue,
                Some(_) => {
                    return Err(format!(
                        "conflicting audit decision already exists for {}",
                        decision.id
                    ));
                }
                None => insert_chained_decision(&mut tx, decision)?,
            }
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn get_decision(&self, id: &str) -> Result<Option<Decision>, String> {
        self.connection()?
            .query_opt(
                "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome
                 FROM sekai_decisions WHERE id=$1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_decision)
            .transpose()
    }

    pub fn list_decisions(&self, filter: &DecisionFilter) -> Result<Vec<Decision>, String> {
        let actor = filter.actor.as_deref();
        let action = filter.action.as_deref();
        let target_id = filter.target_id.as_deref();
        let after = filter.after;
        let limit = if filter.limit > 0 {
            filter.limit
        } else {
            i32::MAX
        };
        let offset = filter.offset.max(0);
        self.connection()?
            .query(
                "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome
                 FROM sekai_decisions
                 WHERE ($1::text IS NULL OR actor=$1)
                   AND ($2::text IS NULL OR action=$2)
                   AND ($3::text IS NULL OR target_id=$3)
                   AND ($4::bigint <= 0 OR timestamp > $4)
                 ORDER BY timestamp DESC, COALESCE(seq, 0) DESC, id DESC
                 LIMIT $5 OFFSET $6",
                &[&actor, &action, &target_id, &after, &limit, &offset],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_decision)
            .collect()
    }

    pub fn list_compliance_decisions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<Decision>, String> {
        // Callers may pass max+1 to detect overflow; allow that sentinel.
        let limit = i64::try_from(limit.min(10_001)).unwrap_or(10_001);
        self.connection()?
            .query(
                "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome
                 FROM sekai_decisions
                 WHERE timestamp >= $1 AND timestamp < $2
                   AND (
                     evidence::jsonb->>'namespace' = $3
                     OR evidence::jsonb->>'project' = $3
                   )
                 ORDER BY timestamp ASC, COALESCE(seq, 0) ASC, id ASC
                 LIMIT $4",
                &[&start_timestamp_ms, &end_timestamp_ms, &namespace, &limit],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_decision)
            .collect()
    }
}

pub(crate) fn insert_chained_decision(
    tx: &mut postgres::Transaction<'_>,
    decision: &Decision,
) -> Result<(), String> {
    validate_decision(decision)?;
    tx.query_one("SELECT pg_advisory_xact_lock(25012)", &[])
        .map_err(|error| error.to_string())?;
    let head = tx
        .query_opt(
            "SELECT seq,entry_hash FROM sekai_decisions
             WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1 FOR UPDATE",
            &[],
        )
        .map_err(|error| error.to_string())?;
    let (head_seq, head_hash) = head
        .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))
        .unwrap_or((0, String::new()));
    let sequence = head_seq + 1;
    let evidence = serde_json::to_string(&decision.evidence).map_err(|error| error.to_string())?;
    let entry_hash = ledger::entry_hash(sequence, &head_hash, decision, &evidence);
    tx.execute(
        "INSERT INTO sekai_decisions
         (id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        &[
            &decision.id,
            &decision.timestamp,
            &decision.actor,
            &decision.action,
            &decision.reason,
            &evidence,
            &decision.target_id,
            &decision.outcome,
            &sequence,
            &head_hash,
            &entry_hash,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn validate_decision(decision: &Decision) -> Result<(), String> {
    if decision.id.trim().is_empty() {
        return Err("decision id required".into());
    }
    // Serialize once so corrupt/non-string evidence never reaches storage.
    let evidence = serde_json::to_string(&decision.evidence).map_err(|error| error.to_string())?;
    let parsed: HashMap<String, String> = serde_json::from_str(&evidence)
        .map_err(|error| format!("decision evidence must be a string map: {error}"))?;
    // Do not persist credential-shaped values as free-form evidence summaries.
    for (key, value) in &parsed {
        if looks_like_secret(value) {
            return Err(format!(
                "decision evidence must not store secret material in field {key}"
            ));
        }
    }
    Ok(())
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "sk-",
        "ghp_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "bearer ",
        "akia",
        "asia",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
        || (lower.starts_with("eyj") && lower.matches('.').count() == 2)
}

fn row_to_decision(row: postgres::Row) -> Result<Decision, String> {
    let evidence_str: String = row.get(5);
    let evidence = serde_json::from_str(&evidence_str).map_err(|error| {
        format!(
            "corrupt decision evidence for {}: {error}",
            row.get::<_, String>(0)
        )
    })?;
    Ok(Decision {
        id: row.get(0),
        timestamp: row.get(1),
        actor: row.get(2),
        action: row.get(3),
        reason: row.get(4),
        evidence,
        target_id: row.get(6),
        outcome: row.get(7),
    })
}
