use crate::db::postgres::PostgresDb;
use crate::sekai::audit::{Decision, DecisionFilter, validate_decision};
use crate::sekai::ledger;

impl PostgresDb {
    /// [`verify_ledger_in`] in one read-only repeatable-read snapshot.
    pub fn verify_ledger(&self) -> Result<ledger::LedgerVerification, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(|error| error.to_string())?;
        let verification = verify_ledger_in(&mut tx)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(verification)
    }

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
        // LIMIT and OFFSET parameters are inferred as bigint.
        let limit = i64::from(if filter.limit > 0 {
            filter.limit
        } else {
            i32::MAX
        });
        let offset = i64::from(filter.offset.max(0));
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

/// The ledger head `(seq, entry_hash)`: the newest chained decision, or,
/// when retention archived every decision, the newest purge anchor, so the
/// chain continues after it; `(0, "")` at genesis. Callers hold the ledger
/// lock (25012).
pub fn chain_head(client: &mut impl postgres::GenericClient) -> Result<(i64, String), String> {
    let head = client
        .query_opt(
            "SELECT seq,COALESCE(entry_hash,'') FROM sekai_decisions
             WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1 FOR UPDATE",
            &[],
        )
        .map_err(|error| error.to_string())?;
    let head = match head {
        Some(row) => Some(row),
        None => client
            .query_opt(
                "SELECT seq,entry_hash FROM sekai_ledger_anchors ORDER BY seq DESC LIMIT 1",
                &[],
            )
            .map_err(|error| error.to_string())?,
    };
    Ok(head
        .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))
        .unwrap_or((0, String::new())))
}

/// Verify the decision ledger as SQLite's `verify_ledger` does, with the
/// same report: no row at or below the latest purge anchor, complete chain
/// metadata, then from the anchor (or genesis) contiguous sequence numbers,
/// previous-hash links and every entry hash. Lifecycle classification is
/// derived from the hashed evidence on PostgreSQL, so it cannot differ.
/// Run it in one snapshot (a repeatable-read transaction, or one holding the
/// ledger lock) so concurrent writes cannot split the walk.
pub fn verify_ledger_in(
    client: &mut impl postgres::GenericClient,
) -> Result<ledger::LedgerVerification, String> {
    const BATCH: i64 = 1000;
    let (anchor_seq, anchor_hash) = client
        .query_opt(
            "SELECT seq,entry_hash FROM sekai_ledger_anchors ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .map_err(|error| error.to_string())?
        .map_or((0, String::new()), |row| (row.get(0), row.get(1)));
    let report =
        |ok: bool, first_bad_seq: i64, error: String, checked: i64, head: (i64, String)| {
            ledger::LedgerVerification {
                ok,
                entries_checked: checked,
                first_bad_seq,
                error,
                anchor_seq,
                head_seq: head.0,
                head_hash: head.1,
            }
        };
    let forged: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM sekai_decisions WHERE seq <= $1",
            &[&anchor_seq],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    if forged > 0 {
        return Ok(report(
            false,
            anchor_seq,
            format!(
                "{forged} entr(ies) at or below purge anchor seq {anchor_seq}: forged historical records"
            ),
            0,
            (anchor_seq, anchor_hash),
        ));
    }
    let incomplete: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM sekai_decisions
             WHERE seq IS NULL OR prev_hash IS NULL OR entry_hash IS NULL",
            &[],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    if incomplete > 0 {
        return Ok(report(
            false,
            anchor_seq + 1,
            "audit ledger contains incomplete chain metadata".into(),
            0,
            (anchor_seq, anchor_hash),
        ));
    }
    let (mut expected_seq, mut expected_prev, mut checked) = (anchor_seq, anchor_hash, 0_i64);
    loop {
        let rows = client
            .query(
                "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome,
                        seq,prev_hash,entry_hash
                 FROM sekai_decisions WHERE seq > $1 ORDER BY seq LIMIT $2",
                &[&expected_seq, &BATCH],
            )
            .map_err(|error| error.to_string())?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let evidence: String = row.get(5);
            let decision = Decision {
                id: row.get(0),
                timestamp: row.get(1),
                actor: row.get(2),
                action: row.get(3),
                reason: row.get(4),
                evidence: serde_json::from_str(&evidence).unwrap_or_default(),
                target_id: row.get(6),
                outcome: row.get(7),
            };
            let (seq, prev_hash, stored_hash): (i64, String, String) =
                (row.get(8), row.get(9), row.get(10));
            let failure = if seq != expected_seq + 1 {
                Some(format!(
                    "sequence gap: expected {}, found {seq}",
                    expected_seq + 1
                ))
            } else if prev_hash != expected_prev {
                Some("previous-hash link mismatch".into())
            } else if ledger::entry_hash(seq, &prev_hash, &decision, &evidence) != stored_hash {
                Some("entry hash mismatch: record was altered".into())
            } else {
                None
            };
            if let Some(error) = failure {
                return Ok(report(
                    false,
                    seq,
                    error,
                    checked,
                    (expected_seq, expected_prev),
                ));
            }
            expected_seq = seq;
            expected_prev = stored_hash;
            checked += 1;
        }
    }
    Ok(report(
        true,
        0,
        String::new(),
        checked,
        (expected_seq, expected_prev),
    ))
}

pub fn insert_chained_decision(
    tx: &mut postgres::Transaction<'_>,
    decision: &Decision,
) -> Result<(), String> {
    validate_decision(decision)?;
    tx.query_one("SELECT pg_advisory_xact_lock(25012)", &[])
        .map_err(|error| error.to_string())?;
    let (head_seq, head_hash) = chain_head(tx)?;
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
