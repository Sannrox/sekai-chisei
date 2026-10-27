use crate::db::definition_branch::binding_object;
use crate::db::postgres::PostgresDb;
use crate::domain::Object;
use crate::sekai::consumer_violation::{
    EmitViolation, ListViolationDeliveries, MEMBER_KIND_DATASET, ViolationDelivery,
    clamp_page_size, decode_page_token, encode_page_token, matching_recipients,
};
use crate::sekai::definition_consumer_impact::BINDING_KIND;
use postgres::Transaction;
use postgres::types::ToSql;

impl PostgresDb {
    pub fn emit_consumer_violation(&self, emit: &EmitViolation<'_>) -> Result<usize, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let written = emit_dataset_violation_postgres(&mut tx, emit)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(written)
    }

    pub fn list_consumer_violation_deliveries(
        &self,
        query: &ListViolationDeliveries,
    ) -> Result<(Vec<ViolationDelivery>, String), String> {
        let page_size = clamp_page_size(query.page_size)?;
        let cursor = decode_page_token(&query.page_token)?;
        if query.recipients.is_empty() {
            return Ok((Vec::new(), String::new()));
        }
        let recipients = query.recipients.clone();
        let mut connection = self.connection()?;
        let mut sql = String::from(
            "SELECT recipient, event_id, kind, namespace, member_kind, member_id, rule_id, evidence, created_at_ms, acknowledged_at_ms
             FROM sekai_consumer_violation_deliveries
             WHERE recipient = ANY($1)",
        );
        if !query.include_acknowledged {
            sql.push_str(" AND acknowledged_at_ms = 0");
        }
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        params.push(&recipients);
        let created_at;
        let event_id;
        let recipient;
        if let Some((ms, id, rec)) = &cursor {
            created_at = *ms;
            event_id = id.clone();
            recipient = rec.clone();
            sql.push_str(
                " AND (created_at_ms < $2 OR (created_at_ms = $2 AND event_id < $3) OR (created_at_ms = $2 AND event_id = $3 AND recipient < $4))",
            );
            params.push(&created_at);
            params.push(&event_id);
            params.push(&recipient);
            sql.push_str(" ORDER BY created_at_ms DESC, event_id DESC, recipient DESC LIMIT $5");
        } else {
            sql.push_str(" ORDER BY created_at_ms DESC, event_id DESC, recipient DESC LIMIT $2");
        }
        let limit = i64::from(page_size) + 1;
        params.push(&limit);
        let rows = connection
            .query(&sql, params.as_slice())
            .map_err(|error| error.to_string())?;
        let mut deliveries = rows
            .into_iter()
            .map(row_to_delivery)
            .collect::<Result<Vec<_>, _>>()?;
        let next = if deliveries.len() > page_size as usize {
            deliveries.pop();
            deliveries.last().map(|delivery| {
                encode_page_token(
                    delivery.created_at_ms,
                    &delivery.event_id,
                    &delivery.recipient,
                )
            })
        } else {
            None
        };
        Ok((deliveries, next.unwrap_or_default()))
    }

    pub fn get_consumer_violation_delivery(
        &self,
        recipients: &[String],
        event_id: &str,
    ) -> Result<Option<ViolationDelivery>, String> {
        if recipients.is_empty() || event_id.trim().is_empty() {
            return Ok(None);
        }
        let recipients = recipients.to_vec();
        let mut connection = self.connection()?;
        let row = connection
            .query_opt(
                "SELECT recipient, event_id, kind, namespace, member_kind, member_id, rule_id, evidence, created_at_ms, acknowledged_at_ms
                 FROM sekai_consumer_violation_deliveries
                 WHERE recipient = ANY($1) AND event_id = $2
                 ORDER BY recipient LIMIT 1",
                &[&recipients, &event_id],
            )
            .map_err(|error| error.to_string())?;
        row.map(row_to_delivery).transpose()
    }

    pub fn acknowledge_consumer_violation(
        &self,
        recipients: &[String],
        event_id: &str,
        now_ms: i64,
    ) -> Result<Option<ViolationDelivery>, String> {
        if recipients.is_empty() || event_id.trim().is_empty() {
            return Ok(None);
        }
        let recipients = recipients.to_vec();
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE sekai_consumer_violation_deliveries
             SET acknowledged_at_ms = CASE WHEN acknowledged_at_ms = 0 THEN $3 ELSE acknowledged_at_ms END
             WHERE recipient = ANY($1) AND event_id = $2",
            &[&recipients, &event_id, &now_ms],
        )
        .map_err(|error| error.to_string())?;
        let row = tx
            .query_opt(
                "SELECT recipient, event_id, kind, namespace, member_kind, member_id, rule_id, evidence, created_at_ms, acknowledged_at_ms
                 FROM sekai_consumer_violation_deliveries
                 WHERE recipient = ANY($1) AND event_id = $2
                 ORDER BY recipient LIMIT 1",
                &[&recipients, &event_id],
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        row.map(row_to_delivery).transpose()
    }
}

pub(crate) fn dataset_object_namespace_postgres(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
) -> Result<String, String> {
    Ok(tx
        .query_opt(
            "SELECT o.namespace
             FROM sekai_datasets d
             JOIN sekai_objects o ON o.id = d.object_id
             WHERE d.id = $1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
        .unwrap_or_default())
}

pub(crate) fn emit_dataset_violation_postgres(
    tx: &mut Transaction<'_>,
    emit: &EmitViolation<'_>,
) -> Result<usize, String> {
    if emit.namespace.is_empty() {
        return Err("namespace is required".into());
    }
    let bindings = load_bindings_postgres(tx, emit.namespace)?;
    let recipients = matching_recipients(&bindings, MEMBER_KIND_DATASET, emit.member_id);
    for recipient in &recipients {
        tx.execute(
            "INSERT INTO sekai_consumer_violation_deliveries
             (recipient, event_id, kind, namespace, member_kind, member_id, rule_id, evidence, created_at_ms, acknowledged_at_ms)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,0)
             ON CONFLICT (recipient, event_id) DO NOTHING",
            &[
                recipient,
                &emit.event_id,
                &emit.kind,
                &emit.namespace,
                &MEMBER_KIND_DATASET,
                &emit.member_id,
                &emit.rule_id,
                &emit.evidence,
                &emit.now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(recipients.len())
}

fn load_bindings_postgres(
    tx: &mut Transaction<'_>,
    namespace: &str,
) -> Result<Vec<Object>, String> {
    let rows = tx
        .query(
            "SELECT namespace, id, properties FROM sekai_objects WHERE kind = $1 AND namespace = $2",
            &[&BINDING_KIND, &namespace],
        )
        .map_err(|error| error.to_string())?;
    rows.into_iter()
        .map(|row| {
            binding_object(
                row.get::<_, String>(0).as_str(),
                row.get(1),
                row.get::<_, &str>(2),
            )
        })
        .collect()
}

fn row_to_delivery(row: postgres::Row) -> Result<ViolationDelivery, String> {
    Ok(ViolationDelivery {
        recipient: row.get(0),
        event_id: row.get(1),
        kind: row.get(2),
        namespace: row.get(3),
        member_kind: row.get(4),
        member_id: row.get(5),
        rule_id: row.get(6),
        evidence: row.get(7),
        created_at_ms: row.get(8),
        acknowledged_at_ms: row.get(9),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::postgres::ScratchDatabase;
    use crate::domain::Object;
    use crate::sekai::consumer_violation::{
        EmitViolation, KIND_FRESHNESS, ListViolationDeliveries, freshness_event_id,
    };
    use crate::sekai::definition_consumer_impact::{
        BINDING_CONTRACT, BINDING_KIND, DefinitionConsumerBinding, binding_digest,
    };
    use std::collections::HashMap;

    fn binding(id: &str, owner: &str, member_id: &str) -> Object {
        let mut binding = DefinitionConsumerBinding {
            contract_version: BINDING_CONTRACT.into(),
            owner: owner.into(),
            resource_identity: format!("app:{id}"),
            namespace: "ops".into(),
            member_kind: MEMBER_KIND_DATASET.into(),
            member_id: member_id.into(),
            property: String::new(),
            declaration_digest: String::new(),
            source_locator: format!("{id}.rs"),
            blocking: false,
        };
        binding.declaration_digest = binding_digest(&binding);
        Object {
            id: id.into(),
            kind: BINDING_KIND.into(),
            name: id.into(),
            namespace: "ops".into(),
            external_id: format!("ops:{id}"),
            properties: HashMap::from([
                ("contract_version".into(), binding.contract_version),
                ("owner".into(), binding.owner),
                ("resource_identity".into(), binding.resource_identity),
                ("member_kind".into(), binding.member_kind),
                ("member_id".into(), binding.member_id),
                ("property".into(), binding.property),
                ("declaration_digest".into(), binding.declaration_digest),
                ("source_locator".into(), binding.source_locator),
            ]),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_writes_one_delivery_per_recipient_and_event() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        db.create_object(&binding("a", "alice", "orders")).unwrap();
        db.create_object(&binding("b", "bob", "orders")).unwrap();
        db.create_object(&binding("c", "carol", "invoices"))
            .unwrap();
        let event = freshness_event_id("orders", "v1", "fresh");
        let n = db
            .emit_consumer_violation(&EmitViolation {
                kind: KIND_FRESHNESS,
                namespace: "ops",
                member_id: "orders",
                event_id: &event,
                rule_id: "fresh",
                evidence: "age_ms=12",
                now_ms: 40,
            })
            .unwrap();
        assert_eq!(n, 2);
        db.emit_consumer_violation(&EmitViolation {
            kind: KIND_FRESHNESS,
            namespace: "ops",
            member_id: "orders",
            event_id: &event,
            rule_id: "fresh",
            evidence: "age_ms=99",
            now_ms: 41,
        })
        .unwrap();
        let (page, next) = db
            .list_consumer_violation_deliveries(&ListViolationDeliveries {
                recipients: vec!["alice".into()],
                page_token: String::new(),
                page_size: 0,
                include_acknowledged: false,
            })
            .unwrap();
        assert!(next.is_empty());
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].evidence, "age_ms=12");
        let carol = db
            .list_consumer_violation_deliveries(&ListViolationDeliveries {
                recipients: vec!["carol".into()],
                page_token: String::new(),
                page_size: 0,
                include_acknowledged: false,
            })
            .unwrap()
            .0;
        assert!(carol.is_empty());
        let acked = db
            .acknowledge_consumer_violation(&["alice".into()], &event, 50)
            .unwrap()
            .unwrap();
        assert_eq!(acked.acknowledged_at_ms, 50);
        let after = db
            .list_consumer_violation_deliveries(&ListViolationDeliveries {
                recipients: vec!["alice".into()],
                page_token: String::new(),
                page_size: 0,
                include_acknowledged: false,
            })
            .unwrap()
            .0;
        assert!(after.is_empty());
    }
}
