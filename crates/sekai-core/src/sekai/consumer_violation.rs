//! Durable consumer notifications for freshness and quality violations (#1636).
//!
//! A delivery record is written per (recipient, violation event) at the
//! moment the violation is committed. Recipients are owners of digest-fresh
//! `sekai.definition-consumer-binding/v1` objects bound to the affected
//! dataset. Transport (email, webhooks) stays out of the core. Evidence is
//! stored in full and filtered by read policy when the caller lists.

use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use crate::sekai::definition_consumer_impact::{
    BINDING_KIND, DefinitionConsumerBinding, binding_digest, binding_from_object,
};
use rusqlite::{OptionalExtension, Transaction, params};
use std::collections::BTreeSet;

pub const KIND_FRESHNESS: &str = "freshness";
pub const KIND_QUALITY: &str = "quality";
pub const MEMBER_KIND_DATASET: &str = "dataset";
pub const DEFAULT_PAGE_SIZE: i32 = 50;
pub const MAX_PAGE_SIZE: i32 = 100;

const SQLITE_SCHEMA: &str = "
            CREATE TABLE IF NOT EXISTS sekai_consumer_violation_deliveries (
                recipient TEXT NOT NULL,
                event_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                namespace TEXT NOT NULL,
                member_kind TEXT NOT NULL,
                member_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                evidence TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                acknowledged_at_ms INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (recipient, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_sekai_consumer_violation_deliveries_recipient
                ON sekai_consumer_violation_deliveries(recipient, created_at_ms, event_id);
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViolationDelivery {
    pub recipient: String,
    pub event_id: String,
    pub kind: String,
    pub namespace: String,
    pub member_kind: String,
    pub member_id: String,
    pub rule_id: String,
    pub evidence: String,
    pub created_at_ms: i64,
    pub acknowledged_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListViolationDeliveries {
    pub recipients: Vec<String>,
    pub page_token: String,
    pub page_size: i32,
    pub include_acknowledged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmitViolation<'a> {
    pub kind: &'a str,
    pub namespace: &'a str,
    pub member_id: &'a str,
    pub event_id: &'a str,
    pub rule_id: &'a str,
    pub evidence: &'a str,
    pub now_ms: i64,
}

pub fn freshness_event_id(dataset_id: &str, version_id: &str, check_id: &str) -> String {
    format!("freshness:{dataset_id}:{version_id}:{check_id}")
}

pub fn quality_event_id(result_id: &str) -> String {
    format!("quality:{result_id}")
}

pub fn clamp_page_size(page_size: i32) -> Result<i32, String> {
    if page_size < 0 {
        return Err("page_size must be >= 0".into());
    }
    if page_size == 0 {
        Ok(DEFAULT_PAGE_SIZE)
    } else {
        Ok(page_size.min(MAX_PAGE_SIZE))
    }
}

pub fn encode_page_token(created_at_ms: i64, event_id: &str, recipient: &str) -> String {
    format!("{created_at_ms}\n{event_id}\n{recipient}")
}

pub fn decode_page_token(token: &str) -> Result<Option<(i64, String, String)>, String> {
    if token.is_empty() {
        return Ok(None);
    }
    let mut parts = token.splitn(3, '\n');
    let ms = parts
        .next()
        .ok_or_else(|| "page_token is invalid".to_string())?;
    let event_id = parts
        .next()
        .ok_or_else(|| "page_token is invalid".to_string())?;
    let recipient = parts
        .next()
        .ok_or_else(|| "page_token is invalid".to_string())?;
    let created_at_ms = ms
        .parse::<i64>()
        .map_err(|_| "page_token is invalid".to_string())?;
    if event_id.is_empty() || recipient.is_empty() {
        return Err("page_token is invalid".into());
    }
    Ok(Some((created_at_ms, event_id.into(), recipient.into())))
}

pub fn matching_recipients(bindings: &[Object], member_kind: &str, member_id: &str) -> Vec<String> {
    let mut owners = BTreeSet::new();
    for object in bindings {
        let Ok(binding) = binding_from_object(object) else {
            continue;
        };
        if binding.declaration_digest != binding_digest(&binding) {
            continue;
        }
        if binding_matches_member(&binding, member_kind, member_id) {
            owners.insert(binding.owner);
        }
    }
    owners.into_iter().collect()
}

fn binding_matches_member(
    binding: &DefinitionConsumerBinding,
    member_kind: &str,
    member_id: &str,
) -> bool {
    binding.member_kind == member_kind && binding.member_id == member_id
}

pub(crate) fn migrate_consumer_violations(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(SQLITE_SCHEMA)
        .map_err(|error| error.to_string())
}

pub(crate) fn dataset_object_namespace_sqlite(
    tx: &Transaction<'_>,
    dataset_id: &str,
) -> Result<String, String> {
    tx.query_row(
        "SELECT o.namespace
         FROM sekai_datasets d
         JOIN sekai_objects o ON o.id = d.object_id
         WHERE d.id = ?1",
        params![dataset_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| error.to_string())
    .map(|namespace| namespace.unwrap_or_default())
}

pub(crate) fn emit_dataset_violation_sqlite(
    tx: &Transaction<'_>,
    emit: &EmitViolation<'_>,
) -> Result<usize, String> {
    if emit.namespace.is_empty() {
        return Err("namespace is required".into());
    }
    // Recipients are owners bound in this namespace at emit time.
    // (recipient, event_id) is unique, so a later emit cannot replace them.
    let bindings = load_bindings_sqlite(tx, emit.namespace)?;
    let recipients = matching_recipients(&bindings, MEMBER_KIND_DATASET, emit.member_id);
    for recipient in &recipients {
        tx.execute(
            "INSERT INTO sekai_consumer_violation_deliveries
             (recipient, event_id, kind, namespace, member_kind, member_id, rule_id, evidence, created_at_ms, acknowledged_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0)
             ON CONFLICT(recipient, event_id) DO NOTHING",
            params![
                recipient,
                emit.event_id,
                emit.kind,
                emit.namespace,
                MEMBER_KIND_DATASET,
                emit.member_id,
                emit.rule_id,
                emit.evidence,
                emit.now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(recipients.len())
}

fn load_bindings_sqlite(tx: &Transaction<'_>, namespace: &str) -> Result<Vec<Object>, String> {
    let mut stmt = tx
        .prepare(
            "SELECT namespace, id, properties FROM sekai_objects WHERE kind = ?1 AND namespace = ?2",
        )
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map(params![BINDING_KIND, namespace], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut bindings = Vec::new();
    for row in rows {
        let (ns, id, properties) = row.map_err(|error| error.to_string())?;
        bindings.push(crate::db::definition_branch::binding_object(
            &ns,
            id,
            &properties,
        )?);
    }
    Ok(bindings)
}

impl SekaiDb {
    pub fn emit_consumer_violation(&self, emit: &EmitViolation<'_>) -> Result<usize, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let written = emit_dataset_violation_sqlite(&tx, emit)?;
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
        let conn = self.conn();
        let placeholders = query
            .recipients
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let mut sql = format!(
            "SELECT recipient, event_id, kind, namespace, member_kind, member_id, rule_id, evidence, created_at_ms, acknowledged_at_ms
             FROM sekai_consumer_violation_deliveries
             WHERE recipient IN ({placeholders})"
        );
        if !query.include_acknowledged {
            sql.push_str(" AND acknowledged_at_ms = 0");
        }
        if cursor.is_some() {
            sql.push_str(
                " AND (created_at_ms < ? OR (created_at_ms = ? AND event_id < ?) OR (created_at_ms = ? AND event_id = ? AND recipient < ?))",
            );
        }
        sql.push_str(" ORDER BY created_at_ms DESC, event_id DESC, recipient DESC LIMIT ?");
        let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let mut values: Vec<rusqlite::types::Value> = query
            .recipients
            .iter()
            .map(|recipient| rusqlite::types::Value::Text(recipient.clone()))
            .collect();
        if let Some((created_at_ms, event_id, recipient)) = &cursor {
            values.push(rusqlite::types::Value::Integer(*created_at_ms));
            values.push(rusqlite::types::Value::Integer(*created_at_ms));
            values.push(rusqlite::types::Value::Text(event_id.clone()));
            values.push(rusqlite::types::Value::Integer(*created_at_ms));
            values.push(rusqlite::types::Value::Text(event_id.clone()));
            values.push(rusqlite::types::Value::Text(recipient.clone()));
        }
        values.push(rusqlite::types::Value::Integer(i64::from(page_size) + 1));
        let params = rusqlite::params_from_iter(values);
        let rows = stmt
            .query_map(params, row_to_delivery)
            .map_err(|error| error.to_string())?;
        let mut deliveries = Vec::new();
        for row in rows {
            deliveries.push(row.map_err(|error| error.to_string())?);
        }
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
        let conn = self.conn();
        let placeholders = recipients.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT recipient, event_id, kind, namespace, member_kind, member_id, rule_id, evidence, created_at_ms, acknowledged_at_ms
             FROM sekai_consumer_violation_deliveries
             WHERE recipient IN ({placeholders}) AND event_id = ? ORDER BY recipient LIMIT 1"
        );
        let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let mut values: Vec<rusqlite::types::Value> = recipients
            .iter()
            .map(|recipient| rusqlite::types::Value::Text(recipient.clone()))
            .collect();
        values.push(rusqlite::types::Value::Text(event_id.into()));
        let mut rows = stmt
            .query(rusqlite::params_from_iter(values))
            .map_err(|error| error.to_string())?;
        rows.next()
            .map_err(|error| error.to_string())?
            .map(row_to_delivery)
            .transpose()
            .map_err(|error| error.to_string())
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
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        for recipient in recipients {
            tx.execute(
                "UPDATE sekai_consumer_violation_deliveries
                 SET acknowledged_at_ms = CASE WHEN acknowledged_at_ms = 0 THEN ?3 ELSE acknowledged_at_ms END
                 WHERE recipient = ?1 AND event_id = ?2",
                params![recipient, event_id, now_ms],
            )
            .map_err(|error| error.to_string())?;
        }
        let mut delivery = None;
        for recipient in recipients {
            delivery = tx
                .query_row(
                    "SELECT recipient, event_id, kind, namespace, member_kind, member_id, rule_id, evidence, created_at_ms, acknowledged_at_ms
                     FROM sekai_consumer_violation_deliveries
                     WHERE recipient = ?1 AND event_id = ?2",
                    params![recipient, event_id],
                    row_to_delivery,
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if delivery.is_some() {
                break;
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(delivery)
    }
}

fn row_to_delivery(row: &rusqlite::Row<'_>) -> rusqlite::Result<ViolationDelivery> {
    Ok(ViolationDelivery {
        recipient: row.get(0)?,
        event_id: row.get(1)?,
        kind: row.get(2)?,
        namespace: row.get(3)?,
        member_kind: row.get(4)?,
        member_id: row.get(5)?,
        rule_id: row.get(6)?,
        evidence: row.get(7)?,
        created_at_ms: row.get(8)?,
        acknowledged_at_ms: row.get(9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_consumer_impact::{BINDING_CONTRACT, binding_digest};
    use std::collections::HashMap;

    fn binding(id: &str, owner: &str, member_id: &str, digest_ok: bool) -> Object {
        binding_in("ops", id, owner, member_id, digest_ok)
    }

    fn binding_in(
        namespace: &str,
        id: &str,
        owner: &str,
        member_id: &str,
        digest_ok: bool,
    ) -> Object {
        let mut binding = DefinitionConsumerBinding {
            contract_version: BINDING_CONTRACT.into(),
            owner: owner.into(),
            resource_identity: format!("app:{id}"),
            namespace: namespace.into(),
            member_kind: MEMBER_KIND_DATASET.into(),
            member_id: member_id.into(),
            property: String::new(),
            declaration_digest: String::new(),
            source_locator: format!("{id}.rs"),
            blocking: false,
        };
        binding.declaration_digest = if digest_ok {
            binding_digest(&binding)
        } else {
            "sha256:dead".into()
        };
        Object {
            id: id.into(),
            kind: BINDING_KIND.into(),
            name: id.into(),
            namespace: namespace.into(),
            external_id: format!("{namespace}:{id}"),
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
    fn matching_recipients_keep_digest_fresh_owners_of_the_member() {
        let bindings = [
            binding("a", "alice", "orders", true),
            binding("b", "bob", "orders", true),
            binding("c", "carol", "invoices", true),
            binding("d", "dave", "orders", false),
        ];
        assert_eq!(
            matching_recipients(&bindings, MEMBER_KIND_DATASET, "orders"),
            ["alice", "bob"]
        );
    }

    #[test]
    fn sqlite_writes_one_delivery_per_recipient_and_event() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&binding("a", "alice", "orders", true))
            .unwrap();
        db.create_object(&binding("b", "bob", "orders", true))
            .unwrap();
        db.create_object(&binding("c", "carol", "invoices", true))
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
        let bob = db
            .list_consumer_violation_deliveries(&ListViolationDeliveries {
                recipients: vec!["bob".into()],
                page_token: String::new(),
                page_size: 0,
                include_acknowledged: false,
            })
            .unwrap()
            .0;
        assert_eq!(bob.len(), 1);
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

    #[test]
    fn sqlite_pages_newest_first() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&binding("a", "alice", "orders", true))
            .unwrap();
        let first = freshness_event_id("orders", "v1", "fresh");
        let second = freshness_event_id("orders", "v2", "fresh");
        db.emit_consumer_violation(&EmitViolation {
            kind: KIND_FRESHNESS,
            namespace: "ops",
            member_id: "orders",
            event_id: &first,
            rule_id: "fresh",
            evidence: "one",
            now_ms: 10,
        })
        .unwrap();
        db.emit_consumer_violation(&EmitViolation {
            kind: KIND_FRESHNESS,
            namespace: "ops",
            member_id: "orders",
            event_id: &second,
            rule_id: "fresh",
            evidence: "two",
            now_ms: 20,
        })
        .unwrap();
        let (page, next) = db
            .list_consumer_violation_deliveries(&ListViolationDeliveries {
                recipients: vec!["alice".into()],
                page_token: String::new(),
                page_size: 1,
                include_acknowledged: false,
            })
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].evidence, "two");
        assert!(!next.is_empty());
        let (second, done) = db
            .list_consumer_violation_deliveries(&ListViolationDeliveries {
                recipients: vec!["alice".into()],
                page_token: next,
                page_size: 1,
                include_acknowledged: false,
            })
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].evidence, "one");
        assert!(done.is_empty());
    }

    #[test]
    fn page_token_round_trips_and_rejects_junk() {
        let token = encode_page_token(40, "freshness:orders:v1:fresh", "alice");
        assert_eq!(
            decode_page_token(&token).unwrap(),
            Some((40, "freshness:orders:v1:fresh".into(), "alice".into()))
        );
        assert!(decode_page_token("").unwrap().is_none());
        assert!(decode_page_token("40").is_err());
        assert!(decode_page_token("x\nid").is_err());
        assert!(decode_page_token("40\nid").is_err());
    }

    #[test]
    fn sqlite_pages_shared_events_across_recipients() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&binding("a", "alice", "orders", true))
            .unwrap();
        db.create_object(&binding("b", "bob", "orders", true))
            .unwrap();
        let event = freshness_event_id("orders", "v1", "fresh");
        db.emit_consumer_violation(&EmitViolation {
            kind: KIND_FRESHNESS,
            namespace: "ops",
            member_id: "orders",
            event_id: &event,
            rule_id: "fresh",
            evidence: "age_ms=12",
            now_ms: 40,
        })
        .unwrap();
        let (page, next) = db
            .list_consumer_violation_deliveries(&ListViolationDeliveries {
                recipients: vec!["alice".into(), "bob".into()],
                page_token: String::new(),
                page_size: 1,
                include_acknowledged: false,
            })
            .unwrap();
        assert_eq!(page.len(), 1);
        assert!(!next.is_empty());
        let (second, done) = db
            .list_consumer_violation_deliveries(&ListViolationDeliveries {
                recipients: vec!["alice".into(), "bob".into()],
                page_token: next,
                page_size: 1,
                include_acknowledged: false,
            })
            .unwrap();
        assert_eq!(second.len(), 1);
        assert!(done.is_empty());
        let mut owners = vec![page[0].recipient.as_str(), second[0].recipient.as_str()];
        owners.sort();
        assert_eq!(owners, ["alice", "bob"]);
    }

    #[test]
    fn sqlite_emit_scopes_bindings_to_the_dataset_namespace() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&binding_in("ops", "a", "alice", "orders", true))
            .unwrap();
        db.create_object(&binding_in("other", "b", "eve", "orders", true))
            .unwrap();
        let event = freshness_event_id("orders", "v1", "fresh");
        db.emit_consumer_violation(&EmitViolation {
            kind: KIND_FRESHNESS,
            namespace: "ops",
            member_id: "orders",
            event_id: &event,
            rule_id: "fresh",
            evidence: "age_ms=12",
            now_ms: 40,
        })
        .unwrap();
        let listed = db
            .list_consumer_violation_deliveries(&ListViolationDeliveries {
                recipients: vec!["alice".into(), "eve".into()],
                page_token: String::new(),
                page_size: 0,
                include_acknowledged: true,
            })
            .unwrap()
            .0;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].recipient, "alice");
        assert_eq!(listed[0].namespace, "ops");
        assert_eq!(
            db.emit_consumer_violation(&EmitViolation {
                kind: KIND_FRESHNESS,
                namespace: "",
                member_id: "orders",
                event_id: &event,
                rule_id: "fresh",
                evidence: "age_ms=12",
                now_ms: 40,
            })
            .unwrap_err(),
            "namespace is required"
        );
    }
}
