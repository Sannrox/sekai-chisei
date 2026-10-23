//! Why a property value is what it is (#1452).
//!
//! The explanation of one object property is the history of the writes that
//! set it, read from the object's change rows. Each row carries the writer
//! recorded with it (#1690): a source transaction, a transform run at a
//! checkpoint, an Action instance, a direct write, or nothing (unattributed,
//! never inferred). The RPC joins each step to its writer's record and
//! receipt and reports a step whose record the caller may not read as hidden,
//! so a chain never looks complete when it is not.

use crate::sekai::audit::{ObjectChange, WRITER_UNATTRIBUTED};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
use std::collections::BTreeMap;

/// Change-row field of an object property: `name`, or `properties.<key>`.
pub fn change_field(property: &str) -> String {
    if property == "name" {
        "name".into()
    } else {
        format!("properties.{property}")
    }
}

/// Change-row field of the object's access marking.
pub fn marking_field() -> String {
    change_field(OBJECT_CLASSIFICATION_PROPERTY)
}

/// A committed source batch that wrote an object, with the object's record
/// result in it when one was kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceWriteRecord {
    pub transaction_id: String,
    pub binding_id: String,
    pub namespace: String,
    pub producer_identity: String,
    pub status: String,
    pub outcome: String,
    pub closed_at_ms: i64,
    pub source_id: String,
    pub source_version: String,
    pub record_outcome: String,
}

/// The value of `field` as of `as_of_ms` (0: now) and the rows that set it.
/// `changes` are the object's rows in write order, oldest first; writes in
/// one millisecond keep that order, which timestamps alone cannot. Creation
/// writes no property rows, so the `_created` row of the latest creation
/// stands for the value the object was created with: the first later row's
/// old value, or, for the current incarnation, the latest value when no row
/// changed it. That row is a step only when the value is known and set. `None` when the object did not exist by
/// `as_of_ms`.
pub fn field_history(
    changes: &[ObjectChange],
    field: &str,
    latest: &str,
    as_of_ms: i64,
) -> Option<(String, Vec<ObjectChange>)> {
    let within = |change: &&ObjectChange| as_of_ms <= 0 || change.timestamp <= as_of_ms;
    // The latest creation: a deleted and re-created object starts over.
    let start = changes
        .iter()
        .rposition(|change| change.field == "_created" && within(&change))?;
    let created = &changes[start];
    let incarnation = changes[start + 1..]
        .iter()
        .take_while(|change| change.field != "_created")
        .collect::<Vec<_>>();
    let current = start + 1 + incarnation.len() == changes.len()
        && incarnation.iter().all(|change| change.field != "_deleted");
    let edits = incarnation
        .into_iter()
        .filter(|change| change.field == field)
        .collect::<Vec<_>>();
    // An earlier incarnation no edit followed has no recorded value.
    let created_value = match edits.first() {
        Some(first) => first.old_value.as_str(),
        None if current => latest,
        None => "",
    };
    let mut steps = Vec::new();
    if !created_value.is_empty() {
        steps.push(ObjectChange {
            field: field.into(),
            old_value: String::new(),
            new_value: created_value.into(),
            ..created.clone()
        });
    }
    steps.extend(edits.into_iter().filter(within).cloned());
    let value = steps
        .last()
        .map(|step| step.new_value.clone())
        .unwrap_or_default();
    Some((value, steps))
}

/// What the caller may see of a step's writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriterView {
    /// The writer's record, as details for the step.
    Visible(BTreeMap<String, String>),
    /// The record exists but the caller may not read it, or it is gone.
    Hidden,
}

/// One explained write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainedStep {
    pub change_id: String,
    pub timestamp: i64,
    pub field: String,
    pub value: String,
    pub writer_kind: String,
    pub hidden: bool,
    /// Empty when hidden.
    pub writer_ref: String,
    pub receipt_id: String,
    pub changed_by: String,
    pub details: BTreeMap<String, String>,
}

/// Explain each row through `resolve`. A hidden step keeps only its time,
/// field, value and writer kind.
pub fn explain_steps<E>(
    rows: Vec<ObjectChange>,
    mut resolve: impl FnMut(&ObjectChange) -> Result<WriterView, E>,
) -> Result<Vec<ExplainedStep>, E> {
    rows.into_iter()
        .map(|row| {
            let view = resolve(&row)?;
            let writer_kind = if row.writer_kind.is_empty() {
                WRITER_UNATTRIBUTED.to_string()
            } else {
                row.writer_kind
            };
            Ok(match view {
                WriterView::Visible(details) => ExplainedStep {
                    change_id: row.id,
                    timestamp: row.timestamp,
                    field: row.field,
                    value: row.new_value,
                    writer_kind,
                    hidden: false,
                    writer_ref: row.writer_ref,
                    receipt_id: row.receipt_id,
                    changed_by: row.changed_by,
                    details,
                },
                WriterView::Hidden => ExplainedStep {
                    change_id: row.id,
                    timestamp: row.timestamp,
                    field: row.field,
                    value: row.new_value,
                    writer_kind,
                    hidden: true,
                    writer_ref: String::new(),
                    receipt_id: String::new(),
                    changed_by: String::new(),
                    details: BTreeMap::new(),
                },
            })
        })
        .collect()
}

/// Whether every step is attributed and visible.
pub fn chain_complete(steps: &[ExplainedStep]) -> bool {
    steps
        .iter()
        .all(|step| !step.hidden && step.writer_kind != WRITER_UNATTRIBUTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::audit::{
        ChangeAttribution, WRITER_ACTION_INSTANCE, WRITER_SOURCE_TRANSACTION,
    };

    fn row(field: &str, old: &str, new: &str, at: i64, by: ChangeAttribution) -> ObjectChange {
        by.stamp(vec![ObjectChange {
            id: format!("{field}@{at}"),
            object_id: "o1".into(),
            field: field.into(),
            old_value: old.into(),
            new_value: new.into(),
            changed_by: "writer".into(),
            timestamp: at,
            ..Default::default()
        }])
        .remove(0)
    }

    /// A value created by a source, rewritten by two transform runs, then
    /// edited by an Action, with the marking stamped by the second run.
    fn chain() -> Vec<ObjectChange> {
        vec![
            row(
                "_created",
                "",
                "note/n1",
                10,
                ChangeAttribution::source("tx-1"),
            ),
            row(
                "properties.body",
                "raw",
                "clean",
                20,
                ChangeAttribution::transform("run-1", "4"),
            ),
            row(
                "properties.body",
                "clean",
                "joined",
                30,
                ChangeAttribution::transform("run-2", "9"),
            ),
            row(
                "properties.access_marking",
                "",
                "confidential",
                30,
                ChangeAttribution::transform("run-2", "9"),
            ),
            row(
                "properties.body",
                "joined",
                "edited",
                40,
                ChangeAttribution::action("ai-1", "op-1"),
            ),
            row(
                "properties.title",
                "",
                "other",
                50,
                ChangeAttribution::direct(),
            ),
        ]
    }

    #[test]
    fn a_value_explains_its_source_two_transforms_and_an_action_with_receipts() {
        let (value, rows) = field_history(&chain(), "properties.body", "edited", 0).unwrap();
        assert_eq!(value, "edited");
        let steps = explain_steps(rows, |row| {
            Ok::<_, ()>(WriterView::Visible(BTreeMap::from([(
                "receipt".into(),
                row.receipt_id.clone(),
            )])))
        })
        .unwrap();
        assert_eq!(
            steps
                .iter()
                .map(|step| (
                    step.value.as_str(),
                    step.writer_kind.as_str(),
                    step.receipt_id.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("raw", WRITER_SOURCE_TRANSACTION, "tx-1"),
                ("clean", "transform_run", "run-1"),
                ("joined", "transform_run", "run-2"),
                ("edited", WRITER_ACTION_INSTANCE, "op-1"),
            ]
        );
        assert!(chain_complete(&steps));

        let (marking, rows) = field_history(&chain(), &marking_field(), "confidential", 0).unwrap();
        assert_eq!(marking, "confidential");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].receipt_id, "run-2");
    }

    #[test]
    fn a_hidden_source_step_keeps_no_source_details_and_the_chain_reads_incomplete() {
        let (_, rows) = field_history(&chain(), "properties.body", "edited", 0).unwrap();
        let steps = explain_steps(rows, |row| {
            Ok::<_, ()>(if row.writer_kind == WRITER_SOURCE_TRANSACTION {
                WriterView::Hidden
            } else {
                WriterView::Visible(BTreeMap::new())
            })
        })
        .unwrap();
        let source = &steps[0];
        assert!(source.hidden);
        assert_eq!(source.writer_kind, WRITER_SOURCE_TRANSACTION);
        assert!(source.writer_ref.is_empty() && source.receipt_id.is_empty());
        assert!(source.changed_by.is_empty() && source.details.is_empty());
        assert!(!chain_complete(&steps));
    }

    #[test]
    fn as_of_reads_the_value_then_and_before_creation_reads_nothing() {
        let (value, rows) = field_history(&chain(), "properties.body", "edited", 35).unwrap();
        assert_eq!(value, "joined");
        assert_eq!(rows.len(), 3);
        let (value, rows) = field_history(&chain(), "properties.body", "edited", 10).unwrap();
        assert_eq!((value.as_str(), rows.len()), ("raw", 1));
        assert!(field_history(&chain(), "properties.body", "edited", 5).is_none());
        // Set after creation: no creation step.
        let (value, rows) = field_history(&chain(), "properties.title", "other", 0).unwrap();
        assert_eq!((value.as_str(), rows.len()), ("other", 1));
        let (value, rows) = field_history(&chain(), "properties.title", "other", 45).unwrap();
        assert_eq!((value.as_str(), rows.len()), ("", 0));
    }

    #[test]
    fn a_recreated_object_explains_each_incarnation_on_its_own() {
        let direct = ChangeAttribution::direct;
        let rows = vec![
            row("_created", "", "note/n1", 10, direct()),
            row("_deleted", "note/n1", "", 20, direct()),
            row("_created", "", "note/n1", 30, direct()),
            row("properties.body", "second", "third", 40, direct()),
        ];
        let (value, steps) = field_history(&rows, "properties.body", "third", 0).unwrap();
        assert_eq!((value.as_str(), steps.len()), ("third", 2));
        assert_eq!(steps[0].new_value, "second");
        // No edit recorded the first incarnation's value, and the current
        // value is not it.
        let (value, steps) = field_history(&rows, "properties.body", "third", 15).unwrap();
        assert_eq!((value.as_str(), steps.len()), ("", 0));
    }

    #[test]
    fn a_row_without_a_writer_reads_unattributed_and_incomplete() {
        let mut rows = chain();
        rows[4].writer_kind.clear();
        let (_, rows) = field_history(&rows, "properties.body", "edited", 0).unwrap();
        let steps =
            explain_steps(rows, |_| Ok::<_, ()>(WriterView::Visible(BTreeMap::new()))).unwrap();
        assert_eq!(steps[3].writer_kind, WRITER_UNATTRIBUTED);
        assert!(!chain_complete(&steps));
    }
}
