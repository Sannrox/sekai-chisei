//! Object-set inputs of governed transforms (ADR 0140, #1977).
//!
//! The plane evaluates an input's object set as the run's principal, with
//! the read policy of `EvaluateObjectSet`, before the run. The objects it may
//! read become rows: `id`, `name`, then the properties it read, in name
//! order. The run pins them: `input_versions` records a digest of each set's
//! rows under [`PIN_PREFIX`] and its alias, and the rows' markings join the
//! run's input markings like a dataset's.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sha2::{Digest, Sha256};

use crate::domain::Object;

pub use crate::sekai::governed_transform::OBJECT_SET_PIN_PREFIX as PIN_PREFIX;

/// One object-set input as the run's principal read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedObjectSet {
    pub alias: String,
    /// The canonical descriptor the set was read with; part of its digest,
    /// so a pin names the set a definition asked for, not only its rows.
    pub descriptor: String,
    pub columns: Vec<String>,
    pub rows: Vec<HashMap<String, String>>,
    /// The marking of each object read, as datasets give their object's; a
    /// replay appends each object's current marking after them.
    pub marking_tokens: Vec<Option<String>>,
}

impl PinnedObjectSet {
    /// The rows of `objects`, in id order. Columns are the kind's
    /// `declared` properties and any others read, so an empty set keeps its
    /// schema. `markings` holds each object's marking by id, as stored: the
    /// rows are a reader's projection and may not carry it. An object with no
    /// entry keeps the marking its row carries.
    pub fn from_objects(
        alias: &str,
        declared: &[String],
        objects: &[Object],
        markings: &HashMap<String, Option<String>>,
    ) -> Self {
        let mut objects: Vec<&Object> = objects.iter().collect();
        objects.sort_by(|left, right| left.id.cmp(&right.id));
        let properties: BTreeSet<&String> = declared
            .iter()
            .chain(objects.iter().flat_map(|object| object.properties.keys()))
            .collect();
        let columns = ["id".to_string(), "name".to_string()]
            .into_iter()
            .chain(
                properties
                    .into_iter()
                    .filter(|name| *name != "id" && *name != "name")
                    .cloned(),
            )
            .collect();
        let rows = objects.iter().map(|object| object_row(object)).collect();
        let marking_tokens = objects
            .iter()
            .map(|object| match markings.get(&object.id) {
                Some(marking) => marking.clone(),
                None => crate::sekai::markings::object_marking_token(object).map(str::to_string),
            })
            .collect();
        Self {
            alias: alias.into(),
            descriptor: String::new(),
            columns,
            rows,
            marking_tokens,
        }
    }

    /// This set as read with `descriptor`, the input's canonical JSON.
    pub fn with_descriptor(self, descriptor: &str) -> Self {
        Self {
            descriptor: descriptor.into(),
            ..self
        }
    }

    /// The rows as input records, numbered from 1 in id order, as runs and
    /// input snapshots carry them.
    pub fn records(&self) -> Vec<(i64, HashMap<String, String>)> {
        (1i64..).zip(self.rows.iter().cloned()).collect()
    }

    /// A set read back from a stored pin: its descriptor, `columns` as JSON,
    /// and rows decoded with [`decode_pin_row`]. Refused unless the rows
    /// still hash to `digest`.
    pub fn from_pin(
        alias: &str,
        digest: &str,
        descriptor: &str,
        columns: &str,
        rows: Vec<(HashMap<String, String>, Option<String>)>,
    ) -> Result<Self, String> {
        let columns: Vec<String> =
            serde_json::from_str(columns).map_err(|error| error.to_string())?;
        let (rows, marking_tokens) = rows.into_iter().unzip();
        let set = Self {
            alias: alias.into(),
            descriptor: descriptor.into(),
            columns,
            rows,
            marking_tokens,
        };
        if set.digest() != digest {
            return Err(format!("{OBJECT_SET_PIN_CORRUPT}: {alias}"));
        }
        Ok(set)
    }

    /// The key this set's pin is recorded under in `input_versions`.
    pub fn pin_key(&self) -> String {
        format!("{PIN_PREFIX}{}", self.alias)
    }

    /// A digest of the set as read: its descriptor, its columns, then each
    /// row and its marking, independent of map order. Two sets with the same
    /// rows and another descriptor, schema or marking, empty ones included,
    /// pin differently.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update((self.descriptor.len() as u64).to_be_bytes());
        hasher.update(self.descriptor.as_bytes());
        let columns = serde_json::to_vec(&self.columns).expect("strings serialize");
        hasher.update((columns.len() as u64).to_be_bytes());
        hasher.update(columns);
        // Each row with the marking it was read under; markings a replay
        // appends after the rows are not part of what was pinned.
        let markings = self.marking_tokens.iter().map(Option::as_deref);
        for (row, marking) in self
            .rows
            .iter()
            .zip(markings.chain(std::iter::repeat(None)))
        {
            let ordered: BTreeMap<&String, &String> = row.iter().collect();
            let encoded = serde_json::to_vec(&ordered).expect("string maps serialize");
            hasher.update((encoded.len() as u64).to_be_bytes());
            hasher.update(encoded);
            let marking = marking.unwrap_or_default();
            hasher.update((marking.len() as u64).to_be_bytes());
            hasher.update(marking.as_bytes());
        }
        format!("sha256:{:x}", hasher.finalize())
    }
}

/// The row an object becomes: its properties, with `id` and `name`.
pub fn object_row(object: &Object) -> HashMap<String, String> {
    let mut row = object.properties.clone();
    row.insert("id".into(), object.id.clone());
    row.insert("name".into(), object.name.clone());
    row
}

/// Refuses a run or preview of `transform` unless `sets` are exactly its
/// declared object-set inputs: a path that cannot evaluate them, such as an
/// operator run from the store, must not execute without them.
pub fn require_evaluated(
    transform: &crate::sekai::governed_transform::GovernedTransform,
    sets: &[PinnedObjectSet],
) -> Result<(), String> {
    let declared: BTreeSet<String> = transform
        .object_set_inputs()
        .into_iter()
        .map(|(alias, _)| alias)
        .collect();
    let supplied: BTreeSet<String> = sets.iter().map(|set| set.alias.clone()).collect();
    if declared == supplied && supplied.len() == sets.len() {
        Ok(())
    } else {
        Err(format!(
            "{OBJECT_SETS_UNEVALUATED}: object-set inputs run only where the plane reads them"
        ))
    }
}

/// Error prefix of a stored pin whose rows no longer hash to its digest.
pub const OBJECT_SET_PIN_CORRUPT: &str = "transform_object_set_pin_corrupt";

/// Error prefix of a run whose object-set inputs were not evaluated.
pub const OBJECT_SETS_UNEVALUATED: &str = "transform_object_sets_unevaluated";

/// One stored pin row, decoded under `budget` as it is read: its encoded
/// size is allowed first, then its values charged, so a pin larger than the
/// replay's budget stops loading instead of being materialized (ADR 0140).
pub fn decode_pin_row(
    values_json: &str,
    marking: String,
    budget: &mut crate::sekai::governed_transform::InputLoadBudget,
) -> Result<(HashMap<String, String>, Option<String>), String> {
    if !budget.allow_encoded(values_json.len() as u64) {
        return Err(budget.exceeded.unwrap_or_default().into());
    }
    let values: HashMap<String, String> =
        serde_json::from_str(values_json).map_err(|error| error.to_string())?;
    if !budget.charge(&values) {
        return Err(budget.exceeded.unwrap_or_default().into());
    }
    Ok((values, Some(marking).filter(|marking| !marking.is_empty())))
}

/// Whether an `input_versions` key pins an object set rather than a dataset.
pub fn is_pin_key(key: &str) -> bool {
    key.starts_with(PIN_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(id: &str, properties: &[(&str, &str)]) -> Object {
        Object {
            id: id.into(),
            kind: "customer".into(),
            name: format!("{id}-name"),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: properties
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn rows_have_a_stable_shape_and_digest() {
        let set = PinnedObjectSet::from_objects(
            "customers",
            &[],
            &[
                object("c2", &[("region", "us")]),
                object("c1", &[("tier", "gold"), ("region", "eu")]),
            ],
            &HashMap::new(),
        );
        assert_eq!(set.columns, ["id", "name", "region", "tier"]);
        assert_eq!(set.rows[0]["id"], "c1");
        assert_eq!(set.rows[0]["name"], "c1-name");
        assert_eq!(set.pin_key(), "object-set:customers");
        let reordered = PinnedObjectSet::from_objects(
            "customers",
            &[],
            &[
                object("c1", &[("region", "eu"), ("tier", "gold")]),
                object("c2", &[("region", "us")]),
            ],
            &HashMap::new(),
        );
        assert_eq!(set.digest(), reordered.digest());
        let changed =
            PinnedObjectSet::from_objects("customers", &[], &[object("c1", &[])], &HashMap::new());
        let empty =
            PinnedObjectSet::from_objects("customers", &["tier".into()], &[], &HashMap::new());
        assert_eq!(empty.columns, ["id", "name", "tier"]);
        let other_empty =
            PinnedObjectSet::from_objects("customers", &["region".into()], &[], &HashMap::new());
        assert_ne!(empty.digest(), other_empty.digest());
        let mut remarked = changed.clone();
        remarked.marking_tokens = vec![Some("internal".into())];
        assert_ne!(changed.digest(), remarked.digest());
        // The stored marking holds when the reader's row does not carry it.
        let projected = PinnedObjectSet::from_objects(
            "customers",
            &[],
            &[object("c1", &[])],
            &HashMap::from([("c1".to_string(), Some("internal".to_string()))]),
        );
        assert_eq!(projected.marking_tokens, [Some("internal".to_string())]);
        assert_ne!(set.digest(), changed.digest());
    }
}
