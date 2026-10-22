//! Replaying a governed transform at past input versions (#1585).
//!
//! A replay runs a transform, as stored or as a candidate definition, over
//! pinned input dataset versions on a fresh branch of its output dataset
//! (ADR 0119), never on the dataset itself. Its record pins what it read and
//! ran, flags steps that may not reproduce, diffs the result against a
//! baseline version of the output, and names what would change downstream.
//! The branch is promoted through the normal branch proposal and merge, or
//! discarded by deleting it.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::dataset_branch::rows_digest;
use crate::governed_transform::GovernedTransform;
use crate::object_type_index::ObjectTypeDatasource;

pub const REPLAY_NOT_FOUND: &str = "transform replay not found";
pub const REPLAY_OUTPUT_MISMATCH: &str =
    "a candidate definition must keep the transform's namespace, id and output dataset";
pub const REPLAY_PIN_NOT_AN_INPUT: &str = "a pinned dataset is not an input of the transform";
pub const REPLAY_TRANSFORM_CHANGED: &str =
    "the transform changed after the replay was authorized; replay again";
pub const REPLAY_PROPERTY_RESTRICTED: &str =
    "a replay reads and returns whole rows, so it refuses datasets with property read grants";
pub const REPLAY_BASELINE_TOO_LARGE: &str = "the baseline version is too large to diff";
/// Most rows a baseline version may hold to be diffed.
pub const MAX_BASELINE_ROWS: i64 = 1_000_000;
/// Most changed keys a diff lists; the totals count all of them.
pub const MAX_CHANGED_KEYS: usize = 100;
/// Most sample rows a diff carries.
pub const MAX_SAMPLES: usize = 10;

/// What to replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplayTransform {
    pub namespace: String,
    pub transform_id: String,
    /// Input dataset id to version id. Unpinned inputs read the version at
    /// `as_of_ms`, or their latest version when that is 0.
    pub input_versions: BTreeMap<String, String>,
    pub as_of_ms: i64,
    /// A candidate definition (JSON) to run instead of the stored one.
    pub definition_json: String,
    /// The output version to diff against; else the version at `as_of_ms`,
    /// else the latest.
    pub baseline_version_id: String,
    /// The column identifying a row; else the key of an object type backed
    /// by the output, else rows are compared whole.
    pub key_column: String,
    /// The stored definition the caller was authorized against; the replay
    /// is refused if the transform changed since. Empty skips the check.
    pub expected_definition_digest: String,
    pub actor: String,
    pub tenant: String,
}

/// One input as the replay read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplayInput {
    pub alias: String,
    pub dataset_id: String,
    /// Empty when the dataset had no version: the input was empty.
    pub version_id: String,
    pub rows: i64,
    pub digest: String,
    /// The declared columns the run used. Versions do not keep their
    /// schema, so these are the dataset's columns at replay time.
    #[serde(default)]
    pub columns: Vec<String>,
}

/// One row whose key exists on both sides with different values, or a row
/// only one side has (`before` or `after` empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplayRowChange {
    pub key: String,
    pub before: BTreeMap<String, String>,
    pub after: BTreeMap<String, String>,
}

/// The replay output against the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplayDiff {
    /// The key the rows were matched by; empty when compared whole.
    pub key_column: String,
    pub columns_added: Vec<String>,
    pub columns_removed: Vec<String>,
    pub baseline_rows: i64,
    pub replay_rows: i64,
    pub baseline_digest: String,
    pub replay_digest: String,
    pub rows_added: i64,
    pub rows_removed: i64,
    pub rows_changed: i64,
    /// Up to [`MAX_CHANGED_KEYS`] keys added, removed or changed, sorted.
    pub changed_keys: Vec<String>,
    /// Up to [`MAX_SAMPLES`] changes with their rows.
    pub samples: Vec<ReplayRowChange>,
}

impl ReplayDiff {
    /// The replay reproduced the baseline exactly.
    pub fn reproduced(&self) -> bool {
        self.baseline_digest == self.replay_digest
    }
}

/// A dataset the replay output feeds, and what reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DownstreamImpact {
    pub dataset_id: String,
    /// The transform that writes it from upstream; empty for the output.
    pub via_transform: String,
    /// Object types backed by the dataset.
    pub object_types: Vec<String>,
}

/// The durable record of one replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransformReplay {
    pub id: String,
    pub namespace: String,
    pub transform_id: String,
    pub output_dataset_id: String,
    /// The output dataset's branch holding the replay result.
    pub branch: String,
    pub inputs: Vec<ReplayInput>,
    pub definition_digest: String,
    /// True when a candidate definition ran instead of the stored one.
    pub candidate: bool,
    pub engine_version: String,
    /// The request's pins and options, as given.
    pub as_of_ms: i64,
    pub baseline_version_id: String,
    /// Steps that may give different results on another run.
    pub non_deterministic: Vec<String>,
    pub markings_out: String,
    /// The replay output's digest in the run receipt's scheme, comparable
    /// with a run's `output_digest`.
    pub output_digest: String,
    pub diff: ReplayDiff,
    pub downstream: Vec<DownstreamImpact>,
    pub actor: String,
    pub tenant: String,
    pub created_at_ms: i64,
}

impl TransformReplay {
    /// The record as stored: counts and digests only. Changed keys and
    /// sample rows are values of the data; they are returned with the
    /// replay and not kept, so redaction never has to chase them here.
    pub fn without_rows(&self) -> Self {
        let mut stored = self.clone();
        stored.diff.changed_keys.clear();
        stored.diff.samples.clear();
        stored
    }
}

/// Makes a replay's record from its branch run, the rows it wrote and the
/// baseline rows, all read in the run's transaction; it must not touch
/// storage itself.
pub type Describe<'a> = dyn Fn(
        &crate::dataset_branch::DatasetBranchRun,
        &[HashMap<String, String>],
        &[HashMap<String, String>],
    ) -> Result<TransformReplay, String>
    + 'a;

/// SQL functions whose results depend on when or where a run happens.
const VOLATILE: &[&str] = &[
    "now",
    "current_timestamp",
    "current_date",
    "current_time",
    "localtime",
    "localtimestamp",
    "random",
    "uuid",
    "gen_random_uuid",
    "rand",
    "randomblob",
];

/// Date and time functions that read the clock when called without
/// arguments or with `'now'`.
const CLOCK: &[&str] = &[
    "date",
    "time",
    "datetime",
    "julianday",
    "unixepoch",
    "strftime",
];

/// The parts of `transform` that may not reproduce: volatile functions in
/// its SQL. Filter and project steps are deterministic.
pub fn non_deterministic_steps(transform: &GovernedTransform) -> Vec<String> {
    let Some(spec) = &transform.analytical else {
        return Vec::new();
    };
    let sql = spec.sql.to_ascii_lowercase();
    // Words outside string literals, so a literal is not read as a call.
    let code: String = sql
        .split('\'')
        .enumerate()
        .filter(|(index, _)| index % 2 == 0)
        .map(|(_, part)| part)
        .collect::<Vec<_>>()
        .join(" ");
    let words: BTreeSet<&str> = code
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .collect();
    let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    // `name()` as a whole name, not the end of a longer one.
    let called_bare = |name: &str| {
        let pattern = format!("{name}()");
        compact.match_indices(&pattern).any(|(at, _)| {
            compact[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
        })
    };
    let mut flags: Vec<String> = VOLATILE
        .iter()
        .filter(|name| words.contains(**name))
        .map(|name| format!("sql calls {name}"))
        .collect();
    flags.extend(
        CLOCK
            .iter()
            .filter(|name| called_bare(name))
            .map(|name| format!("sql calls {name}() for the current time")),
    );
    if sql
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .contains("'now'")
    {
        flags.push("sql reads the clock through 'now'".into());
    }
    flags
}

fn columns(rows: &[HashMap<String, String>]) -> BTreeSet<String> {
    rows.iter().flat_map(|row| row.keys().cloned()).collect()
}

fn sorted(row: &HashMap<String, String>) -> BTreeMap<String, String> {
    row.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// The changed keys and sample rows a diff keeps, bounded; the totals
/// count everything.
#[derive(Default)]
struct Kept {
    keys: Vec<String>,
    samples: Vec<ReplayRowChange>,
}

impl Kept {
    fn full(&self) -> bool {
        self.keys.len() >= MAX_CHANGED_KEYS && self.samples.len() >= MAX_SAMPLES
    }

    fn note(&mut self, change: ReplayRowChange) {
        if !change.key.is_empty() && self.keys.len() < MAX_CHANGED_KEYS {
            self.keys.push(change.key.clone());
        }
        if self.samples.len() < MAX_SAMPLES {
            self.samples.push(change);
        }
    }
}

/// Diff `replay` against `baseline`. With a key column naming every row once
/// on each side, rows are matched by key; otherwise rows are compared whole,
/// as multisets.
pub fn diff_replay(
    baseline: &[HashMap<String, String>],
    replay: &[HashMap<String, String>],
    key_column: &str,
) -> ReplayDiff {
    let (before_columns, after_columns) = (columns(baseline), columns(replay));
    let mut diff = ReplayDiff {
        columns_added: after_columns.difference(&before_columns).cloned().collect(),
        columns_removed: before_columns.difference(&after_columns).cloned().collect(),
        baseline_rows: baseline.len() as i64,
        replay_rows: replay.len() as i64,
        baseline_digest: rows_digest(baseline),
        replay_digest: rows_digest(replay),
        ..ReplayDiff::default()
    };
    // A key must name every row once per side; otherwise rows that share
    // it would hide each other, so the rows are compared whole.
    let unique = |rows: &[HashMap<String, String>]| {
        let mut seen = BTreeSet::new();
        rows.iter()
            .all(|row| row.get(key_column).is_some_and(|key| seen.insert(key)))
    };
    let keyed = !key_column.is_empty() && unique(baseline) && unique(replay);
    let mut kept = Kept::default();
    if keyed {
        diff.key_column = key_column.into();
        let index =
            |rows: &[HashMap<String, String>]| -> BTreeMap<String, BTreeMap<String, String>> {
                rows.iter()
                    .map(|row| (row[key_column].clone(), sorted(row)))
                    .collect()
            };
        let (before, after) = (index(baseline), index(replay));
        let keys: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
        for key in keys {
            match (before.get(key), after.get(key)) {
                (Some(b), Some(a)) if a == b => continue,
                (Some(_), Some(_)) => diff.rows_changed += 1,
                (None, Some(_)) => diff.rows_added += 1,
                (Some(_), None) => diff.rows_removed += 1,
                (None, None) => continue,
            }
            if !kept.full() {
                kept.note(ReplayRowChange {
                    key: key.clone(),
                    before: before.get(key).cloned().unwrap_or_default(),
                    after: after.get(key).cloned().unwrap_or_default(),
                });
            }
        }
    } else {
        // Whole rows as multisets: what one side has more of.
        let count = |rows: &[HashMap<String, String>]| {
            let mut counts: BTreeMap<String, (i64, BTreeMap<String, String>)> = BTreeMap::new();
            for row in rows {
                let row = sorted(row);
                let encoded = serde_json::to_string(&row).unwrap_or_default();
                counts.entry(encoded).or_insert((0, row)).0 += 1;
            }
            counts
        };
        let (before, after) = (count(baseline), count(replay));
        let encodings: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
        for encoded in encodings {
            let (b, a) = (
                before.get(encoded).map_or(0, |entry| entry.0),
                after.get(encoded).map_or(0, |entry| entry.0),
            );
            let row = before
                .get(encoded)
                .or_else(|| after.get(encoded))
                .map(|entry| entry.1.clone())
                .unwrap_or_default();
            if a > b {
                diff.rows_added += a - b;
                kept.note(ReplayRowChange {
                    after: row,
                    ..ReplayRowChange::default()
                });
            } else if b > a {
                diff.rows_removed += b - a;
                kept.note(ReplayRowChange {
                    before: row,
                    ..ReplayRowChange::default()
                });
            }
        }
    }
    diff.changed_keys = kept.keys;
    diff.samples = kept.samples;
    diff
}

/// The datasets the output feeds through `transforms` (transitively,
/// starting with the output itself) and the object types backed by each.
pub fn downstream(
    output_dataset_id: &str,
    transforms: &[GovernedTransform],
    datasources: &[ObjectTypeDatasource],
) -> Vec<DownstreamImpact> {
    let mut impacts: Vec<DownstreamImpact> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<(String, String)> = vec![(output_dataset_id.to_string(), String::new())];
    while let Some((dataset_id, via)) = queue.pop() {
        if !seen.insert(dataset_id.clone()) {
            continue;
        }
        let mut object_types: Vec<String> = datasources
            .iter()
            .filter(|binding| binding.dataset_id == dataset_id)
            .map(|binding| binding.kind.clone())
            .collect();
        object_types.sort();
        for transform in transforms {
            if transform.consumes_dataset(&dataset_id) {
                queue.push((
                    transform.output_dataset_id.clone(),
                    transform.transform_id.clone(),
                ));
            }
        }
        impacts.push(DownstreamImpact {
            dataset_id,
            via_transform: via,
            object_types,
        });
    }
    // The output first, then what it feeds, by dataset id.
    impacts.sort_by(|a, b| {
        (!a.via_transform.is_empty(), &a.dataset_id)
            .cmp(&(!b.via_transform.is_empty(), &b.dataset_id))
    });
    impacts
}

/// The key a diff matches rows by: the request's, else the key of an object
/// type backed by the output dataset.
pub fn diff_key(
    requested: &str,
    output_dataset_id: &str,
    datasources: &[ObjectTypeDatasource],
) -> String {
    if !requested.trim().is_empty() {
        return requested.trim().to_string();
    }
    let mut keys: Vec<&str> = datasources
        .iter()
        .filter(|binding| binding.dataset_id == output_dataset_id)
        .map(|binding| binding.key_column.as_str())
        .filter(|key| !key.is_empty())
        .collect();
    keys.sort_unstable();
    keys.dedup();
    // Two types keyed differently give no single key.
    match keys.as_slice() {
        [key] => (*key).to_string(),
        _ => String::new(),
    }
}

/// The branch a replay writes: `replay-` and the start of its id.
pub fn replay_branch(id: &str) -> String {
    let short: String = id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(16)
        .collect();
    format!("replay-{short}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn keyed_diffs_count_added_removed_and_changed_rows() {
        let baseline = [
            row(&[("id", "1"), ("v", "a")]),
            row(&[("id", "2"), ("v", "b")]),
            row(&[("id", "3"), ("v", "c")]),
        ];
        let replay = [
            row(&[("id", "1"), ("v", "a")]),
            row(&[("id", "2"), ("v", "B")]),
            row(&[("id", "4"), ("v", "d")]),
        ];
        let diff = diff_replay(&baseline, &replay, "id");
        assert_eq!(
            (diff.rows_added, diff.rows_removed, diff.rows_changed),
            (1, 1, 1)
        );
        assert_eq!(diff.changed_keys, ["2", "3", "4"]);
        assert_eq!(diff.samples[0].before["v"], "b");
        assert_eq!(diff.samples[0].after["v"], "B");
        assert!(!diff.reproduced());
        assert!(diff_replay(&baseline, &baseline, "id").reproduced());
    }

    #[test]
    fn rows_without_the_key_compare_whole_and_columns_are_diffed() {
        let baseline = [row(&[("a", "1")]), row(&[("a", "1")])];
        let replay = [row(&[("a", "1")]), row(&[("b", "2")])];
        let diff = diff_replay(&baseline, &replay, "id");
        assert_eq!(diff.key_column, "");
        // A repeated key falls back to whole rows rather than hide a row.
        let doubled = [
            row(&[("id", "1"), ("v", "a")]),
            row(&[("id", "1"), ("v", "b")]),
        ];
        let once = [row(&[("id", "1"), ("v", "b")])];
        let fallback = diff_replay(&doubled, &once, "id");
        assert_eq!(
            (fallback.key_column.as_str(), fallback.rows_removed),
            ("", 1)
        );
        assert_eq!((diff.rows_added, diff.rows_removed), (1, 1));
        assert_eq!(diff.columns_added, ["b"]);
        assert!(diff.columns_removed.is_empty());
    }

    #[test]
    fn volatile_sql_is_flagged_and_branches_are_valid_names() {
        let mut transform = GovernedTransform {
            contract_version: String::new(),
            namespace: String::new(),
            transform_id: String::new(),
            input_dataset_id: String::new(),
            output_dataset_id: String::new(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        };
        assert!(non_deterministic_steps(&transform).is_empty());
        transform.analytical = Some(crate::governed_transform::AnalyticalSpec {
            sql: "SELECT id, NOW() AS seen, random() FROM input".into(),
            ..Default::default()
        });
        assert_eq!(
            non_deterministic_steps(&transform),
            ["sql calls now", "sql calls random"]
        );
        transform.analytical = Some(crate::governed_transform::AnalyticalSpec {
            sql: "SELECT hex(randomblob(16)), datetime( ), date('now') FROM input".into(),
            ..Default::default()
        });
        assert_eq!(
            non_deterministic_steps(&transform),
            [
                "sql calls randomblob",
                "sql calls date() for the current time",
                "sql calls datetime() for the current time",
                "sql reads the clock through 'now'"
            ]
        );
        let branch = replay_branch("0b9e2c5a-7d41-4c55-9a77-12ab34cd56ef");
        assert_eq!(branch, "replay-0b9e2c5a7d414c55");
        assert!(crate::dataset_branch::validate_branch_name(&branch).is_ok());
    }
}
