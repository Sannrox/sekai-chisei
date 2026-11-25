//! Notes a source sync reports instead of stalling (ADR 0163): what the
//! connector could not apply, by position, never by record content. The
//! connector runtime gathers them and the plane stores them with the sync
//! outcome, so both sides share this one bounded, validated type.

use serde::{Deserialize, Serialize};

/// The most notes one sync keeps (ADR 0163); past it only a count.
pub const MAX_SYNC_NOTES: usize = 64;

/// Why a connector skipped one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SkipReason {
    /// The record's value is not JSON.
    NotJson,
    /// The record has no id field.
    MissingId,
}

impl SkipReason {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NotJson => "not_json",
            Self::MissingId => "missing_id",
        }
    }

    pub fn from_wire_name(name: &str) -> Option<Self> {
        [Self::NotJson, Self::MissingId]
            .into_iter()
            .find(|reason| reason.wire_name() == name)
    }
}

/// One thing a sync could not apply and reports instead of stalling. It
/// names positions, never record content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SyncNote {
    /// Retention passed the stored offset: offsets `from_offset` up to,
    /// not including, `to_offset` were never read.
    OffsetGap {
        partition: i32,
        from_offset: i64,
        to_offset: i64,
    },
    /// The record at `offset` was skipped.
    SkippedRecord {
        partition: i32,
        offset: i64,
        reason: SkipReason,
    },
}

impl SyncNote {
    /// A note names a partition and offsets that are not negative, and a
    /// gap ends after it starts.
    fn is_valid(&self) -> bool {
        match *self {
            Self::OffsetGap {
                partition,
                from_offset,
                to_offset,
            } => partition >= 0 && from_offset >= 0 && from_offset < to_offset,
            Self::SkippedRecord {
                partition, offset, ..
            } => partition >= 0 && offset >= 0,
        }
    }
}

const INVALID_NOTE: &str = "a note names a partition and offsets that are not negative, \
                            and a gap ends after it starts";

/// The bounded notes of one sync: at most [`MAX_SYNC_NOTES`], and how many
/// more the runtime did not send.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncNotes {
    notes: Vec<SyncNote>,
    overflow: i64,
}

impl SyncNotes {
    /// Refuses more than [`MAX_SYNC_NOTES`] notes, a negative count or
    /// position, and an empty or reversed gap.
    pub fn new(notes: Vec<SyncNote>, overflow: i64) -> Result<Self, String> {
        if notes.len() > MAX_SYNC_NOTES {
            return Err(format!("a sync keeps at most {MAX_SYNC_NOTES} notes"));
        }
        if overflow < 0 {
            return Err("the overflow count is not negative".into());
        }
        if !notes.iter().all(SyncNote::is_valid) {
            return Err(INVALID_NOTE.into());
        }
        Ok(Self { notes, overflow })
    }

    /// Keeps `note` while fewer than [`MAX_SYNC_NOTES`] are kept, and
    /// counts it as overflow after that. Refuses an invalid note, as
    /// [`SyncNotes::new`] does. A runtime gathers a sync's notes page by
    /// page through this.
    pub fn push(&mut self, note: SyncNote) -> Result<(), String> {
        if !note.is_valid() {
            return Err(INVALID_NOTE.into());
        }
        if self.notes.len() < MAX_SYNC_NOTES {
            self.notes.push(note);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
        Ok(())
    }

    pub fn notes(&self) -> &[SyncNote] {
        &self.notes
    }

    /// Notes the runtime counted but did not send.
    pub fn overflow(&self) -> i64 {
        self.overflow
    }

    pub fn is_empty(&self) -> bool {
        self.notes.is_empty() && self.overflow == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_keeps_the_first_notes_and_counts_the_rest() {
        let mut notes = SyncNotes::default();
        for offset in 0..70 {
            notes
                .push(SyncNote::SkippedRecord {
                    partition: 0,
                    offset,
                    reason: SkipReason::NotJson,
                })
                .unwrap();
        }
        assert_eq!(notes.notes().len(), MAX_SYNC_NOTES);
        assert_eq!(notes.overflow(), 6);
        assert!(
            notes
                .push(SyncNote::OffsetGap {
                    partition: 0,
                    from_offset: 5,
                    to_offset: 5,
                })
                .is_err()
        );
        assert_eq!(notes.overflow(), 6);
    }
}
