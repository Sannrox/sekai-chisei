//! Notes a source sync reports instead of stalling (ADR 0163): what the
//! connector could not apply, by position, never by record content, and
//! what it measured at the source, such as the log a replication slot
//! retains. The connector runtime gathers them and the plane stores them
//! with the sync outcome, so both sides share this one bounded, validated
//! type.

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

/// How much log a replication slot's server still guarantees to keep, as
/// the server reports it for the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WalStatus {
    /// Within the server's normal log size.
    Reserved,
    /// Past it, still kept because the slot needs it.
    Extended,
    /// No longer guaranteed: the next checkpoint may remove what the slot
    /// needs.
    Unreserved,
    /// Removed: the slot can no longer stream from its position.
    Lost,
}

impl WalStatus {
    const ALL: [Self; 4] = [Self::Reserved, Self::Extended, Self::Unreserved, Self::Lost];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Extended => "extended",
            Self::Unreserved => "unreserved",
            Self::Lost => "lost",
        }
    }

    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.wire_name() == name)
    }
}

/// The longest slot name a note carries, the server's identifier limit.
pub const MAX_SLOT_NAME_BYTES: usize = 63;

/// A slot name a note or the plane accepts: 1 to [`MAX_SLOT_NAME_BYTES`]
/// lowercase letters, digits and `_`, what the capture child accepts.
pub fn is_slot_name(slot: &str) -> bool {
    !slot.is_empty()
        && slot.len() <= MAX_SLOT_NAME_BYTES
        && slot
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// One thing a sync could not apply and reports instead of stalling, or
/// measured at the source. It names positions, never record content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The source keeps `bytes` of log for `slot` from its restart
    /// position to the server's current position, measured on the sync's
    /// last page. A sync reports at most one per slot: the last.
    RetainedLog {
        slot: String,
        bytes: i64,
        wal_status: WalStatus,
    },
}

impl SyncNote {
    /// A note names a partition and offsets that are not negative, and a
    /// gap ends after it starts; a retained log names a valid slot and a
    /// size that is not negative.
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
            Self::RetainedLog {
                ref slot, bytes, ..
            } => is_slot_name(slot) && bytes >= 0,
        }
    }
}

const INVALID_NOTE: &str = "a note names a partition and offsets that are not negative, \
                            a gap ends after it starts, and a retained log names a slot \
                            and a size that is not negative";

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
    /// counts it as overflow after that. A retained log replaces the one
    /// kept for its slot, so a sync carries the last measurement. Refuses
    /// an invalid note, as [`SyncNotes::new`] does. A runtime gathers a
    /// sync's notes page by page through this.
    pub fn push(&mut self, note: SyncNote) -> Result<(), String> {
        if !note.is_valid() {
            return Err(INVALID_NOTE.into());
        }
        if let SyncNote::RetainedLog { slot, .. } = &note
            && let Some(kept) = self.notes.iter_mut().find(
                |kept| matches!(kept, SyncNote::RetainedLog { slot: kept, .. } if kept == slot),
            )
        {
            *kept = note;
            return Ok(());
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

    #[test]
    fn a_retained_log_keeps_the_last_measurement_per_slot() {
        let retained = |slot: &str, bytes| SyncNote::RetainedLog {
            slot: slot.into(),
            bytes,
            wal_status: WalStatus::Reserved,
        };
        let mut notes = SyncNotes::default();
        for note in [retained("a", 1), retained("b", 5), retained("a", 9)] {
            notes.push(note).unwrap();
        }
        assert_eq!(notes.notes(), [retained("a", 9), retained("b", 5)]);
        assert!(notes.push(retained("A-slot", 1)).is_err());
        assert!(notes.push(retained("a", -1)).is_err());
    }
}
