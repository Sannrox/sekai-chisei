//! The one claim contract of ADR 0129, shared by every work kind (ADR 0149).
//!
//! Each kind keeps its claim state in its own row and reads and writes it in
//! its own transaction. It maps that state onto a [`ClaimRecord`] and its
//! status onto a [`Hold`], and leaves every decision about who holds the
//! work to the functions here: taking, counting a lapsed lease, renewing,
//! the fence check and releasing. Admission, payload and write-back stay
//! with the kind.

use std::fmt;

/// A kind of claimable work, with a stable wire name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WorkKind {
    Transform,
    Action,
    AgentTurn,
    /// A saved-export artifact awaiting delivery (ADR 0148).
    ExportDelivery,
    /// A Source's due sync bucket (ADR 0148).
    SourceSync,
}

impl WorkKind {
    pub const ALL: [WorkKind; 5] = [
        WorkKind::Transform,
        WorkKind::Action,
        WorkKind::AgentTurn,
        WorkKind::ExportDelivery,
        WorkKind::SourceSync,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            WorkKind::Transform => "transform",
            WorkKind::Action => "action",
            WorkKind::AgentTurn => "agent_turn",
            WorkKind::ExportDelivery => "export_delivery",
            WorkKind::SourceSync => "source_sync",
        }
    }

    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.wire_name() == name)
    }
}

impl fmt::Display for WorkKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// What a kind's status means for its claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hold {
    /// Waiting for a claimer.
    Open,
    /// Claimed; the lease may have lapsed.
    Held,
    /// Finished, parked, or otherwise not claimable.
    Closed,
}

/// Who holds a piece of work, as stored in the kind's row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimRecord {
    pub owner: String,
    pub generation: i64,
    pub fencing_token: String,
    pub expires_at_ms: i64,
    pub lease_expiries: i64,
}

/// The claim a caller presents on heartbeat, write-back or acknowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fence<'a> {
    pub owner: &'a str,
    pub generation: i64,
    pub token: &'a str,
}

/// Why a claim transition was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimError {
    /// Another claimer holds a live lease.
    Held,
    /// The work is not claimable.
    Closed,
    /// The lapsed lease reached the kind's limit; the kind fails the work.
    LeaseLimit,
    /// The presented claim is not the current, live one.
    FenceLost,
}

impl fmt::Display for ClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            ClaimError::Held => "work is held by a live claim",
            ClaimError::Closed => "work is not claimable",
            ClaimError::LeaseLimit => "lease expiry limit reached",
            ClaimError::FenceLost => "claim is not current",
        })
    }
}

impl std::error::Error for ClaimError {}

/// How open work became takeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Takeable {
    /// Never claimed, or released back to the queue.
    Open,
    /// A lapsed lease, now counted against the limit.
    Lapsed,
}

impl ClaimRecord {
    /// Whether the work may be taken at `now_ms`, without counting anything.
    /// `max_lease_expiries` of 0 means no limit.
    pub fn is_takeable(&self, hold: Hold, max_lease_expiries: i64, now_ms: i64) -> bool {
        match hold {
            Hold::Open => true,
            Hold::Held => {
                self.expires_at_ms <= now_ms
                    && (max_lease_expiries <= 0 || self.lease_expiries < max_lease_expiries)
            }
            Hold::Closed => false,
        }
    }

    /// The first step of a claim: refuses live or closed work and counts a
    /// lapsed lease. [`ClaimError::LeaseLimit`] leaves the counted lapse in
    /// the record; the kind then fails the work and persists it.
    pub fn count_lapse(
        &mut self,
        hold: Hold,
        max_lease_expiries: i64,
        now_ms: i64,
    ) -> Result<Takeable, ClaimError> {
        match hold {
            Hold::Open => Ok(Takeable::Open),
            Hold::Closed => Err(ClaimError::Closed),
            Hold::Held if self.expires_at_ms > now_ms => Err(ClaimError::Held),
            Hold::Held => {
                self.lease_expiries = self.lease_expiries.saturating_add(1);
                if max_lease_expiries > 0 && self.lease_expiries >= max_lease_expiries {
                    return Err(ClaimError::LeaseLimit);
                }
                Ok(Takeable::Lapsed)
            }
        }
    }

    /// The second step of a claim: grants it to `owner` for `ttl_ms` under
    /// the next generation. `mint` makes the fencing token for that
    /// generation; each kind keeps its own token format.
    pub fn grant(
        &mut self,
        owner: &str,
        ttl_ms: i64,
        now_ms: i64,
        mint: impl FnOnce(i64) -> String,
    ) {
        self.generation = self.generation.saturating_add(1).max(1);
        self.owner = owner.to_string();
        self.fencing_token = mint(self.generation);
        self.expires_at_ms = now_ms.saturating_add(ttl_ms);
    }

    /// Whether `fence` names this claim, whatever its lease or the work's
    /// status. Kinds use it to replay an acknowledged write-back.
    pub fn matches(&self, fence: Fence<'_>) -> bool {
        !fence.token.trim().is_empty()
            && self.owner == fence.owner
            && self.generation == fence.generation
            && self.fencing_token == fence.token
    }

    /// Whether `fence` names the held claim, lapsed or not.
    pub fn is_current(&self, hold: Hold, fence: Fence<'_>) -> bool {
        hold == Hold::Held && self.matches(fence)
    }

    /// The fence check every call on claimed work needs: the work is held,
    /// the lease is live and `fence` names the claim.
    pub fn require_live(
        &self,
        hold: Hold,
        fence: Fence<'_>,
        now_ms: i64,
    ) -> Result<(), ClaimError> {
        if self.is_current(hold, fence) && self.expires_at_ms > now_ms {
            Ok(())
        } else {
            Err(ClaimError::FenceLost)
        }
    }

    /// Extends the live claim by `ttl_ms` from `now_ms`.
    pub fn heartbeat(
        &mut self,
        hold: Hold,
        fence: Fence<'_>,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<(), ClaimError> {
        self.require_live(hold, fence, now_ms)?;
        self.expires_at_ms = now_ms.saturating_add(ttl_ms);
        Ok(())
    }

    /// Hands the held claim back to the queue, for a kind that refuses to
    /// start work it was granted (a quota refusal). A first claim is undone
    /// to generation 0; later ones keep their generation so older fences
    /// stay stale. `restore_lapse` returns a lapse the claim counted.
    pub fn requeue(
        &mut self,
        hold: Hold,
        fence: Fence<'_>,
        restore_lapse: bool,
    ) -> Result<(), ClaimError> {
        if !self.is_current(hold, fence) {
            return Err(ClaimError::FenceLost);
        }
        if self.generation <= 1 {
            self.generation = 0;
        }
        if restore_lapse {
            self.lease_expiries = self.lease_expiries.saturating_sub(1);
        }
        self.owner.clear();
        self.fencing_token.clear();
        self.expires_at_ms = 0;
        Ok(())
    }

    /// Ends the live claim, for an acknowledge. Owner, generation and token
    /// stay, so a retry of the same acknowledge can be matched.
    pub fn release(&mut self, hold: Hold, fence: Fence<'_>, now_ms: i64) -> Result<(), ClaimError> {
        self.require_live(hold, fence, now_ms)?;
        self.expires_at_ms = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fence(record: &ClaimRecord) -> Fence<'_> {
        Fence {
            owner: &record.owner,
            generation: record.generation,
            token: &record.fencing_token,
        }
    }

    fn take(
        record: &mut ClaimRecord,
        hold: Hold,
        owner: &str,
        now_ms: i64,
    ) -> Result<Takeable, ClaimError> {
        let takeable = record.count_lapse(hold, 3, now_ms)?;
        record.grant(owner, 100, now_ms, |generation| {
            format!("{owner}-{generation}")
        });
        Ok(takeable)
    }

    #[test]
    fn wire_names_round_trip() {
        for kind in WorkKind::ALL {
            assert_eq!(WorkKind::from_wire_name(kind.wire_name()), Some(kind));
        }
        assert_eq!(WorkKind::from_wire_name("external_effect"), None);
    }

    #[test]
    fn a_live_claim_excludes_and_a_lapsed_one_is_reclaimed_under_a_higher_generation() {
        let mut record = ClaimRecord::default();
        assert_eq!(take(&mut record, Hold::Open, "a", 10), Ok(Takeable::Open));
        assert_eq!((record.generation, record.expires_at_ms), (1, 110));
        let first = record.clone();

        assert_eq!(
            record.clone().count_lapse(Hold::Held, 3, 50),
            Err(ClaimError::Held)
        );
        assert_eq!(record.heartbeat(Hold::Held, fence(&first), 100, 50), Ok(()));
        assert_eq!(record.expires_at_ms, 150);

        assert_eq!(
            take(&mut record, Hold::Held, "b", 150),
            Ok(Takeable::Lapsed)
        );
        assert_eq!((record.generation, record.lease_expiries), (2, 1));
        assert_eq!(
            record.require_live(Hold::Held, fence(&first), 160),
            Err(ClaimError::FenceLost)
        );
        assert_eq!(
            record.release(Hold::Held, fence(&record.clone()), 160),
            Ok(())
        );
        assert!(record.matches(fence(&record.clone())));
        assert_eq!(
            record.count_lapse(Hold::Closed, 3, 170),
            Err(ClaimError::Closed)
        );
    }

    #[test]
    fn an_expired_lease_fences_and_the_limit_stops_reclaiming() {
        let mut record = ClaimRecord::default();
        take(&mut record, Hold::Open, "a", 0).unwrap();
        let held = record.clone();
        assert_eq!(
            record.heartbeat(Hold::Held, fence(&held), 100, 100),
            Err(ClaimError::FenceLost)
        );
        take(&mut record, Hold::Held, "b", 100).unwrap();
        take(&mut record, Hold::Held, "c", 200).unwrap();
        assert!(!record.is_takeable(Hold::Held, 2, 300));
        assert!(record.is_takeable(Hold::Held, 0, 300));
        assert_eq!(
            record.count_lapse(Hold::Held, 3, 300),
            Err(ClaimError::LeaseLimit)
        );
        assert_eq!(record.lease_expiries, 3);
    }

    #[test]
    fn a_blank_token_never_matches() {
        let record = ClaimRecord::default();
        let blank = Fence {
            owner: "",
            generation: 0,
            token: " ",
        };
        assert!(!record.matches(blank));
    }
}
