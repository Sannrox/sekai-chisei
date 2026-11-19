//! Rebase and archive of governed definition branches (#2434).
//!
//! A proposal pins the published head as its base, so a branch that fell
//! behind cannot merge. Rebase moves such a branch onto the current published
//! revision. Each member is compared three ways: branch base, branch head and
//! published revision. A member changed on one side only takes that side; a
//! member changed on both sides to different content (or removed on one side
//! and changed on the other) is a conflict. Nothing is written until every
//! conflict has an explicit resolution. A dry run computes the same answer and
//! writes nothing, which is how a stale branch is previewed.
//!
//! Both backends load the rows inside their own transaction and call into
//! this module, so the merge rules exist once.
//!
//! Archive takes a branch out of open work: it closes the branch's open
//! proposals and refuses edits, proposals and rebase until it is restored.
//! Members and revisions are content addressed and kept.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::sekai::definition_branch::{
    DefinitionBranch, DefinitionMemberRef, DefinitionRevision, DefinitionRevisionMember,
    MAX_DEFINITION_ID_BYTES, MAX_DEFINITION_MEMBERS, canonical_digest, prepare_revision,
    validate_digest, validate_identifier, validate_namespace,
};
use crate::sekai::definition_proposal::{
    DefinitionProposal, STATUS_CLOSED, STATUS_MERGED, STATUS_OPEN,
};

/// Longest archive reason a caller may give.
pub const MAX_ARCHIVE_REASON_BYTES: usize = 1024;

/// How one conflicting member is resolved. Nothing is resolved without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RebaseChoice {
    /// Keep the member as the branch head has it.
    KeepBranch,
    /// Take the member as the published revision has it.
    TakePublished,
}

impl RebaseChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeepBranch => "keep_branch",
            Self::TakePublished => "take_published",
        }
    }

    /// The choice named `name`, as written on the wire.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "keep_branch" => Some(Self::KeepBranch),
            "take_published" => Some(Self::TakePublished),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RebaseResolution {
    pub member_kind: String,
    pub member_id: String,
    pub choice: RebaseChoice,
}

/// A member changed on both sides. An empty digest means the side does not
/// have the member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebaseConflict {
    pub member_kind: String,
    pub member_id: String,
    pub base_member_digest: String,
    pub branch_member_digest: String,
    pub published_member_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebaseDefinitionBranch {
    pub namespace: String,
    pub branch_id: String,
    pub expected_head_digest: String,
    /// The published revision to rebase onto; it must still be published.
    pub onto_published_digest: String,
    pub resolutions: Vec<RebaseResolution>,
    /// Compute the outcome and write nothing.
    pub dry_run: bool,
    /// Required unless `dry_run`.
    pub idempotency_key: String,
}

#[derive(Serialize)]
struct RebaseDigestInput<'a> {
    namespace: &'a str,
    branch_id: &'a str,
    expected_head_digest: &'a str,
    onto_published_digest: &'a str,
    resolutions: &'a [RebaseResolution],
}

impl RebaseDefinitionBranch {
    /// Validates the request and returns its digest. The digest leaves out
    /// `dry_run`, so a dry run with the key of a finished rebase replays it.
    pub fn prepare(&self) -> Result<String, String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("branch_id", &self.branch_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("expected_head_digest", &self.expected_head_digest)?;
        validate_digest("onto_published_digest", &self.onto_published_digest)?;
        if !self.dry_run || !self.idempotency_key.is_empty() {
            validate_identifier(
                "idempotency_key",
                &self.idempotency_key,
                MAX_DEFINITION_ID_BYTES,
            )?;
        }
        if self.resolutions.len() > MAX_DEFINITION_MEMBERS {
            return Err("rebase resolutions exceed the supported member count".into());
        }
        let mut resolutions = self.resolutions.clone();
        resolutions.sort();
        let mut seen = BTreeSet::new();
        for resolution in &resolutions {
            DefinitionMemberRef {
                member_kind: resolution.member_kind.clone(),
                member_id: resolution.member_id.clone(),
            }
            .validate()?;
            if !seen.insert((&resolution.member_kind, &resolution.member_id)) {
                return Err("rebase names one member in two resolutions".into());
            }
        }
        canonical_digest(
            "rebase_definition_branch",
            &RebaseDigestInput {
                namespace: &self.namespace,
                branch_id: &self.branch_id,
                expected_head_digest: &self.expected_head_digest,
                onto_published_digest: &self.onto_published_digest,
                resolutions: &resolutions,
            },
        )
    }

    /// Refuses a rebase of `branch` while `published_digest` is the
    /// published head.
    pub fn check(&self, branch: &DefinitionBranch, published_digest: &str) -> Result<(), String> {
        branch.require_active()?;
        if branch.head_revision_digest != self.expected_head_digest {
            return Err("stale_definition_branch_head: expected head is no longer current".into());
        }
        if published_digest != self.onto_published_digest {
            return Err(
                "stale_published_definition_head: onto_published_digest is not the published head"
                    .into(),
            );
        }
        if branch.base_revision_digest == published_digest {
            return Err(
                "definition_rebase_no_change: the branch is already based on the published head"
                    .into(),
            );
        }
        Ok(())
    }
}

/// What a rebase did, or would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionBranchRebaseResult {
    /// The branch after the rebase, or as it is when nothing was applied.
    pub branch: DefinitionBranch,
    pub previous_head_digest: String,
    /// The rebased head revision; `None` while a conflict is unresolved.
    /// It is the published revision itself when nothing of the branch is
    /// left after the rebase.
    pub revision: Option<DefinitionRevision>,
    pub conflicts: Vec<RebaseConflict>,
    /// Members whose content differs from the branch head after the rebase.
    pub changed_members: Vec<DefinitionMemberRef>,
    /// Open proposals the rebase closed as superseded.
    pub superseded_proposal_ids: Vec<String>,
    /// False for a dry run and when a conflict is unresolved.
    pub applied: bool,
}

/// The three-way merge of one branch onto a published revision.
pub fn rebase_branch(
    branch: &DefinitionBranch,
    base: &DefinitionRevision,
    head: &DefinitionRevision,
    published: &DefinitionRevision,
    resolutions: &[RebaseResolution],
    actor: &str,
    now_ms: i64,
) -> Result<DefinitionBranchRebaseResult, String> {
    let index = |revision: &DefinitionRevision| {
        revision
            .members
            .iter()
            .map(|member| {
                (
                    (member.member_kind.clone(), member.member_id.clone()),
                    member.member_digest.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let (base_members, head_members, published_members) =
        (index(base), index(head), index(published));
    let mut chosen = resolutions
        .iter()
        .map(|resolution| {
            (
                (resolution.member_kind.clone(), resolution.member_id.clone()),
                resolution.choice,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let keys = base_members
        .keys()
        .chain(head_members.keys())
        .chain(published_members.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut members = Vec::new();
    let mut conflicts = Vec::new();
    let mut changed_members = Vec::new();
    for key in keys {
        let (in_base, in_head, in_published) = (
            base_members.get(&key),
            head_members.get(&key),
            published_members.get(&key),
        );
        let merged = if in_head == in_base || in_head == in_published {
            in_published
        } else if in_published == in_base {
            in_head
        } else {
            match chosen.remove(&key) {
                Some(RebaseChoice::KeepBranch) => in_head,
                Some(RebaseChoice::TakePublished) => in_published,
                None => {
                    let digest = |side: Option<&String>| side.cloned().unwrap_or_default();
                    conflicts.push(RebaseConflict {
                        member_kind: key.0.clone(),
                        member_id: key.1.clone(),
                        base_member_digest: digest(in_base),
                        branch_member_digest: digest(in_head),
                        published_member_digest: digest(in_published),
                    });
                    continue;
                }
            }
        };
        if merged != in_head {
            changed_members.push(DefinitionMemberRef {
                member_kind: key.0.clone(),
                member_id: key.1.clone(),
            });
        }
        if let Some(digest) = merged {
            members.push(DefinitionRevisionMember {
                member_kind: key.0,
                member_id: key.1,
                member_digest: digest.clone(),
            });
        }
    }
    if let Some((kind, id)) = chosen.keys().next() {
        return Err(format!(
            "definition_rebase_resolution_unused: {kind}/{id} is not in conflict"
        ));
    }
    let revision = if !conflicts.is_empty() {
        None
    } else if members == published.members {
        Some(published.clone())
    } else {
        Some(prepare_revision(
            &published.namespace,
            &published.revision_digest,
            members,
            false,
            actor,
            now_ms,
        )?)
    };
    Ok(DefinitionBranchRebaseResult {
        branch: branch.clone(),
        previous_head_digest: branch.head_revision_digest.clone(),
        revision,
        conflicts,
        changed_members,
        superseded_proposal_ids: Vec::new(),
        applied: false,
    })
}

impl DefinitionBranchRebaseResult {
    /// Moves the branch onto the published revision and its new head. Call
    /// only when the rebase is written; `superseded` are the proposals it
    /// closed.
    pub fn apply(
        &mut self,
        published_digest: &str,
        superseded: Vec<String>,
        now_ms: i64,
    ) -> Result<(), String> {
        let revision = self
            .revision
            .as_ref()
            .ok_or("definition_rebase_conflict: resolve every conflict before rebasing")?;
        self.branch.base_revision_digest = published_digest.into();
        self.branch.head_revision_digest = revision.revision_digest.clone();
        self.branch.updated_at_ms = now_ms;
        self.superseded_proposal_ids = superseded;
        self.applied = true;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetDefinitionBranchArchived {
    pub namespace: String,
    pub branch_id: String,
    /// True archives the branch, false restores it.
    pub archived: bool,
    pub reason: String,
    pub idempotency_key: String,
}

impl SetDefinitionBranchArchived {
    pub fn request_digest(&self) -> Result<String, String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("branch_id", &self.branch_id, MAX_DEFINITION_ID_BYTES)?;
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )?;
        if self.reason.len() > MAX_ARCHIVE_REASON_BYTES || self.reason.chars().any(char::is_control)
        {
            return Err("archive reason must be short single-line text".into());
        }
        canonical_digest("set_definition_branch_archived", self)
    }

    /// Archives or restores `branch`. `proposals` are every proposal of the
    /// branch; archiving returns the open ones closed as `operator_abort`,
    /// which the caller writes. A merged branch is terminal and refused.
    pub fn apply(
        &self,
        branch: &mut DefinitionBranch,
        proposals: Vec<DefinitionProposal>,
        now_ms: i64,
    ) -> Result<Vec<DefinitionProposal>, String> {
        if proposals.iter().any(|proposal| {
            proposal.status == STATUS_MERGED
                && proposal.candidate_digest == branch.head_revision_digest
        }) {
            return Err("definition_branch_merged: a merged branch stays as it is".into());
        }
        match (self.archived, branch.archived_at_ms != 0) {
            (true, true) => {
                return Err("definition_branch_archived: branch is already archived".into());
            }
            (false, false) => {
                return Err("definition_branch_not_archived: branch is open work".into());
            }
            (true, false) => {
                branch.archived_at_ms = now_ms;
                branch.archive_reason = self.reason.clone();
            }
            (false, true) => {
                branch.archived_at_ms = 0;
                branch.archive_reason = String::new();
            }
        }
        branch.updated_at_ms = now_ms;
        Ok(if self.archived {
            close_open(
                proposals,
                crate::sekai::definition_proposal::CLOSE_REASON_OPERATOR_ABORT,
                now_ms,
            )
        } else {
            Vec::new()
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionBranchArchiveResult {
    pub branch: DefinitionBranch,
    /// Open proposals the archive closed as `operator_abort`.
    pub closed_proposal_ids: Vec<String>,
}

/// The open proposals of `proposals`, closed with `reason_code`.
pub fn close_open(
    proposals: Vec<DefinitionProposal>,
    reason_code: &str,
    now_ms: i64,
) -> Vec<DefinitionProposal> {
    proposals
        .into_iter()
        .filter(|proposal| proposal.status == STATUS_OPEN)
        .map(|mut proposal| {
            proposal.status = STATUS_CLOSED.into();
            proposal.close_reason_code = reason_code.into();
            proposal.updated_at_ms = now_ms;
            proposal
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn revision(parent: &str, members: &[(&str, char)]) -> DefinitionRevision {
        prepare_revision(
            "ns",
            parent,
            members
                .iter()
                .map(|(id, content)| DefinitionRevisionMember {
                    member_kind: "object_type".into(),
                    member_id: (*id).into(),
                    member_digest: digest(*content),
                }),
            false,
            "author",
            1,
        )
        .unwrap()
    }

    fn branch(base: &DefinitionRevision, head: &DefinitionRevision) -> DefinitionBranch {
        DefinitionBranch {
            contract_version: crate::sekai::definition_branch::BRANCH_CONTRACT_VERSION.into(),
            namespace: "ns".into(),
            branch_id: "b".into(),
            base_revision_digest: base.revision_digest.clone(),
            head_revision_digest: head.revision_digest.clone(),
            created_by: "author".into(),
            created_at_ms: 1,
            updated_at_ms: 1,
            archived_at_ms: 0,
            archive_reason: String::new(),
        }
    }

    fn resolve(id: &str, choice: RebaseChoice) -> RebaseResolution {
        RebaseResolution {
            member_kind: "object_type".into(),
            member_id: id.into(),
            choice,
        }
    }

    #[test]
    fn members_changed_on_one_side_take_that_side() {
        let base = revision("", &[("a", '1'), ("b", '1'), ("c", '1')]);
        // The branch changes a and removes c; the published side changes b
        // and adds d.
        let head = revision(&base.revision_digest, &[("a", '2'), ("b", '1')]);
        let published = revision(
            &base.revision_digest,
            &[("a", '1'), ("b", '3'), ("c", '1'), ("d", '4')],
        );
        let result = rebase_branch(
            &branch(&base, &head),
            &base,
            &head,
            &published,
            &[],
            "author",
            2,
        )
        .unwrap();
        assert!(result.conflicts.is_empty());
        let rebased = result.revision.unwrap();
        assert_eq!(rebased.parent_revision_digest, published.revision_digest);
        let members = rebased
            .members
            .iter()
            .map(|member| (member.member_id.as_str(), member.member_digest.clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            members,
            [("a", digest('2')), ("b", digest('3')), ("d", digest('4'))]
        );
        let changed = result
            .changed_members
            .iter()
            .map(|member| member.member_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(changed, ["b", "d"]);
    }

    #[test]
    fn a_member_changed_on_both_sides_is_a_conflict_until_resolved() {
        let base = revision("", &[("a", '1'), ("b", '1')]);
        let head = revision(&base.revision_digest, &[("a", '2')]);
        let published = revision(&base.revision_digest, &[("a", '3'), ("b", '4')]);
        let branch = branch(&base, &head);
        let result = rebase_branch(&branch, &base, &head, &published, &[], "author", 2).unwrap();
        assert_eq!(result.revision, None);
        let conflicts = result
            .conflicts
            .iter()
            .map(|c| {
                (
                    c.member_id.as_str(),
                    c.branch_member_digest.clone(),
                    c.published_member_digest.clone(),
                )
            })
            .collect::<Vec<_>>();
        // b was removed on the branch and changed on the published side.
        assert_eq!(
            conflicts,
            [
                ("a", digest('2'), digest('3')),
                ("b", String::new(), digest('4'))
            ]
        );

        let resolutions = [
            resolve("a", RebaseChoice::KeepBranch),
            resolve("b", RebaseChoice::TakePublished),
        ];
        let result =
            rebase_branch(&branch, &base, &head, &published, &resolutions, "author", 2).unwrap();
        let members = result.revision.unwrap().members;
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].member_digest, digest('2'));
        assert_eq!(members[1].member_digest, digest('4'));
    }

    #[test]
    fn a_resolution_for_a_member_without_conflict_is_refused() {
        let base = revision("", &[("a", '1')]);
        let head = revision(&base.revision_digest, &[("a", '2')]);
        let published = revision(&base.revision_digest, &[("a", '1'), ("b", '1')]);
        let error = rebase_branch(
            &branch(&base, &head),
            &base,
            &head,
            &published,
            &[resolve("a", RebaseChoice::KeepBranch)],
            "author",
            2,
        )
        .unwrap_err();
        assert!(
            error.starts_with("definition_rebase_resolution_unused"),
            "{error}"
        );
    }

    #[test]
    fn a_branch_with_nothing_left_lands_on_the_published_revision() {
        let base = revision("", &[("a", '1')]);
        let head = revision(&base.revision_digest, &[("a", '2')]);
        let published = revision(&base.revision_digest, &[("a", '2')]);
        let result = rebase_branch(
            &branch(&base, &head),
            &base,
            &head,
            &published,
            &[],
            "author",
            2,
        )
        .unwrap();
        assert_eq!(result.revision, Some(published));
    }

    #[test]
    fn archive_is_reversible_and_refused_on_a_merged_branch() {
        let base = revision("", &[("a", '1')]);
        let head = revision(&base.revision_digest, &[("a", '2')]);
        let mut branch = branch(&base, &head);
        let archive = SetDefinitionBranchArchived {
            namespace: "ns".into(),
            branch_id: "b".into(),
            archived: true,
            reason: "abandoned".into(),
            idempotency_key: "k".into(),
        };
        archive.apply(&mut branch, Vec::new(), 5).unwrap();
        assert_eq!(branch.archived_at_ms, 5);
        assert!(branch.require_active().is_err());
        assert!(archive.apply(&mut branch, Vec::new(), 6).is_err());
        let restore = SetDefinitionBranchArchived {
            archived: false,
            reason: String::new(),
            ..archive
        };
        restore.apply(&mut branch, Vec::new(), 7).unwrap();
        assert_eq!(
            (branch.archived_at_ms, branch.archive_reason.as_str()),
            (0, "")
        );
        assert!(branch.require_active().is_ok());
    }

    #[test]
    fn a_dry_run_shares_the_digest_of_the_real_call() {
        let request = RebaseDefinitionBranch {
            namespace: "ns".into(),
            branch_id: "b".into(),
            expected_head_digest: digest('1'),
            onto_published_digest: digest('2'),
            resolutions: vec![
                resolve("b", RebaseChoice::KeepBranch),
                resolve("a", RebaseChoice::TakePublished),
            ],
            dry_run: false,
            idempotency_key: "k".into(),
        };
        let dry = RebaseDefinitionBranch {
            dry_run: true,
            ..request.clone()
        };
        assert_eq!(request.prepare().unwrap(), dry.prepare().unwrap());
        let unkeyed = RebaseDefinitionBranch {
            idempotency_key: String::new(),
            ..dry
        };
        assert!(unkeyed.prepare().is_ok());
        let duplicated = RebaseDefinitionBranch {
            resolutions: vec![
                resolve("a", RebaseChoice::KeepBranch),
                resolve("a", RebaseChoice::TakePublished),
            ],
            ..request
        };
        assert!(duplicated.prepare().is_err());
    }
}
