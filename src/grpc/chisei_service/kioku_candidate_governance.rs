use std::collections::HashSet;
use std::sync::Arc;

use base64::Engine as _;
use tonic::Status;

use crate::chisei::kioku::{
    HumanMemoryReview, HumanReviewAction, KiokuCandidateCursor, KiokuEvidenceBasis,
    KiokuEvidenceLink, KiokuEvidenceReassessmentRequest, KiokuMemory, MemoryLifecycleEvent,
};
use crate::db::runtime_db::RuntimeDb;

const CANDIDATE_PAGE_SIZE: usize = 100;
const MAX_CANDIDATE_PAGES: usize = 4;

pub(super) struct CandidateDiscovery {
    pub memories: Vec<KiokuMemory>,
    pub cursor: Option<KiokuCandidateCursor>,
    pub has_more: bool,
}

pub(super) struct CandidateDiscoveryCommand {
    pub namespace: String,
    pub operation_class: String,
    pub actor: String,
    pub limit: usize,
    pub cursor: Option<KiokuCandidateCursor>,
    pub now_ms: i64,
}

pub(super) enum CandidateReviewCommand {
    Reassess {
        memory_id: String,
        memory_version: u32,
        reassessment_key: String,
        actor: String,
        evidence_basis: Vec<KiokuEvidenceBasis>,
        now_ms: i64,
    },
    Human {
        memory_id: String,
        memory_version: u32,
        action: String,
        actor: String,
        rationale: String,
        now_ms: i64,
    },
}

pub(super) struct CandidateReviewOutcome {
    pub memory: KiokuMemory,
    pub lifecycle_events: Vec<MemoryLifecycleEvent>,
    pub evidence: Vec<KiokuEvidenceLink>,
    pub idempotent: bool,
}

pub(super) struct KiokuCandidateGovernance {
    db: Arc<RuntimeDb>,
}

impl KiokuCandidateGovernance {
    pub fn new(db: Arc<RuntimeDb>) -> Self {
        Self { db }
    }

    pub fn decode_cursor(
        namespace: &str,
        operation_class: &str,
        page_token: &str,
    ) -> Result<Option<KiokuCandidateCursor>, Status> {
        if page_token.is_empty() {
            return Ok(None);
        }
        let invalid = || Status::invalid_argument("invalid Kioku candidate page token");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(page_token)
            .map_err(|_| invalid())?;
        let token: serde_json::Value = serde_json::from_slice(&decoded).map_err(|_| invalid())?;
        let token_namespace = token
            .get("namespace")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        let token_operation_class = token
            .get("operation_class")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        let id = token
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(invalid)?;
        let version = token
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|version| u32::try_from(version).ok())
            .filter(|version| *version > 0)
            .ok_or_else(invalid)?;
        if token_namespace != namespace || token_operation_class != operation_class {
            return Err(Status::invalid_argument(
                "Kioku candidate page token does not match the request filters",
            ));
        }
        Ok(Some(KiokuCandidateCursor {
            id: id.to_string(),
            version,
        }))
    }

    pub fn encode_cursor(
        namespace: &str,
        operation_class: &str,
        cursor: &KiokuCandidateCursor,
    ) -> String {
        let token = serde_json::json!({
            "namespace": namespace,
            "operation_class": operation_class,
            "id": cursor.id,
            "version": cursor.version,
        });
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&token).expect("Kioku candidate page token is serializable"))
    }

    pub fn discover(
        &self,
        command: CandidateDiscoveryCommand,
    ) -> Result<CandidateDiscovery, Status> {
        let CandidateDiscoveryCommand {
            namespace,
            operation_class,
            actor,
            limit,
            mut cursor,
            now_ms,
        } = command;
        let mut memories = Vec::new();
        let mut seen = HashSet::new();
        let classification_ceiling = self
            .db
            .kioku_authorized_classification_ceiling(&namespace, &actor)
            .ok();
        let mut has_more = false;
        for _ in 0..MAX_CANDIDATE_PAGES {
            let page = self
                .db
                .list_kioku_candidate_page(&namespace, CANDIDATE_PAGE_SIZE, cursor.as_ref())
                .map_err(Status::internal)?;
            let page_len = page.len();
            if page_len == 0 {
                break;
            }
            let page_last = page.last().map(|memory| KiokuCandidateCursor {
                id: memory.id.clone(),
                version: memory.version,
            });
            let mut last_examined = None;
            let mut stopped_early = false;
            for memory in page {
                let current_cursor = KiokuCandidateCursor {
                    id: memory.id.clone(),
                    version: memory.version,
                };
                last_examined = Some(current_cursor);
                if !seen.insert((memory.id.clone(), memory.version)) {
                    continue;
                }
                if !operation_class.is_empty()
                    && !memory
                        .operation_classes
                        .iter()
                        .any(|candidate| candidate == &operation_class)
                {
                    continue;
                }
                let authorized = classification_ceiling.is_some_and(|ceiling| {
                    memory.classification <= ceiling
                        && memory
                            .retention_until_ms
                            .is_none_or(|retention| retention > now_ms)
                        && memory.expires_at_ms.is_none_or(|expires| expires > now_ms)
                });
                if !authorized {
                    continue;
                }
                let evidence_authorized = memory.evidence_basis.iter().all(|basis| {
                    basis.source_submission_id.is_empty()
                        || self
                            .db
                            .authorize_kioku_evidence(
                                &crate::chisei::kioku::KiokuEvidenceAuthorizationRequest {
                                    source_submission_id: basis.source_submission_id.clone(),
                                    namespace: memory.namespace.clone(),
                                    memory_classification: memory.classification,
                                    evidence_digest: basis.evidence_digest.clone(),
                                    lifecycle_state: basis.lifecycle_state,
                                    observed_at_ms: basis.observed_at_ms,
                                    actor: actor.clone(),
                                    now_ms,
                                },
                            )
                            .is_ok()
                });
                if evidence_authorized {
                    memories.push(memory);
                    if memories.len() >= limit {
                        stopped_early = true;
                        break;
                    }
                }
            }
            cursor = last_examined.or(page_last.clone());
            has_more = if stopped_early {
                cursor.as_ref() != page_last.as_ref() || page_len == CANDIDATE_PAGE_SIZE
            } else {
                page_len == CANDIDATE_PAGE_SIZE
            };
            if memories.len() >= limit || !has_more {
                break;
            }
        }
        Ok(CandidateDiscovery {
            memories,
            cursor,
            has_more,
        })
    }

    pub fn review(
        &self,
        command: CandidateReviewCommand,
    ) -> Result<CandidateReviewOutcome, Status> {
        match command {
            CandidateReviewCommand::Reassess {
                memory_id,
                memory_version,
                reassessment_key,
                actor,
                evidence_basis,
                now_ms,
            } => {
                let result = self
                    .db
                    .reassess_kioku_memory(KiokuEvidenceReassessmentRequest {
                        memory_id,
                        memory_version,
                        reassessment_key,
                        actor,
                        evidence_basis,
                        now_ms,
                    })
                    .map_err(Status::failed_precondition)?;
                let lifecycle_events = self
                    .db
                    .list_kioku_lifecycle_events(&result.candidate.id, result.candidate.version)
                    .map_err(Status::internal)?;
                Ok(CandidateReviewOutcome {
                    memory: result.candidate,
                    lifecycle_events,
                    evidence: result.evidence,
                    idempotent: result.idempotent,
                })
            }
            CandidateReviewCommand::Human {
                memory_id,
                memory_version,
                action,
                actor,
                rationale,
                now_ms,
            } => {
                let memory = match action.as_str() {
                    "promote" | "reject" | "supersede" => {
                        let memory = self
                            .db
                            .get_kioku_memory(&memory_id, memory_version)
                            .map_err(Status::internal)?
                            .ok_or_else(|| Status::not_found("memory version not found"))?;
                        if action == "supersede" && memory.supersedes.is_none() {
                            return Err(Status::failed_precondition(
                                "supersede requires candidate lineage to an active memory",
                            ));
                        }
                        self.db
                            .review_kioku_candidate(
                                &memory_id,
                                memory_version,
                                HumanMemoryReview {
                                    action: if action == "reject" {
                                        HumanReviewAction::Reject
                                    } else {
                                        HumanReviewAction::Promote
                                    },
                                    reviewer: actor,
                                    rationale,
                                    reviewed_at_ms: now_ms,
                                },
                            )
                            .map_err(Status::failed_precondition)?
                    }
                    "disable" => self
                        .db
                        .disable_kioku_memory(
                            &memory_id,
                            memory_version,
                            &actor,
                            &rationale,
                            now_ms,
                        )
                        .map_err(Status::failed_precondition)?,
                    _ => {
                        return Err(Status::invalid_argument(
                            "action must be promote, reject, supersede, or disable",
                        ));
                    }
                };
                let lifecycle_events = self
                    .db
                    .list_kioku_lifecycle_events(&memory.id, memory.version)
                    .map_err(Status::internal)?;
                Ok(CandidateReviewOutcome {
                    memory,
                    lifecycle_events,
                    evidence: Vec::new(),
                    idempotent: false,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_cursor_round_trips_with_filter_binding() {
        let cursor = KiokuCandidateCursor {
            id: "memory-7".into(),
            version: 3,
        };
        let token = KiokuCandidateGovernance::encode_cursor("team-a", "chat", &cursor);

        assert_eq!(
            KiokuCandidateGovernance::decode_cursor("team-a", "chat", &token).unwrap(),
            Some(cursor)
        );
        let error = KiokuCandidateGovernance::decode_cursor("team-b", "chat", &token)
            .expect_err("cursor must remain bound to its namespace");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn candidate_cursor_rejects_malformed_input() {
        let error = KiokuCandidateGovernance::decode_cursor("team-a", "chat", "not-base64!")
            .expect_err("malformed tokens must fail closed");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}
