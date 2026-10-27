//! Trust scoring rule and object trust score RPCs (#1456).
//!
//! `ScoreObjectTrust` evaluates one object-set page through the ordinary
//! authorized path, then scores each visible member. Every signal is read as
//! the caller: hidden properties, hidden linked objects and undisclosed
//! sources contribute nothing.

use super::*;
use crate::sekai::source_health::{
    CLASS_UNAVAILABLE, DEFAULT_DELAYED_AFTER_MS, SourceHealthQuery, project_source_health,
};
use crate::sekai::trust_score::{
    self, StoredTrustScoringRule, TrustInputs, TrustRuleError, TrustScoringRule,
};
use std::collections::{BTreeSet, HashMap};

fn to_proto_rule(stored: &StoredTrustScoringRule) -> Result<TrustScoringRuleRevision, Status> {
    Ok(TrustScoringRuleRevision {
        namespace: stored.rule.namespace.clone(),
        rule_json: stored.rule.canonical_json().map_err(Status::internal)?,
        revision_digest: stored.revision_digest.clone(),
        version: stored.version,
        updated_by: stored.updated_by.clone(),
        updated_at_ms: stored.updated_at_ms,
    })
}

fn load_rule(
    service: &SekaiServiceImpl,
    namespace: &str,
) -> Result<StoredTrustScoringRule, Status> {
    trust_score::get_rule(service.db.runtime(), namespace)
        .map_err(|_| Status::failed_precondition("stored trust scoring rule is invalid"))?
        .ok_or_else(|| Status::failed_precondition("namespace has no trust scoring rule"))
}

pub(super) async fn put_trust_scoring_rule(
    service: &SekaiServiceImpl,
    req: Request<PutTrustScoringRuleRequest>,
) -> Result<Response<PutTrustScoringRuleResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let db = service.db.runtime();
    let tenant_context = request_tenant_context(db, &req)?;
    let input = req.into_inner();
    let rule = TrustScoringRule::parse(&input.rule_json).map_err(Status::invalid_argument)?;
    enforce_namespace_tenant_context(db, tenant_context.as_ref(), &rule.namespace, true)?;
    check_team_namespace(db, &principals, &rule.namespace, true)?;
    let actor = principals.first().cloned().unwrap_or_default();
    let stored = trust_score::put_rule(
        db,
        &rule,
        &input.expected_revision_digest,
        &actor,
        now_millis(),
    )
    .map_err(|error| match error {
        TrustRuleError::Invalid(message) => Status::invalid_argument(message),
        TrustRuleError::RevisionMismatch => Status::failed_precondition(
            "expected_revision_digest does not name the current trust scoring rule",
        ),
        TrustRuleError::Storage(message) => Status::internal(message),
    })?;
    Ok(Response::new(PutTrustScoringRuleResponse {
        rule: Some(to_proto_rule(&stored)?),
    }))
}

pub(super) async fn get_trust_scoring_rule(
    service: &SekaiServiceImpl,
    req: Request<GetTrustScoringRuleRequest>,
) -> Result<Response<GetTrustScoringRuleResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let db = service.db.runtime();
    let tenant_context = request_tenant_context(db, &req)?;
    let namespace = req.into_inner().namespace;
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &namespace,
        false,
    )?;
    let stored = trust_score::get_rule(db, &namespace)
        .map_err(|_| Status::failed_precondition("stored trust scoring rule is invalid"))?
        .ok_or_else(|| Status::not_found("not found"))?;
    Ok(Response::new(GetTrustScoringRuleResponse {
        rule: Some(to_proto_rule(&stored)?),
    }))
}

pub(super) async fn score_object_trust(
    service: &SekaiServiceImpl,
    req: Request<ScoreObjectTrustRequest>,
) -> Result<Response<ScoreObjectTrustResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let db = service.db.runtime();
    let tenant_context = request_tenant_context(db, &req)?;
    let purpose = request_purpose_presentation(&req, &principals);
    let policy_context = principal_policy_context(&req);
    let (metadata, extensions, input) = req.into_parts();
    if input.min_score > u32::from(trust_score::MAX_TRUST_SCORE) {
        return Err(Status::invalid_argument("min_score must be at most 100"));
    }
    let descriptor = input
        .descriptor
        .ok_or_else(|| Status::invalid_argument("object-set descriptor required"))?;
    let namespace = descriptor.namespace.clone();
    let page = service
        .evaluate_visible_object_set(Request::from_parts(
            metadata,
            extensions,
            EvaluateObjectSetRequest {
                descriptor: Some(descriptor),
                page_token: input.page_token,
                required_freshness_ms: 0,
            },
        ))
        .await?
        .into_inner();
    let stored = load_rule(service, &namespace)?;
    let rule = &stored.rule;
    let now_ms = now_millis();
    // Source health is disclosed only to namespace members, as on
    // `ReportSourceHealth`; anyone else sees every source as unavailable.
    let sources_disclosed = principals.first().is_some_and(|actor| {
        crate::sekai::namespace_access::principal_can_access_namespace(db, actor, &namespace)
            .unwrap_or(false)
    });
    let mut links = LinkScan {
        service,
        principals: &principals,
        tenant_context: tenant_context.as_ref(),
        purpose: purpose.as_ref(),
        policy_context: &policy_context,
        remaining: LINK_SCAN_LIMIT,
    };

    let mut source_classes: HashMap<(String, String), String> = HashMap::new();
    let mut scores = Vec::new();
    for member in &page.members {
        let object = from_proto_obj(member);
        let source = match (
            object.properties.get("sync_source_instance"),
            object.properties.get("sync_type_digest"),
        ) {
            (Some(instance), Some(digest)) => Some(
                source_classes
                    .entry((instance.clone(), digest.clone()))
                    .or_insert_with(|| {
                        if sources_disclosed {
                            source_class(db, &namespace, instance, digest, now_ms)
                        } else {
                            CLASS_UNAVAILABLE.into()
                        }
                    })
                    .clone(),
            ),
            _ => None,
        };
        let inputs = TrustInputs {
            source_class: source,
            age_ms: now_ms.saturating_sub(object.updated).max(0),
            verified: trust_score::is_verified(rule, &object),
            agreements: links.count(&object.id, &rule.agreement_relation, rule.agreement_bonus)?,
            conflicts: links.count(&object.id, &rule.conflict_relation, rule.conflict_penalty)?,
        };
        let scored = trust_score::score(rule, &inputs);
        if u32::from(scored.score) < input.min_score {
            continue;
        }
        scores.push(ObjectTrustScore {
            object_id: object.id,
            score: u32::from(scored.score),
            reasons: scored
                .reasons
                .into_iter()
                .map(|reason| TrustReason {
                    factor: reason.factor,
                    delta: reason.delta,
                    detail: reason.detail,
                })
                .collect(),
        });
    }
    if input.order_by_score {
        scores.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.object_id.cmp(&right.object_id))
        });
    }
    Ok(Response::new(ScoreObjectTrustResponse {
        rule_revision_digest: stored.revision_digest,
        scores,
        next_page_token: page.next_page_token,
    }))
}

/// Health class of a source, or `unavailable` when it cannot be read.
fn source_class(
    db: &crate::db::runtime_db::RuntimeDb,
    namespace: &str,
    source_instance: &str,
    type_digest: &str,
    now_ms: i64,
) -> String {
    let query = SourceHealthQuery {
        namespace: namespace.into(),
        source_instance: source_instance.into(),
        type_digest: type_digest.into(),
        delayed_after_ms: DEFAULT_DELAYED_AFTER_MS,
        contract_version: None,
    };
    match db.get_source_sync_state(namespace, source_instance, type_digest) {
        Ok(Some(state)) => project_source_health(&state, &query, now_ms).class,
        Ok(None) | Err(_) => CLASS_UNAVAILABLE.into(),
    }
}

/// Raw link rows one `ScoreObjectTrust` request may read across all members.
/// Past it the request fails with `RESOURCE_EXHAUSTED`.
pub(crate) const LINK_SCAN_LIMIT: usize = 10_000;

/// Counts linking objects for the agreement and conflict factors under one
/// request-wide row budget.
struct LinkScan<'a> {
    service: &'a SekaiServiceImpl,
    principals: &'a [String],
    tenant_context: Option<&'a RequestEnterpriseContext>,
    purpose: Option<&'a crate::sekai::purpose_authorization::PurposePresentation>,
    policy_context: &'a crate::sekai::object_security::PrincipalPolicyContext,
    remaining: usize,
}

impl LinkScan<'_> {
    /// Distinct objects the caller can see, with the request's purpose, that
    /// link to `object_id` with `relation`. A factor with no weight reads
    /// nothing.
    fn count(&mut self, object_id: &str, relation: &str, weight: u8) -> Result<u32, Status> {
        if relation.is_empty() || weight == 0 {
            return Ok(0);
        }
        let db = self.service.db.runtime();
        let links = db
            .get_links_with_policy_context_limited(
                object_id,
                relation,
                &domain::Direction::Incoming,
                self.policy_context,
                self.remaining + 1,
            )
            .map_err(Status::internal)?;
        if links.len() > self.remaining {
            return Err(Status::resource_exhausted(
                "too many linked objects to score in one request",
            ));
        }
        self.remaining -= links.len();
        let mut visible = BTreeSet::new();
        for link in links {
            if link.from_id == object_id || visible.contains(&link.from_id) {
                continue;
            }
            let shown = db
                .get_object(&link.from_id)
                .map_err(Status::internal)?
                .is_some_and(|linked| {
                    object_is_visible_for_purpose(
                        db,
                        &self.service.security,
                        &linked,
                        self.principals,
                        self.tenant_context,
                        crate::sekai::object_security::ObjectSecurityOperation::Read,
                        self.purpose,
                    )
                });
            if shown {
                visible.insert(link.from_id);
            }
        }
        Ok(visible.len() as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
            RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap())),
        )))
    }

    fn as_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn seed_definition(svc: &SekaiServiceImpl) -> String {
        let members = vec![
            DefinitionMemberInput {
                member_kind: "object_type".into(),
                member_id: "Report".into(),
                definition_json: r#"{"name":"Report","properties":{"verified_by":{"type":"string"},"sync_source_instance":{"type":"string"},"sync_type_digest":{"type":"string"}}}"#.into(),
                member_digest: String::new(),
            }
            .prepare("acme")
            .unwrap(),
        ];
        let revision = prepare_revision(
            "acme",
            "",
            members.iter().map(|item| DefinitionRevisionMember {
                member_kind: item.member_kind.clone(),
                member_id: item.member_id.clone(),
                member_digest: item.member_digest.clone(),
            }),
            true,
            "root",
            1,
        )
        .unwrap();
        svc.db
            .runtime()
            .seed_published_definition_revision(&revision, &members)
            .unwrap();
        revision.revision_digest
    }

    fn object(id: &str, kind: &str, properties: &[(&str, &str)], updated: i64) -> domain::Object {
        domain::Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: format!("acme:{id}"),
            properties: properties
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
            created: updated,
            updated,
        }
    }

    fn link(svc: &SekaiServiceImpl, from: &str, to: &str, relation: &str) {
        svc.db
            .runtime()
            .create_link(&domain::Link {
                id: format!("{from}-{relation}-{to}"),
                from_id: from.into(),
                to_id: to.into(),
                relation: relation.into(),
                created: 1,
            })
            .unwrap();
    }

    fn rule_json() -> String {
        serde_json::json!({
            "contract_version": trust_score::TRUST_SCORING_RULE_CONTRACT,
            "namespace": "acme",
            "base": 60,
            "source_penalties": {"unavailable": 30},
            "expected_freshness_ms": 86_400_000,
            "stale_penalty": 20,
            "verification_property": "verified_by",
            "verified_bonus": 25,
            "agreement_relation": "corroborates",
            "agreement_bonus": 10,
            "conflict_relation": "contradicts",
            "conflict_penalty": 10
        })
        .to_string()
    }

    fn descriptor(digest: &str) -> ObjectSetDescriptor {
        ObjectSetDescriptor {
            contract_version: crate::sekai::object_set::CONTRACT_VERSION.into(),
            namespace: "acme".into(),
            kind: "Report".into(),
            definition_digest: digest.into(),
            limit: 10,
            ..Default::default()
        }
    }

    /// `stale` comes from a source the plane cannot vouch for, was last
    /// updated long ago and is contradicted; `fresh` is recent, verified and
    /// corroborated.
    fn fixture() -> (SekaiServiceImpl, String) {
        let svc = service();
        let digest = seed_definition(&svc);
        let now = now_millis();
        for item in [
            object(
                "stale",
                "Report",
                &[
                    ("sync_source_instance", "ledger"),
                    ("sync_type_digest", "sha256:types"),
                ],
                now - 30 * 86_400_000,
            ),
            object("fresh", "Report", &[("verified_by", "alice")], now),
            object("witness", "Evidence", &[], now),
        ] {
            svc.db.runtime().create_object(&item).unwrap();
        }
        link(&svc, "witness", "stale", "contradicts");
        link(&svc, "witness", "fresh", "corroborates");
        (svc, digest)
    }

    async fn put(
        svc: &SekaiServiceImpl,
        expected: &str,
    ) -> Result<TrustScoringRuleRevision, Status> {
        put_trust_scoring_rule(
            svc,
            as_principal(
                PutTrustScoringRuleRequest {
                    rule_json: rule_json(),
                    expected_revision_digest: expected.into(),
                },
                "root",
            ),
        )
        .await
        .map(|response| response.into_inner().rule.unwrap())
    }

    #[tokio::test]
    async fn trust_scores_rank_fresh_verified_objects_above_stale_failing_ones() {
        let (svc, digest) = fixture();
        let rule = put(&svc, "").await.unwrap();
        let scored = |min_score| {
            score_object_trust(
                &svc,
                as_principal(
                    ScoreObjectTrustRequest {
                        descriptor: Some(descriptor(&digest)),
                        page_token: String::new(),
                        min_score,
                        order_by_score: true,
                    },
                    "root",
                ),
            )
        };
        let all = scored(0).await.unwrap().into_inner();
        assert_eq!(all.rule_revision_digest, rule.revision_digest);
        let ids: Vec<&str> = all.scores.iter().map(|s| s.object_id.as_str()).collect();
        assert_eq!(ids, ["fresh", "stale"]);
        let factors = |id: &str| -> Vec<(String, i32)> {
            all.scores
                .iter()
                .find(|s| s.object_id == id)
                .unwrap()
                .reasons
                .iter()
                .map(|r| (r.factor.clone(), r.delta))
                .collect()
        };
        assert_eq!(all.scores[0].score, 95);
        assert_eq!(
            factors("fresh"),
            [
                ("base".into(), 60),
                ("verification".into(), 25),
                ("agreement".into(), 10)
            ]
        );
        assert_eq!(all.scores[1].score, 0);
        assert_eq!(
            factors("stale"),
            [
                ("base".into(), 60),
                ("source".into(), -30),
                ("freshness".into(), -20),
                ("conflict".into(), -10)
            ]
        );

        let trusted = scored(50).await.unwrap().into_inner();
        let ids: Vec<&str> = trusted
            .scores
            .iter()
            .map(|s| s.object_id.as_str())
            .collect();
        assert_eq!(ids, ["fresh"]);
    }

    #[tokio::test]
    async fn changing_the_rule_is_governed_and_audited() {
        let (svc, _) = fixture();
        let denied = put_trust_scoring_rule(
            &svc,
            as_principal(
                PutTrustScoringRuleRequest {
                    rule_json: rule_json(),
                    expected_revision_digest: String::new(),
                },
                "alice",
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let first = put(&svc, "").await.unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(put(&svc, "").await.unwrap(), first, "a retry is a no-op");
        let stale_write = put_trust_scoring_rule(
            &svc,
            as_principal(
                PutTrustScoringRuleRequest {
                    rule_json: rule_json().replace("\"base\":60", "\"base\":50"),
                    expected_revision_digest: "sha256:other".into(),
                },
                "root",
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(stale_write.code(), tonic::Code::FailedPrecondition);

        // The audit trail is the rule object's change log, written with it.
        let changes = svc
            .db
            .runtime()
            .list_object_changes(
                &format!("{}:acme", trust_score::TRUST_SCORING_RULE_KIND),
                10,
                0,
            )
            .unwrap();
        assert!(
            changes
                .iter()
                .any(|change| change.field == "_created" && change.changed_by == "root")
        );
        let got = get_trust_scoring_rule(
            &svc,
            as_principal(
                GetTrustScoringRuleRequest {
                    namespace: "acme".into(),
                },
                "root",
            ),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(got.rule.unwrap(), first);

        // The rule object is reserved: generic reads and writes do not see it.
        let listed = svc
            .db
            .runtime()
            .get_object(&format!("{}:acme", trust_score::TRUST_SCORING_RULE_KIND))
            .unwrap()
            .unwrap();
        assert!(is_reserved_governance_kind(&listed.kind));
    }
}
