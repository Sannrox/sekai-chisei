//! `ListPendingDecisions` (#2203): per review kind, the list holds exactly
//! what that kind's decide RPC accepts from the caller. Each test lists
//! first, then checks every listed item is accepted and every caller left
//! out is refused by the decide RPC itself.

use super::*;

fn pending(namespace: &str, kinds: &[PendingDecisionKind]) -> ListPendingDecisionsRequest {
    ListPendingDecisionsRequest {
        namespace: namespace.into(),
        kinds: kinds.iter().map(|kind| *kind as i32).collect(),
        limit: 0,
        page_token: String::new(),
    }
}

/// The `(kind, subject_id)` of each decision `principal` sees, as a
/// credentialed caller.
async fn listed(
    svc: &SekaiServiceImpl,
    request: ListPendingDecisionsRequest,
    principal: &str,
) -> Vec<(PendingDecisionKind, String)> {
    svc.list_pending_decisions(as_decider(request, principal))
        .await
        .unwrap()
        .into_inner()
        .decisions
        .into_iter()
        .map(|decision| (decision.kind(), decision.subject_id))
        .collect()
}

#[tokio::test]
async fn pending_actions_and_plans_are_what_their_decide_rpcs_accept() {
    use PendingDecisionKind::{ActionInstance, PlanReview};
    let svc = service();
    let steps = plan_review_fixture(&svc);
    let digest = simulated_plan(&svc, "plan-p", "sim-1", steps.clone()).await;
    svc.submit_plan_review(with_principal(SubmitPlanReviewRequest {
        namespace: "acme".into(),
        plan_id: "plan-p".into(),
        simulation_id: "sim-1".into(),
    }))
    .await
    .unwrap();
    // plan.a parks for alice or bob; the planner `tester` submits it.
    let mut require_approval = action_policy::ActionPolicy::allow_all("agent:tester");
    require_approval.action_overrides.insert(
        crate::sekai::action_instance::SUBMIT_POLICY_ACTION.into(),
        action_policy::ActionDecision::RequireApproval,
    );
    svc.db
        .runtime()
        .upsert_action_policy(&require_approval)
        .unwrap();
    let instance_id = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: steps[0].type_id.clone(),
            version: steps[0].version.clone(),
            parameters_json: steps[0].parameters_json.clone(),
            idempotency_key: "pending-1".into(),
            request_id: "req-pending-1".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap()
        .instance_id;
    let both = pending("acme", &[ActionInstance, PlanReview]);

    // alice approves every step; bob not plan.c; tester submitted both.
    assert_eq!(
        listed(&svc, both.clone(), "alice").await,
        [
            (ActionInstance, instance_id.clone()),
            (PlanReview, "plan-p".to_string())
        ]
    );
    assert_eq!(
        listed(&svc, both.clone(), "bob").await,
        [(ActionInstance, instance_id.clone())]
    );
    for outsider in ["tester", "carol"] {
        assert!(listed(&svc, both.clone(), outsider).await.is_empty());
        let plan = decide_plan(&svc, "plan-p", &digest, "grant", outsider)
            .await
            .unwrap_err();
        assert_eq!(plan.code(), tonic::Code::PermissionDenied, "{outsider}");
    }
    let partial = decide_plan(&svc, "plan-p", &digest, "grant", "bob")
        .await
        .unwrap_err();
    assert_eq!(partial.code(), tonic::Code::PermissionDenied);
    let decide = |principal: &str| {
        svc.decide_action_instance(as_decider(
            DecideActionInstanceRequest {
                instance_id: instance_id.clone(),
                decision: "deny".into(),
                reason: String::new(),
            },
            principal,
        ))
    };
    for outsider in ["tester", "carol"] {
        let refused = decide(outsider).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{outsider}");
    }
    // The operator socket's self-asserted identity decides neither kind.
    let local = svc
        .list_pending_decisions(with_principal(both.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(local.decisions.is_empty());

    // One decision per page; a full page may be followed by an empty one.
    let mut token = String::new();
    let mut paged = Vec::new();
    loop {
        let page = svc
            .list_pending_decisions(as_decider(
                ListPendingDecisionsRequest {
                    limit: 1,
                    page_token: token,
                    ..both.clone()
                },
                "alice",
            ))
            .await
            .unwrap()
            .into_inner();
        paged.extend(page.decisions.into_iter().map(|item| item.subject_id));
        if page.next_page_token.is_empty() {
            break;
        }
        token = page.next_page_token;
    }
    assert_eq!(paged, [instance_id.clone(), "plan-p".to_string()]);

    decide("bob").await.unwrap();
    decide_plan(&svc, "plan-p", &digest, "grant", "alice")
        .await
        .unwrap();
    assert!(listed(&svc, both, "alice").await.is_empty());
}

#[tokio::test]
async fn pending_definition_proposals_are_what_approval_accepts() {
    use PendingDecisionKind::DefinitionProposal;
    let svc = service();
    let namespace = "pending-def";
    let parent = seed_definition_parent(&svc, namespace);
    grant_source_namespace(&svc, namespace, "tester", security::Role::Editor);
    grant_source_namespace(&svc, namespace, "carol", security::Role::Editor);
    // Only root and tester administer the proposal's member.
    for principal in ["root", "tester"] {
        let grant = security::Grant {
            id: format!("pending-def-ticket-{principal}"),
            object_id: schema_object_id("Ticket"),
            principal: principal.into(),
            role: security::Role::Admin,
            created: 1,
            ..Default::default()
        };
        svc.db.runtime().create_grant(&grant).unwrap();
        svc.security.add_grant(&grant);
    }
    svc.create_definition_branch(with_named_principal(
        CreateDefinitionBranchRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            parent_revision_digest: parent.revision_digest.clone(),
            idempotency_key: "create-1".into(),
        },
        "root",
    ))
    .await
    .unwrap();
    let candidate = svc
        .apply_definition_branch_edit(with_named_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: namespace.into(),
                branch_id: "feature".into(),
                expected_head_digest: parent.revision_digest.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "object_type".into(),
                    member_id: "Ticket".into(),
                    definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
                    member_digest: String::new(),
                }],
                removals: Vec::new(),
                idempotency_key: "edit-1".into(),
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .revision_digest;
    svc.create_definition_proposal(with_named_principal(
        CreateDefinitionProposalRequest {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            proposal_id: "cs-1".into(),
            base_digest: parent.revision_digest,
            candidate_digest: candidate,
            idempotency_key: "propose-1".into(),
            ..Default::default()
        },
        "root",
    ))
    .await
    .unwrap();
    let request = pending(namespace, &[DefinitionProposal]);
    let approve = |principal: &str| {
        svc.approve_definition_proposal(with_named_principal(
            ApproveDefinitionProposalRequest {
                namespace: namespace.into(),
                proposal_id: "cs-1".into(),
                idempotency_key: format!("approve-{principal}"),
            },
            principal,
        ))
    };

    assert_eq!(
        listed(&svc, request.clone(), "tester").await,
        [(DefinitionProposal, "cs-1".to_string())]
    );
    // carol may edit the namespace but not the member; mallory neither.
    for outsider in ["carol", "mallory"] {
        assert!(listed(&svc, request.clone(), outsider).await.is_empty());
        // A revision the caller may not read answers as missing.
        let refused = approve(outsider).await.unwrap_err();
        assert!(
            matches!(
                refused.code(),
                tonic::Code::PermissionDenied | tonic::Code::NotFound
            ),
            "{outsider}: {refused:?}"
        );
    }
    approve("tester").await.unwrap();
    // An approval already given is no longer pending on its approver.
    assert!(listed(&svc, request, "tester").await.is_empty());
}

#[tokio::test]
async fn pending_dataset_proposals_are_what_merge_accepts() {
    use PendingDecisionKind::DatasetBranchProposal;
    let svc = service();
    let namespace = "pending-ds";
    svc.db
        .runtime()
        .create_object(&crate::domain::Object {
            id: "ds-binding".into(),
            kind: "widget".into(),
            name: "binding".into(),
            namespace: namespace.into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    grant_object_role(&svc, "ds-binding", "tester", security::Role::Admin);
    grant_object_role(&svc, "ds-binding", "reviewer", security::Role::Editor);
    grant_object_role(&svc, "ds-binding", "viewer", security::Role::Viewer);
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: "pending-ds".into(),
            name: "pending-ds".into(),
            columns: vec![ColumnDef {
                name: "kind".into(),
                r#type: "string".into(),
                classification: "public".into(),
            }],
            object_id: "ds-binding".into(),
            created: 1,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    svc.create_dataset_branch(with_principal(CreateDatasetBranchRequest {
        dataset_id: "pending-ds".into(),
        name: "dev".into(),
        from_version_id: String::new(),
    }))
    .await
    .unwrap();
    svc.db
        .runtime()
        .write_dataset_branch_rows(
            "pending-ds",
            "dev",
            &[[("kind".to_string(), "v1".to_string())].into()],
            false,
        )
        .unwrap();
    let proposal = svc
        .propose_dataset_branch_merge(with_principal(ProposeDatasetBranchMergeRequest {
            dataset_id: "pending-ds".into(),
            name: "dev".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .proposal
        .unwrap();
    let merge = |principal: &str| {
        svc.merge_dataset_branch(with_named_principal(
            MergeDatasetBranchRequest {
                dataset_id: "pending-ds".into(),
                proposal_id: proposal.id.clone(),
                reason: String::new(),
            },
            principal,
        ))
    };
    let request = pending(namespace, &[DatasetBranchProposal]);

    let shown = svc
        .list_pending_decisions(with_named_principal(request.clone(), "reviewer"))
        .await
        .unwrap()
        .into_inner()
        .decisions;
    assert_eq!(shown.len(), 1);
    assert_eq!(
        (shown[0].subject_id.as_str(), shown[0].dataset_id.as_str()),
        (proposal.id.as_str(), "pending-ds")
    );
    // The proposer and a read-only member may not merge.
    for outsider in ["tester", "viewer"] {
        assert!(listed(&svc, request.clone(), outsider).await.is_empty());
        let refused = merge(outsider).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{outsider}");
    }
    // Listed only under the binding object's namespace.
    assert!(
        listed(&svc, pending("acme", &[DatasetBranchProposal]), "reviewer")
            .await
            .is_empty()
    );
    merge("reviewer").await.unwrap();
    assert!(listed(&svc, request, "reviewer").await.is_empty());
}

/// A tenant caller sees its own tenant's decisions and an empty list, not
/// a refusal, for another tenant's namespace, which the decide RPC refuses.
#[tokio::test]
async fn a_foreign_tenant_namespace_lists_nothing() {
    let svc = enterprise_service();
    let db = svc.db.runtime();
    for namespace in ["allowed", "denied"] {
        db.put_governed_action_type(
            crate::sekai::governed_action_type::GovernedActionType {
                namespace: namespace.into(),
                type_id: "review".into(),
                version: "1".into(),
                description: "Review".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec!["notify".into()],
                enabled: true,
                approvers: vec!["subject-a".into()],
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
        db.put_action_instance(&crate::sekai::action_instance::ActionInstance {
            instance_id: format!("parked-{namespace}"),
            idempotency_key: format!("key-{namespace}"),
            operation_id: format!("operation-{namespace}"),
            ..action_read_fixture(namespace)
        })
        .unwrap();
    }
    let tenant_list = |namespace: &str| {
        let mut request = with_tenant_context(pending(namespace, &[]));
        request
            .metadata_mut()
            .insert("x-sekai-auth-source", MetadataValue::from_static("token"));
        svc.list_pending_decisions(request)
    };
    let own = tenant_list("allowed").await.unwrap().into_inner().decisions;
    assert_eq!(own.len(), 1);
    assert_eq!(own[0].subject_id, "parked-allowed");
    let foreign = tenant_list("denied").await.unwrap().into_inner();
    assert!(foreign.decisions.is_empty());
    assert!(foreign.next_page_token.is_empty());

    let mut decide = with_tenant_context(DecideActionInstanceRequest {
        instance_id: "parked-denied".into(),
        decision: "deny".into(),
        reason: String::new(),
    });
    decide
        .metadata_mut()
        .insert("x-sekai-auth-source", MetadataValue::from_static("token"));
    let refused = svc.decide_action_instance(decide).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn pending_decisions_reject_unknown_kinds_and_tokens() {
    let svc = service();
    for request in [
        ListPendingDecisionsRequest {
            kinds: vec![0],
            ..pending("acme", &[])
        },
        ListPendingDecisionsRequest {
            kinds: vec![99],
            ..pending("acme", &[])
        },
        ListPendingDecisionsRequest {
            page_token: "not-a-token".into(),
            ..pending("acme", &[])
        },
        pending("", &[]),
    ] {
        let error = svc
            .list_pending_decisions(as_decider(request, "alice"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}
