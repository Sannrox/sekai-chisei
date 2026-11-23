//! Transform chain reads (#3084): a namespace reader lists chains, reads a
//! definition and pages a chain's runs; others are refused.

use super::*;
use crate::sekai::transform_chain::{CHAIN_CONTRACT, ChainStep, TransformChain as Chain};

/// Seeds namespace `ops` with transform `t1` and the one-step chains `pipe`
/// and `alpha`.
fn seed_chains(svc: &SekaiServiceImpl) {
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{CONTRACT_VERSION, GovernedTransform, TransformStep};

    let runtime = svc.db.runtime();
    for id in ["in", "out"] {
        runtime
            .create_dataset(&Dataset {
                id: id.into(),
                name: id.into(),
                columns: vec![ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                }],
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
    }
    runtime
        .append_rows("in", &[HashMap::from([("id".into(), "1".into())])])
        .unwrap();
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "ops".into(),
        transform_id: "t1".into(),
        input_dataset_id: "in".into(),
        output_dataset_id: "out".into(),
        steps: vec![TransformStep {
            kind: "project".into(),
            column: String::new(),
            op: String::new(),
            value: String::new(),
            columns: vec!["id".into()],
        }],
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: None,
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    runtime.put_governed_transform(&transform, 10).unwrap();
    for chain_id in ["pipe", "alpha"] {
        let chain = Chain {
            contract_version: CHAIN_CONTRACT.into(),
            namespace: "ops".into(),
            chain_id: chain_id.into(),
            steps: vec![ChainStep {
                name: "a".into(),
                transform_id: "t1".into(),
                transform_digest: String::new(),
                assertions: Vec::new(),
            }],
            edges: Vec::new(),
            definition_digest: String::new(),
        };
        runtime.put_transform_chain(&chain, 20).unwrap();
    }
}

fn start_run(svc: &SekaiServiceImpl, key: &str, now_ms: i64) -> String {
    svc.db
        .runtime()
        .run_transform_chain("ops", "pipe", key, "", now_ms)
        .unwrap()
        .0
        .run_id
}

fn runs_page(token: &str) -> ListTransformChainRunsRequest {
    ListTransformChainRunsRequest {
        namespace: "ops".into(),
        chain_id: "pipe".into(),
        page_size: 2,
        page_token: token.into(),
    }
}

#[tokio::test]
async fn a_namespace_reader_lists_chains_and_pages_runs_once_each() {
    let svc = service();
    seed_chains(&svc);
    let older = [
        start_run(&svc, "k1", 30),
        start_run(&svc, "k2", 40),
        start_run(&svc, "k3", 40),
    ];

    let chains = svc
        .list_transform_chains(with_principal(ListTransformChainsRequest {
            namespace: "ops".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .chains;
    let ids: Vec<_> = chains.iter().map(|chain| chain.chain_id.as_str()).collect();
    assert_eq!(ids, ["alpha", "pipe"]);
    let chain = svc
        .get_transform_chain(with_principal(GetTransformChainRequest {
            namespace: "ops".into(),
            chain_id: "pipe".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .chain
        .unwrap();
    assert_eq!(chain.steps[0].transform_id, "t1");
    assert!(!chain.definition_digest.is_empty());
    let missing = svc
        .get_transform_chain(with_principal(GetTransformChainRequest {
            namespace: "ops".into(),
            chain_id: "nope".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    let first = svc
        .list_transform_chain_runs(with_principal(runs_page("")))
        .await
        .unwrap()
        .into_inner();
    // A run started between pages lands before the cursor, not on page two.
    let newer = start_run(&svc, "k4", 50);
    let second = svc
        .list_transform_chain_runs(with_principal(runs_page(&first.next_page_token)))
        .await
        .unwrap()
        .into_inner();
    assert!(second.next_page_token.is_empty());
    let mut seen: Vec<_> = first.runs.iter().chain(&second.runs).collect();
    assert!(
        seen.iter()
            .all(|run| run.status == "completed" && run.chain_id == "pipe")
    );
    assert!(seen.iter().all(|run| run.receipt.is_some()));
    assert!(
        seen.windows(2)
            .all(|pair| pair[0].created_at_ms >= pair[1].created_at_ms)
    );
    seen.sort_by(|a, b| a.run_id.cmp(&b.run_id));
    let mut expected = older.to_vec();
    expected.sort();
    assert_eq!(
        seen.iter()
            .map(|run| run.run_id.as_str())
            .collect::<Vec<_>>(),
        expected
    );
    assert!(!seen.iter().any(|run| run.run_id == newer));

    let bad = svc
        .list_transform_chain_runs(with_principal(runs_page("not-a-token")))
        .await
        .unwrap_err();
    assert_eq!(bad.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn chain_reads_refuse_a_caller_without_namespace_read() {
    let svc = service();
    seed_chains(&svc);
    start_run(&svc, "k1", 30);
    svc.ensure_team_namespace(with_named_principal(
        EnsureTeamNamespaceRequest {
            namespace: "ops".into(),
            principal: "bob".into(),
            role: "viewer".into(),
        },
        "local",
    ))
    .await
    .unwrap();
    let as_ = |principal: &str| {
        (
            with_named_principal(
                ListTransformChainsRequest {
                    namespace: "ops".into(),
                },
                principal,
            ),
            with_named_principal(
                GetTransformChainRequest {
                    namespace: "ops".into(),
                    chain_id: "pipe".into(),
                },
                principal,
            ),
            with_named_principal(runs_page(""), principal),
        )
    };
    let (list, get, runs) = as_("bob");
    assert_eq!(
        svc.list_transform_chains(list)
            .await
            .unwrap()
            .into_inner()
            .chains
            .len(),
        2
    );
    svc.get_transform_chain(get).await.unwrap();
    assert_eq!(
        svc.list_transform_chain_runs(runs)
            .await
            .unwrap()
            .into_inner()
            .runs
            .len(),
        1
    );

    let (list, get, runs) = as_("outsider");
    let codes = [
        svc.list_transform_chains(list).await.unwrap_err().code(),
        svc.get_transform_chain(get).await.unwrap_err().code(),
        svc.list_transform_chain_runs(runs)
            .await
            .unwrap_err()
            .code(),
    ];
    assert_eq!(codes, [tonic::Code::PermissionDenied; 3]);
}

#[tokio::test]
async fn chain_reads_hide_another_tenants_namespace() {
    // The test extension binds tenant-test to namespace `allowed` only.
    let svc = enterprise_service();
    seed_chains(&svc);
    start_run(&svc, "k1", 30);
    let codes = [
        svc.list_transform_chains(with_tenant_context(ListTransformChainsRequest {
            namespace: "ops".into(),
        }))
        .await
        .unwrap_err()
        .code(),
        svc.get_transform_chain(with_tenant_context(GetTransformChainRequest {
            namespace: "ops".into(),
            chain_id: "pipe".into(),
        }))
        .await
        .unwrap_err()
        .code(),
        svc.list_transform_chain_runs(with_tenant_context(runs_page("")))
            .await
            .unwrap_err()
            .code(),
    ];
    assert_eq!(codes, [tonic::Code::NotFound; 3]);
}
