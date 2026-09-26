//! Independent MCP-client conformance for the v1 projection host (#839).

use std::collections::BTreeMap;
use std::sync::Arc;

use sekai_chisei::mcp_adapter::{
    FixtureObject, FixtureSurface, InProcessSurface, MAX_FRAME_BYTES, handle_message, read_frame,
    run_synthetic_host, serve_io, write_frame,
};
use serde_json::json;
use tokio::io::BufReader;

#[tokio::test]
async fn independent_client_lists_reads_invokes_and_inspects_receipt() {
    let report = run_synthetic_host().await.expect("synthetic MCP host");
    assert_eq!(
        report.tools,
        vec![
            "sekai.objects.get",
            "sekai.objects.evaluate_set",
            "sekai.actions.describe",
            "sekai.actions.preview",
            "sekai.actions.submit",
            "chisei.receipt.read",
            "sekai.links.get",
            "sekai.links.create",
            "chisei.evaluation.resolve",
            "chisei.evaluation.execute"
        ]
    );
    assert_eq!(report.object_id, "widget-1");
    assert_eq!(report.object_color, "blue");
    assert_eq!(report.action_status, "admitted");
    assert_eq!(report.action_operation_id, "op-act-1");
    assert!(report.receipt_present);
}

#[tokio::test]
async fn framed_client_rejects_unknown_mapping_forged_metadata_and_oversize() {
    let mut fixture = FixtureSurface::new("tester", "acme");
    fixture.insert_object(FixtureObject {
        id: "widget-1".into(),
        kind: "widget".into(),
        name: "spinner".into(),
        namespace: "acme".into(),
        properties: [("color".into(), "blue".into())].into(),
    });
    let surface = Arc::new(fixture);
    let (client_out, server_in) = tokio::io::duplex(64 * 1024);
    let (server_out, client_in) = tokio::io::duplex(64 * 1024);
    let served = surface.clone();
    tokio::spawn(async move { serve_io(served, BufReader::new(server_in), server_out).await });
    let mut writer = client_out;
    let mut reader = BufReader::new(client_in);

    write_frame(
        &mut writer,
        &json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{"name":"sekai.relations.traverse","arguments":{"operation_id":"op-x","input":{}}}
        }),
    )
    .await
    .unwrap();
    let unsupported = read_frame(&mut reader).await.unwrap();
    assert_eq!(
        unsupported["result"]["structuredContent"]["code"],
        "unimplemented"
    );

    write_frame(
        &mut writer,
        &json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"tools/call",
            "params":{
                "name":"sekai.objects.get",
                "arguments":{"operation_id":"op-y","x-principal":"forged","input":{"id":"widget-1"}}
            }
        }),
    )
    .await
    .unwrap();
    let forged = read_frame(&mut reader).await.unwrap();
    assert_eq!(
        forged["result"]["structuredContent"]["code"],
        "invalid_argument"
    );

    let oversize = vec![b'x'; MAX_FRAME_BYTES + 8];
    tokio::io::AsyncWriteExt::write_all(&mut writer, &oversize)
        .await
        .unwrap();
}

#[tokio::test]
async fn duplicate_action_submission_replays_native_identity() {
    let surface = InProcessSurface::synthetic().await.unwrap();
    let first = handle_message(
        &surface,
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{
                "name":"sekai.actions.submit",
                "arguments":{
                    "operation_id":"op-dup",
                    "input":{
                        "type_id": surface.action_type,
                        "version": surface.action_version,
                        "parameters_json": {"summary":"ship it"},
                        "idempotency_key":"idem-dup"
                    }
                }
            }
        }),
    )
    .await
    .unwrap();
    let second = handle_message(
        &surface,
        json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"tools/call",
            "params":{
                "name":"sekai.actions.submit",
                "arguments":{
                    "operation_id":"op-dup",
                    "input":{
                        "type_id": surface.action_type,
                        "version": surface.action_version,
                        "parameters_json": {"summary":"ship it"},
                        "idempotency_key":"idem-dup"
                    }
                }
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(first["result"]["isError"], false);
    assert_eq!(
        second["result"]["structuredContent"]["output"]["replay"],
        true
    );
    assert_eq!(
        first["result"]["structuredContent"]["output"]["instance"]["instance_id"],
        second["result"]["structuredContent"]["output"]["instance"]["instance_id"]
    );
}

#[tokio::test]
async fn revoked_discovery_and_hidden_object_fail_closed() {
    let mut fixture = FixtureSurface::new("tester", "acme");
    fixture.revoked = true;
    let denied = handle_message(
        &fixture,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await
    .unwrap();
    assert!(
        denied["error"]["message"]
            .as_str()
            .unwrap()
            .contains("denied")
    );

    let mut fixture = FixtureSurface::new("tester", "acme");
    fixture.insert_object(FixtureObject {
        id: "secret".into(),
        kind: "widget".into(),
        name: "hidden".into(),
        namespace: "other".into(),
        properties: BTreeMap::new(),
    });
    let hidden = handle_message(
        &fixture,
        json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"tools/call",
            "params":{"name":"sekai.objects.get","arguments":{"operation_id":"op-h","input":{"id":"secret"}}}
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        hidden["result"]["structuredContent"]["code"],
        "permission_denied"
    );
}

#[tokio::test]
async fn link_tools_create_and_read_links_and_fail_closed() {
    // #1093: link read/create join the allowlist because GetLinks and
    // CreateLink are stable; forged or incomplete input fails closed.
    let surface = InProcessSurface::synthetic().await.unwrap();
    let call = |id: i64, name: &str, input: serde_json::Value| {
        json!({
            "jsonrpc":"2.0",
            "id":id,
            "method":"tools/call",
            "params":{"name":name,"arguments":{"operation_id":format!("op-link-{id}"),"input":input}}
        })
    };
    let created = handle_message(
        &surface,
        call(
            1,
            "sekai.links.create",
            json!({"from_id": surface.object_id, "to_id": surface.peer_object_id, "relation": "pairs_with", "id": "forged-id"}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(created["result"]["isError"], false, "{created}");
    let link = &created["result"]["structuredContent"]["output"]["link"];
    assert_eq!(link["from_id"], surface.object_id);
    assert_eq!(link["to_id"], surface.peer_object_id);
    assert_eq!(link["relation"], "pairs_with");
    assert_ne!(
        link["id"], "forged-id",
        "the client cannot choose the link id"
    );
    assert!(
        link["id"].as_str().is_some_and(|id| !id.is_empty()),
        "{created}"
    );
    let second = handle_message(
        &surface,
        call(
            8,
            "sekai.links.create",
            json!({"from_id": surface.peer_object_id, "to_id": surface.object_id, "relation": "feeds"}),
        ),
    )
    .await
    .unwrap();
    let second_link = &second["result"]["structuredContent"]["output"]["link"];
    assert!(
        second_link["id"].as_str().is_some_and(|id| !id.is_empty()),
        "{second}"
    );
    assert_ne!(second_link["id"], link["id"]);
    let feeds = handle_message(
        &surface,
        call(
            9,
            "sekai.links.get",
            json!({"object_id": surface.peer_object_id, "relation": "feeds"}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        feeds["result"]["structuredContent"]["output"]["links"][0]["id"], second_link["id"],
        "{feeds}"
    );

    let read = handle_message(
        &surface,
        call(
            2,
            "sekai.links.get",
            json!({"object_id": surface.object_id, "relation": "pairs_with"}),
        ),
    )
    .await
    .unwrap();
    let links = read["result"]["structuredContent"]["output"]["links"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(links.len(), 1, "{read}");
    assert_eq!(links[0]["id"], link["id"]);

    for (id, input) in [
        (
            3,
            json!({"from_id": surface.object_id, "to_id": surface.peer_object_id}),
        ),
        (
            4,
            json!({"from_id": surface.object_id, "to_id": "missing", "relation": "pairs_with"}),
        ),
        (
            5,
            json!({"from_id": surface.object_id, "to_id": surface.peer_object_id, "relation": "pairs_with", "x-principal": "root"}),
        ),
        (
            6,
            json!({"from_id": 7, "to_id": surface.peer_object_id, "relation": "pairs_with"}),
        ),
    ] {
        let refused = handle_message(&surface, call(id, "sekai.links.create", input.clone()))
            .await
            .unwrap();
        assert!(
            refused.get("error").is_some() || refused["result"]["isError"] == true,
            "{input} -> {refused}"
        );
    }
    let unscoped = handle_message(&surface, call(7, "sekai.links.get", json!({})))
        .await
        .unwrap();
    assert!(unscoped.get("error").is_some() || unscoped["result"]["isError"] == true);
}

#[tokio::test]
async fn evaluation_tools_bind_the_session_namespace_and_fail_closed() {
    // #1093: resolve and execute are listed because both RPCs are stable
    // (#1090). The session namespace is bound, a foreign one is refused, and
    // unknown plans or manifests never invent a result.
    let surface = InProcessSurface::synthetic().await.unwrap();
    let call = |id: i64, name: &str, input: serde_json::Value| {
        json!({
            "jsonrpc":"2.0",
            "id":id,
            "method":"tools/call",
            "params":{"name":name,"arguments":{"operation_id":format!("op-eval-{id}"),"input":input}}
        })
    };
    let resolution = |namespace: &str| {
        json!({"resolution": {
            "contractVersion": "chisei.evaluation-resolution-request/v1",
            "resolverVersion": "chisei.evaluation-resolver/v1",
            "namespace": namespace,
            "requestId": "resolve-missing",
            "planVersionId": "plan-missing",
            "subjectProfile": "example.profile/v1",
            "subjectIdentity": "subject-1",
            "subjectContentDigest": format!("sha256:{}", "a".repeat(64)),
            "evidenceObjectIds": [],
            "evaluationTimeMs": 1
        }})
    };
    let failed = |reply: &serde_json::Value| {
        reply.get("error").is_some() || reply["result"]["isError"] == true
    };
    let foreign = handle_message(
        &surface,
        call(1, "chisei.evaluation.resolve", resolution("other")),
    )
    .await
    .unwrap();
    assert!(failed(&foreign), "{foreign}");
    let unknown = handle_message(
        &surface,
        call(2, "chisei.evaluation.resolve", resolution("")),
    )
    .await
    .unwrap();
    // The call reaches the server, which has no such plan.
    assert_eq!(
        unknown["result"]["structuredContent"]["code"], "not_found",
        "{unknown}"
    );
    let missing = handle_message(&surface, call(3, "chisei.evaluation.resolve", json!({})))
        .await
        .unwrap();
    assert!(failed(&missing), "{missing}");
    let execute = handle_message(
        &surface,
        call(
            4,
            "chisei.evaluation.execute",
            json!({"execution": {
                "contractVersion": "chisei.evaluation-execution-request/v1",
                "executorVersion": "chisei.deterministic-evaluation-executor/v1",
                "manifestDigest": format!("sha256:{}", "b".repeat(64)),
                "maxTotalDurationMs": 0
            }}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        execute["result"]["structuredContent"]["code"], "not_found",
        "{execute}"
    );
    let forged = handle_message(
        &surface,
        call(
            5,
            "chisei.evaluation.execute",
            json!({"execution": {}, "authorization": "Bearer x"}),
        ),
    )
    .await
    .unwrap();
    assert!(failed(&forged), "{forged}");
}
