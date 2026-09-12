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
            "sekai.actions.submit",
            "chisei.receipt.read"
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
