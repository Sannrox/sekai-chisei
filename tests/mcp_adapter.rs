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
            "chisei.evaluation.execute",
            "sekai.definitions.branch.create",
            "sekai.definitions.branch.edit",
            "sekai.definitions.diff",
            "sekai.definitions.impact",
            "sekai.definitions.proposal.create",
            "sekai.search.query"
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

    // #1203: session namespace binds get root and both create endpoints.
    // ACL on a foreign-namespace object is not enough.
    let foreign_get = handle_message(
        &surface,
        call(
            10,
            "sekai.links.get",
            json!({"object_id": surface.foreign_object_id, "relation": "pairs_with"}),
        ),
    )
    .await
    .unwrap();
    assert!(
        foreign_get.get("error").is_some() || foreign_get["result"]["isError"] == true,
        "foreign get root must refuse: {foreign_get}"
    );
    let foreign_create_to = handle_message(
        &surface,
        call(
            11,
            "sekai.links.create",
            json!({
                "from_id": surface.object_id,
                "to_id": surface.foreign_object_id,
                "relation": "pairs_with"
            }),
        ),
    )
    .await
    .unwrap();
    assert!(
        foreign_create_to.get("error").is_some() || foreign_create_to["result"]["isError"] == true,
        "foreign create to_id must refuse: {foreign_create_to}"
    );
    let foreign_create_from = handle_message(
        &surface,
        call(
            12,
            "sekai.links.create",
            json!({
                "from_id": surface.foreign_object_id,
                "to_id": surface.object_id,
                "relation": "pairs_with"
            }),
        ),
    )
    .await
    .unwrap();
    assert!(
        foreign_create_from.get("error").is_some()
            || foreign_create_from["result"]["isError"] == true,
        "foreign create from_id must refuse: {foreign_create_from}"
    );
    let foreign_create_both = handle_message(
        &surface,
        call(
            13,
            "sekai.links.create",
            json!({
                "from_id": surface.foreign_object_id,
                "to_id": surface.foreign_peer_object_id,
                "relation": "pairs_with"
            }),
        ),
    )
    .await
    .unwrap();
    assert!(
        foreign_create_both.get("error").is_some()
            || foreign_create_both["result"]["isError"] == true,
        "foreign create both endpoints must refuse: {foreign_create_both}"
    );
    let leaked = handle_message(
        &surface,
        call(
            14,
            "sekai.links.get",
            json!({"object_id": surface.object_id, "relation": "leaks_to"}),
        ),
    )
    .await
    .unwrap();
    let leaked_links = leaked["result"]["structuredContent"]["output"]["links"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        leaked.get("error").is_none() && leaked["result"]["isError"] != true,
        "same-namespace get root stays readable: {leaked}"
    );
    assert!(
        leaked_links.is_empty(),
        "cross-namespace link endpoints must not be disclosed: {leaked}"
    );
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

fn evaluate_set_call(
    id: i64,
    operation_id: &str,
    descriptor: serde_json::Value,
) -> serde_json::Value {
    json!({
        "jsonrpc":"2.0",
        "id": id,
        "method":"tools/call",
        "params":{
            "name":"sekai.objects.evaluate_set",
            "arguments":{
                "operation_id": operation_id,
                "input":{"descriptor": descriptor}
            }
        }
    })
}

fn receipt_call(id: i64, operation_id: &str) -> serde_json::Value {
    json!({
        "jsonrpc":"2.0",
        "id": id,
        "method":"tools/call",
        "params":{
            "name":"chisei.receipt.read",
            "arguments":{
                "operation_id": operation_id,
                "input":{"operation_id": operation_id}
            }
        }
    })
}

fn query_record_from_receipt(reply: &serde_json::Value) -> serde_json::Value {
    let receipt_json = reply["result"]["structuredContent"]["output"]["receipt_json"]
        .as_str()
        .expect("receipt_json");
    let receipt: serde_json::Value = serde_json::from_str(receipt_json).expect("receipt json");
    let outcome = receipt["events"]
        .as_array()
        .expect("events")
        .iter()
        .find(|event| event["kind"] == "outcome_recorded")
        .expect("outcome event");
    serde_json::from_str(
        outcome["attributes"]["query_record"]
            .as_str()
            .expect("query_record"),
    )
    .expect("query record json")
}

#[tokio::test]
async fn evaluate_set_returns_rows_and_a_receipt_naming_query_and_versions() {
    let surface = InProcessSurface::synthetic().await.unwrap();
    let evaluated = handle_message(
        &surface,
        evaluate_set_call(1, "op-set-ok", surface.object_set_descriptor("widget")),
    )
    .await
    .unwrap();
    assert_eq!(evaluated["result"]["isError"], false, "{evaluated}");
    let output = &evaluated["result"]["structuredContent"]["output"];
    assert_eq!(output["outcome"], "ok");
    assert!(
        !output["queryDigest"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
    let members = output["members"].as_array().expect("members");
    assert_eq!(members.len(), 2, "{evaluated}");
    assert!(
        members
            .iter()
            .any(|member| member["id"] == surface.object_id)
    );
    assert!(
        members
            .iter()
            .any(|member| member["id"] == surface.peer_object_id)
    );
    let versions = output["objectVersions"].as_array().expect("objectVersions");
    assert_eq!(versions.len(), members.len());
    for member in members {
        let id = member["id"].as_str().unwrap();
        assert!(
            versions.iter().any(|version| version["id"] == id
                && !version["version"].as_str().unwrap_or_default().is_empty()),
            "missing version for {id}: {output}"
        );
    }

    let receipt = handle_message(&surface, receipt_call(2, "op-set-ok"))
        .await
        .unwrap();
    assert_eq!(receipt["result"]["isError"], false, "{receipt}");
    let record = query_record_from_receipt(&receipt);
    assert_eq!(record["query_digest"], output["queryDigest"]);
    assert_eq!(record["outcome"], "ok");
    assert_eq!(
        record["object_versions"].as_array().map(Vec::len),
        Some(members.len())
    );
    let replayed = sekai_chisei::sekai::object_set::replay_object_set_query(
        &serde_json::from_value(record.clone()).expect("query record"),
    )
    .expect("replay");
    assert_eq!(replayed.len(), members.len());
    assert!(replayed.iter().any(|member| member.id == surface.object_id));
}

#[tokio::test]
async fn evaluate_set_denies_unauthorized_type_with_receipt_and_no_leaked_rows() {
    let surface = InProcessSurface::synthetic().await.unwrap();
    surface.deny_object_type("secret").expect("deny secret");
    let evaluated = handle_message(
        &surface,
        evaluate_set_call(1, "op-set-deny", surface.object_set_descriptor("secret")),
    )
    .await
    .unwrap();
    assert_eq!(evaluated["result"]["isError"], false, "{evaluated}");
    let output = &evaluated["result"]["structuredContent"]["output"];
    assert_eq!(output["outcome"], "denied", "{evaluated}");
    assert_eq!(output["total"], 0);
    assert!(output["members"].as_array().unwrap().is_empty());
    assert!(output["objectVersions"].as_array().unwrap().is_empty());
    let dumped = evaluated.to_string();
    assert!(
        !dumped.contains(&surface.secret_object_id),
        "denied evaluate_set leaked the secret id: {evaluated}"
    );
    assert!(
        !dumped.contains("classified-token-xyz"),
        "denied evaluate_set leaked secret payload: {evaluated}"
    );

    let receipt = handle_message(&surface, receipt_call(2, "op-set-deny"))
        .await
        .unwrap();
    assert_eq!(receipt["result"]["isError"], false, "{receipt}");
    let dumped_receipt = receipt.to_string();
    assert!(
        !dumped_receipt.contains(&surface.secret_object_id),
        "denied receipt leaked the secret id: {receipt}"
    );
    assert!(
        !dumped_receipt.contains("classified-token-xyz"),
        "denied receipt leaked secret payload: {receipt}"
    );
    let record = query_record_from_receipt(&receipt);
    assert_eq!(record["outcome"], "denied");
    assert!(record["members"].as_array().unwrap().is_empty());
    assert!(record["object_versions"].as_array().unwrap().is_empty());
    let replayed = sekai_chisei::sekai::object_set::replay_object_set_query(
        &serde_json::from_value(record).expect("query record"),
    )
    .expect("replay denied");
    assert!(replayed.is_empty());
}

#[tokio::test]
async fn evaluate_set_receipt_replays_the_read_at_recorded_versions() {
    let surface = InProcessSurface::synthetic().await.unwrap();
    let first = handle_message(
        &surface,
        evaluate_set_call(1, "op-set-replay", surface.object_set_descriptor("widget")),
    )
    .await
    .unwrap();
    assert_eq!(first["result"]["isError"], false, "{first}");
    let first_output = &first["result"]["structuredContent"]["output"];
    let original_color = first_output["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["id"] == surface.object_id)
        .and_then(|member| member["properties"]["color"].as_str())
        .unwrap()
        .to_string();
    let original_version = first_output["objectVersions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|version| version["id"] == surface.object_id)
        .and_then(|version| version["version"].as_str())
        .unwrap()
        .to_string();
    assert_eq!(original_color, "blue");

    surface
        .mutate_object_color(&surface.object_id, "green")
        .await
        .expect("mutate");

    let live = handle_message(
        &surface,
        evaluate_set_call(2, "op-set-live", surface.object_set_descriptor("widget")),
    )
    .await
    .unwrap();
    let live_output = &live["result"]["structuredContent"]["output"];
    let live_color = live_output["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["id"] == surface.object_id)
        .and_then(|member| member["properties"]["color"].as_str())
        .unwrap();
    let live_version = live_output["objectVersions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|version| version["id"] == surface.object_id)
        .and_then(|version| version["version"].as_str())
        .unwrap();
    assert_eq!(live_color, "green");
    assert_ne!(live_version, original_version);

    let receipt = handle_message(&surface, receipt_call(3, "op-set-replay"))
        .await
        .unwrap();
    let record: sekai_chisei::sekai::object_set::ObjectSetQueryRecord =
        serde_json::from_value(query_record_from_receipt(&receipt)).expect("query record");
    let replayed =
        sekai_chisei::sekai::object_set::replay_object_set_query(&record).expect("replay");
    let replayed_widget = replayed
        .iter()
        .find(|member| member.id == surface.object_id)
        .expect("replayed widget");
    assert_eq!(
        replayed_widget.properties.get("color").map(String::as_str),
        Some("blue")
    );
    assert_eq!(replayed_widget.version, original_version);
}
