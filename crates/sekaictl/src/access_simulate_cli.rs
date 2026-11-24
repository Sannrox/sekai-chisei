//! `sekaictl admin access simulate` (#2709): the grant simulation of
//! `SekaiService.SimulateObjectPolicyChange` (#2304) at the terminal, before
//! an administrator runs the grant command. The plane computes everything;
//! this module parses flags, sends one simulation and renders its answer. It
//! creates and removes no grant.

use sekai_admin_client::client::{GatewayClient, connect_sekai};
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{
    CandidateGrant, SimulateObjectPolicyChangeRequest, SimulateObjectPolicyChangeResponse,
};
use serde::Deserialize;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "Usage: sekaictl admin access simulate --namespace <name> --principal <name> \
     (--add-grant <file> | --remove-grant <id>)... [--json]\n\
     \n\
     An --add-grant file holds one grant as JSON: \
     {\"object_id\": ..., \"principal\": ..., \"role\": \"viewer|editor|admin\", \"not_after_ms\": 0}.\n\
     --principal, --add-grant and --remove-grant may be repeated."
}

/// A grant file. `not_after_ms` 0, or left out, never expires.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantFile {
    object_id: String,
    principal: String,
    role: String,
    #[serde(default)]
    not_after_ms: i64,
}

/// `sekaictl admin access simulate`: simulates against the plane at
/// `CHISEI_GRPC_URL` or `SEKAI_SOCKET`.
pub async fn run(args: &[String]) -> Result<(), BoxErr> {
    if args.is_empty() {
        println!("{}", usage());
        return Ok(());
    }
    let target = std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into());
    let mut client = SekaiServiceClient::new(connect_sekai(&target).await?);
    print!("{}", simulate_command(&mut client, args).await?);
    Ok(())
}

/// Parses `args`, runs the simulation on `client` and returns what to print.
async fn simulate_command(
    client: &mut SekaiServiceClient<GatewayClient>,
    args: &[String],
) -> Result<String, BoxErr> {
    let request = parse_request(args)?;
    let response = client
        .simulate_object_policy_change(request.clone())
        .await?
        .into_inner();
    require_echo(&request, &response)?;
    Ok(if args.iter().any(|arg| arg == "--json") {
        format!("{}\n", serde_json::to_string_pretty(&response)?)
    } else {
        render(&response)
    })
}

fn parse_request(args: &[String]) -> Result<SimulateObjectPolicyChangeRequest, BoxErr> {
    let value_args: Vec<String> = args
        .iter()
        .filter(|arg| *arg != "--json")
        .cloned()
        .collect();
    crate::value_flags::check_value_flags_allowing_repeats(
        &value_args,
        &[
            "--namespace",
            "--principal",
            "--add-grant",
            "--remove-grant",
        ],
        &["--principal", "--add-grant", "--remove-grant"],
    )
    .map_err(|error| std::io::Error::other(format!("{error}\n{}", usage())))?;
    let values = |name: &str| -> Vec<String> {
        value_args
            .chunks(2)
            .filter(|pair| pair[0] == name)
            .map(|pair| pair[1].clone())
            .collect()
    };
    let namespace = values("--namespace")
        .pop()
        .ok_or_else(|| std::io::Error::other("--namespace is required"))?;
    let principals = values("--principal");
    if principals.is_empty() {
        return Err(std::io::Error::other("--principal is required").into());
    }
    let add_grants = values("--add-grant")
        .iter()
        .map(|path| read_grant(path))
        .collect::<Result<Vec<_>, _>>()?;
    let remove_grant_ids = values("--remove-grant");
    if add_grants.is_empty() && remove_grant_ids.is_empty() {
        return Err(
            std::io::Error::other("give at least one --add-grant or --remove-grant").into(),
        );
    }
    Ok(SimulateObjectPolicyChangeRequest {
        namespace,
        principals,
        add_grants,
        remove_grant_ids,
        ..Default::default()
    })
}

fn read_grant(path: &str) -> Result<CandidateGrant, BoxErr> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| std::io::Error::other(format!("--add-grant {path}: {error}")))?;
    let grant: GrantFile = serde_json::from_str(&text)
        .map_err(|error| std::io::Error::other(format!("--add-grant {path}: {error}")))?;
    Ok(CandidateGrant {
        object_id: grant.object_id,
        principal: grant.principal,
        role: grant.role,
        not_after_ms: grant.not_after_ms,
    })
}

/// A plane that predates grant simulation ignores the grant fields and
/// answers a plain policy simulation, which would read as "nothing changes".
/// Refuse unless the plane echoes exactly the requested grant changes.
fn require_echo(
    request: &SimulateObjectPolicyChangeRequest,
    response: &SimulateObjectPolicyChangeResponse,
) -> Result<(), BoxErr> {
    // The plane echoes roles in its canonical spelling.
    let key = |grant: &CandidateGrant| {
        (
            grant.object_id.clone(),
            grant.principal.clone(),
            grant.role.to_ascii_lowercase(),
            grant.not_after_ms,
        )
    };
    let sorted = |grants: &[CandidateGrant]| {
        let mut keys: Vec<_> = grants.iter().map(key).collect();
        keys.sort();
        keys
    };
    let sorted_ids = |ids: &[String]| {
        let mut ids = ids.to_vec();
        ids.sort();
        ids
    };
    if sorted(&request.add_grants) == sorted(&response.applied_add_grants)
        && sorted_ids(&request.remove_grant_ids) == sorted_ids(&response.applied_remove_grant_ids)
    {
        return Ok(());
    }
    Err(std::io::Error::other(
        "the plane did not apply the requested grant changes; it does not support grant \
         simulation (SimulateObjectPolicyChange add_grants/remove_grant_ids), so no summary \
         is printed",
    )
    .into())
}

fn render(response: &SimulateObjectPolicyChangeResponse) -> String {
    let mut out = format!(
        "namespace: {}\ncurrent: {}\ncandidate: {}\n",
        response.namespace, response.current_activation_digest, response.candidate_digest,
    );
    for grant in &response.applied_add_grants {
        let expiry = match grant.not_after_ms {
            0 => String::new(),
            ms => format!(" until_ms={ms}"),
        };
        out.push_str(&format!(
            "add grant: {} {} on {}{expiry}\n",
            grant.principal, grant.role, grant.object_id
        ));
    }
    for id in &response.applied_remove_grant_ids {
        out.push_str(&format!("remove grant: {id}\n"));
    }
    let counts = |map: &std::collections::HashMap<String, u64>| {
        let mut pairs: Vec<_> = map.iter().map(|(name, n)| format!("{name}={n}")).collect();
        pairs.sort();
        pairs.join(",")
    };
    for summary in &response.kind_summaries {
        out.push_str(&format!(
            "{} {}: readable {} -> {}",
            summary.principal,
            summary.object_kind,
            summary.current_readable,
            summary.candidate_readable,
        ));
        if !summary.candidate_denied_by.is_empty() {
            out.push_str(&format!(
                " denied_by={}",
                counts(&summary.candidate_denied_by)
            ));
        }
        if !summary.candidate_hidden_properties.is_empty() {
            out.push_str(&format!(
                " hidden={}",
                counts(&summary.candidate_hidden_properties)
            ));
        }
        out.push('\n');
    }
    out.push_str(&format!(
        "differences: {}{}\n",
        response.differences.len(),
        if response.differences_truncated {
            " (truncated)"
        } else {
            ""
        }
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_proto::sekai::PolicySimulationKindSummary;
    use sekai_proto::sekai::sekai_service_server::{SekaiService, SekaiServiceServer};
    use std::sync::{Arc, Mutex};
    use tonic::{Request, Response, Status};

    /// A plane that answers every simulation with one kind summary and
    /// records the requests. `echoes: false` is a plane that predates grant
    /// simulation: it ignores the grant fields and echoes nothing. It serves
    /// no other RPC, so the command can change no grant.
    #[derive(Clone)]
    struct Plane {
        echoes: bool,
        received: Arc<Mutex<Vec<SimulateObjectPolicyChangeRequest>>>,
    }

    #[tonic::async_trait]
    impl SekaiService for Plane {
        async fn simulate_object_policy_change(
            &self,
            request: Request<SimulateObjectPolicyChangeRequest>,
        ) -> Result<Response<SimulateObjectPolicyChangeResponse>, Status> {
            let request = request.into_inner();
            self.received.lock().unwrap().push(request.clone());
            let mut response = SimulateObjectPolicyChangeResponse {
                namespace: request.namespace.clone(),
                current_activation_digest: "sha256:current".into(),
                candidate_digest: "sha256:candidate".into(),
                kind_summaries: vec![PolicySimulationKindSummary {
                    principal: "bob".into(),
                    object_kind: "shipment".into(),
                    current_readable: 0,
                    candidate_readable: 3,
                    candidate_denied_by: [("marking".to_string(), 1)].into(),
                    candidate_hidden_properties: [("price".to_string(), 2)].into(),
                }],
                ..Default::default()
            };
            if self.echoes {
                response.applied_add_grants = request
                    .add_grants
                    .iter()
                    .map(|grant| CandidateGrant {
                        role: grant.role.to_ascii_lowercase(),
                        ..grant.clone()
                    })
                    .collect();
                response.applied_remove_grant_ids = request.remove_grant_ids.clone();
            }
            Ok(Response::new(response))
        }
    }

    async fn client(plane: Plane) -> SekaiServiceClient<GatewayClient> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(SekaiServiceServer::new(plane))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );
        SekaiServiceClient::new(connect_sekai(&format!("http://{address}")).await.unwrap())
    }

    /// `--namespace acme --principal bob`, adding the grant in a file under
    /// `dir` and removing `grant-old`, plus `extra`.
    fn args(dir: &tempfile::TempDir, extra: &[&str]) -> Vec<String> {
        let grant = dir.path().join("grant.json");
        std::fs::write(
            &grant,
            r#"{"object_id": "ns-acme", "principal": "bob", "role": "Viewer"}"#,
        )
        .unwrap();
        [
            "--namespace",
            "acme",
            "--principal",
            "bob",
            "--add-grant",
            grant.to_str().unwrap(),
            "--remove-grant",
            "grant-old",
        ]
        .iter()
        .chain(extra)
        .map(|arg| arg.to_string())
        .collect()
    }

    #[tokio::test]
    async fn prints_the_summary_the_plane_returned_for_the_requested_grants() {
        let dir = tempfile::tempdir().unwrap();
        let plane = Plane {
            echoes: true,
            received: Arc::default(),
        };
        let mut client = client(plane.clone()).await;
        let text = simulate_command(&mut client, &args(&dir, &[]))
            .await
            .unwrap();
        assert_eq!(
            text,
            "namespace: acme\ncurrent: sha256:current\ncandidate: sha256:candidate\n\
             add grant: bob viewer on ns-acme\nremove grant: grant-old\n\
             bob shipment: readable 0 -> 3 denied_by=marking=1 hidden=price=2\n\
             differences: 0\n"
        );
        let json = simulate_command(&mut client, &args(&dir, &["--json"]))
            .await
            .unwrap();
        let rows: SimulateObjectPolicyChangeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(rows.kind_summaries[0].candidate_readable, 3);
        assert_eq!(rows.applied_remove_grant_ids, ["grant-old"]);
        let received = plane.received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].principals, ["bob"]);
        assert_eq!(received[0].add_grants[0].object_id, "ns-acme");
        assert_eq!(received[0].remove_grant_ids, ["grant-old"]);
    }

    #[tokio::test]
    async fn a_plane_that_ignores_the_grant_changes_gets_no_summary() {
        let dir = tempfile::tempdir().unwrap();
        let mut client = client(Plane {
            echoes: false,
            received: Arc::default(),
        })
        .await;
        let error = simulate_command(&mut client, &args(&dir, &[]))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not support grant simulation"),
            "{error}"
        );
    }
}
