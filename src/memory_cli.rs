use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::{ListKiokuCandidatesRequest, ReviewKiokuMemoryRequest};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin governance memory candidates --namespace <name> [--operation-class <class>] [--limit <n>]\n  sekaictl admin governance memory review <id> <version> <promote|reject|supersede|disable> --reason <text>"
}

pub async fn run_memory_command(args: Vec<String>) -> Result<(), BoxErr> {
    let target = std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into());
    let mut client = ChiseiServiceClient::new(connect_sekai(&target).await?);
    match args.first().map(String::as_str) {
        Some("candidates") => {
            let namespace = flag(&args, "--namespace")
                .ok_or_else(|| std::io::Error::other("--namespace is required"))?;
            let operation_class = flag(&args, "--operation-class").unwrap_or_default();
            let limit = flag(&args, "--limit")
                .map(|value| value.parse::<u32>())
                .transpose()?
                .unwrap_or(50);
            let response = client
                .list_kioku_candidates(ListKiokuCandidatesRequest {
                    namespace,
                    operation_class,
                    limit,
                })
                .await?
                .into_inner();
            let candidates = response
                .candidates
                .into_iter()
                .map(|candidate| -> Result<serde_json::Value, serde_json::Error> {
                    Ok(serde_json::json!({
                        "memory": serde_json::from_str::<serde_json::Value>(&candidate.memory_json)?,
                        "evidence": candidate.evidence_json.iter().map(|value| serde_json::from_str::<serde_json::Value>(value)).collect::<Result<Vec<_>, _>>()?,
                        "validation": {
                            "valid": candidate.valid,
                            "errors": candidate.validation_errors,
                            "supporting_evidence": candidate.supporting_evidence,
                            "contradicting_evidence": candidate.contradicting_evidence,
                        }
                    }))
                })
                .collect::<Result<Vec<_>, _>>()?;
            println!("{}", serde_json::to_string_pretty(&candidates)?);
        }
        Some("review") if args.len() >= 5 => {
            let memory_version = args[2].parse::<u32>()?;
            let rationale = flag(&args, "--reason")
                .ok_or_else(|| std::io::Error::other("--reason is required"))?;
            let response = client
                .review_kioku_memory(ReviewKiokuMemoryRequest {
                    memory_id: args[1].clone(),
                    memory_version,
                    action: args[3].clone(),
                    rationale,
                })
                .await?
                .into_inner();
            let output = serde_json::json!({
                "memory": serde_json::from_str::<serde_json::Value>(&response.memory_json)?,
                "lifecycle_events": response.lifecycle_events_json.iter().map(|value| serde_json::from_str::<serde_json::Value>(value)).collect::<Result<Vec<_>, _>>()?,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => return Err(std::io::Error::other(usage()).into()),
    }
    Ok(())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}
