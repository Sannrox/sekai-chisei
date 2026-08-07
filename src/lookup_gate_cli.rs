//! Operator CLI for the strict lookup-vs-golden promotion gate.

use std::fmt;
use std::path::Path;

use serde_json::{Value, json};
use tonic::{Code, Request, Status};

use crate::chisei::lookup_first::{
    LOOKUP_FIRST_GATE_CONTRACT_VERSION, parse_lookup_promotion_gate_suite,
};
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::RunLookupFirstPromotionGateRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;

pub const EXIT_VALIDATION: i32 = 2;
pub const EXIT_UNAVAILABLE: i32 = 5;
pub const EXIT_COMPATIBILITY: i32 = 6;
pub const EXIT_DENIED: i32 = 7;

pub fn usage() -> &'static str {
    "Usage: sekaictl admin evaluation lookup-first-gate run <suite.json> --namespace <ns> [--target <url-or-socket>] [--json]\n\n\
     Runs the strict v1 lookup-vs-golden suite without provider calls. The\n\
     result is audited; a deny result never applies route policy."
}

#[derive(Debug)]
pub struct LookupGateCliError {
    code: i32,
    message: String,
}

impl LookupGateCliError {
    fn validation(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_VALIDATION,
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_UNAVAILABLE,
            message: message.into(),
        }
    }

    fn compatibility(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_COMPATIBILITY,
            message: message.into(),
        }
    }

    fn denied(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_DENIED,
            message: message.into(),
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.code
    }
}

impl fmt::Display for LookupGateCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LookupGateCliError {}

pub async fn run(args: Vec<String>) -> Result<(), LookupGateCliError> {
    if args.first().map(String::as_str) != Some("run") {
        return Err(LookupGateCliError::validation(usage()));
    }
    let mut suite_path = None;
    let mut namespace = None;
    let mut target = None;
    let mut json_output = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--namespace" | "--target" => {
                let flag = &args[index];
                let value = args.get(index + 1).ok_or_else(|| {
                    LookupGateCliError::validation(format!("{flag} requires a value"))
                })?;
                if value.is_empty() || value.starts_with('-') {
                    return Err(LookupGateCliError::validation(format!(
                        "{flag} requires a non-option value"
                    )));
                }
                if flag == "--namespace" {
                    if namespace.replace(value.clone()).is_some() {
                        return Err(LookupGateCliError::validation(
                            "--namespace may only be provided once",
                        ));
                    }
                } else if target.replace(value.clone()).is_some() {
                    return Err(LookupGateCliError::validation(
                        "--target may only be provided once",
                    ));
                }
                index += 2;
            }
            "--json" => {
                json_output = true;
                index += 1;
            }
            option if option.starts_with('-') => {
                return Err(LookupGateCliError::validation(format!(
                    "unknown option {option:?}"
                )));
            }
            path => {
                if suite_path.replace(path.to_owned()).is_some() {
                    return Err(LookupGateCliError::validation(
                        "lookup-first-gate run requires exactly one suite.json path",
                    ));
                }
                index += 1;
            }
        }
    }
    let suite_path = Path::new(suite_path.as_deref().ok_or_else(|| {
        LookupGateCliError::validation("lookup-first-gate run requires exactly one suite.json path")
    })?);
    let namespace =
        namespace.ok_or_else(|| LookupGateCliError::validation("--namespace is required"))?;
    let target = target.unwrap_or_else(default_target);
    let suite_json = std::fs::read_to_string(suite_path).map_err(|error| {
        LookupGateCliError::validation(format!("read {}: {error}", suite_path.display()))
    })?;
    let suite =
        parse_lookup_promotion_gate_suite(&suite_json).map_err(LookupGateCliError::validation)?;
    if suite.contract_version != LOOKUP_FIRST_GATE_CONTRACT_VERSION {
        return Err(LookupGateCliError::validation(
            "suite contract does not match the lookup-first gate v1 contract",
        ));
    }
    if suite.namespace != namespace {
        return Err(LookupGateCliError::validation(
            "suite namespace must match --namespace",
        ));
    }

    let channel = connect_sekai(&target).await.map_err(|error| {
        LookupGateCliError::unavailable(format!("connect to evaluation service: {error}"))
    })?;
    let mut client = ChiseiServiceClient::new(channel);
    let response = client
        .run_lookup_first_promotion_gate(Request::new(RunLookupFirstPromotionGateRequest {
            contract_version: LOOKUP_FIRST_GATE_CONTRACT_VERSION.into(),
            namespace,
            suite_json,
        }))
        .await
        .map_err(rpc_error)?
        .into_inner();
    let report = response
        .report
        .ok_or_else(|| LookupGateCliError::unavailable("gate response omitted report"))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report_json(&report))
                .map_err(|error| LookupGateCliError::validation(error.to_string()))?
        );
    } else {
        println!(
            "lookup-first gate suite={} namespace={} verdict={} passed={} failed={} hits={} model_path={} refusals={} audit={} suite_digest={}",
            report.suite_id,
            report.namespace,
            report.verdict,
            report.passed,
            report.failed,
            report.lookup_hits,
            report.model_path,
            report.lookup_refusals,
            report.audit_decision_id,
            report.suite_digest,
        );
        for case in &report.cases {
            println!(
                "  {}: path={} passed={} refusal={}{}",
                case.id,
                case.answer_path,
                case.passed,
                if case.lookup_refusal.is_empty() {
                    "-"
                } else {
                    &case.lookup_refusal
                },
                if case.detail.is_empty() {
                    String::new()
                } else {
                    format!(" detail={}", case.detail)
                },
            );
        }
    }

    if report.verdict != "allow" {
        return Err(LookupGateCliError::denied(
            "lookup-first promotion gate denied; prior route policy was not changed",
        ));
    }
    Ok(())
}

fn default_target() -> String {
    std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into())
}

fn report_json(report: &crate::grpc::pb::chisei::LookupFirstPromotionGateReport) -> Value {
    json!({
        "contract_version": report.contract_version,
        "suite_id": report.suite_id,
        "namespace": report.namespace,
        "suite_digest": report.suite_digest,
        "audit_decision_id": report.audit_decision_id,
        "verdict": report.verdict,
        "lookup_hits": report.lookup_hits,
        "model_path": report.model_path,
        "lookup_refusals": report.lookup_refusals,
        "passed": report.passed,
        "failed": report.failed,
        "cases": report.cases.iter().map(|case| json!({
            "id": case.id,
            "answer_path": case.answer_path,
            "lookup_refusal": (!case.lookup_refusal.is_empty()).then_some(&case.lookup_refusal),
            "passed": case.passed,
            "detail": (!case.detail.is_empty()).then_some(&case.detail),
        })).collect::<Vec<_>>(),
    })
}

fn rpc_error(status: Status) -> LookupGateCliError {
    match status.code() {
        Code::Unimplemented => LookupGateCliError::compatibility(
            "run lookup-first promotion gate: server does not implement the v1 gate contract",
        ),
        Code::Unavailable | Code::DeadlineExceeded | Code::Internal | Code::DataLoss => {
            LookupGateCliError::unavailable(
                "run lookup-first promotion gate: evaluation service unavailable",
            )
        }
        _ => LookupGateCliError::validation(format!(
            "run lookup-first promotion gate: {}",
            status.message()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_names_the_non_mutating_gate() {
        assert!(usage().contains("lookup-vs-golden"));
        assert!(usage().contains("never applies route policy"));
    }

    #[test]
    fn report_json_omits_empty_optional_fields() {
        let report = crate::grpc::pb::chisei::LookupFirstPromotionGateReport {
            contract_version: LOOKUP_FIRST_GATE_CONTRACT_VERSION.into(),
            suite_id: "suite".into(),
            namespace: "acme".into(),
            suite_digest: "sha256:digest".into(),
            audit_decision_id: "decision".into(),
            verdict: "allow".into(),
            lookup_hits: 1,
            model_path: 0,
            lookup_refusals: 0,
            passed: 1,
            failed: 0,
            cases: vec![
                crate::grpc::pb::chisei::LookupFirstPromotionGateCaseResult {
                    id: "hit".into(),
                    answer_path: "lookup_hit".into(),
                    lookup_refusal: String::new(),
                    passed: true,
                    detail: String::new(),
                },
            ],
        };
        let value = report_json(&report);
        assert!(
            value["cases"][0]
                .get("lookup_refusal")
                .is_some_and(Value::is_null)
        );
        assert!(value["cases"][0].get("detail").is_some_and(Value::is_null));
    }
}
