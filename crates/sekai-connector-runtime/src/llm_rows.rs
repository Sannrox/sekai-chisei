//! Row-wise model steps of `llm-rows` transforms (#3025).
//!
//! A runtime given a [`GatewayRoute`] registers the model step placement
//! label and claims `llm-rows` transform work. It reads the run's input,
//! renders the definition's prompt template once per row, and sends each
//! prompt to the model egress gateway (ADR 0152) as an ordinary gateway
//! principal. The gateway's own policy (routes, quotas, egress) decides
//! every call; the runtime holds no provider key and contacts no provider.
//!
//! Every prompt is rendered before the first call, so a row missing a
//! column ends the run before any model is reached. A reply that is not a
//! value of the step's output type quarantines the run with a reason that
//! names the row. A refused or failed gateway call fails the run. A runtime
//! without a route fails any such work it is offered, before any call.
//! The plane keeps every piece of state: a runtime that dies mid-run leaves
//! a lease that lapses, and the next holder runs the step again.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::StreamExt;
use sekai_client::claim::{
    ClaimAttempt, RuntimeClaimClient, RuntimeClaimError, TransformFence, TransformWrite, WorkFence,
    WorkKind,
};
use sekai_client::protocol::sekai::{
    ClaimTransformWorkResponse, GovernedTransform, TransformRunInputRow,
};
use sekai_types::governed_transform::rows_digest;
use sekai_types::transform_llm_step::{
    LLM_ROWS_ENGINE, LLM_STEP_LABEL, LLM_STEP_LABEL_VALUE, LlmOutputType, LlmRowStep, render_prompt,
};

use crate::runtime::{LIST_LIMIT, Ran, Runtime};

/// Reason a run is failed with when this runtime has no gateway route.
pub const NO_GATEWAY_ROUTE: &str = "no_gateway_route";
/// Reason a run is failed with when the gateway refused a call (4xx).
pub const GATEWAY_REFUSED: &str = "gateway_refused";
/// Reason a run is failed with when the gateway could not be reached or
/// failed a call, or replied with no message.
pub const GATEWAY_UNAVAILABLE: &str = "gateway_unavailable";
/// Reason a run is failed with when the definition it was handed is not a
/// valid model step, or a prompt cannot be rendered for a row.
pub const LLM_STEP_INVALID: &str = "llm_step_invalid";

/// How long one gateway call may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Rows read per input page.
const PAGE_ROWS: i32 = 500;

/// The gateway's compatible surface and the key this runtime presents to
/// it. The key names a gateway principal, never a provider credential.
#[derive(Clone)]
pub struct GatewayRoute {
    /// Base URL ending in the API version, such as `http://127.0.0.1:8788/v1`.
    pub base_url: String,
    pub key: String,
}

impl std::fmt::Debug for GatewayRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayRoute")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Why a model step run ended without output.
enum StepEnd {
    /// Failed for good with this reason code.
    Failed(&'static str),
    /// Quarantined with this reason, naming the row.
    Quarantined(String),
    /// The plane could not be read; nothing is acknowledged, so the lease
    /// lapses and the run is claimed again.
    Plane(RuntimeClaimError),
}

impl Runtime {
    /// Lets this runtime run model steps through `route`. It then registers
    /// the model step placement label, so the plane offers it such work.
    pub fn with_gateway(mut self, route: GatewayRoute) -> Self {
        self.options
            .labels
            .insert(LLM_STEP_LABEL.into(), LLM_STEP_LABEL_VALUE.into());
        self.gateway = Some(route);
        self
    }

    fn runs_llm_steps(&self) -> bool {
        self.options.labels.get(LLM_STEP_LABEL).map(String::as_str) == Some(LLM_STEP_LABEL_VALUE)
    }

    /// Claims the next `llm-rows` transform run in the namespace at `index`,
    /// with its admitted definition. Other engines' work is left alone.
    pub async fn claim_llm_rows(
        &self,
        index: usize,
    ) -> Result<Option<ClaimTransformWorkResponse>, RuntimeClaimError> {
        if !self.runs_llm_steps() {
            return Ok(None);
        }
        let claims = self.clients[index].runtime_claim();
        let listed = claims
            .list_transform_work(&self.options.runtime_id, LIST_LIMIT)
            .await?;
        for work in listed {
            if work.engine != LLM_ROWS_ENGINE {
                continue;
            }
            let attempt = claims
                .claim_transform_work(&self.options.runtime_id, &work.run_id, self.options.lease)
                .await;
            match attempt {
                Ok(ClaimAttempt::Claimed(claimed)) => return Ok(Some(claimed)),
                Ok(_) | Err(RuntimeClaimError::Contention) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// Runs a claimed model step under a heartbeated lease and writes its
    /// output back, or ends the run with the reason it could not.
    pub async fn run_llm_rows(
        &self,
        index: usize,
        claimed: ClaimTransformWorkResponse,
    ) -> Result<Ran, RuntimeClaimError> {
        let claims = self.clients[index].runtime_claim();
        let work = claimed.work.unwrap_or_default();
        let run_id = work.run_id.clone();
        let fence = TransformFence {
            run_id: run_id.clone(),
            runtime_id: work.claim_owner.clone(),
            generation: work.claim_generation,
            fencing_token: work.fencing_token.clone(),
        };
        let work_fence = WorkFence {
            kind: WorkKind::Transform,
            work_id: run_id.clone(),
            runtime_id: fence.runtime_id.clone(),
            generation: fence.generation,
            fencing_token: fence.fencing_token.clone(),
        };
        let step = async {
            Ok::<_, crate::SyncFailure>(
                self.step(&claims, &fence, claimed.transform.unwrap_or_default())
                    .await,
            )
        };
        let Some(Ok(ended)) = self.heartbeated(&claims, &work_fence, step).await else {
            return Ok(Ran::TransformLost { run_id });
        };
        let written = match ended {
            Ok(rows) => claims
                .write_transform_result(
                    &fence,
                    TransformWrite {
                        output_digest: rows_digest(&rows),
                        rows: rows.into_iter().map(output_row).collect(),
                        quarantined: false,
                        quality_rule: String::new(),
                        partitions: Vec::new(),
                        model_outputs: Vec::new(),
                    },
                )
                .await
                .map(|_| Ok(())),
            Err(StepEnd::Quarantined(reason)) => claims
                .write_transform_result(
                    &fence,
                    TransformWrite {
                        rows: Vec::new(),
                        output_digest: String::new(),
                        quarantined: true,
                        quality_rule: reason.clone(),
                        partitions: Vec::new(),
                        model_outputs: Vec::new(),
                    },
                )
                .await
                .map(|_| Err(reason)),
            Err(StepEnd::Plane(error)) => Err(error),
            Err(StepEnd::Failed(code)) => claims
                .fail_transform(&fence, code)
                .await
                .map(|()| Err(code.to_string())),
        };
        match written {
            Ok(outcome) => Ok(Ran::Transformed { run_id, outcome }),
            Err(RuntimeClaimError::FenceLost) => Ok(Ran::TransformLost { run_id }),
            Err(error) => Err(error),
        }
    }

    async fn step(
        &self,
        claims: &RuntimeClaimClient<'_>,
        fence: &TransformFence,
        transform: GovernedTransform,
    ) -> Result<Vec<HashMap<String, String>>, StepEnd> {
        let Some(route) = &self.gateway else {
            return Err(StepEnd::Failed(NO_GATEWAY_ROUTE));
        };
        let step = step_of(&transform).ok_or(StepEnd::Failed(LLM_STEP_INVALID))?;
        let rows = read_rows(claims, fence).await?;
        let prompts = rows
            .iter()
            .map(|row| render_prompt(&transform.code, &row.values))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StepEnd::Failed(LLM_STEP_INVALID))?;
        let http = reqwest::Client::builder()
            .timeout(CALL_TIMEOUT)
            .build()
            .map_err(|_| StepEnd::Failed(GATEWAY_UNAVAILABLE))?;
        let mut out = Vec::with_capacity(rows.len());
        for (row, prompt) in rows.iter().zip(prompts) {
            let reply = call(&http, route, &step.model, &fence.run_id, &prompt).await?;
            let label = format!("row {}", row.row_id);
            out.push(
                step.output_row(&row.values, &reply, &label)
                    .map_err(StepEnd::Quarantined)?,
            );
        }
        Ok(out)
    }
}

/// The model step of a claimed definition, or `None` when it is missing or
/// names an output type this runtime does not know.
fn step_of(transform: &GovernedTransform) -> Option<LlmRowStep> {
    let step = transform.llm_step.as_ref()?;
    let step = LlmRowStep {
        model: step.model.clone(),
        output_column: step.output_column.clone(),
        output_type: LlmOutputType::parse_name(&step.output_type)?,
    };
    step.validate().ok().map(|()| step)
}

/// Every input row of the run, in the plane's order.
async fn read_rows(
    claims: &RuntimeClaimClient<'_>,
    fence: &TransformFence,
) -> Result<Vec<TransformRunInputRow>, StepEnd> {
    let mut rows = Vec::new();
    let (mut after_alias, mut after_row_id) = (String::new(), 0);
    loop {
        let mut page = claims
            .read_transform_inputs(fence, "", after_alias.clone(), after_row_id, PAGE_ROWS)
            .await
            .map_err(StepEnd::Plane)?;
        let mut read = 0;
        while let Some(item) = page.next().await {
            let row = item.map_err(StepEnd::Plane)?.row.unwrap_or_default();
            after_alias.clone_from(&row.alias);
            after_row_id = row.row_id;
            rows.push(row);
            read += 1;
        }
        if read < PAGE_ROWS {
            return Ok(rows);
        }
    }
}

/// One chat completion through the gateway; the reply's message text. The
/// run id is the operation id, so the gateway's admission record names it.
async fn call(
    http: &reqwest::Client,
    route: &GatewayRoute,
    model: &str,
    run_id: &str,
    prompt: &str,
) -> Result<String, StepEnd> {
    let response = http
        .post(format!(
            "{}/chat/completions",
            route.base_url.trim_end_matches('/')
        ))
        .bearer_auth(&route.key)
        .header("x-chisei-operation-id", run_id)
        .json(&serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }))
        .send()
        .await
        .map_err(|_| StepEnd::Failed(GATEWAY_UNAVAILABLE))?;
    if response.status().is_client_error() {
        return Err(StepEnd::Failed(GATEWAY_REFUSED));
    }
    if !response.status().is_success() {
        return Err(StepEnd::Failed(GATEWAY_UNAVAILABLE));
    }
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|_| StepEnd::Failed(GATEWAY_UNAVAILABLE))?;
    body.pointer("/choices/0/message/content")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or(StepEnd::Failed(GATEWAY_UNAVAILABLE))
}

fn output_row(values: HashMap<String, String>) -> TransformRunInputRow {
    TransformRunInputRow {
        values,
        ..Default::default()
    }
}
