use sekai_chisei::grpc::pb::chisei::{ChatMessage, ExecutionInput, PlanExecutionRequest};

fn main() {
    let local_plan = local_private_plan();
    let frontier_template = frontier_template_request();
    let local_compose =
        local_private_compose_request("Rubric:\n- Check assumptions\n- Check downside");
    let frontier_polish = frontier_polish_request("Draft answer with private facts removed.");

    println!("delegation chain request ids:");
    for request in [
        &local_plan,
        &frontier_template,
        &local_compose,
        &frontier_polish,
    ] {
        let input = request.input.as_ref().expect("example input");
        println!(
            "- {} namespace={} model={} task_class={}",
            input.request_id, input.namespace, input.preferred_model, input.task_class
        );
    }

    println!();
    println!("Run these with PlanExecution/ExecutePlan in order against a configured server.");
    println!(
        "Private steps use Ollama. Frontier steps use task_class=template_only and are leak checked."
    );
}

fn local_private_plan() -> PlanExecutionRequest {
    PlanExecutionRequest {
        input: Some(ExecutionInput {
            request_id: "delegation-local-plan".into(),
            namespace: "alpha".into(),
            spec: "Plan the private analysis using locally available portfolio context.".into(),
            preferred_model: "ollama/llama3.2:latest".into(),
            preferred_runtime: "kiro".into(),
            task_type: "analysis".into(),
            priority: 5,
            user_id: "delegation-example".into(),
            estimated_tokens: 0,
            messages: vec![],
            tools: vec![],
            system: "Use private context locally. Do not prepare text for external providers."
                .into(),
            max_tokens: 512,
            task_class: String::new(),
            ..Default::default()
        }),
    }
}

fn frontier_template_request() -> PlanExecutionRequest {
    PlanExecutionRequest {
        input: Some(ExecutionInput {
            request_id: "delegation-frontier-template".into(),
            namespace: "alpha".into(),
            spec: "Create a generic evaluation rubric for an investment memo. Do not mention sectors, tickers, timing, positions, customers, or proprietary signals.".into(),
            preferred_model: "claude-sonnet-4-20250514".into(),
            preferred_runtime: "kiro".into(),
            task_type: "template".into(),
            priority: 5,
            user_id: "delegation-example".into(),
            estimated_tokens: 0,
            messages: vec![],
            tools: vec![],
            system: "Return an abstract checklist only.".into(),
            max_tokens: 512,
            task_class: "template_only".into(),
            ..Default::default()
        }),
    }
}

fn local_private_compose_request(template: &str) -> PlanExecutionRequest {
    PlanExecutionRequest {
        input: Some(ExecutionInput {
            request_id: "delegation-local-compose".into(),
            namespace: "alpha".into(),
            spec: "Use private local context to fill the external rubric.".into(),
            preferred_model: "ollama/llama3.2:latest".into(),
            preferred_runtime: "kiro".into(),
            task_type: "analysis".into(),
            priority: 5,
            user_id: "delegation-example".into(),
            estimated_tokens: 0,
            messages: vec![ChatMessage {
                role: "user".into(),
                content: template.into(),
                tool_call_id: String::new(),
                tool_calls: vec![],
            }],
            tools: vec![],
            system: "Use private context locally and keep the result on this machine.".into(),
            max_tokens: 1024,
            task_class: String::new(),
            ..Default::default()
        }),
    }
}

fn frontier_polish_request(scrubbed_draft: &str) -> PlanExecutionRequest {
    PlanExecutionRequest {
        input: Some(ExecutionInput {
            request_id: "delegation-frontier-polish".into(),
            namespace: "alpha".into(),
            spec: "Polish this already scrubbed memo into clearer prose. Preserve the abstraction level and do not infer or add private facts.".into(),
            preferred_model: "claude-sonnet-4-20250514".into(),
            preferred_runtime: "kiro".into(),
            task_type: "polish".into(),
            priority: 5,
            user_id: "delegation-example".into(),
            estimated_tokens: 0,
            messages: vec![ChatMessage {
                role: "user".into(),
                content: scrubbed_draft.into(),
                tool_call_id: String::new(),
                tool_calls: vec![],
            }],
            tools: vec![],
            system: "Edit only. Do not add specifics.".into(),
            max_tokens: 512,
            task_class: "template_only".into(),
            ..Default::default()
        }),
    }
}
