pub const METRIC_REQUESTS: &str = "requests";

pub fn is_cheap_eligible_task_class(task_class: &str) -> bool {
    matches!(
        task_class.trim().to_ascii_lowercase().as_str(),
        "background" | "bulk" | "batch" | "small_fast" | "small-fast"
    )
}

pub fn llm_call_column_classification(name: &str) -> &'static str {
    if matches!(
        name,
        "request_id" | "agent" | "user_id" | "key_id" | "work_unit_id" | "refusal_reason"
    ) {
        "sensitive"
    } else if matches!(
        name,
        "project" | "route_bias" | "policy_scope" | "policy_version"
    ) {
        "internal"
    } else {
        "public"
    }
}

pub fn is_restricted_property_classification(value: &str) -> bool {
    matches!(value.trim(), "internal" | "sensitive")
}
