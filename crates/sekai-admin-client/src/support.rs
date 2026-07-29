pub const METRIC_REQUESTS: &str = "requests";

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
