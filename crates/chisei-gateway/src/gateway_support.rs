pub fn is_cheap_eligible_task_class(task_class: &str) -> bool {
    matches!(
        task_class.trim().to_ascii_lowercase().as_str(),
        "background" | "bulk" | "batch" | "small_fast" | "small-fast"
    )
}
