use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub id: String,
    pub spec: String,
    pub status: String,
    pub namespace: String,
    pub tokens_used: i32,
    pub created: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub pattern: String,
    pub occurrences: i32,
    pub success_rate: f64,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub total_tasks: i32,
    pub succeeded: i32,
    pub failed: i32,
    pub success_rate: f64,
    pub patterns: Vec<Pattern>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Template {
    pub namespace: String,
    pub name: String,
    pub content: String,
}

fn is_terminal(status: &str) -> bool {
    matches!(status, "done" | "failed")
}

pub fn mine_patterns(tasks: &[TaskRecord]) -> Vec<Pattern> {
    let mut word_stats: HashMap<String, (i32, i32)> = HashMap::new(); // word -> (total, succeeded)
    for t in tasks {
        if !is_terminal(&t.status) {
            continue;
        }
        let words: Vec<&str> = t.spec.split_whitespace().take(5).collect();
        for w in words {
            let key = w.to_lowercase();
            let entry = word_stats.entry(key).or_insert((0, 0));
            entry.0 += 1;
            if t.status == "done" {
                entry.1 += 1;
            }
        }
    }
    let mut patterns: Vec<_> = word_stats
        .into_iter()
        .filter(|(_, (total, _))| *total >= 3)
        .map(|(word, (total, succ))| Pattern {
            pattern: word,
            occurrences: total,
            success_rate: succ as f64 / total as f64,
            category: "keyword".into(),
        })
        .collect();
    patterns.sort_by(|left, right| {
        right
            .occurrences
            .cmp(&left.occurrences)
            .then_with(|| left.pattern.cmp(&right.pattern))
    });
    patterns
}

pub fn report(tasks: &[TaskRecord]) -> Report {
    let terminal: Vec<_> = tasks
        .iter()
        .filter(|task| is_terminal(&task.status))
        .collect();
    let total = terminal.len() as i32;
    let succeeded = terminal.iter().filter(|t| t.status == "done").count() as i32;
    let failed = terminal.iter().filter(|t| t.status == "failed").count() as i32;
    let rate = if total > 0 {
        succeeded as f64 / total as f64
    } else {
        0.0
    };
    Report {
        total_tasks: total,
        succeeded,
        failed,
        success_rate: rate,
        patterns: mine_patterns(tasks),
    }
}

pub fn generate_templates(tasks: &[TaskRecord]) -> Vec<Template> {
    let mut by_namespace: HashMap<&str, Vec<&TaskRecord>> = HashMap::new();
    for task in tasks {
        if task.namespace.is_empty() || task.status != "done" {
            continue;
        }
        by_namespace.entry(&task.namespace).or_default().push(task);
    }

    let mut templates: Vec<Template> = by_namespace
        .into_iter()
        .filter_map(|(namespace, namespace_tasks)| {
            if namespace_tasks.len() < 2 {
                return None;
            }
            let patterns = mine_patterns(
                &namespace_tasks
                    .iter()
                    .map(|task| (*task).clone())
                    .collect::<Vec<TaskRecord>>(),
            );
            let top_patterns: Vec<String> = patterns
                .into_iter()
                .filter(|pattern| pattern.success_rate >= 0.5)
                .take(3)
                .map(|pattern| pattern.pattern)
                .collect();
            let content = if top_patterns.is_empty() {
                "Spec template:\n- Goal:\n- Constraints:\n- Verification:".to_string()
            } else {
                format!(
                    "Spec template:\n- Goal:\n- Constraints:\n- Verification:\n- Learned keywords: {}",
                    top_patterns.join(", ")
                )
            };
            Some(Template {
                namespace: namespace.to_string(),
                name: format!("evolve-{namespace}"),
                content,
            })
        })
        .collect();
    templates.sort_by(|a, b| a.name.cmp(&b.name));
    templates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tasks() -> Vec<TaskRecord> {
        vec![
            TaskRecord {
                id: "1".into(),
                spec: "fix the broken test in namespace".into(),
                status: "done".into(),
                namespace: "r".into(),
                tokens_used: 100,
                created: 100,
            },
            TaskRecord {
                id: "2".into(),
                spec: "fix the broken build".into(),
                status: "done".into(),
                namespace: "r".into(),
                tokens_used: 200,
                created: 200,
            },
            TaskRecord {
                id: "3".into(),
                spec: "fix the broken deploy".into(),
                status: "failed".into(),
                namespace: "r".into(),
                tokens_used: 300,
                created: 300,
            },
            TaskRecord {
                id: "4".into(),
                spec: "add new feature for users".into(),
                status: "done".into(),
                namespace: "r".into(),
                tokens_used: 150,
                created: 400,
            },
            TaskRecord {
                id: "5".into(),
                spec: "fix the ci pipeline issue".into(),
                status: "failed".into(),
                namespace: "r".into(),
                tokens_used: 100,
                created: 500,
            },
        ]
    }

    #[test]
    fn test_mine_patterns() {
        let patterns = mine_patterns(&tasks());
        assert!(!patterns.is_empty());
        let fix = patterns.iter().find(|p| p.pattern == "fix");
        assert!(fix.is_some());
        assert!(fix.unwrap().occurrences >= 4);
    }

    #[test]
    fn test_report() {
        let r = report(&tasks());
        assert_eq!(r.total_tasks, 5);
        assert_eq!(r.succeeded, 3);
        assert_eq!(r.failed, 2);
    }

    #[test]
    fn test_generate_templates() {
        let templates = generate_templates(&tasks());
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].name, "evolve-r");
        assert!(templates[0].content.contains("Verification:"));
    }

    #[test]
    fn test_report_ignores_non_terminal_tasks() {
        let mut tasks = tasks();
        tasks.push(TaskRecord {
            id: "6".into(),
            spec: "fix another broken test".into(),
            status: "planned".into(),
            namespace: "r".into(),
            tokens_used: 50,
            created: 600,
        });
        let r = report(&tasks);
        assert_eq!(r.total_tasks, 5);
        assert_eq!(r.failed, 2);
    }
}
