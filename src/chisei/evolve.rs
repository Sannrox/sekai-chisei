use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub id: String,
    pub spec: String,
    pub status: String,
    pub namespace: String,
    pub tokens_used: i32,
    pub original_spec: Option<String>,
    pub created: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    pub message: String,
    pub confidence: f64,
    pub category: String,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbGroup {
    pub total: i32,
    pub succeeded: i32,
    pub success_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbReport {
    pub enhanced: AbGroup,
    pub non_enhanced: AbGroup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VarianceWindow {
    pub window: String,
    pub total: i32,
    pub succeeded: i32,
    pub success_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternVariance {
    pub pattern: String,
    pub sample_size: i32,
    pub mean_success_rate: f64,
    pub std_dev: f64,
    pub ci_95_lower: f64,
    pub ci_95_upper: f64,
    pub risk_flag: bool,
    pub trend: String,
    pub windows: Vec<VarianceWindow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VarianceReport {
    pub patterns: Vec<PatternVariance>,
    pub insights: Vec<String>,
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
    word_stats
        .into_iter()
        .filter(|(_, (total, _))| *total >= 3)
        .map(|(word, (total, succ))| Pattern {
            pattern: word,
            occurrences: total,
            success_rate: succ as f64 / total as f64,
            category: "keyword".into(),
        })
        .collect()
}

pub fn suggest(task: &TaskRecord, patterns: &[Pattern]) -> Vec<Suggestion> {
    let mut suggestions = Vec::new();
    if task.spec.len() < 50 {
        suggestions.push(Suggestion {
            message: "Spec is very short — consider adding more detail".into(),
            confidence: 0.7,
            category: "length".into(),
        });
    }
    for p in patterns {
        if p.success_rate < 0.4 && task.spec.to_lowercase().contains(&p.pattern) {
            suggestions.push(Suggestion {
                message: format!(
                    "Pattern '{}' has low success rate ({:.0}%)",
                    p.pattern,
                    p.success_rate * 100.0
                ),
                confidence: 0.6,
                category: "pattern".into(),
            });
        }
    }
    suggestions
}

pub fn enhance_spec(spec: &str, patterns: &[Pattern]) -> (String, bool) {
    let mut enhanced = spec.to_string();
    let mut modified = false;
    // Add high-success patterns as hints
    let good: Vec<&Pattern> = patterns
        .iter()
        .filter(|p| p.success_rate > 0.8 && p.occurrences >= 5)
        .collect();
    if !good.is_empty() && !spec.contains("Context:") {
        enhanced.push_str(
            "\n\nContext: Based on historical patterns, tasks with these characteristics succeed:",
        );
        for p in good.iter().take(3) {
            enhanced.push_str(&format!(" [{}]", p.pattern));
        }
        modified = true;
    }
    (enhanced, modified)
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

pub fn compute_ab_results(tasks: &[TaskRecord]) -> AbReport {
    let mut enhanced = AbGroup {
        total: 0,
        succeeded: 0,
        success_rate: 0.0,
    };
    let mut non_enhanced = AbGroup {
        total: 0,
        succeeded: 0,
        success_rate: 0.0,
    };
    for task in tasks {
        if !is_terminal(&task.status) {
            continue;
        }
        let group = if task.original_spec.is_some() {
            &mut enhanced
        } else {
            &mut non_enhanced
        };
        group.total += 1;
        if task.status == "done" {
            group.succeeded += 1;
        }
    }
    if enhanced.total > 0 {
        enhanced.success_rate = enhanced.succeeded as f64 / enhanced.total as f64;
    }
    if non_enhanced.total > 0 {
        non_enhanced.success_rate = non_enhanced.succeeded as f64 / non_enhanced.total as f64;
    }
    AbReport {
        enhanced,
        non_enhanced,
    }
}

pub fn recommend(task: &TaskRecord) -> Option<Recommendation> {
    if task.status != "failed" {
        return None;
    }
    if task.original_spec.is_some() {
        return Some(Recommendation {
            action: "reassign".into(),
            reason: "enhanced spec still failed — try a different runtime or model".into(),
        });
    }
    if task.spec.len() < 50 {
        return Some(Recommendation {
            action: "rewrite".into(),
            reason: "failed task spec is still very short — rewrite with more detail".into(),
        });
    }
    Some(Recommendation {
        action: "retry".into(),
        reason: "single failed execution without prior enhancement — retry may succeed".into(),
    })
}

pub fn analyze_variance(tasks: &[TaskRecord], now: i64) -> VarianceReport {
    let mut clusters: HashMap<String, Vec<TaskRecord>> = HashMap::new();
    for task in tasks {
        if !is_terminal(&task.status) {
            continue;
        }
        clusters
            .entry(feature_key(task))
            .or_default()
            .push(task.clone());
    }

    let mut patterns: Vec<PatternVariance> = clusters
        .into_iter()
        .map(|(pattern, group)| compute_pattern_variance(pattern, &group, now))
        .collect();
    patterns.sort_by(|left, right| {
        right
            .std_dev
            .partial_cmp(&left.std_dev)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let insights = derive_variance_insights(&patterns);
    VarianceReport { patterns, insights }
}

fn feature_key(task: &TaskRecord) -> String {
    let mut key = if task.spec.len() < 80 {
        "short".to_string()
    } else if task.spec.len() < 240 {
        "medium".to_string()
    } else {
        "long".to_string()
    };
    if task.original_spec.is_some() {
        key.push_str("+enhanced");
    }
    if !task.namespace.is_empty() {
        key.push(':');
        key.push_str(&task.namespace);
    }
    key
}

fn compute_pattern_variance(pattern: String, tasks: &[TaskRecord], now: i64) -> PatternVariance {
    let sample_size = tasks.len() as i32;
    let succeeded = tasks.iter().filter(|task| task.status == "done").count() as i32;
    let mean_success_rate = succeeded as f64 / tasks.len() as f64;
    let std_dev = binary_stddev(succeeded, sample_size);
    let (ci_95_lower, ci_95_upper) =
        confidence_interval_95(mean_success_rate, std_dev, sample_size);
    let windows = temporal_windows(tasks, now);
    let trend = detect_trend(&windows);
    PatternVariance {
        pattern,
        sample_size,
        mean_success_rate,
        std_dev,
        ci_95_lower,
        ci_95_upper,
        risk_flag: std_dev > 0.25 && sample_size >= 5,
        trend,
        windows,
    }
}

fn temporal_windows(tasks: &[TaskRecord], now: i64) -> Vec<VarianceWindow> {
    let windows = [("7d", now - 7 * 86_400), ("30d", now - 30 * 86_400)];
    windows
        .into_iter()
        .map(|(label, start)| {
            let group: Vec<_> = tasks.iter().filter(|task| task.created >= start).collect();
            let total = group.len() as i32;
            let succeeded = group.iter().filter(|task| task.status == "done").count() as i32;
            VarianceWindow {
                window: label.into(),
                total,
                succeeded,
                success_rate: if total > 0 {
                    succeeded as f64 / total as f64
                } else {
                    0.0
                },
            }
        })
        .collect()
}

fn detect_trend(windows: &[VarianceWindow]) -> String {
    if windows.len() < 2 || windows[0].total < 3 || windows[1].total < 3 {
        return "insufficient".into();
    }
    let delta = windows[0].success_rate - windows[1].success_rate;
    if delta > 0.1 {
        "improving".into()
    } else if delta < -0.1 {
        "declining".into()
    } else {
        "stable".into()
    }
}

fn binary_stddev(successes: i32, total: i32) -> f64 {
    if total <= 1 {
        return 0.0;
    }
    let p = successes as f64 / total as f64;
    (p * (1.0 - p)).sqrt()
}

fn confidence_interval_95(mean: f64, std_dev: f64, n: i32) -> (f64, f64) {
    if n <= 1 {
        return (0.0, 1.0);
    }
    let margin = 1.96 * (std_dev / (n as f64).sqrt());
    ((mean - margin).max(0.0), (mean + margin).min(1.0))
}

fn derive_variance_insights(patterns: &[PatternVariance]) -> Vec<String> {
    if patterns.is_empty() {
        return vec!["No completed tasks to analyze.".into()];
    }
    let mut insights = Vec::new();
    for pattern in patterns {
        if pattern.risk_flag {
            insights.push(format!(
                "{} is high-variance (stddev={:.2}) — risky to automate",
                pattern.pattern, pattern.std_dev
            ));
        }
        if pattern.trend == "declining" {
            insights.push(format!(
                "{} quality is declining in the last 7 days",
                pattern.pattern
            ));
        }
    }
    if insights.is_empty() {
        insights.push("No high-variance patterns detected.".into());
    }
    insights
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
                original_spec: None,
                created: 100,
            },
            TaskRecord {
                id: "2".into(),
                spec: "fix the broken build".into(),
                status: "done".into(),
                namespace: "r".into(),
                tokens_used: 200,
                original_spec: None,
                created: 200,
            },
            TaskRecord {
                id: "3".into(),
                spec: "fix the broken deploy".into(),
                status: "failed".into(),
                namespace: "r".into(),
                tokens_used: 300,
                original_spec: Some("fix the broken deploy".into()),
                created: 300,
            },
            TaskRecord {
                id: "4".into(),
                spec: "add new feature for users".into(),
                status: "done".into(),
                namespace: "r".into(),
                tokens_used: 150,
                original_spec: Some("add new feature".into()),
                created: 400,
            },
            TaskRecord {
                id: "5".into(),
                spec: "fix the ci pipeline issue".into(),
                status: "failed".into(),
                namespace: "r".into(),
                tokens_used: 100,
                original_spec: None,
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
    fn test_suggest_short_spec() {
        let t = TaskRecord {
            id: "x".into(),
            spec: "fix".into(),
            status: "".into(),
            namespace: "".into(),
            tokens_used: 0,
            original_spec: None,
            created: 0,
        };
        let s = suggest(&t, &[]);
        assert!(s.iter().any(|s| s.category == "length"));
    }

    #[test]
    fn test_report() {
        let r = report(&tasks());
        assert_eq!(r.total_tasks, 5);
        assert_eq!(r.succeeded, 3);
        assert_eq!(r.failed, 2);
    }

    #[test]
    fn test_enhance() {
        let patterns = vec![Pattern {
            pattern: "test".into(),
            occurrences: 10,
            success_rate: 0.9,
            category: "keyword".into(),
        }];
        let (enhanced, modified) = enhance_spec("fix the bug", &patterns);
        assert!(modified);
        assert!(enhanced.contains("test"));
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
            original_spec: None,
            created: 600,
        });
        let r = report(&tasks);
        assert_eq!(r.total_tasks, 5);
        assert_eq!(r.failed, 2);
    }

    #[test]
    fn test_compute_ab_results() {
        let report = compute_ab_results(&tasks());
        assert_eq!(report.enhanced.total, 2);
        assert_eq!(report.enhanced.succeeded, 1);
        assert_eq!(report.non_enhanced.total, 3);
        assert_eq!(report.non_enhanced.succeeded, 2);
    }

    #[test]
    fn test_recommend() {
        let failed = TaskRecord {
            id: "f".into(),
            spec: "too short".into(),
            status: "failed".into(),
            namespace: "r".into(),
            tokens_used: 1,
            original_spec: None,
            created: 1,
        };
        let recommendation = recommend(&failed).expect("recommendation");
        assert_eq!(recommendation.action, "rewrite");
    }

    #[test]
    fn test_variance_report() {
        let report = analyze_variance(&tasks(), 31 * 86_400);
        assert!(!report.patterns.is_empty());
        assert!(!report.insights.is_empty());
    }
}
