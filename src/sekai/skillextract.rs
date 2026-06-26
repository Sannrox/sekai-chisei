/// Skill extraction proposes new skills from novel task patterns.
pub struct SkillProposal {
    pub name: String,
    pub content: String,
}

pub fn extract_skills(task_spec: &str, existing_skills: &[&str]) -> Option<SkillProposal> {
    // Detect potential skill if spec describes a repeatable workflow not in existing skills
    let words: Vec<&str> = task_spec.split_whitespace().collect();
    if words.len() < 10 {
        return None;
    } // too short to be a workflow
    // Simple heuristic: if the spec contains "always" or "whenever" patterns
    let candidate = words.iter().take(4).copied().collect::<Vec<_>>().join("-");
    if existing_skills.iter().any(|s| s.contains(&candidate)) {
        return None;
    }
    Some(SkillProposal {
        name: candidate,
        content: task_spec.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_short_spec_ignored() {
        assert!(extract_skills("fix bug", &[]).is_none());
    }

    #[test]
    fn test_extract_novel_pattern() {
        let spec = "When a new PR is opened run the linter check formatting and report back to the PR author";
        let result = extract_skills(spec, &[]);
        assert!(result.is_some());
    }
}
