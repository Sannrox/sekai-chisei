pub mod action_describe_preview;
pub mod action_instance_admission;
pub(crate) mod action_work_lifecycle;
pub mod affinity;
pub mod billing_adapter;
pub mod budget;
pub mod cache_policy;
pub mod capability;
pub mod controller;
pub mod data_quality;
pub mod egress;
pub mod entitlements;
pub mod epistemic_descriptor;
pub mod epistemic_eval;
pub mod eval;
pub mod evaluation_execution;
pub mod evaluation_manifest;
pub mod evaluation_plan;
pub mod evolve;
pub mod execution_evidence;
pub mod external_action;
pub mod external_action_lifecycle;
pub mod external_permit;
pub mod federation;
pub mod gate;
pub mod gateway_decide;
pub mod governed_subject;
pub mod governed_subject_provenance;
pub mod gunshi;
pub mod gunshi_auto;
pub mod gunshi_dispatch;
pub mod gunshi_feedback;
pub mod gunshi_feedback_eval;
pub mod gunshi_optimization;
pub mod gunshi_policy;
pub mod kioku;
pub mod learning_change;
pub mod lookup_first;
pub use sekai_provider::model_availability;
pub mod model_routing;
pub mod pipeline;
pub mod policy;
pub mod policy_dry_run;
pub mod portfolio;
pub mod privacy;
pub mod promotion;
pub use sekai_provider::receipt;
pub mod residency;
pub mod sampling;
pub mod scoring;
pub mod sekai_clerk;
pub mod stochastic_evaluation;
pub mod tenant_quota;
pub mod usage_ledger;
pub mod workflow_action;

#[cfg(test)]
mod layering {
    use std::fs;
    use std::path::Path;

    fn rust_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(dir).expect("src/chisei") {
            let path = entry.expect("dirent").path();
            if path.is_dir() {
                rust_files(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }

    #[test]
    fn chisei_imports_sekai_only_through_facts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chisei");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        let mut offenders = Vec::new();
        let facts = format!("{}{}", "crate::sekai::", "facts");
        let any = format!("{}{}", "crate::", "sekai::");
        for path in files {
            if path.file_name().is_some_and(|name| name == "mod.rs") {
                continue;
            }
            let source = fs::read_to_string(&path).expect("read chisei module");
            for (index, line) in source.lines().enumerate() {
                if !line.contains(&any) {
                    continue;
                }
                if line.contains(&facts) {
                    continue;
                }
                offenders.push(format!("{}:{}:{}", path.display(), index + 1, line.trim()));
            }
        }
        assert!(
            offenders.is_empty(),
            "Chisei may import Sekai only through facts: {offenders:?}"
        );
    }
}
