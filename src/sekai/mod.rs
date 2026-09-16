pub mod action;
pub mod action_effect;
pub mod action_instance;
pub(crate) mod action_object_mutation;
pub mod action_policy;
pub mod action_type_criteria;
pub mod attestation;
pub mod audit;
pub mod autonomous_envelope;
pub mod capability;
pub mod capability_package;
pub mod capacity;
pub mod classification_lattice;
pub mod client_package;
pub mod compute;
pub mod connector_certification;
pub mod coordination;
pub mod credentials;
pub mod dataset;
pub mod deduplication;
pub mod definition_branch;
pub mod definition_consumer_impact;
pub mod definition_diff;
pub mod definition_migration;
pub mod definition_proposal;
pub mod document;
pub mod escalation;
pub mod event_stream;
pub mod event_subscription;
pub mod evidence;
pub(crate) mod evidence_admission_lifecycle;
pub mod evidence_projection;
pub mod evidence_store;
pub mod facts;
pub mod federation_conflict;
pub mod federation_network;
pub mod federation_profile;
pub mod federation_revocation;
pub mod function;
pub mod geospatial;
pub mod governed_action_type;
pub mod governed_facts;
pub mod governed_transform;
pub mod handoff;
pub(crate) mod handoff_lifecycle;
pub mod image;
pub mod json;
pub mod lakehouse_snapshot;
pub mod learning;
pub mod lease;
pub(crate) mod lease_lifecycle;
pub mod ledger;
pub mod lineage;
pub mod markings;
pub mod model_platform;
pub mod namespace_snapshot;
pub mod object_change_subscription;
pub mod object_index_engine;
pub mod object_index_envelope;
pub mod object_lineage;
pub mod object_mutation;
pub mod object_security;
pub mod object_set;
pub mod object_sync;
pub mod object_type_index;
pub mod observation;
pub mod ontology;
pub mod open_table;
pub mod operation_correlation;
pub mod parameter_schema;
pub mod parked_work;
pub mod peer_import;
pub mod policy_decision;
pub mod propagation;
pub mod purpose_authorization;
pub mod query;
pub mod relation_object;
pub mod retention;
pub mod retrieval;
pub mod schema;
pub mod security;
pub mod semantic;
pub mod sentinel;
pub mod skillextract;
pub mod source_health;
pub mod source_quarantine;
pub mod source_type_descriptor;
pub mod source_webhook;
pub mod virtual_pushdown;
pub mod warehouse_projection;
pub(crate) mod work_unit_lifecycle;

#[cfg(test)]
mod layering {
    use std::fs;
    use std::path::Path;

    fn rust_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(dir).expect("src/sekai") {
            let path = entry.expect("dirent").path();
            if path.is_dir() {
                rust_files(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }

    #[test]
    fn sekai_modules_do_not_import_chisei() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sekai");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        let mut offenders = Vec::new();
        for path in files {
            let source = fs::read_to_string(&path).expect("read sekai module");
            let import = format!("{}{}", "crate::", "chisei::");
            let use_import = format!("{}{}", "use crate::", "chisei");
            if source.contains(&use_import) || source.contains(&import) {
                offenders.push(path.display().to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "Sekai facts must not import Chisei; one-way Chisei → Sekai only: {offenders:?}"
        );
    }
}
