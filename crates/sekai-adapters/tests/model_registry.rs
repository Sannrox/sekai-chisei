//! A model saved through its adapter, stored in the local registry, resolved
//! by reference and loaded back predicts the same (#3020).

use sekai_adapters::model_registry::{
    LocalDirectoryRegistry, ModelAdapter, ModelRegistry, ModelRow,
};
use sekai_proto::sekai::{ColumnDef, ModelAdapterContract, ModelInput};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

/// Flags a row whose `tenure` is below a learned threshold.
struct ThresholdModel {
    threshold: f64,
}

fn column(name: &str) -> ColumnDef {
    ColumnDef {
        name: name.into(),
        r#type: "float".into(),
        ..Default::default()
    }
}

impl ModelAdapter for ThresholdModel {
    fn contract(&self) -> ModelAdapterContract {
        ModelAdapterContract {
            inputs: vec![ModelInput {
                name: "features".into(),
                columns: vec![column("tenure")],
            }],
            output: vec![column("churn")],
        }
    }

    fn predict(&self, inputs: &HashMap<String, Vec<ModelRow>>) -> io::Result<Vec<ModelRow>> {
        let rows = inputs
            .get("features")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "features missing"))?;
        rows.iter()
            .map(|row| {
                let tenure: f64 = row
                    .get("tenure")
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tenure"))?;
                Ok(HashMap::from([(
                    "churn".to_string(),
                    (tenure < self.threshold).to_string(),
                )]))
            })
            .collect()
    }

    fn save(&self, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir.join("weights"))?;
        std::fs::write(dir.join("weights/threshold"), self.threshold.to_string())
    }

    fn load(dir: &Path) -> io::Result<Self> {
        let threshold = std::fs::read_to_string(dir.join("weights/threshold"))?
            .parse()
            .map_err(io::Error::other)?;
        Ok(Self { threshold })
    }
}

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sekai-model-registry-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn features(tenure: &str) -> HashMap<String, Vec<ModelRow>> {
    HashMap::from([(
        "features".to_string(),
        vec![HashMap::from([("tenure".to_string(), tenure.to_string())])],
    )])
}

#[test]
fn stored_model_resolves_loads_and_refuses_tampered_bytes() {
    let state = scratch_dir("state");
    let registry_root = scratch_dir("registry");
    let registry = LocalDirectoryRegistry::new(&registry_root);
    let model = ThresholdModel { threshold: 12.0 };
    model.save(&state).unwrap();

    let stored = registry.store("churn", &state).unwrap();
    assert!(stored.digest.starts_with("sha256:"));
    assert_eq!(registry.store("churn", &state).unwrap(), stored);

    let resolved = registry
        .resolve(&stored.registry_locator, &stored.digest)
        .unwrap();
    let loaded = ThresholdModel::load(&resolved).unwrap();
    assert_eq!(loaded.contract(), model.contract());
    assert_eq!(
        loaded.predict(&features("3")).unwrap(),
        model.predict(&features("3")).unwrap()
    );

    std::fs::write(resolved.join("weights/threshold"), "99").unwrap();
    let refused = registry
        .resolve(&stored.registry_locator, &stored.digest)
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
    assert!(registry.resolve("../outside", &stored.digest).is_err());

    std::fs::remove_dir_all(state).unwrap();
    std::fs::remove_dir_all(registry_root).unwrap();
}
