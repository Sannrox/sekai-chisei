//! Model adapter and registry interfaces that run outside the plane (#3020,
//! ADR 0147).
//!
//! The plane holds a model version reference: digest, adapter id and
//! version, the registry locator, and the adapter contract
//! (`sekai.ModelAdapterContract`). Model bytes never enter the plane. A
//! [`ModelAdapter`] owns the framework: it predicts over named tabular inputs
//! and saves and loads its state in a directory. A [`ModelRegistry`] stores
//! that directory and resolves a reference back to a loadable directory.

use sekai_proto::sekai::ModelAdapterContract;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// One tabular row, column name to value, as datasets carry rows.
pub type ModelRow = HashMap<String, String>;

/// A trained model behind the contract the plane records.
pub trait ModelAdapter: Sized {
    /// The named inputs and output the plane sees.
    fn contract(&self) -> ModelAdapterContract;
    /// Scores one batch: rows for each named input, one output row per result.
    fn predict(&self, inputs: &HashMap<String, Vec<ModelRow>>) -> io::Result<Vec<ModelRow>>;
    /// Writes the model's state into `dir`, which the registry then stores.
    fn save(&self, dir: &Path) -> io::Result<()>;
    /// Rebuilds the model from a directory written by [`ModelAdapter::save`].
    fn load(dir: &Path) -> io::Result<Self>;
}

/// Where a registry keeps a stored state directory, and the digest the plane
/// records for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredModel {
    pub registry_locator: String,
    pub digest: String,
}

/// Stores model state outside the plane and resolves references to it.
pub trait ModelRegistry {
    /// Stores `state_dir` for `model_name`. Storing the same bytes again
    /// returns the same reference.
    fn store(&self, model_name: &str, state_dir: &Path) -> io::Result<StoredModel>;
    /// A directory an adapter can [`ModelAdapter::load`], refused when its
    /// bytes no longer match `digest`.
    fn resolve(&self, registry_locator: &str, digest: &str) -> io::Result<PathBuf>;
}

/// A registry on a local directory: `<root>/<model_name>/<digest hex>/`.
#[derive(Debug, Clone)]
pub struct LocalDirectoryRegistry {
    root: PathBuf,
}

impl LocalDirectoryRegistry {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl ModelRegistry for LocalDirectoryRegistry {
    fn store(&self, model_name: &str, state_dir: &Path) -> io::Result<StoredModel> {
        if model_name.is_empty() || model_name.contains(['/', '\\']) || model_name.starts_with('.')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "model name must be one plain path segment",
            ));
        }
        let digest = state_digest(state_dir)?;
        let hex = digest.trim_start_matches("sha256:");
        let registry_locator = format!("{model_name}/{hex}");
        let target = self.root.join(&registry_locator);
        if !target.exists() {
            // Copy beside the target, then rename: a crash leaves only a
            // staging directory, never a partial version.
            let parent = self.root.join(model_name);
            fs::create_dir_all(&parent)?;
            let staging = parent.join(format!(".staging-{}", uuid::Uuid::new_v4().simple()));
            copy_dir(state_dir, &staging)?;
            if let Err(error) = fs::rename(&staging, &target) {
                let _ = fs::remove_dir_all(&staging);
                // Another writer stored the same bytes first.
                if !target.exists() {
                    return Err(error);
                }
            }
        }
        Ok(StoredModel {
            registry_locator,
            digest,
        })
    }

    fn resolve(&self, registry_locator: &str, digest: &str) -> io::Result<PathBuf> {
        let path = self.root.join(registry_locator);
        let inside = Path::new(registry_locator)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)));
        if !inside || state_digest(&path)? != digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored model does not match its digest",
            ));
        }
        Ok(path)
    }
}

/// `sha256:` over every regular file under `dir`, by sorted relative path,
/// so the digest names the bytes and not where they sit.
pub fn state_digest(dir: &Path) -> io::Result<String> {
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for relative in files {
        let bytes = fs::read(dir.join(&relative))?;
        let name = relative.to_string_lossy();
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("sha256:{hex}"))
}

fn collect_files(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_files(root, &entry.path(), files)?;
        } else if kind.is_file() {
            files.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(io::Error::other)?
                    .to_path_buf(),
            );
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "model state may hold only files and directories",
            ));
        }
    }
    Ok(())
}

fn copy_dir(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
