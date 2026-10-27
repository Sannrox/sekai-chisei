//! Embedding models behind one seam.
//!
//! The embedding index calls an [`Embedder`]; a route from the model catalog
//! supplies the implementation. [`HashEmbedder`] is a deterministic local
//! embedder for tests and offline development.

use async_trait::async_trait;
use sha2::{Digest, Sha256};

/// An embedding model route. `model` and `model_version` tag every stored
/// vector; `external` is true when the route sends text out of the deployment.
#[async_trait]
pub trait Embedder: Send + Sync {
    fn model(&self) -> &str;
    fn model_version(&self) -> &str;
    fn external(&self) -> bool;
    /// Refuse a whole source text before it is chunked and sent; a route
    /// with payload rules checks them here, where no chunk boundary can split
    /// a match. Allows everything by default.
    fn screen(&self, _text: &str) -> Result<(), String> {
        Ok(())
    }
    /// One vector per input text, in order.
    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String>;
}

/// Deterministic, local embedder: each component comes from SHA-256 of the
/// text, so equal texts get equal vectors and no text leaves the process.
#[derive(Debug, Clone)]
pub struct HashEmbedder {
    pub model: String,
    pub model_version: String,
    pub dimension: usize,
}

impl HashEmbedder {
    pub fn new(
        model: impl Into<String>,
        model_version: impl Into<String>,
        dimension: usize,
    ) -> Self {
        Self {
            model: model.into(),
            model_version: model_version.into(),
            dimension,
        }
    }
}

#[async_trait]
impl Embedder for HashEmbedder {
    fn model(&self) -> &str {
        &self.model
    }

    fn model_version(&self) -> &str {
        &self.model_version
    }

    fn external(&self) -> bool {
        false
    }

    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        Ok(texts
            .iter()
            .map(|text| {
                (0..self.dimension)
                    .map(|component| {
                        let digest = Sha256::new()
                            .chain_update(self.model_version.as_bytes())
                            .chain_update((component as u64).to_le_bytes())
                            .chain_update(text.as_bytes())
                            .finalize();
                        f32::from(digest[0]) / 255.0
                    })
                    .collect()
            })
            .collect())
    }
}
