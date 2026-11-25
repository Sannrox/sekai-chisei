//! The `object_storage` connector type: the rows of the objects under one
//! bucket prefix of an S3-compatible store.
//!
//! This part holds only the signed storage client; the type
//! and its listing mirror build on it.

// The connector type is the only caller, so the client is dead code until
// it lands; `expect` fails the build once the client is used, removing this.
#[expect(dead_code)]
mod store;
