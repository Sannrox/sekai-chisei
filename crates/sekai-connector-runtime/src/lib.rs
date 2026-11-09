//! The one connector runtime (ADR 0148).
//!
//! A worker that claims Source work from the plane's one work queue
//! (ADR 0149) and runs the connector types it implements. It talks to the
//! plane only over gRPC and never links the control-plane packages. It
//! holds the operator's credential bindings; the plane holds only the
//! handles. Placement, schedules and claims stay on the plane, so any
//! number of runtimes can serve a namespace and any of them can stop.

pub mod credentials;
pub mod runtime;
pub mod sync;

pub use credentials::{CredentialBinding, CredentialBindings, Credentials, Secret, SlotSource};
pub use runtime::{Ran, Runtime, RuntimeOptions};
pub use sync::{Connectors, Open, Prepared, SyncFailure, prepare};
