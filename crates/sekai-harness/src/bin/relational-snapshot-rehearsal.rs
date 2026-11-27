//! Rehearse a relational snapshot against a known-content fixture (#2358).
//!
//! ```text
//! relational-snapshot-rehearsal --plane <url> --keiko <url> --keiko-ca <pem>
//!     --db-endpoint <host:port> --out <dir>
//!     [--advance-steps n] [--run-name name] [--ensure-only]
//! ```

use std::process::ExitCode;

use sekai_harness::relational_snapshot::{Rehearsal, run};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match play(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relational-snapshot-rehearsal: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn play(args: Vec<String>) -> Result<(), String> {
    run(Rehearsal::from_args(&args)?).await
}
