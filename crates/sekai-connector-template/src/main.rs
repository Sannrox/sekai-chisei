//! Run the connector until the source is up to date.
//!
//! sekai-connector-template [--config connector.json] [--fake]

use sekai_connector_template::config::ConnectorConfig;
use sekai_connector_template::fake::FakeSource;
use sekai_connector_template::source::Source;
use sekai_connector_template::transport::GrpcTransport;
use sekai_connector_template::{RunOutcome, run_once};
use sekai_source_sdk::{OutboxLimits, SnapshotPageSource, SourceInspector, SourceOutbox};
use std::path::PathBuf;

fn main() -> Result<(), String> {
    let mut config_path = PathBuf::from("connector.json");
    let mut fake = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next().ok_or("--config needs a path")?.into(),
            "--fake" => fake = true,
            _ => return Err(format!("unknown argument {arg:?}")),
        }
    }
    let config = ConnectorConfig::load(&config_path)?;
    if fake {
        sync(
            &config,
            FakeSource::new(&config.source, &config.source_instance),
        )
    } else {
        sync(&config, Source::new(config.source_credential()))
    }
}

fn sync<S: SourceInspector + SnapshotPageSource>(
    config: &ConnectorConfig,
    mut source: S,
) -> Result<(), String> {
    source
        .check()
        .map_err(|failure| format!("source check failed: {failure}"))?;
    let outbox = SourceOutbox::open(&config.outbox_dir, OutboxLimits::default())?;
    let mut transport = GrpcTransport::connect(&config.target, config.credential())?;
    loop {
        let outcome = run_once(config, &outbox, &mut source, &mut transport)?;
        println!("{outcome:?}");
        match outcome {
            RunOutcome::Committed {
                complete: false, ..
            } => {}
            RunOutcome::Committed { complete: true, .. } | RunOutcome::UpToDate => return Ok(()),
            RunOutcome::Pending => return Err("delivery is pending; run again".into()),
            RunOutcome::Quarantined => {
                return Err("the plane rejected a batch; see the outbox quarantine".into());
            }
        }
    }
}
