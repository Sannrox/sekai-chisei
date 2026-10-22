//! sekaictl admin model-release-evidence commands (#1396).

use crate::chisei::model_release_evidence::{
    self, EvaluationTrustRoots, ModelReleaseFeedback, ModelReleaseIdentity, ModelRuntimeEvidence,
};
use crate::chisei_store::ChiseiStore;
use crate::combined_stores::CombinedStoreLayout;
use crate::config::Config;
use chrono::Utc;
use ed25519_dalek::SigningKey;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin model-release-evidence trust-set --file <roots.json>\n  sekaictl admin model-release-evidence trust-get\n  sekaictl admin model-release-evidence ingest --file <runtime.json>\n  sekaictl admin model-release-evidence get --provider <id> --model <id> --profile-version <v> --digest <digest> --endpoint <uri>\n  sekaictl admin model-release-evidence export --provider <id> --model <id> --profile-version <v> --digest <digest> --endpoint <uri> --suite <id> --baseline <run> --candidate <run> --eval-run <id> [--signing-key-hex <64 hex>] [--actor <principal>]\n  sekaictl admin model-release-evidence feedback --namespace <ns> --provider <id> --model <id> --profile-version <v> --digest <digest> --endpoint <uri> --note <text> [--actor <principal>]"
}

pub async fn run_model_release_evidence_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("trust-set") => trust_set(flag(&args[1..], "--file")?).await,
        Some("trust-get") => trust_get().await,
        Some("ingest") => ingest(flag(&args[1..], "--file")?).await,
        Some("get") => get(parse_identity(&args[1..])?).await,
        Some("export") => export(parse_export(&args[1..])?).await,
        Some("feedback") => feedback(parse_feedback(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

fn open_store() -> Result<ChiseiStore, BoxErr> {
    let cfg = Config::from_env();
    let layout = CombinedStoreLayout::from_env(&cfg.db_path).map_err(std::io::Error::other)?;
    Ok(layout.handles().1)
}

fn flag(args: &[String], name: &str) -> Result<String, BoxErr> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].clone())
        .ok_or_else(|| std::io::Error::other(format!("{name} is required")).into())
}

fn optional_flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].clone())
}

fn parse_identity(args: &[String]) -> Result<ModelReleaseIdentity, BoxErr> {
    let identity = ModelReleaseIdentity {
        provider: flag(args, "--provider")?,
        model: flag(args, "--model")?,
        profile_version: flag(args, "--profile-version")?,
        artifact_digest: flag(args, "--digest")?,
        endpoint: flag(args, "--endpoint")?,
    };
    identity.validate().map_err(std::io::Error::other)?;
    Ok(identity)
}

struct ExportArgs {
    identity: ModelReleaseIdentity,
    suite: String,
    baseline: String,
    candidate: String,
    eval_run: String,
    signing_key_hex: Option<String>,
    actor: String,
}

fn parse_export(args: &[String]) -> Result<ExportArgs, BoxErr> {
    Ok(ExportArgs {
        identity: parse_identity(args)?,
        suite: flag(args, "--suite")?,
        baseline: flag(args, "--baseline")?,
        candidate: flag(args, "--candidate")?,
        eval_run: flag(args, "--eval-run")?,
        signing_key_hex: optional_flag(args, "--signing-key-hex"),
        actor: optional_flag(args, "--actor").unwrap_or_else(|| "root".into()),
    })
}

struct FeedbackArgs {
    namespace: String,
    identity: ModelReleaseIdentity,
    note: String,
    actor: String,
}

fn parse_feedback(args: &[String]) -> Result<FeedbackArgs, BoxErr> {
    Ok(FeedbackArgs {
        namespace: flag(args, "--namespace")?,
        identity: parse_identity(args)?,
        note: flag(args, "--note")?,
        actor: optional_flag(args, "--actor").unwrap_or_else(|| "root".into()),
    })
}

fn signing_key(hex: Option<String>) -> Result<SigningKey, BoxErr> {
    let raw = match hex {
        Some(value) => value,
        None => std::env::var("SEKAI_MODEL_EVALUATION_SIGNING_KEY")
            .map_err(|_| std::io::Error::other("signing key is required"))?,
    };
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::other("signing key must be 64 hex characters").into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|_| std::io::Error::other("signing key is not valid hex"))?;
    }
    Ok(SigningKey::from_bytes(&out))
}

async fn trust_set(path: String) -> Result<(), BoxErr> {
    let db = open_store()?;
    let json = std::fs::read_to_string(path)?;
    let roots: EvaluationTrustRoots = serde_json::from_str(&json)?;
    let stored =
        model_release_evidence::install_trust_roots(&db, roots, Utc::now().timestamp_millis())
            .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&stored)?);
    Ok(())
}

async fn trust_get() -> Result<(), BoxErr> {
    let db = open_store()?;
    match model_release_evidence::load_trust_roots(&db).map_err(std::io::Error::other)? {
        Some(roots) => println!("{}", serde_json::to_string_pretty(&roots)?),
        None => println!("null"),
    }
    Ok(())
}

async fn ingest(path: String) -> Result<(), BoxErr> {
    let db = open_store()?;
    let json = std::fs::read_to_string(path)?;
    let evidence = ModelRuntimeEvidence::parse_json(&json)
        .map_err(|failure| std::io::Error::other(failure.as_str()))?;
    let stored = model_release_evidence::ingest_runtime_evidence(
        &db,
        evidence,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&stored)?);
    Ok(())
}

async fn get(identity: ModelReleaseIdentity) -> Result<(), BoxErr> {
    let db = open_store()?;
    match model_release_evidence::load_runtime_evidence_json(&db, &identity)
        .map_err(std::io::Error::other)?
    {
        Some(json) => println!("{json}"),
        None => println!("null"),
    }
    Ok(())
}

async fn export(args: ExportArgs) -> Result<(), BoxErr> {
    let db = open_store()?;
    let key = signing_key(args.signing_key_hex)?;
    let evidence = model_release_evidence::export_evaluation_from_compare(
        &db,
        args.identity,
        &args.suite,
        &args.baseline,
        &args.candidate,
        &args.eval_run,
        &key,
        Utc::now().timestamp_millis(),
        &args.actor,
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    Ok(())
}

async fn feedback(args: FeedbackArgs) -> Result<(), BoxErr> {
    let db = open_store()?;
    let record = model_release_evidence::record_model_release_feedback(
        &db,
        ModelReleaseFeedback {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: args.namespace,
            identity: args.identity,
            actor: args.actor,
            note: args.note,
            recorded_at_ms: Utc::now().timestamp_millis(),
        },
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_names_trust_ingest_export_and_feedback() {
        let usage = usage();
        assert!(usage.contains("sekaictl admin model-release-evidence trust-set"));
        assert!(usage.contains("ingest"));
        assert!(usage.contains("export"));
        assert!(usage.contains("feedback"));
    }
}
