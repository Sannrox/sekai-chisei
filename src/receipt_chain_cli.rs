//! sekaictl admin assurance receipts export/verify commands (#1449).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use sekai_types::receipt_chain::{ReceiptChainBundle, verify_bundle};
use std::path::{Path, PathBuf};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin assurance receipts export --namespace <ns> --output <file>\n  sekaictl admin assurance receipts verify <bundle> --trusted-key <hex> [--trusted-key <hex> ...]"
}

pub async fn run_receipts_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("export") => export(parse_export(&args[1..])?).await,
        Some("verify") => verify(parse_verify(&args[1..])?),
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

struct ExportConfig {
    namespace: String,
    output: PathBuf,
}

struct VerifyConfig {
    bundle: PathBuf,
    trusted_keys: Vec<String>,
}

async fn export(config: ExportConfig) -> Result<(), BoxErr> {
    crate::combined_stores::refuse_split_single_store_cli("ChiseiService.GetOperationReceipt")
        .map_err(std::io::Error::other)?;
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    if config.output.exists() {
        return Err(std::io::Error::other(format!(
            "output already exists: {} (refusing to overwrite a receipt-chain artifact)",
            config.output.display()
        ))
        .into());
    }
    let bundle = backend
        .database()
        .export_receipt_chain(&config.namespace)
        .map_err(std::io::Error::other)?;
    write_bundle(&config.output, &bundle)?;
    println!(
        "exported {} entries={} keys={}",
        config.output.display(),
        bundle.entries.len(),
        bundle.keys.len()
    );
    Ok(())
}

fn verify(config: VerifyConfig) -> Result<(), BoxErr> {
    let bundle: ReceiptChainBundle = serde_json::from_slice(&std::fs::read(&config.bundle)?)?;
    let trusted: Vec<&str> = config.trusted_keys.iter().map(String::as_str).collect();
    match verify_bundle(&bundle, &trusted) {
        Ok(()) => {
            println!(
                "ok namespace={} entries={} keys={}",
                bundle.namespace,
                bundle.entries.len(),
                bundle.keys.len()
            );
            Ok(())
        }
        Err(error) => {
            eprintln!("error: {error}");
            Err(std::io::Error::other("receipt chain verification failed").into())
        }
    }
}

fn write_bundle(path: &Path, bundle: &ReceiptChainBundle) -> Result<(), BoxErr> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staged = parent.join(format!(
        ".receipt-chain-{}-{}.partial",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let bytes = serde_json::to_vec_pretty(bundle)?;
    let write_result = (|| {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&staged)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok::<(), BoxErr>(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    if let Err(error) = std::fs::hard_link(&staged, path) {
        let _ = std::fs::remove_file(&staged);
        return Err(std::io::Error::new(
            error.kind(),
            format!(
                "failed to publish {}: {error} (destination must not already exist)",
                path.display()
            ),
        )
        .into());
    }
    let _ = std::fs::remove_file(&staged);
    Ok(())
}

fn parse_export(args: &[String]) -> Result<ExportConfig, BoxErr> {
    let mut namespace = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, index, "--namespace")?.to_string());
                index += 2;
            }
            "--output" => {
                output = Some(PathBuf::from(require_value(args, index, "--output")?));
                index += 2;
            }
            other => return Err(std::io::Error::other(format!("unknown flag {other}")).into()),
        }
    }
    Ok(ExportConfig {
        namespace: namespace.ok_or_else(|| std::io::Error::other(usage()))?,
        output: output.ok_or_else(|| std::io::Error::other(usage()))?,
    })
}

fn parse_verify(args: &[String]) -> Result<VerifyConfig, BoxErr> {
    let mut bundle = None;
    let mut trusted_keys = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--trusted-key" => {
                trusted_keys.push(require_value(args, index, "--trusted-key")?.to_string());
                index += 2;
            }
            other if !other.starts_with('-') && bundle.is_none() => {
                bundle = Some(PathBuf::from(other));
                index += 1;
            }
            other => return Err(std::io::Error::other(format!("unknown flag {other}")).into()),
        }
    }
    if trusted_keys.is_empty() {
        return Err(std::io::Error::other("verify requires --trusted-key <hex>").into());
    }
    Ok(VerifyConfig {
        bundle: bundle.ok_or_else(|| std::io::Error::other(usage()))?,
        trusted_keys,
    })
}

fn require_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, BoxErr> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| std::io::Error::other(format!("{flag} requires a value")).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_types::receipt_chain::{ReceiptChain, ReceiptKind, SigningKeySet};

    #[test]
    fn verify_accepts_a_library_bundle_and_names_the_tamper_position() {
        let keys = SigningKeySet::from_seed_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
            1,
        )
        .unwrap();
        let trusted = keys.current_public_key_hex();
        let mut chain = ReceiptChain::genesis("ns", keys, 10).unwrap();
        chain
            .append(
                ReceiptKind::Action,
                "op-1",
                r#"{"operation_id":"op-1","events":[]}"#,
                11,
            )
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "receipt-chain-cli-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bundle.json");
        write_bundle(&path, &chain.bundle()).unwrap();
        verify(VerifyConfig {
            bundle: path.clone(),
            trusted_keys: vec![trusted.clone()],
        })
        .unwrap();
        let mut tampered: ReceiptChainBundle =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        tampered.entries[0].receipt_json.push('x');
        let bad = dir.join("bad.json");
        std::fs::write(&bad, serde_json::to_vec(&tampered).unwrap()).unwrap();
        let error = verify(VerifyConfig {
            bundle: bad,
            trusted_keys: vec![trusted],
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("receipt chain verification failed")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
