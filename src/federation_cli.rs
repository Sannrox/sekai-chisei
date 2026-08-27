//! sekaictl admin federation profile commands (#291).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::federation_conflict;
use crate::sekai::federation_profile::{
    self, JoinPeerRequest, LocalSiteIdentity, PeerHealth, PolicyPackPin, TRUST_ROOT_NAMESPACE,
};
use crate::sekai::namespace_snapshot::{self, ExportSnapshotRequest, GrantNamespaceRequest};
use crate::sekai::peer_import::PeerTrustRoot;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin federation register-site --site-id <id> --key-id <id> --public-key-hex <hex> [--region <label>] [--data-class <class>]... [--actor <principal>]\n  sekaictl admin federation show-site\n  sekaictl admin federation pin-trust-root --site-identity <id> --key-id <id> --public-key-hex <hex> [--namespace <ns>] [--actor <principal>]\n  sekaictl admin federation join --peer-site-id <id> --peer-key-id <id> --peer-public-key-hex <hex> --pack-id <id> --pack-version <ver> --pack-digest <digest> [--region <label>] [--data-class <class>]... [--trust-namespace <ns>] [--actor <principal>]\n  sekaictl admin federation leave --peer-site-id <id> [--actor <principal>]\n  sekaictl admin federation set-health --peer-site-id <id> --health up|down|unknown\n  sekaictl admin federation set-pack-pin --peer-site-id <id> --pack-id <id> --pack-version <ver> --pack-digest <digest>\n  sekaictl admin federation list-peers\n  sekaictl admin federation import-availability --peer-site-id <id>\n  sekaictl admin federation grant-namespace --peer-site-id <id> --namespace <ns> [--kind <kind>]... [--max-classification <class>] [--not-before-ms <ts>] [--not-after-ms <ts>] [--actor <principal>]\n  sekaictl admin federation revoke-namespace-grant --grant-id <id> [--actor <principal>]\n  sekaictl admin federation list-namespace-grants [--namespace <ns>] [--peer-site-id <id>]\n  sekaictl admin federation export-snapshot --namespace <ns> --output <file> --signing-key <file> --pack-id <id> --pack-version <ver> --pack-digest <digest> [--kind <kind>]... [--actor <principal>] [--not-before-ms <ts>] [--not-after-ms <ts>]\n  sekaictl admin federation import-snapshot --namespace <ns> --bundle <file> [--actor <principal>]\n  sekaictl admin federation list-snapshot-imports [--namespace <ns>]\n  sekaictl admin federation show-snapshot-facts --import-id <id>\n  sekaictl admin federation show-snapshot-provenance --import-id <id> --object-id <id>\n  sekaictl admin federation list-conflicts [--namespace <ns>]\n  sekaictl admin federation show-conflict --namespace <ns> --object-id <id>\n  sekaictl admin federation resolve-conflict --namespace <ns> --object-id <id> --claim-id <id> [--actor <principal>]\n  sekaictl admin federation reopen-conflict --namespace <ns> --object-id <id> [--actor <principal>]"
}

pub async fn run_federation_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("register-site") => register_site(parse_register_site(&args[1..])?).await,
        Some("show-site") => show_site().await,
        Some("pin-trust-root") => pin_trust_root(parse_pin_trust_root(&args[1..])?).await,
        Some("join") => join_peer(parse_join(&args[1..])?).await,
        Some("leave") => leave_peer(parse_leave(&args[1..])?).await,
        Some("set-health") => set_health(parse_set_health(&args[1..])?).await,
        Some("set-pack-pin") => set_pack_pin(parse_set_pack_pin(&args[1..])?).await,
        Some("list-peers") => list_peers().await,
        Some("import-availability") => {
            import_availability(parse_import_availability(&args[1..])?).await
        }
        Some("grant-namespace") => grant_namespace(parse_grant_namespace(&args[1..])?).await,
        Some("revoke-namespace-grant") => {
            revoke_namespace_grant(parse_revoke_grant(&args[1..])?).await
        }
        Some("list-namespace-grants") => {
            list_namespace_grants(parse_list_grants(&args[1..])?).await
        }
        Some("export-snapshot") => export_snapshot(parse_export_snapshot(&args[1..])?).await,
        Some("import-snapshot") => import_snapshot(parse_import_snapshot(&args[1..])?).await,
        Some("list-snapshot-imports") => {
            list_snapshot_imports(parse_list_imports(&args[1..])?).await
        }
        Some("show-snapshot-facts") => show_snapshot_facts(parse_show_facts(&args[1..])?).await,
        Some("show-snapshot-provenance") => {
            show_snapshot_provenance(parse_show_provenance(&args[1..])?).await
        }
        Some("list-conflicts") => list_conflicts(parse_list_conflicts(&args[1..])?).await,
        Some("show-conflict") => show_conflict(parse_show_conflict(&args[1..])?).await,
        Some("resolve-conflict") => resolve_conflict(parse_resolve_conflict(&args[1..])?).await,
        Some("reopen-conflict") => reopen_conflict(parse_reopen_conflict(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

async fn open_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

#[derive(Debug, Clone)]
struct RegisterSiteConfig {
    site_id: String,
    key_id: String,
    public_key_hex: String,
    region: Option<String>,
    data_classes: Vec<String>,
    actor: String,
}

async fn register_site(config: RegisterSiteConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let site = LocalSiteIdentity {
        site_id: config.site_id,
        key_id: config.key_id,
        public_key_hex: config.public_key_hex,
        region: config.region,
        residency_data_classes: config.data_classes,
        registered_by: config.actor,
        registered_at_ms: Utc::now().timestamp_millis(),
    };
    federation_profile::register_local_site(db.as_ref(), &site).map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&site)?);
    Ok(())
}

async fn show_site() -> Result<(), BoxErr> {
    let db = open_db().await?;
    match federation_profile::get_local_site(db.as_ref()).map_err(std::io::Error::other)? {
        Some(site) => println!("{}", serde_json::to_string_pretty(&site)?),
        None => println!("{{\"registered\":false}}"),
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct PinTrustRootConfig {
    namespace: String,
    site_identity: String,
    key_id: String,
    public_key_hex: String,
    actor: String,
}

async fn pin_trust_root(config: PinTrustRootConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let root = PeerTrustRoot {
        namespace: config.namespace,
        site_identity: config.site_identity,
        key_id: config.key_id,
        public_key_hex: config.public_key_hex,
        enabled: true,
        created_by: config.actor,
        created_at_ms: Utc::now().timestamp_millis(),
    };
    federation_profile::pin_trust_root(db.as_ref(), &root).map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&root)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct JoinConfig {
    peer_site_id: String,
    peer_key_id: String,
    peer_public_key_hex: String,
    pack_id: String,
    pack_version: String,
    pack_digest: String,
    region: Option<String>,
    data_classes: Vec<String>,
    trust_namespace: String,
    actor: String,
}

async fn join_peer(config: JoinConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let peer = federation_profile::join_peer(
        db.as_ref(),
        &config.actor,
        &JoinPeerRequest {
            peer_site_id: config.peer_site_id,
            peer_key_id: config.peer_key_id,
            peer_public_key_hex: config.peer_public_key_hex,
            policy_pack: PolicyPackPin {
                pack_id: config.pack_id,
                version: config.pack_version,
                content_digest: config.pack_digest,
            },
            residency_region: config.region,
            residency_data_classes: config.data_classes,
            trust_namespace: config.trust_namespace,
        },
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&peer)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct LeaveConfig {
    peer_site_id: String,
    actor: String,
}

async fn leave_peer(config: LeaveConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let peer = federation_profile::leave_peer(
        db.as_ref(),
        &config.actor,
        &config.peer_site_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&peer)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct SetHealthConfig {
    peer_site_id: String,
    health: PeerHealth,
}

async fn set_health(config: SetHealthConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let peer =
        federation_profile::set_peer_health(db.as_ref(), &config.peer_site_id, config.health)
            .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&peer)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct SetPackPinConfig {
    peer_site_id: String,
    pack: PolicyPackPin,
}

async fn set_pack_pin(config: SetPackPinConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let peer =
        federation_profile::set_policy_pack_pin(db.as_ref(), &config.peer_site_id, config.pack)
            .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&peer)?);
    Ok(())
}

async fn list_peers() -> Result<(), BoxErr> {
    let db = open_db().await?;
    let peers = federation_profile::list_peers(db.as_ref()).map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&peers)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ImportAvailabilityConfig {
    peer_site_id: String,
}

async fn import_availability(config: ImportAvailabilityConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let status =
        federation_profile::cross_site_import_availability(db.as_ref(), &config.peer_site_id)
            .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

fn parse_register_site(args: &[String]) -> Result<RegisterSiteConfig, String> {
    let mut site_id = None;
    let mut key_id = None;
    let mut public_key_hex = None;
    let mut region = None;
    let mut data_classes = Vec::new();
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--site-id" => {
                site_id = Some(require_value(args, i, "--site-id")?);
                i += 2;
            }
            "--key-id" => {
                key_id = Some(require_value(args, i, "--key-id")?);
                i += 2;
            }
            "--public-key-hex" => {
                public_key_hex = Some(require_value(args, i, "--public-key-hex")?);
                i += 2;
            }
            "--region" => {
                region = Some(require_value(args, i, "--region")?);
                i += 2;
            }
            "--data-class" => {
                data_classes.push(require_value(args, i, "--data-class")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown register-site option {other}")),
        }
    }
    Ok(RegisterSiteConfig {
        site_id: site_id.ok_or("--site-id is required")?,
        key_id: key_id.ok_or("--key-id is required")?,
        public_key_hex: public_key_hex.ok_or("--public-key-hex is required")?,
        region,
        data_classes,
        actor,
    })
}

fn parse_pin_trust_root(args: &[String]) -> Result<PinTrustRootConfig, String> {
    let mut namespace = TRUST_ROOT_NAMESPACE.to_string();
    let mut site_identity = None;
    let mut key_id = None;
    let mut public_key_hex = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = require_value(args, i, "--namespace")?;
                i += 2;
            }
            "--site-identity" => {
                site_identity = Some(require_value(args, i, "--site-identity")?);
                i += 2;
            }
            "--key-id" => {
                key_id = Some(require_value(args, i, "--key-id")?);
                i += 2;
            }
            "--public-key-hex" => {
                public_key_hex = Some(require_value(args, i, "--public-key-hex")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown pin-trust-root option {other}")),
        }
    }
    Ok(PinTrustRootConfig {
        namespace,
        site_identity: site_identity.ok_or("--site-identity is required")?,
        key_id: key_id.ok_or("--key-id is required")?,
        public_key_hex: public_key_hex.ok_or("--public-key-hex is required")?,
        actor,
    })
}

fn parse_join(args: &[String]) -> Result<JoinConfig, String> {
    let mut peer_site_id = None;
    let mut peer_key_id = None;
    let mut peer_public_key_hex = None;
    let mut pack_id = None;
    let mut pack_version = None;
    let mut pack_digest = None;
    let mut region = None;
    let mut data_classes = Vec::new();
    let mut trust_namespace = TRUST_ROOT_NAMESPACE.to_string();
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--peer-site-id" => {
                peer_site_id = Some(require_value(args, i, "--peer-site-id")?);
                i += 2;
            }
            "--peer-key-id" => {
                peer_key_id = Some(require_value(args, i, "--peer-key-id")?);
                i += 2;
            }
            "--peer-public-key-hex" => {
                peer_public_key_hex = Some(require_value(args, i, "--peer-public-key-hex")?);
                i += 2;
            }
            "--pack-id" => {
                pack_id = Some(require_value(args, i, "--pack-id")?);
                i += 2;
            }
            "--pack-version" => {
                pack_version = Some(require_value(args, i, "--pack-version")?);
                i += 2;
            }
            "--pack-digest" => {
                pack_digest = Some(require_value(args, i, "--pack-digest")?);
                i += 2;
            }
            "--region" => {
                region = Some(require_value(args, i, "--region")?);
                i += 2;
            }
            "--data-class" => {
                data_classes.push(require_value(args, i, "--data-class")?);
                i += 2;
            }
            "--trust-namespace" => {
                trust_namespace = require_value(args, i, "--trust-namespace")?;
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown join option {other}")),
        }
    }
    Ok(JoinConfig {
        peer_site_id: peer_site_id.ok_or("--peer-site-id is required")?,
        peer_key_id: peer_key_id.ok_or("--peer-key-id is required")?,
        peer_public_key_hex: peer_public_key_hex.ok_or("--peer-public-key-hex is required")?,
        pack_id: pack_id.ok_or("--pack-id is required")?,
        pack_version: pack_version.ok_or("--pack-version is required")?,
        pack_digest: pack_digest.ok_or("--pack-digest is required")?,
        region,
        data_classes,
        trust_namespace,
        actor,
    })
}

fn parse_leave(args: &[String]) -> Result<LeaveConfig, String> {
    let mut peer_site_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--peer-site-id" => {
                peer_site_id = Some(require_value(args, i, "--peer-site-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown leave option {other}")),
        }
    }
    Ok(LeaveConfig {
        peer_site_id: peer_site_id.ok_or("--peer-site-id is required")?,
        actor,
    })
}

fn parse_set_health(args: &[String]) -> Result<SetHealthConfig, String> {
    let mut peer_site_id = None;
    let mut health = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--peer-site-id" => {
                peer_site_id = Some(require_value(args, i, "--peer-site-id")?);
                i += 2;
            }
            "--health" => {
                health = Some(PeerHealth::parse(&require_value(args, i, "--health")?)?);
                i += 2;
            }
            other => return Err(format!("unknown set-health option {other}")),
        }
    }
    Ok(SetHealthConfig {
        peer_site_id: peer_site_id.ok_or("--peer-site-id is required")?,
        health: health.ok_or("--health is required")?,
    })
}

fn parse_set_pack_pin(args: &[String]) -> Result<SetPackPinConfig, String> {
    let mut peer_site_id = None;
    let mut pack_id = None;
    let mut pack_version = None;
    let mut pack_digest = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--peer-site-id" => {
                peer_site_id = Some(require_value(args, i, "--peer-site-id")?);
                i += 2;
            }
            "--pack-id" => {
                pack_id = Some(require_value(args, i, "--pack-id")?);
                i += 2;
            }
            "--pack-version" => {
                pack_version = Some(require_value(args, i, "--pack-version")?);
                i += 2;
            }
            "--pack-digest" => {
                pack_digest = Some(require_value(args, i, "--pack-digest")?);
                i += 2;
            }
            other => return Err(format!("unknown set-pack-pin option {other}")),
        }
    }
    Ok(SetPackPinConfig {
        peer_site_id: peer_site_id.ok_or("--peer-site-id is required")?,
        pack: PolicyPackPin {
            pack_id: pack_id.ok_or("--pack-id is required")?,
            version: pack_version.ok_or("--pack-version is required")?,
            content_digest: pack_digest.ok_or("--pack-digest is required")?,
        },
    })
}

fn parse_import_availability(args: &[String]) -> Result<ImportAvailabilityConfig, String> {
    let mut peer_site_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--peer-site-id" => {
                peer_site_id = Some(require_value(args, i, "--peer-site-id")?);
                i += 2;
            }
            other => return Err(format!("unknown import-availability option {other}")),
        }
    }
    Ok(ImportAvailabilityConfig {
        peer_site_id: peer_site_id.ok_or("--peer-site-id is required")?,
    })
}

#[derive(Debug, Clone)]
struct GrantNamespaceConfig {
    peer_site_id: String,
    namespace: String,
    kinds: Vec<String>,
    max_classification: Option<String>,
    not_before_ms: i64,
    not_after_ms: Option<i64>,
    actor: String,
}

async fn grant_namespace(config: GrantNamespaceConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let grant = namespace_snapshot::grant_namespace(
        db.as_ref(),
        &config.actor,
        &GrantNamespaceRequest {
            peer_site_id: config.peer_site_id,
            namespace: config.namespace,
            object_kinds: config.kinds,
            max_classification: config.max_classification,
            not_before_ms: config.not_before_ms,
            not_after_ms: config.not_after_ms,
        },
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&grant)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct RevokeGrantConfig {
    grant_id: String,
    actor: String,
}

async fn revoke_namespace_grant(config: RevokeGrantConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let grant = namespace_snapshot::revoke_namespace_grant(
        db.as_ref(),
        &config.actor,
        &config.grant_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&grant)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ListGrantsConfig {
    namespace: Option<String>,
    peer_site_id: Option<String>,
}

async fn list_namespace_grants(config: ListGrantsConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let grants = namespace_snapshot::list_namespace_grants(
        db.as_ref(),
        config.namespace.as_deref(),
        config.peer_site_id.as_deref(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&grants)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ExportSnapshotConfig {
    namespace: String,
    output: PathBuf,
    signing_key: PathBuf,
    pack: PolicyPackPin,
    kinds: Vec<String>,
    actor: String,
    not_before_ms: i64,
    not_after_ms: Option<i64>,
}

async fn export_snapshot(config: ExportSnapshotConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let signing_key = load_signing_key(&config.signing_key).map_err(std::io::Error::other)?;
    let bundle = namespace_snapshot::export_namespace_snapshot(
        db.as_ref(),
        &ExportSnapshotRequest {
            namespace: config.namespace,
            actor: config.actor,
            object_kinds: config.kinds,
            policy_pack: config.pack,
            not_before_ms: config.not_before_ms,
            not_after_ms: config.not_after_ms,
        },
        &signing_key,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config.output)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                std::io::Error::other(format!(
                    "output already exists: {} (refusing to overwrite a signed snapshot)",
                    config.output.display()
                ))
            } else {
                error
            }
        })?;
    std::io::Write::write_all(&mut output, &serde_json::to_vec_pretty(&bundle)?)?;
    println!("{}", serde_json::to_string_pretty(&bundle.manifest)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ImportSnapshotConfig {
    namespace: String,
    bundle: PathBuf,
    actor: String,
}

async fn import_snapshot(config: ImportSnapshotConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let bytes = std::fs::read(&config.bundle)?;
    let bundle = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    let result = namespace_snapshot::import_namespace_snapshot(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &bundle,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ListImportsConfig {
    namespace: Option<String>,
}

async fn list_snapshot_imports(config: ListImportsConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let imports =
        namespace_snapshot::list_snapshot_imports(db.as_ref(), config.namespace.as_deref())
            .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&imports)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ShowFactsConfig {
    import_id: String,
}

#[derive(Debug, Clone)]
struct ShowProvenanceConfig {
    import_id: String,
    object_id: String,
}

async fn show_snapshot_provenance(config: ShowProvenanceConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let chain = namespace_snapshot::get_imported_fact_provenance(
        db.as_ref(),
        &config.import_id,
        &config.object_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&chain)?);
    Ok(())
}

async fn show_snapshot_facts(config: ShowFactsConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let facts = namespace_snapshot::list_snapshot_facts(
        db.as_ref(),
        &config.import_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&facts)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ListConflictsConfig {
    namespace: Option<String>,
}

async fn list_conflicts(config: ListConflictsConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let records = federation_conflict::list_conflicts(db.as_ref(), config.namespace.as_deref())
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ShowConflictConfig {
    namespace: String,
    object_id: String,
}

async fn show_conflict(config: ShowConflictConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let record =
        federation_conflict::get_conflict(db.as_ref(), &config.namespace, &config.object_id)
            .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ResolveConflictConfig {
    namespace: String,
    object_id: String,
    claim_id: String,
    actor: String,
}

async fn resolve_conflict(config: ResolveConflictConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let record = federation_conflict::resolve_conflict(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.object_id,
        &config.claim_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct ReopenConflictConfig {
    namespace: String,
    object_id: String,
    actor: String,
}

async fn reopen_conflict(config: ReopenConflictConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let record = federation_conflict::reopen_conflict(
        db.as_ref(),
        &config.actor,
        &config.namespace,
        &config.object_id,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

fn parse_grant_namespace(args: &[String]) -> Result<GrantNamespaceConfig, String> {
    let mut peer_site_id = None;
    let mut namespace = None;
    let mut kinds = Vec::new();
    let mut max_classification = None;
    let mut not_before_ms = 0;
    let mut not_after_ms = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--peer-site-id" => {
                peer_site_id = Some(require_value(args, i, "--peer-site-id")?);
                i += 2;
            }
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--kind" => {
                kinds.push(require_value(args, i, "--kind")?);
                i += 2;
            }
            "--max-classification" => {
                max_classification = Some(require_value(args, i, "--max-classification")?);
                i += 2;
            }
            "--not-before-ms" => {
                not_before_ms = parse_i64(&require_value(args, i, "--not-before-ms")?)?;
                i += 2;
            }
            "--not-after-ms" => {
                not_after_ms = Some(parse_i64(&require_value(args, i, "--not-after-ms")?)?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown grant-namespace option {other}")),
        }
    }
    Ok(GrantNamespaceConfig {
        peer_site_id: peer_site_id.ok_or("--peer-site-id is required")?,
        namespace: namespace.ok_or("--namespace is required")?,
        kinds,
        max_classification,
        not_before_ms,
        not_after_ms,
        actor,
    })
}

fn parse_revoke_grant(args: &[String]) -> Result<RevokeGrantConfig, String> {
    let mut grant_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--grant-id" => {
                grant_id = Some(require_value(args, i, "--grant-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown revoke-namespace-grant option {other}")),
        }
    }
    Ok(RevokeGrantConfig {
        grant_id: grant_id.ok_or("--grant-id is required")?,
        actor,
    })
}

fn parse_list_grants(args: &[String]) -> Result<ListGrantsConfig, String> {
    let mut namespace = None;
    let mut peer_site_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--peer-site-id" => {
                peer_site_id = Some(require_value(args, i, "--peer-site-id")?);
                i += 2;
            }
            other => return Err(format!("unknown list-namespace-grants option {other}")),
        }
    }
    Ok(ListGrantsConfig {
        namespace,
        peer_site_id,
    })
}

fn parse_export_snapshot(args: &[String]) -> Result<ExportSnapshotConfig, String> {
    let mut namespace = None;
    let mut output = None;
    let mut signing_key = None;
    let mut pack_id = None;
    let mut pack_version = None;
    let mut pack_digest = None;
    let mut kinds = Vec::new();
    let mut actor = "operator".to_string();
    let mut not_before_ms = 0;
    let mut not_after_ms = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--output" => {
                output = Some(PathBuf::from(require_value(args, i, "--output")?));
                i += 2;
            }
            "--signing-key" => {
                signing_key = Some(PathBuf::from(require_value(args, i, "--signing-key")?));
                i += 2;
            }
            "--pack-id" => {
                pack_id = Some(require_value(args, i, "--pack-id")?);
                i += 2;
            }
            "--pack-version" => {
                pack_version = Some(require_value(args, i, "--pack-version")?);
                i += 2;
            }
            "--pack-digest" => {
                pack_digest = Some(require_value(args, i, "--pack-digest")?);
                i += 2;
            }
            "--kind" => {
                kinds.push(require_value(args, i, "--kind")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            "--not-before-ms" => {
                not_before_ms = parse_i64(&require_value(args, i, "--not-before-ms")?)?;
                i += 2;
            }
            "--not-after-ms" => {
                not_after_ms = Some(parse_i64(&require_value(args, i, "--not-after-ms")?)?);
                i += 2;
            }
            other => return Err(format!("unknown export-snapshot option {other}")),
        }
    }
    Ok(ExportSnapshotConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        output: output.ok_or("--output is required")?,
        signing_key: signing_key.ok_or("--signing-key is required")?,
        pack: PolicyPackPin {
            pack_id: pack_id.ok_or("--pack-id is required")?,
            version: pack_version.ok_or("--pack-version is required")?,
            content_digest: pack_digest.ok_or("--pack-digest is required")?,
        },
        kinds,
        actor,
        not_before_ms,
        not_after_ms,
    })
}

fn parse_import_snapshot(args: &[String]) -> Result<ImportSnapshotConfig, String> {
    let mut namespace = None;
    let mut bundle = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--bundle" => {
                bundle = Some(PathBuf::from(require_value(args, i, "--bundle")?));
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown import-snapshot option {other}")),
        }
    }
    Ok(ImportSnapshotConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        bundle: bundle.ok_or("--bundle is required")?,
        actor,
    })
}

fn parse_list_imports(args: &[String]) -> Result<ListImportsConfig, String> {
    let mut namespace = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            other => return Err(format!("unknown list-snapshot-imports option {other}")),
        }
    }
    Ok(ListImportsConfig { namespace })
}

fn parse_show_facts(args: &[String]) -> Result<ShowFactsConfig, String> {
    let mut import_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--import-id" => {
                import_id = Some(require_value(args, i, "--import-id")?);
                i += 2;
            }
            other => return Err(format!("unknown show-snapshot-facts option {other}")),
        }
    }
    Ok(ShowFactsConfig {
        import_id: import_id.ok_or("--import-id is required")?,
    })
}

fn parse_show_provenance(args: &[String]) -> Result<ShowProvenanceConfig, String> {
    let mut import_id = None;
    let mut object_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--import-id" => {
                import_id = Some(require_value(args, i, "--import-id")?);
                i += 2;
            }
            "--object-id" => {
                object_id = Some(require_value(args, i, "--object-id")?);
                i += 2;
            }
            other => return Err(format!("unknown show-snapshot-provenance option {other}")),
        }
    }
    Ok(ShowProvenanceConfig {
        import_id: import_id.ok_or("--import-id is required")?,
        object_id: object_id.ok_or("--object-id is required")?,
    })
}

fn parse_list_conflicts(args: &[String]) -> Result<ListConflictsConfig, String> {
    let mut namespace = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            other => return Err(format!("unknown list-conflicts option {other}")),
        }
    }
    Ok(ListConflictsConfig { namespace })
}

fn parse_show_conflict(args: &[String]) -> Result<ShowConflictConfig, String> {
    let mut namespace = None;
    let mut object_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--object-id" => {
                object_id = Some(require_value(args, i, "--object-id")?);
                i += 2;
            }
            other => return Err(format!("unknown show-conflict option {other}")),
        }
    }
    Ok(ShowConflictConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        object_id: object_id.ok_or("--object-id is required")?,
    })
}

fn parse_resolve_conflict(args: &[String]) -> Result<ResolveConflictConfig, String> {
    let mut namespace = None;
    let mut object_id = None;
    let mut claim_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--object-id" => {
                object_id = Some(require_value(args, i, "--object-id")?);
                i += 2;
            }
            "--claim-id" => {
                claim_id = Some(require_value(args, i, "--claim-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown resolve-conflict option {other}")),
        }
    }
    Ok(ResolveConflictConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        object_id: object_id.ok_or("--object-id is required")?,
        claim_id: claim_id.ok_or("--claim-id is required")?,
        actor,
    })
}

fn parse_reopen_conflict(args: &[String]) -> Result<ReopenConflictConfig, String> {
    let mut namespace = None;
    let mut object_id = None;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--object-id" => {
                object_id = Some(require_value(args, i, "--object-id")?);
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown reopen-conflict option {other}")),
        }
    }
    Ok(ReopenConflictConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        object_id: object_id.ok_or("--object-id is required")?,
        actor,
    })
}

fn parse_i64(value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|error| format!("invalid integer {value}: {error}"))
}

fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let seed = if bytes.len() == 32 {
        bytes
    } else {
        decode_hex(String::from_utf8_lossy(&bytes).trim())?
    };
    let array: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "signing key must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&array))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&trimmed[index..index + 2], 16)
                .map_err(|error| format!("invalid hex: {error}"))
        })
        .collect()
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}
