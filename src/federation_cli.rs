//! sekaictl federation profile commands (#291).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::federation_profile::{
    self, JoinPeerRequest, LocalSiteIdentity, PeerHealth, PolicyPackPin, TRUST_ROOT_NAMESPACE,
};
use crate::sekai::peer_import::PeerTrustRoot;
use chrono::Utc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl federation register-site --site-id <id> --key-id <id> --public-key-hex <hex> [--region <label>] [--data-class <class>]... [--actor <principal>]\n  sekaictl federation show-site\n  sekaictl federation pin-trust-root --site-identity <id> --key-id <id> --public-key-hex <hex> [--namespace <ns>] [--actor <principal>]\n  sekaictl federation join --peer-site-id <id> --peer-key-id <id> --peer-public-key-hex <hex> --pack-id <id> --pack-version <ver> --pack-digest <digest> [--region <label>] [--data-class <class>]... [--trust-namespace <ns>] [--actor <principal>]\n  sekaictl federation leave --peer-site-id <id> [--actor <principal>]\n  sekaictl federation set-health --peer-site-id <id> --health up|down|unknown\n  sekaictl federation set-pack-pin --peer-site-id <id> --pack-id <id> --pack-version <ver> --pack-digest <digest>\n  sekaictl federation list-peers\n  sekaictl federation import-availability --peer-site-id <id>"
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

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}
