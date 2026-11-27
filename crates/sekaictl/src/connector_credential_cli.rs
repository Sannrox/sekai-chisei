//! `sekaictl admin connector-credential`: register a fleet public key,
//! issue a handle sealed to it, and revoke one (ADR 0175).

use crypto_box::{PublicKey, SecretKey};
use sekai_admin_client::client::{GatewayClient, connect_sekai};
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{
    GetRuntimeFleetKeyRequest, IssueCredentialHandleRequest, RegisterRuntimeFleetKeyRequest,
    RevokeCredentialHandleRequest, SealedCredentialSlot,
};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    concat!(
        "Usage: sekaictl admin connector-credential register-fleet-key <key-id> --public-key-hex <hex>\n",
        "       sekaictl admin connector-credential issue <name> --key-id <id> --namespace <ns> --destination <host> --slot <name>=<value>\n",
        "       sekaictl admin connector-credential revoke <name>\n",
        "  Slot values may be literal, @path, or $ENV. Repeat --namespace, --destination, and --slot.\n",
        "  sekaictl seals each slot to the registered public key before IssueCredentialHandle."
    )
}

pub async fn run(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("register-fleet-key") => register_fleet_key(&args[1..]).await,
        Some("issue") => issue(&args[1..]).await,
        Some("revoke") => revoke(&args[1..]).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

fn target() -> String {
    std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".to_string())
}

async fn client() -> Result<SekaiServiceClient<GatewayClient>, BoxErr> {
    Ok(SekaiServiceClient::new(connect_sekai(&target()).await?))
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, BoxErr> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(std::io::Error::other("hex must have even length").into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| std::io::Error::other("value is not hex"))
        })
        .map(|byte| byte.map_err(BoxErr::from))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn take_value<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, BoxErr> {
    args.get(i + 1)
        .filter(|value| !value.starts_with("--"))
        .map(String::as_str)
        .ok_or_else(|| std::io::Error::other(format!("{flag} requires a value")).into())
}

fn seal(public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BoxErr> {
    let bytes: [u8; 32] = public
        .try_into()
        .map_err(|_| std::io::Error::other("public key must be 32 bytes"))?;
    PublicKey::from(bytes)
        .seal(&mut crypto_box::aead::OsRng, plaintext)
        .map_err(|_| std::io::Error::other("failed to seal slot"))
        .map_err(BoxErr::from)
}

fn slot_value(raw: &str) -> Result<Vec<u8>, BoxErr> {
    if let Some(path) = raw.strip_prefix('@') {
        let mut text = std::fs::read_to_string(path)?;
        if text.ends_with('\n') {
            text.pop();
        }
        return Ok(text.into_bytes());
    }
    if let Some(name) = raw.strip_prefix('$') {
        return Ok(std::env::var(name)
            .map_err(|_| std::io::Error::other(format!("environment {name} is unset")))?
            .into_bytes());
    }
    Ok(raw.as_bytes().to_vec())
}

async fn register_fleet_key(args: &[String]) -> Result<(), BoxErr> {
    let mut key_id = None;
    let mut public_hex = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--public-key-hex" => {
                public_hex = Some(take_value(args, i, "--public-key-hex")?);
                i += 2;
            }
            flag if flag.starts_with("--") => {
                return Err(std::io::Error::other(format!("unknown argument {flag}")).into());
            }
            value if key_id.is_none() => {
                key_id = Some(value);
                i += 1;
            }
            other => return Err(std::io::Error::other(format!("unexpected {other}")).into()),
        }
    }
    let key_id = key_id.ok_or_else(|| std::io::Error::other(usage()))?;
    let public_key = match public_hex {
        Some(hex) => hex_decode(hex)?,
        None => {
            let secret = std::env::var("SEKAI_RUNTIME_FLEET_KEY").map_err(|_| {
                std::io::Error::other("--public-key-hex or SEKAI_RUNTIME_FLEET_KEY")
            })?;
            let bytes = hex_decode(&secret)?;
            let secret: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| std::io::Error::other("fleet key must be 32 bytes"))?;
            SecretKey::from(secret).public_key().as_bytes().to_vec()
        }
    };
    let response = client()
        .await?
        .register_runtime_fleet_key(RegisterRuntimeFleetKeyRequest {
            key_id: key_id.to_string(),
            public_key,
        })
        .await?
        .into_inner();
    let key = response
        .key
        .ok_or_else(|| std::io::Error::other("plane returned no fleet key"))?;
    println!("{}\t{}", key.key_id, hex_encode(&key.public_key));
    Ok(())
}

async fn issue(args: &[String]) -> Result<(), BoxErr> {
    let mut name = None;
    let mut key_id = None;
    let mut namespaces = Vec::new();
    let mut destinations = Vec::new();
    let mut slots = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key-id" => {
                key_id = Some(take_value(args, i, "--key-id")?);
                i += 2;
            }
            "--namespace" => {
                namespaces.push(take_value(args, i, "--namespace")?.to_string());
                i += 2;
            }
            "--destination" => {
                destinations.push(take_value(args, i, "--destination")?.to_string());
                i += 2;
            }
            "--slot" => {
                slots.push(take_value(args, i, "--slot")?.to_string());
                i += 2;
            }
            flag if flag.starts_with("--") => {
                return Err(std::io::Error::other(format!("unknown argument {flag}")).into());
            }
            value if name.is_none() => {
                name = Some(value);
                i += 1;
            }
            other => return Err(std::io::Error::other(format!("unexpected {other}")).into()),
        }
    }
    let name = name.ok_or_else(|| std::io::Error::other(usage()))?;
    let key_id = key_id.ok_or_else(|| std::io::Error::other("--key-id is required"))?;
    if namespaces.is_empty() || destinations.is_empty() || slots.is_empty() {
        return Err(
            std::io::Error::other("--namespace, --destination, and --slot are required").into(),
        );
    }
    let public = client()
        .await?
        .get_runtime_fleet_key(GetRuntimeFleetKeyRequest {
            key_id: key_id.to_string(),
        })
        .await?
        .into_inner()
        .key
        .ok_or_else(|| std::io::Error::other("fleet key not found"))?
        .public_key;
    let mut sealed = Vec::new();
    for spec in slots {
        let (slot_name, raw) = spec.split_once('=').ok_or_else(|| {
            std::io::Error::other("--slot requires name=value, name=@path, or name=$ENV")
        })?;
        sealed.push(SealedCredentialSlot {
            name: slot_name.to_string(),
            fleet_key_id: key_id.to_string(),
            ciphertext: seal(&public, &slot_value(raw)?)?,
        });
    }
    let response = client()
        .await?
        .issue_credential_handle(IssueCredentialHandleRequest {
            name: name.to_string(),
            namespaces,
            destinations,
            slots: sealed,
        })
        .await?
        .into_inner();
    println!("{}\t{}", response.name, response.content_digest);
    Ok(())
}

async fn revoke(args: &[String]) -> Result<(), BoxErr> {
    let name = args
        .first()
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| std::io::Error::other(usage()))?;
    if args.len() != 1 {
        return Err(std::io::Error::other("unexpected trailing arguments").into());
    }
    client()
        .await?
        .revoke_credential_handle(RevokeCredentialHandleRequest {
            name: name.to_string(),
        })
        .await?;
    println!("{name}\trevoked");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_values_read_literal_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "from-file\n").unwrap();
        assert_eq!(slot_value("literal").unwrap(), b"literal");
        assert_eq!(
            slot_value(&format!("@{}", path.display())).unwrap(),
            b"from-file"
        );
    }
}
