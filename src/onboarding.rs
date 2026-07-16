use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::sekai::SekaiDb;
use crate::gateway_keys::hash_gateway_key;

pub const DEFAULT_STATE_DIR: &str = "./data";
pub const DEFAULT_CREDENTIAL_PATH: &str = "./data/local-credential.json";
const LOCAL_PRINCIPAL: &str = "local-onboarding";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCredential {
    pub principal: String,
    pub token: String,
    pub database: String,
    pub socket: String,
}

pub fn ensure_local_credential(
    db_path: &str,
    socket: &str,
    credential_path: &Path,
) -> Result<LocalCredential, String> {
    let db = SekaiDb::new(db_path).map_err(|error| format!("initialize database: {error}"))?;
    let database_identity = canonical_path(db_path)?;
    if credential_path.exists() {
        let credential: LocalCredential = serde_json::from_slice(
            &std::fs::read(credential_path)
                .map_err(|error| format!("read {}: {error}", credential_path.display()))?,
        )
        .map_err(|error| format!("parse {}: {error}", credential_path.display()))?;
        if credential.database != database_identity || credential.socket != socket {
            return Err(format!(
                "{} belongs to a different local state directory; remove it or pass matching --database and --socket values",
                credential_path.display()
            ));
        }
        if db
            .get_principal_credential(&hash_gateway_key(&credential.token))?
            .is_some_and(|record| record.principal == LOCAL_PRINCIPAL)
        {
            return Ok(credential);
        }
        let replacement = new_local_credential(&database_identity, socket);
        if db
            .list_credentials(Some(LOCAL_PRINCIPAL), Some("active"))?
            .is_empty()
        {
            db.create_principal_credential(
                LOCAL_PRINCIPAL,
                &hash_gateway_key(&replacement.token),
                chrono::Utc::now().timestamp_millis(),
            )?;
        } else {
            db.rotate_principal_credential(LOCAL_PRINCIPAL, &hash_gateway_key(&replacement.token))?;
        }
        std::fs::remove_file(credential_path)
            .map_err(|error| format!("replace {}: {error}", credential_path.display()))?;
        write_private_json(credential_path, &replacement)?;
        return Ok(replacement);
    }

    let credential = new_local_credential(&database_identity, socket);
    if db
        .list_credentials(Some(LOCAL_PRINCIPAL), Some("active"))?
        .is_empty()
    {
        db.create_principal_credential(
            LOCAL_PRINCIPAL,
            &hash_gateway_key(&credential.token),
            chrono::Utc::now().timestamp_millis(),
        )?;
    } else {
        db.rotate_principal_credential(LOCAL_PRINCIPAL, &hash_gateway_key(&credential.token))?;
    }
    write_private_json(credential_path, &credential)?;
    Ok(credential)
}

fn new_local_credential(db_path: &str, socket: &str) -> LocalCredential {
    LocalCredential {
        principal: LOCAL_PRINCIPAL.into(),
        token: format!(
            "sekai_{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        ),
        database: db_path.into(),
        socket: socket.into(),
    }
}

pub fn default_credential_path() -> PathBuf {
    std::env::var_os("CHISEI_LOCAL_CREDENTIAL_FILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CREDENTIAL_PATH))
}

pub fn load_local_credential() -> Option<LocalCredential> {
    let path = default_credential_path();
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn canonical_path(path: &str) -> Result<String, String> {
    std::fs::canonicalize(path)
        .map_err(|error| format!("resolve database path {path:?}: {error}"))?
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("database path {path:?} is not valid UTF-8"))
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        file.write_all(&bytes)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reuses_private_local_credential() {
        let root = std::env::temp_dir().join(format!("chisei-onboarding-{}", Uuid::new_v4()));
        let db = root.join("sekai.db");
        let credential_path = root.join("credential.json");
        let first =
            ensure_local_credential(db.to_str().unwrap(), "./data/sekai.sock", &credential_path)
                .unwrap();
        let second =
            ensure_local_credential(db.to_str().unwrap(), "./data/sekai.sock", &credential_path)
                .unwrap();
        assert_eq!(first.token, second.token);
        assert_eq!(first.principal, LOCAL_PRINCIPAL);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&credential_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replaces_a_revoked_local_credential() {
        let root = std::env::temp_dir().join(format!("chisei-onboarding-{}", Uuid::new_v4()));
        let db_path = root.join("sekai.db");
        let credential_path = root.join("credential.json");
        let first = ensure_local_credential(
            db_path.to_str().unwrap(),
            "./data/sekai.sock",
            &credential_path,
        )
        .unwrap();
        let db = SekaiDb::new(db_path.to_str().unwrap()).unwrap();
        db.revoke_principal_credential(LOCAL_PRINCIPAL).unwrap();
        let second = ensure_local_credential(
            db_path.to_str().unwrap(),
            "./data/sekai.sock",
            &credential_path,
        )
        .unwrap();
        assert_ne!(first.token, second.token);
        assert!(
            db.get_principal_credential(&hash_gateway_key(&second.token))
                .unwrap()
                .is_some()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
