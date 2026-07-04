use std::collections::HashMap;
use std::sync::{
    RwLock,
    atomic::{AtomicI64, Ordering},
};

use crate::db::sekai::{PrincipalCredential, SekaiDb};
use crate::gateway_keys::hash_gateway_key;

const CREDENTIAL_RELOAD_INTERVAL_MS: i64 = 5000;

fn in_progress_epoch(activity_epoch: i64) -> i64 {
    -(activity_epoch + 1)
}

#[derive(Debug)]
pub struct PrincipalCredentialStore {
    pub by_hash: RwLock<HashMap<String, String>>,
    pub last_reload_ms: AtomicI64,
    pub last_data_version: AtomicI64,
}

impl PrincipalCredentialStore {
    pub fn new() -> Self {
        Self {
            by_hash: RwLock::new(HashMap::new()),
            last_reload_ms: AtomicI64::new(0),
            last_data_version: AtomicI64::new(0),
        }
    }

    pub fn load(&self, credentials: &[PrincipalCredential]) {
        let mut map = self.by_hash.write().unwrap();
        map.clear();
        for credential in credentials.iter().filter(|c| c.status == "active") {
            map.insert(credential.token_hash.clone(), credential.principal.clone());
        }
    }

    pub fn load_credential(&self, credential: &PrincipalCredential) {
        let mut map = self.by_hash.write().unwrap();
        map.insert(credential.token_hash.clone(), credential.principal.clone());
    }

    pub fn remove_hash(&self, token_hash: &str) {
        self.by_hash.write().unwrap().remove(token_hash);
    }

    fn resolve_hashed(&self, token_hash: &str) -> Option<String> {
        self.by_hash
            .read()
            .unwrap()
            .get(token_hash)
            .map(std::string::ToString::to_string)
    }

    pub fn resolve(&self, token: &str) -> Option<String> {
        self.resolve_hashed(&hash_gateway_key(token))
    }

    pub fn maybe_reload(&self, db: &SekaiDb) -> bool {
        let activity_epoch = match db.principal_credentials_activity_epoch() {
            Ok(activity_epoch) => activity_epoch,
            Err(_) => return false,
        };
        let last_activity_epoch = self.last_data_version.load(Ordering::Acquire);
        if last_activity_epoch < 0 {
            return false;
        }

        let mut restore_reload_ms = None;
        if activity_epoch == last_activity_epoch {
            let now = chrono::Utc::now().timestamp_millis();
            let last = self.last_reload_ms.load(Ordering::Acquire);
            if now - last < CREDENTIAL_RELOAD_INTERVAL_MS {
                return true;
            }
            restore_reload_ms = Some(last);
        }
        if self
            .last_data_version
            .compare_exchange(
                last_activity_epoch,
                in_progress_epoch(activity_epoch),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }

        let now = chrono::Utc::now().timestamp_millis();
        let reload_result = db.list_active_credentials();
        match reload_result {
            Ok(credentials) => {
                self.load(&credentials);
                match db.principal_credentials_activity_epoch() {
                    Ok(current_activity_epoch) if current_activity_epoch == activity_epoch => {
                        self.last_data_version
                            .store(activity_epoch, Ordering::Release);
                        self.last_reload_ms.store(now, Ordering::Release);
                        true
                    }
                    _ => {
                        self.last_data_version
                            .store(last_activity_epoch, Ordering::Release);
                        false
                    }
                }
            }
            Err(_) => {
                self.last_data_version
                    .store(last_activity_epoch, Ordering::Release);
                if let Some(last) = restore_reload_ms {
                    self.last_reload_ms.store(last, Ordering::Release);
                }
                false
            }
        }
    }

    pub fn has_any(&self) -> bool {
        !self.by_hash.read().unwrap().is_empty()
    }
}

impl Default for PrincipalCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    fn fixed_time(i: i64) -> i64 {
        i * 1000
    }

    #[test]
    fn load_and_resolve_principal() {
        let db = test_db();
        let alice_token = hash_gateway_key("alice-token");
        let bob_token = hash_gateway_key("bob-token");
        db.create_principal_credential("alice", &alice_token, fixed_time(1))
            .unwrap();
        db.create_principal_credential("bob", &bob_token, fixed_time(2))
            .unwrap();
        let credentials = db.list_active_credentials().unwrap();
        let store = PrincipalCredentialStore::new();
        store.load(&credentials);

        assert_eq!(store.resolve("alice-token"), Some("alice".to_string()));
        assert_eq!(store.resolve("bob-token"), Some("bob".to_string()));
    }

    #[test]
    fn maybe_reload_picks_up_new_records() {
        let db = test_db();
        let store = PrincipalCredentialStore::new();
        let token = hash_gateway_key("token-alice");
        db.create_principal_credential("alice", &token, fixed_time(3))
            .unwrap();
        assert!(store.resolve("token-alice").is_none());
        store.maybe_reload(&db);
        assert_eq!(store.resolve("token-alice"), Some("alice".to_string()));
        assert!(store.has_any());
    }

    #[test]
    fn maybe_reload_evicts_revoked_cached_records() {
        let db = test_db();
        let store = PrincipalCredentialStore::new();
        let token = hash_gateway_key("token-alice");
        db.create_principal_credential("alice", &token, fixed_time(4))
            .unwrap();

        assert!(store.maybe_reload(&db));
        assert_eq!(store.resolve("token-alice"), Some("alice".to_string()));

        db.revoke_principal_credential("alice").unwrap();

        assert!(store.maybe_reload(&db));
        assert!(store.resolve("token-alice").is_none());
    }

    #[test]
    fn maybe_reload_does_not_advance_epoch_after_failed_reload() {
        let db = test_db();
        let store = PrincipalCredentialStore::new();

        {
            let conn = db.conn.lock().unwrap();
            conn.execute_batch(
                "DROP TABLE sekai_principal_credentials;
                CREATE TABLE sekai_principal_credentials (
                    id TEXT PRIMARY KEY,
                    principal TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    created INTEGER NOT NULL,
                    rotated_at INTEGER NOT NULL DEFAULT 0,
                    revoked_at INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO sekai_principal_credentials
                    (id, principal, token_hash, created, rotated_at, revoked_at)
                VALUES
                    ('credential-bad', 'alice', 'hash', 1000, 2000, 0);",
            )
            .unwrap();
        }

        assert!(!store.maybe_reload(&db));
        assert_eq!(store.last_data_version.load(Ordering::Acquire), 0);
    }
}
