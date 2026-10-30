//! Dual-backend community-store dispatch for federation.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn put_peer_trust_root(
        &self,
        root: &crate::sekai::peer_import::PeerTrustRoot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_peer_trust_root(root),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_peer_trust_root(root)),
        }
    }

    pub fn list_peer_trust_roots(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::peer_import::PeerTrustRoot>, String> {
        match self {
            Self::Sqlite(db) => db.list_peer_trust_roots(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_peer_trust_roots(namespace))
            }
        }
    }

    pub fn put_peer_import(
        &self,
        record: &crate::sekai::peer_import::PeerImportRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_peer_import(record),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_peer_import(record)),
        }
    }

    pub fn get_peer_import(
        &self,
        import_id: &str,
    ) -> Result<Option<crate::sekai::peer_import::PeerImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_peer_import(import_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_peer_import(import_id))
            }
        }
    }

    pub fn put_federation_local_site(
        &self,
        site: &crate::sekai::federation_profile::LocalSiteIdentity,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_local_site(site),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_local_site(site))
            }
        }
    }

    pub fn get_federation_local_site(
        &self,
    ) -> Result<Option<crate::sekai::federation_profile::LocalSiteIdentity>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_local_site(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_local_site())
            }
        }
    }

    pub fn put_federation_peer(
        &self,
        peer: &crate::sekai::federation_profile::FederationPeer,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_peer(peer),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_federation_peer(peer)),
        }
    }

    pub fn get_federation_peer(
        &self,
        peer_site_id: &str,
    ) -> Result<Option<crate::sekai::federation_profile::FederationPeer>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_peer(peer_site_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_peer(peer_site_id))
            }
        }
    }

    pub fn list_federation_peers(
        &self,
    ) -> Result<Vec<crate::sekai::federation_profile::FederationPeer>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_peers(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_federation_peers()),
        }
    }

    pub fn put_federation_namespace_grant(
        &self,
        grant: &crate::sekai::namespace_snapshot::PeerNamespaceGrant,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_namespace_grant(grant),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_namespace_grant(grant))
            }
        }
    }

    pub fn get_federation_namespace_grant(
        &self,
        grant_id: &str,
    ) -> Result<Option<crate::sekai::namespace_snapshot::PeerNamespaceGrant>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_namespace_grant(grant_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_namespace_grant(grant_id))
            }
        }
    }

    pub fn list_federation_namespace_grants(
        &self,
        namespace: Option<&str>,
        peer_site_id: Option<&str>,
    ) -> Result<Vec<crate::sekai::namespace_snapshot::PeerNamespaceGrant>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_namespace_grants(namespace, peer_site_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_federation_namespace_grants(namespace, peer_site_id)
            }),
        }
    }

    pub fn reserve_federation_snapshot_sequence(&self, namespace: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.reserve_federation_snapshot_sequence(namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reserve_federation_snapshot_sequence(namespace)
            }),
        }
    }

    pub fn put_federation_snapshot_export(
        &self,
        export: &crate::sekai::namespace_snapshot::SnapshotExportRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_snapshot_export(export),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_snapshot_export(export))
            }
        }
    }

    pub fn put_federation_snapshot_import(
        &self,
        record: &crate::sekai::namespace_snapshot::SnapshotImportRecord,
        facts: &[crate::sekai::namespace_snapshot::SnapshotFact],
        conflicts: &[crate::sekai::federation_conflict::FederationConflict],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_snapshot_import(record, facts, conflicts),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_federation_snapshot_import(record, facts, conflicts)
            }),
        }
    }

    pub fn get_federation_snapshot_import(
        &self,
        import_id: &str,
    ) -> Result<Option<crate::sekai::namespace_snapshot::SnapshotImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_snapshot_import(import_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_snapshot_import(import_id))
            }
        }
    }

    pub fn latest_federation_snapshot_import(
        &self,
        peer_site_id: &str,
        namespace: &str,
    ) -> Result<Option<crate::sekai::namespace_snapshot::SnapshotImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.latest_federation_snapshot_import(peer_site_id, namespace),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.latest_federation_snapshot_import(peer_site_id, namespace)
            }),
        }
    }

    pub fn list_federation_snapshot_imports(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::sekai::namespace_snapshot::SnapshotImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_snapshot_imports(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_federation_snapshot_imports(namespace))
            }
        }
    }

    pub fn list_federation_snapshot_facts(
        &self,
        import_id: &str,
    ) -> Result<Vec<crate::sekai::namespace_snapshot::SnapshotFact>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_snapshot_facts(import_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_federation_snapshot_facts(import_id))
            }
        }
    }

    pub fn put_federation_conflict(
        &self,
        record: &crate::sekai::federation_conflict::FederationConflict,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_conflict(record),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_conflict(record))
            }
        }
    }

    pub fn get_federation_conflict(
        &self,
        conflict_id: &str,
    ) -> Result<Option<crate::sekai::federation_conflict::FederationConflict>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_conflict(conflict_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_conflict(conflict_id))
            }
        }
    }

    pub fn list_federation_conflicts(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<crate::sekai::federation_conflict::FederationConflict>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_conflicts(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_federation_conflicts(namespace))
            }
        }
    }

    pub fn put_federation_revocation(
        &self,
        record: &crate::sekai::federation_revocation::FederationRevocation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_revocation(record),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_federation_revocation(record))
            }
        }
    }

    pub fn get_network_contract(
        &self,
        namespace: &str,
        contract_id: &str,
    ) -> Result<Option<crate::sekai::federation_network::NetworkContract>, String> {
        match self {
            Self::Sqlite(db) => db.get_network_contract(namespace, contract_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_network_contract(namespace, contract_id))
            }
        }
    }

    pub fn put_network_contract(
        &self,
        contract: &crate::sekai::federation_network::NetworkContract,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_network_contract(contract),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_network_contract(contract))
            }
        }
    }

    pub fn cas_network_contract(
        &self,
        expected: &crate::sekai::federation_network::NetworkContract,
        next: &crate::sekai::federation_network::NetworkContract,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.cas_network_contract(expected, next),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.cas_network_contract(expected, next))
            }
        }
    }

    pub fn get_network_exchange(
        &self,
        namespace: &str,
        contract_id: &str,
        exchange_id: &str,
    ) -> Result<Option<crate::sekai::federation_network::NetworkExchange>, String> {
        match self {
            Self::Sqlite(db) => db.get_network_exchange(namespace, contract_id, exchange_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_network_exchange(namespace, contract_id, exchange_id)
            }),
        }
    }

    pub fn put_network_exchange(
        &self,
        item: &crate::sekai::federation_network::NetworkExchange,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_network_exchange(item),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_network_exchange(item))
            }
        }
    }

    pub fn get_federation_revocation(
        &self,
        revocation_id: &str,
    ) -> Result<Option<crate::sekai::federation_revocation::FederationRevocation>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_revocation(revocation_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_federation_revocation(revocation_id))
            }
        }
    }

    pub fn list_federation_revocations(
        &self,
        subject_kind: Option<&str>,
    ) -> Result<Vec<crate::sekai::federation_revocation::FederationRevocation>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_revocations(subject_kind),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_federation_revocations(subject_kind))
            }
        }
    }
}
