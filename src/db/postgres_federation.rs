//! PostgreSQL persistence for federation network, profile, conflict,
//! revocation, snapshot, grant, and peer-import stores (#1475, #1476).

use crate::db::postgres::PostgresDb;
use crate::sekai::federation_conflict::FederationConflict;
use crate::sekai::federation_network::{
    NETWORK_UNAVAILABLE, NetworkContract, NetworkExchange, PEER_LOST, STATUS_ACCEPTED,
    STATUS_DISCONNECTED,
};
use crate::sekai::federation_profile::{FederationPeer, LocalSiteIdentity};
use crate::sekai::federation_revocation::FederationRevocation;
use crate::sekai::namespace_snapshot::{
    PeerNamespaceGrant, SnapshotExportRecord, SnapshotFact, SnapshotImportRecord,
};
use crate::sekai::peer_import::{PeerImportRecord, PeerTrustRoot};

impl PostgresDb {
    pub fn put_federation_local_site(&self, site: &LocalSiteIdentity) -> Result<(), String> {
        let classes = serde_json::to_string(&site.residency_data_classes)
            .map_err(|error| format!("encode residency data classes: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_local_site
                    (site_id, key_id, public_key_hex, region, residency_data_classes_json,
                     registered_by, registered_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (site_id) DO UPDATE SET
                    key_id = EXCLUDED.key_id,
                    public_key_hex = EXCLUDED.public_key_hex,
                    region = EXCLUDED.region,
                    residency_data_classes_json = EXCLUDED.residency_data_classes_json,
                    registered_by = EXCLUDED.registered_by,
                    registered_at_ms = EXCLUDED.registered_at_ms",
                &[
                    &site.site_id,
                    &site.key_id,
                    &site.public_key_hex,
                    &site.region,
                    &classes,
                    &site.registered_by,
                    &site.registered_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_federation_local_site(&self) -> Result<Option<LocalSiteIdentity>, String> {
        self.connection()?
            .query_opt(
                "SELECT site_id, key_id, public_key_hex, region, residency_data_classes_json,
                        registered_by, registered_at_ms
                 FROM sekai_federation_local_site
                 ORDER BY registered_at_ms ASC
                 LIMIT 1",
                &[],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let classes_json: String = row.get(4);
                let residency_data_classes: Vec<String> = serde_json::from_str(&classes_json)
                    .map_err(|error| format!("decode residency data classes: {error}"))?;
                Ok(LocalSiteIdentity {
                    site_id: row.get(0),
                    key_id: row.get(1),
                    public_key_hex: row.get(2),
                    region: row.get(3),
                    residency_data_classes,
                    registered_by: row.get(5),
                    registered_at_ms: row.get(6),
                })
            })
            .transpose()
    }

    pub fn put_federation_peer(&self, peer: &FederationPeer) -> Result<(), String> {
        let json = serde_json::to_string(peer)
            .map_err(|error| format!("encode federation peer: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_peers
                    (local_site_id, peer_site_id, record_json, membership, health, joined_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (local_site_id, peer_site_id) DO UPDATE SET
                    record_json = EXCLUDED.record_json,
                    membership = EXCLUDED.membership,
                    health = EXCLUDED.health,
                    joined_at_ms = EXCLUDED.joined_at_ms",
                &[
                    &peer.local_site_id,
                    &peer.peer_site_id,
                    &json,
                    &peer.membership.as_str(),
                    &peer.health.as_str(),
                    &peer.joined_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_federation_peer(
        &self,
        peer_site_id: &str,
    ) -> Result<Option<FederationPeer>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_peers WHERE peer_site_id = $1 LIMIT 1",
                &[&peer_site_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_peer(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_federation_peers(&self) -> Result<Vec<FederationPeer>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_federation_peers ORDER BY peer_site_id",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_peer(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn put_federation_conflict(&self, record: &FederationConflict) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode federation conflict: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_conflicts
                    (conflict_id, namespace, object_id, status, record_json, updated_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (conflict_id) DO UPDATE SET
                    namespace = EXCLUDED.namespace,
                    object_id = EXCLUDED.object_id,
                    status = EXCLUDED.status,
                    record_json = EXCLUDED.record_json,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[
                    &record.conflict_id,
                    &record.namespace,
                    &record.object_id,
                    &record.status,
                    &json,
                    &record.updated_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_federation_conflict(
        &self,
        conflict_id: &str,
    ) -> Result<Option<FederationConflict>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_conflicts WHERE conflict_id = $1",
                &[&conflict_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_conflict(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_federation_conflicts(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<FederationConflict>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_federation_conflicts
                 WHERE ($1::text IS NULL OR namespace = $1)
                 ORDER BY updated_at_ms ASC, object_id ASC",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_conflict(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn put_federation_revocation(&self, record: &FederationRevocation) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode federation revocation: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_revocations
                    (revocation_id, subject_kind, subject_id, status, record_json, updated_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (revocation_id) DO UPDATE SET
                    subject_kind = EXCLUDED.subject_kind,
                    subject_id = EXCLUDED.subject_id,
                    status = EXCLUDED.status,
                    record_json = EXCLUDED.record_json,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[
                    &record.revocation_id,
                    &record.subject_kind.as_str(),
                    &record.subject_id,
                    &record.status,
                    &json,
                    &record.updated_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_federation_revocation(
        &self,
        revocation_id: &str,
    ) -> Result<Option<FederationRevocation>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_revocations WHERE revocation_id = $1",
                &[&revocation_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_revocation(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_federation_revocations(
        &self,
        subject_kind: Option<&str>,
    ) -> Result<Vec<FederationRevocation>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_federation_revocations
                 WHERE ($1::text IS NULL OR subject_kind = $1)
                 ORDER BY updated_at_ms ASC, subject_id ASC",
                &[&subject_kind],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_revocation(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn get_network_contract(
        &self,
        namespace: &str,
        contract_id: &str,
    ) -> Result<Option<NetworkContract>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_network_contracts
                 WHERE namespace = $1 AND contract_id = $2",
                &[&namespace, &contract_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_contract(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn put_network_contract(&self, contract: &NetworkContract) -> Result<(), String> {
        let json = serde_json::to_string(contract)
            .map_err(|error| format!("encode federation network: {error}"))?;
        let changed = self
            .connection()?
            .execute(
                "INSERT INTO sekai_federation_network_contracts
                    (namespace, contract_id, owner, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, contract_id) DO NOTHING",
                &[
                    &contract.namespace,
                    &contract.contract_id,
                    &contract.owner,
                    &json,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        Ok(())
    }

    pub fn cas_network_contract(
        &self,
        expected: &NetworkContract,
        next: &NetworkContract,
    ) -> Result<(), String> {
        if expected.namespace != next.namespace
            || expected.contract_id != next.contract_id
            || expected.owner != next.owner
        {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode federation network: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_opt(
                "SELECT record_json FROM sekai_federation_network_contracts
                 WHERE namespace = $1 AND contract_id = $2 FOR UPDATE",
                &[&expected.namespace, &expected.contract_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_contract(&row.get::<_, String>(0)))
            .transpose()?
            .ok_or(NETWORK_UNAVAILABLE)?;
        if current != *expected {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_federation_network_contracts
                 SET record_json = $1
                 WHERE namespace = $2 AND contract_id = $3 AND owner = $4",
                &[&next_json, &next.namespace, &next.contract_id, &next.owner],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_network_exchange(
        &self,
        namespace: &str,
        contract_id: &str,
        exchange_id: &str,
    ) -> Result<Option<NetworkExchange>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_network_exchanges
                 WHERE namespace = $1 AND contract_id = $2 AND exchange_id = $3",
                &[&namespace, &contract_id, &exchange_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_exchange(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn put_network_exchange(&self, item: &NetworkExchange) -> Result<(), String> {
        let json = serde_json::to_string(item)
            .map_err(|error| format!("encode federation exchange: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let parent = tx
            .query_opt(
                "SELECT record_json FROM sekai_federation_network_contracts
                 WHERE namespace = $1 AND contract_id = $2 FOR UPDATE",
                &[&item.namespace, &item.contract_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_contract(&row.get::<_, String>(0)))
            .transpose()?
            .ok_or(NETWORK_UNAVAILABLE)?;
        if parent.status != STATUS_ACCEPTED {
            return Err(if parent.status == STATUS_DISCONNECTED {
                PEER_LOST.into()
            } else {
                NETWORK_UNAVAILABLE.into()
            });
        }
        let changed = tx
            .execute(
                "INSERT INTO sekai_federation_network_exchanges
                    (namespace, contract_id, exchange_id, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, contract_id, exchange_id) DO NOTHING",
                &[&item.namespace, &item.contract_id, &item.exchange_id, &json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(NETWORK_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn put_peer_trust_root(&self, root: &PeerTrustRoot) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_peer_trust_roots
                    (namespace, site_identity, key_id, public_key_hex, enabled, created_by, created_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (namespace, site_identity, key_id) DO UPDATE SET
                    public_key_hex = EXCLUDED.public_key_hex,
                    enabled = EXCLUDED.enabled,
                    created_by = EXCLUDED.created_by,
                    created_at_ms = EXCLUDED.created_at_ms",
                &[
                    &root.namespace,
                    &root.site_identity,
                    &root.key_id,
                    &root.public_key_hex,
                    &root.enabled,
                    &root.created_by,
                    &root.created_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_peer_trust_roots(&self, namespace: &str) -> Result<Vec<PeerTrustRoot>, String> {
        self.connection()?
            .query(
                "SELECT namespace, site_identity, key_id, public_key_hex, enabled, created_by, created_at_ms
                 FROM sekai_peer_trust_roots
                 WHERE namespace = $1
                 ORDER BY site_identity, key_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| {
                Ok(PeerTrustRoot {
                    namespace: row.get(0),
                    site_identity: row.get(1),
                    key_id: row.get(2),
                    public_key_hex: row.get(3),
                    enabled: row.get(4),
                    created_by: row.get(5),
                    created_at_ms: row.get(6),
                })
            })
            .collect()
    }

    pub fn put_peer_import(&self, record: &PeerImportRecord) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode peer import: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_peer_imports (import_id, namespace, record_json, imported_at_ms)
                 VALUES ($1, $2, $3, $4)",
                &[
                    &record.import_id,
                    &record.namespace,
                    &json,
                    &record.imported_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_peer_import(&self, import_id: &str) -> Result<Option<PeerImportRecord>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_peer_imports WHERE import_id = $1",
                &[&import_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_peer_import(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn put_federation_namespace_grant(&self, grant: &PeerNamespaceGrant) -> Result<(), String> {
        let json = serde_json::to_string(grant)
            .map_err(|error| format!("encode namespace grant: {error}"))?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_namespace_grants
                    (grant_id, peer_site_id, namespace, record_json, revoked, granted_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (grant_id) DO UPDATE SET
                    peer_site_id = EXCLUDED.peer_site_id,
                    namespace = EXCLUDED.namespace,
                    record_json = EXCLUDED.record_json,
                    revoked = EXCLUDED.revoked,
                    granted_at_ms = EXCLUDED.granted_at_ms",
                &[
                    &grant.grant_id,
                    &grant.peer_site_id,
                    &grant.namespace,
                    &json,
                    &grant.revoked,
                    &grant.granted_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_federation_namespace_grant(
        &self,
        grant_id: &str,
    ) -> Result<Option<PeerNamespaceGrant>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_namespace_grants WHERE grant_id = $1",
                &[&grant_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_grant(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_federation_namespace_grants(
        &self,
        namespace: Option<&str>,
        peer_site_id: Option<&str>,
    ) -> Result<Vec<PeerNamespaceGrant>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_federation_namespace_grants
                 WHERE ($1::text IS NULL OR namespace = $1)
                   AND ($2::text IS NULL OR peer_site_id = $2)
                 ORDER BY granted_at_ms ASC, grant_id ASC",
                &[&namespace, &peer_site_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_grant(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn reserve_federation_snapshot_sequence(&self, namespace: &str) -> Result<u64, String> {
        let sequence: i64 = self
            .connection()?
            .query_one(
                "INSERT INTO sekai_federation_snapshot_sequences (namespace, next_sequence)
                 VALUES ($1, 1::bigint)
                 ON CONFLICT (namespace) DO UPDATE SET
                    next_sequence = sekai_federation_snapshot_sequences.next_sequence + 1
                 RETURNING next_sequence",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        Ok(sequence as u64)
    }

    pub fn put_federation_snapshot_export(
        &self,
        export: &SnapshotExportRecord,
    ) -> Result<(), String> {
        let json = serde_json::to_string(export)
            .map_err(|error| format!("encode snapshot export: {error}"))?;
        let sequence = export.sequence as i64;
        self.connection()?
            .execute(
                "INSERT INTO sekai_federation_snapshot_exports
                    (snapshot_digest, namespace, sequence, record_json, exported_at_ms)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (snapshot_digest) DO UPDATE SET
                    namespace = EXCLUDED.namespace,
                    sequence = EXCLUDED.sequence,
                    record_json = EXCLUDED.record_json,
                    exported_at_ms = EXCLUDED.exported_at_ms",
                &[
                    &export.snapshot_digest,
                    &export.namespace,
                    &sequence,
                    &json,
                    &export.exported_at_ms,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn put_federation_snapshot_import(
        &self,
        record: &SnapshotImportRecord,
        facts: &[SnapshotFact],
        conflicts: &[FederationConflict],
    ) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|error| format!("encode snapshot import: {error}"))?;
        let sequence = record.sequence as i64;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| format!("begin snapshot import: {error}"))?;
        tx.execute(
            "INSERT INTO sekai_federation_snapshot_imports
                (import_id, namespace, peer_site_id, snapshot_digest, sequence, record_json, imported_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &record.import_id,
                &record.namespace,
                &record.peer_site_id,
                &record.snapshot_digest,
                &sequence,
                &json,
                &record.imported_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        for fact in facts {
            let fact_json = serde_json::to_string(fact)
                .map_err(|error| format!("encode snapshot fact: {error}"))?;
            tx.execute(
                "INSERT INTO sekai_federation_snapshot_facts (import_id, object_id, fact_json)
                 VALUES ($1, $2, $3)",
                &[&record.import_id, &fact.object_id, &fact_json],
            )
            .map_err(|error| error.to_string())?;
        }
        for conflict in conflicts {
            let conflict_json = serde_json::to_string(conflict)
                .map_err(|error| format!("encode federation conflict: {error}"))?;
            tx.execute(
                "INSERT INTO sekai_federation_conflicts
                    (conflict_id, namespace, object_id, status, record_json, updated_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (conflict_id) DO UPDATE SET
                    namespace = EXCLUDED.namespace,
                    object_id = EXCLUDED.object_id,
                    status = EXCLUDED.status,
                    record_json = EXCLUDED.record_json,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[
                    &conflict.conflict_id,
                    &conflict.namespace,
                    &conflict.object_id,
                    &conflict.status,
                    &conflict_json,
                    &conflict.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit()
            .map_err(|error| format!("commit snapshot import: {error}"))?;
        Ok(())
    }

    pub fn get_federation_snapshot_import(
        &self,
        import_id: &str,
    ) -> Result<Option<SnapshotImportRecord>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_snapshot_imports WHERE import_id = $1",
                &[&import_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_snapshot_import(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn latest_federation_snapshot_import(
        &self,
        peer_site_id: &str,
        namespace: &str,
    ) -> Result<Option<SnapshotImportRecord>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_federation_snapshot_imports
                 WHERE peer_site_id = $1 AND namespace = $2
                 ORDER BY sequence DESC, imported_at_ms DESC
                 LIMIT 1",
                &[&peer_site_id, &namespace],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_snapshot_import(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn list_federation_snapshot_imports(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<SnapshotImportRecord>, String> {
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_federation_snapshot_imports
                 WHERE ($1::text IS NULL OR namespace = $1)
                 ORDER BY imported_at_ms ASC, import_id ASC",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_snapshot_import(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn list_federation_snapshot_facts(
        &self,
        import_id: &str,
    ) -> Result<Vec<SnapshotFact>, String> {
        self.connection()?
            .query(
                "SELECT fact_json FROM sekai_federation_snapshot_facts
                 WHERE import_id = $1
                 ORDER BY object_id ASC",
                &[&import_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_snapshot_fact(&row.get::<_, String>(0)))
            .collect()
    }
}

fn decode_peer(json: &str) -> Result<FederationPeer, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation peer: {error}"))
}

fn decode_conflict(json: &str) -> Result<FederationConflict, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation conflict: {error}"))
}

fn decode_revocation(json: &str) -> Result<FederationRevocation, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation revocation: {error}"))
}

fn decode_contract(json: &str) -> Result<NetworkContract, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation network: {error}"))
}

fn decode_exchange(json: &str) -> Result<NetworkExchange, String> {
    serde_json::from_str(json).map_err(|error| format!("decode federation exchange: {error}"))
}

fn decode_grant(json: &str) -> Result<PeerNamespaceGrant, String> {
    serde_json::from_str(json).map_err(|error| format!("decode namespace grant: {error}"))
}

fn decode_snapshot_import(json: &str) -> Result<SnapshotImportRecord, String> {
    serde_json::from_str(json).map_err(|error| format!("decode snapshot import: {error}"))
}

fn decode_snapshot_fact(json: &str) -> Result<SnapshotFact, String> {
    serde_json::from_str(json).map_err(|error| format!("decode snapshot fact: {error}"))
}

fn decode_peer_import(json: &str) -> Result<PeerImportRecord, String> {
    serde_json::from_str(json).map_err(|error| format!("decode peer import: {error}"))
}
