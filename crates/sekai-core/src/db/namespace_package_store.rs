//! Namespace package installations (#3093, ADR 0169) on SQLite and
//! PostgreSQL: one record per `(namespace, package name)`.

use rusqlite::{OptionalExtension, params};

use super::postgres::PostgresDb;
use super::sekai::SekaiDb;
use crate::sekai::namespace_package::NamespacePackageInstallation;

fn decode(json: &str) -> Result<NamespacePackageInstallation, String> {
    serde_json::from_str(json).map_err(|error| format!("decode package installation: {error}"))
}

fn encode(installation: &NamespacePackageInstallation) -> Result<String, String> {
    serde_json::to_string(installation)
        .map_err(|error| format!("encode package installation: {error}"))
}

impl SekaiDb {
    pub fn get_namespace_package_installation(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Option<NamespacePackageInstallation>, String> {
        self.conn()
            .query_row(
                "SELECT record_json FROM sekai_namespace_package_installations
                 WHERE namespace = ?1 AND package_name = ?2",
                params![namespace, package_name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|json| decode(&json))
            .transpose()
    }

    /// Stores `installation` unless its namespace already holds an
    /// installation of the package, and returns the stored one: a racing or
    /// repeated install keeps the first.
    pub fn put_namespace_package_installation(
        &self,
        installation: &NamespacePackageInstallation,
    ) -> Result<NamespacePackageInstallation, String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_namespace_package_installations
                    (namespace, package_name, record_json)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(namespace, package_name) DO NOTHING",
                params![
                    installation.namespace,
                    installation.package_name,
                    encode(installation)?
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_namespace_package_installation(
            &installation.namespace,
            &installation.package_name,
        )?
        .ok_or_else(|| "package installation unavailable".to_string())
    }
}

impl PostgresDb {
    pub fn get_namespace_package_installation(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Option<NamespacePackageInstallation>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_namespace_package_installations
                 WHERE namespace = $1 AND package_name = $2",
                &[&namespace, &package_name],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode(&row.get::<_, String>(0)))
            .transpose()
    }

    /// As the SQLite store: the first stored installation wins.
    pub fn put_namespace_package_installation(
        &self,
        installation: &NamespacePackageInstallation,
    ) -> Result<NamespacePackageInstallation, String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_namespace_package_installations
                    (namespace, package_name, record_json)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (namespace, package_name) DO NOTHING",
                &[
                    &installation.namespace,
                    &installation.package_name,
                    &encode(installation)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_namespace_package_installation(
            &installation.namespace,
            &installation.package_name,
        )?
        .ok_or_else(|| "package installation unavailable".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::namespace_package::{EntryRole, InstalledResource};

    fn installation(package_digest: &str) -> NamespacePackageInstallation {
        NamespacePackageInstallation {
            installation_id: "sha256:install".into(),
            namespace: "target".into(),
            package_name: "desk".into(),
            package_version: 1,
            package_digest: package_digest.into(),
            ontology_digest: "sha256:ontology".into(),
            source_namespace: "source".into(),
            signer_identity: "plane-a".into(),
            branch_id: "package/desk/v1".into(),
            proposal_id: "package/desk/v1".into(),
            resources: vec![InstalledResource {
                kind: "dataset_version".into(),
                entry_id: "tickets".into(),
                role: EntryRole::Output,
                resource_id: "desk-tickets".into(),
            }],
            installed_by: "root".into(),
            installed_at_ms: 1,
        }
    }

    /// A namespace holds one installation per package name: a racing or
    /// repeated put keeps the first one stored.
    fn first_install_wins(
        put: impl Fn(&NamespacePackageInstallation) -> Result<NamespacePackageInstallation, String>,
        get: impl Fn(&str, &str) -> Result<Option<NamespacePackageInstallation>, String>,
    ) {
        assert_eq!(get("target", "desk").unwrap(), None);
        let first = installation("sha256:first");
        assert_eq!(put(&first).unwrap(), first);
        assert_eq!(put(&installation("sha256:second")).unwrap(), first);
        assert_eq!(get("target", "desk").unwrap(), Some(first));
        assert_eq!(get("other", "desk").unwrap(), None);
    }

    #[test]
    fn sqlite_keeps_the_first_installation_of_a_package() {
        let db = SekaiDb::new(":memory:").unwrap();
        first_install_wins(
            |installation| db.put_namespace_package_installation(installation),
            |namespace, name| db.get_namespace_package_installation(namespace, name),
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_keeps_the_first_installation_of_a_package() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = scratch.connect();
        first_install_wins(
            |installation| db.put_namespace_package_installation(installation),
            |namespace, name| db.get_namespace_package_installation(namespace, name),
        );
    }
}
