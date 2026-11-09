//! The `relational` connector type, over PostgreSQL: a reachability check
//! and saved-export delivery into the Source's `delivery_table`.
//!
//! Each delivery is one row keyed by its receipt, inserted with
//! `ON CONFLICT (receipt_id) DO NOTHING`. A redelivery after a crash or a
//! takeover therefore writes nothing twice. A row already present for the
//! receipt with different content fails the delivery as invalid rather
//! than being overwritten. The table needs the columns `receipt_id` (unique
//! text), `namespace`, `definition_id`, `content_digest` (text) and
//! `content` (bytea).
//!
//! The connection always uses TLS and verifies the server's certificate
//! against the system roots plus an optional operator CA. It goes to the
//! `endpoint` the egress allowlist admitted, parsed the same way. When the
//! endpoint's name resolves to several addresses, a failure reports the
//! last one tried, so an endpoint is best named by one address. Page
//! reads need a registered type descriptor (ADR 0100) and are not
//! implemented yet, so a relational Source's syncs fail as `unsupported`.

use std::time::Duration;

use native_tls::{Certificate, TlsConnector};
use postgres::config::SslMode;
use postgres::error::SqlState;
use postgres_native_tls::MakeTlsConnector;
use sekai_source_sdk::{ConfigValue, Connector, ConnectorFailure, Destination, ExportArtifact};

use crate::sync::Prepared;

/// The PostgreSQL port an endpoint without one connects to.
const DEFAULT_PORT: u16 = 5432;

/// How long one connection or statement may take.
const TIMEOUT: Duration = Duration::from_secs(30);

/// One database, reached as the Source's user with its bound password.
pub struct Relational {
    config: postgres::Config,
    tls: MakeTlsConnector,
    /// The quoted, validated delivery table, when the Source names one.
    delivery_table: Option<String>,
}

/// The TLS connector every relational Source connects with: the system
/// roots, plus `ca_pem` when the operator trusts a private CA.
pub fn tls(ca_pem: Option<&[u8]>) -> Result<MakeTlsConnector, String> {
    let mut builder = TlsConnector::builder();
    if let Some(pem) = ca_pem {
        let certificate =
            Certificate::from_pem(pem).map_err(|error| format!("parse CA certificate: {error}"))?;
        builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map(MakeTlsConnector::new)
        .map_err(|error| format!("build TLS connector: {error}"))
}

/// Opens the relational type for a prepared Source; register it with
/// `Connectors::with(&RELATIONAL_CONNECTOR, move |prepared| relational::open(prepared, &tls))`.
pub fn open(
    prepared: &Prepared,
    tls: &MakeTlsConnector,
) -> Result<Box<dyn Connector + Send>, ConnectorFailure> {
    let text = |name: &str| match prepared.config.get(name) {
        Some(ConfigValue::Text(value)) => Ok(Some(value.as_str())),
        None => Ok(None),
        Some(_) => Err(ConnectorFailure::Invalid),
    };
    let required = |name: &str| text(name)?.ok_or(ConnectorFailure::Invalid);
    let endpoint = Destination::parse(required("endpoint")?).ok_or(ConnectorFailure::Invalid)?;
    let password = prepared
        .credentials
        .get("password")
        .ok_or(ConnectorFailure::AuthFailed)?;
    let mut config = postgres::Config::new();
    config
        .host(&endpoint.host)
        .port(endpoint.port.unwrap_or(DEFAULT_PORT))
        .dbname(required("database")?)
        .user(required("user")?)
        .password(password.expose())
        .ssl_mode(SslMode::Require)
        .connect_timeout(TIMEOUT)
        // A locked table or a half-open connection ends an attempt rather
        // than pinning its thread past the claim.
        .options(&format!("-c statement_timeout={}", TIMEOUT.as_millis()))
        .keepalives_idle(TIMEOUT)
        .tcp_user_timeout(TIMEOUT)
        .application_name("sekai-connector-runtime");
    let delivery_table = text("delivery_table")?
        .map(|table| quoted_table(table).ok_or(ConnectorFailure::Invalid))
        .transpose()?;
    Ok(Box::new(Relational {
        config,
        tls: tls.clone(),
        delivery_table,
    }))
}

impl Relational {
    fn connect(&self) -> Result<postgres::Client, ConnectorFailure> {
        self.config.connect(self.tls.clone()).map_err(failure)
    }
}

impl Connector for Relational {
    fn check(&mut self) -> Result<(), ConnectorFailure> {
        self.connect()?.simple_query("SELECT 1").map_err(failure)?;
        Ok(())
    }

    fn deliver(&mut self, artifact: &ExportArtifact<'_>) -> Result<(), ConnectorFailure> {
        let table = self
            .delivery_table
            .as_deref()
            .ok_or(ConnectorFailure::Invalid)?;
        let mut client = self.connect()?;
        let inserted = client
            .execute(
                &format!(
                    "INSERT INTO {table} \
                     (receipt_id, namespace, definition_id, content_digest, content) \
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT (receipt_id) DO NOTHING"
                ),
                &[
                    &artifact.receipt_id,
                    &artifact.namespace,
                    &artifact.definition_id,
                    &artifact.content_digest,
                    &artifact.bytes,
                ],
            )
            .map_err(failure)?;
        if inserted == 1 {
            return Ok(());
        }
        // Delivered before: the same content is a replay, other content is
        // a conflict the operator resolves.
        let present: String = client
            .query_one(
                &format!("SELECT content_digest FROM {table} WHERE receipt_id = $1"),
                &[&artifact.receipt_id],
            )
            .map_err(failure)?
            .get(0);
        if present == artifact.content_digest {
            Ok(())
        } else {
            Err(ConnectorFailure::Invalid)
        }
    }
}

/// `table` or `schema.table` as a quoted identifier, when every part is a
/// plain identifier. Parts fold to lower case, as PostgreSQL folds an
/// unquoted name.
fn quoted_table(table: &str) -> Option<String> {
    let parts: Vec<&str> = table.split('.').collect();
    let plain = |part: &&str| {
        (1..=63).contains(&part.len())
            && part
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    };
    (parts.len() <= 2 && parts.iter().all(plain)).then(|| {
        parts
            .iter()
            .map(|part| format!("\"{}\"", part.to_ascii_lowercase()))
            .collect::<Vec<_>>()
            .join(".")
    })
}

/// A database refusal as the connector's failure class.
fn failure(error: postgres::Error) -> ConnectorFailure {
    let Some(code) = error.code() else {
        // No server answer. The connection, TLS or the network failed, or
        // the client refused the table's shape (a column type, a missing
        // row), which is the Source's configuration.
        let source = std::error::Error::source(&error);
        let transport = error.is_closed()
            || source.is_some_and(|source| {
                source.is::<std::io::Error>() || source.is::<native_tls::Error>()
            });
        return if transport {
            ConnectorFailure::Unreachable
        } else {
            ConnectorFailure::Invalid
        };
    };
    match code.code().get(..2) {
        // Invalid authorization specification, invalid password.
        Some("28") => ConnectorFailure::AuthFailed,
        // Connection exception, insufficient resources, operator
        // intervention: the database is not there to serve.
        Some("08" | "53" | "57") => ConnectorFailure::Unreachable,
        _ if *code == SqlState::INSUFFICIENT_PRIVILEGE => ConnectorFailure::PermissionMissing,
        _ => ConnectorFailure::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Secret;
    use sekai_source_sdk::{RELATIONAL_CONNECTOR, SourceConfig};
    use std::collections::BTreeMap;

    fn prepared(config: &[(&str, &str)], password: Option<&str>) -> Prepared {
        Prepared {
            connector: &RELATIONAL_CONNECTOR,
            source_instance: "orders".into(),
            config: config
                .iter()
                .map(|(name, value)| (name.to_string(), ConfigValue::Text(value.to_string())))
                .collect::<SourceConfig>(),
            credentials: password
                .map(|password| BTreeMap::from([("password".into(), Secret(password.into()))]))
                .unwrap_or_default(),
        }
    }

    const BASE: [(&str, &str); 3] = [
        ("endpoint", "127.0.0.1:1"),
        ("database", "orders"),
        ("user", "writer"),
    ];

    #[test]
    fn delivery_tables_are_plain_identifiers() {
        assert_eq!(quoted_table("exports").as_deref(), Some("\"exports\""));
        assert_eq!(
            quoted_table("Ops.Exports_v2").as_deref(),
            Some("\"ops\".\"exports_v2\"")
        );
        for refused in [
            "",
            "a.b.c",
            "1exports",
            "exports; DROP TABLE x",
            "ex\"ports",
            ".exports",
        ] {
            assert_eq!(quoted_table(refused), None, "{refused}");
        }
    }

    #[test]
    fn a_source_opens_only_with_its_settings() {
        let tls = tls(None).unwrap();
        let open =
            |config: &[(&str, &str)], password| open(&prepared(config, password), &tls).map(|_| ());
        assert_eq!(open(&BASE, Some("pw")), Ok(()));
        assert_eq!(open(&BASE, None), Err(ConnectorFailure::AuthFailed));
        assert_eq!(
            open(&BASE[1..], Some("pw")),
            Err(ConnectorFailure::Invalid),
            "no endpoint"
        );
        let mut bad_table = BASE.to_vec();
        bad_table.push(("delivery_table", "x; --"));
        assert_eq!(open(&bad_table, Some("pw")), Err(ConnectorFailure::Invalid));
        assert!(super::tls(Some(b"not a certificate")).is_err());
    }

    /// On a blocking thread of the runtime, as deliveries run: the
    /// client's own executor starts there without a nested-runtime panic.
    #[tokio::test]
    async fn an_unreachable_database_fails_as_unreachable() {
        let check = crate::sync::blocking(|| {
            // Port 1 on loopback refuses the connection.
            let mut relational = open(&prepared(&BASE, Some("pw")), &tls(None).unwrap()).unwrap();
            Ok(relational.check())
        });
        assert_eq!(check.await, Ok(Err(ConnectorFailure::Unreachable)));
    }

    #[test]
    fn delivering_without_a_delivery_table_is_invalid() {
        let mut relational = open(&prepared(&BASE, Some("pw")), &tls(None).unwrap()).unwrap();
        let artifact = ExportArtifact {
            receipt_id: "r1",
            namespace: "ops",
            definition_id: "d1",
            content_digest: "sha256:00",
            bytes: b"x",
        };
        assert_eq!(
            relational.deliver(&artifact),
            Err(ConnectorFailure::Invalid)
        );
    }

    /// Delivers into a real PostgreSQL over TLS. Run through
    /// `scripts/postgres-conformance.sh`, which sets
    /// `SEKAI_TEST_POSTGRES_URL` and `SEKAI_TEST_POSTGRES_CA_CERT`.
    #[test]
    #[ignore = "requires PostgreSQL; run scripts/postgres-conformance.sh"]
    fn postgres_delivery_is_idempotent_per_receipt() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL").expect("SEKAI_TEST_POSTGRES_URL");
        let ca = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT")
            .map(|path| std::fs::read(path).expect("read CA certificate"))
            .ok();
        let tls = tls(ca.as_deref()).unwrap();
        let target: postgres::Config = url.parse().unwrap();
        let host = match &target.get_hosts()[0] {
            postgres::config::Host::Tcp(host) => host.clone(),
            #[cfg(unix)]
            postgres::config::Host::Unix(_) => panic!("a TCP URL"),
        };
        let password = String::from_utf8(target.get_password().unwrap().to_vec()).unwrap();
        // A table of its own, so another run against the same database
        // never meets this one's rows.
        let table = format!(
            "delivery_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let mut admin = target.connect(tls.clone()).unwrap();
        admin
            .batch_execute(&format!(
                "CREATE TABLE {table} (receipt_id text PRIMARY KEY, namespace text NOT NULL, \
                 definition_id text NOT NULL, content_digest text NOT NULL, content bytea NOT NULL)"
            ))
            .unwrap();
        // One address: the client reports the last address's failure, so
        // a name that also resolves to an address nothing listens on would
        // hide an authentication failure behind a refused connection.
        let host = if host == "localhost" {
            "127.0.0.1".to_string()
        } else {
            host
        };
        let endpoint = format!("{host}:{}", target.get_ports()[0]);
        let config = [
            ("endpoint", endpoint.as_str()),
            ("database", target.get_dbname().unwrap()),
            ("user", target.get_user().unwrap()),
            ("delivery_table", table.as_str()),
        ];
        let mut relational = open(&prepared(&config, Some(&password)), &tls).unwrap();
        relational.check().unwrap();
        let artifact = ExportArtifact {
            receipt_id: "r1",
            namespace: "ops",
            definition_id: "d1",
            content_digest: "sha256:aa",
            bytes: b"rows",
        };
        relational.deliver(&artifact).unwrap();
        relational.deliver(&artifact).unwrap();
        let conflicting = ExportArtifact {
            content_digest: "sha256:bb",
            ..artifact
        };
        assert_eq!(
            relational.deliver(&conflicting),
            Err(ConnectorFailure::Invalid)
        );
        let rows = admin
            .query(&format!("SELECT content_digest, content FROM {table}"), &[])
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<_, String>(0), "sha256:aa");
        assert_eq!(rows[0].get::<_, Vec<u8>>(1), b"rows");
        let mut wrong = open(&prepared(&config, Some("wrong")), &tls).unwrap();
        assert_eq!(wrong.check(), Err(ConnectorFailure::AuthFailed));
        // A table of another shape is the Source's configuration, refused
        // by the client before the server answers.
        let misshaped = format!("{table}_uuid");
        admin
            .batch_execute(&format!(
                "CREATE TABLE {misshaped} (receipt_id uuid PRIMARY KEY, namespace text, \
                 definition_id text, content_digest text, content bytea)"
            ))
            .unwrap();
        let mut config = config;
        config[3].1 = misshaped.as_str();
        let mut relational = open(&prepared(&config, Some(&password)), &tls).unwrap();
        assert_eq!(
            relational.deliver(&artifact),
            Err(ConnectorFailure::Invalid)
        );
        admin
            .batch_execute(&format!("DROP TABLE {table}; DROP TABLE {misshaped}"))
            .unwrap();
    }
}
