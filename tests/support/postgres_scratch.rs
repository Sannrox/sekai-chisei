//! Scratch PostgreSQL databases for conformance tests that must not share
//! state: one database per test on the server `SEKAI_TEST_POSTGRES_URL`
//! names, dropped when the guard goes out of scope. `SEKAI_TEST_POSTGRES_CA_CERT`
//! supplies a private CA.

use sekai_chisei::db::postgres::PostgresDb;

pub struct ScratchDatabase {
    admin_url: String,
    pub ca_cert: Option<String>,
    name: String,
    pub url: String,
}

impl ScratchDatabase {
    pub fn create() -> Self {
        let admin_url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must identify a PostgreSQL test server");
        let ca_cert = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT").ok();
        let name = format!("sekai_scratch_{}", uuid::Uuid::new_v4().simple());
        let (base, query) = match admin_url.split_once('?') {
            Some((base, query)) => (base, format!("?{query}")),
            None => (admin_url.as_str(), String::new()),
        };
        let prefix = base.rsplit_once('/').expect("database URL path").0;
        let url = format!("{prefix}/{name}{query}");
        let scratch = Self {
            admin_url,
            ca_cert,
            name,
            url,
        };
        scratch.admin(&format!("CREATE DATABASE {}", scratch.name));
        scratch
    }

    #[allow(dead_code)]
    pub fn connect(&self, pool_size: u32) -> PostgresDb {
        off_runtime(|| match &self.ca_cert {
            Some(path) => PostgresDb::connect_with_ca_certificate(
                &self.url,
                pool_size,
                &std::fs::read(path).expect("read CA certificate"),
            ),
            None => PostgresDb::connect(&self.url, pool_size),
        })
        .expect("connect scratch database")
    }

    fn admin(&self, statement: &str) {
        off_runtime(|| {
            let mut builder = native_tls::TlsConnector::builder();
            if let Some(path) = &self.ca_cert {
                let pem = std::fs::read(path).expect("read CA certificate");
                builder.add_root_certificate(
                    native_tls::Certificate::from_pem(&pem).expect("parse CA certificate"),
                );
            }
            let tls = postgres_native_tls::MakeTlsConnector::new(builder.build().expect("tls"));
            postgres::Client::connect(&self.admin_url, tls)
                .expect("connect PostgreSQL test server")
                .batch_execute(statement)
                .expect("scratch database statement");
        });
    }
}

impl Drop for ScratchDatabase {
    fn drop(&mut self) {
        self.admin(&format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.name
        ));
    }
}

/// The synchronous client runs its own runtime; keep it off an async worker.
fn off_runtime<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => tokio::task::block_in_place(work),
        Err(_) => work(),
    }
}
