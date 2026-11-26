//! The PostgreSQL family against a real server, in process and without the
//! sandbox (which `sandbox.rs` proves on Linux). Needs
//! `SEKAI_TEST_POSTGRES_URL` for a TLS server with `wal_level=logical` and
//! `SEKAI_TEST_POSTGRES_CA_CERT` for its CA; `scripts/postgres-conformance.sh`
//! provides both. Every test names its own table, publication, slot and
//! role, so runs against one server do not collide.

use std::net::TcpStream;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres::config::Host;
use postgres_native_tls::MakeTlsConnector;
use sekai_change_capture::output::Line;
use sekai_change_capture::pg::{self, Refusal, Settings};

struct Server {
    config: postgres::Config,
    ca_pem: String,
}

impl Server {
    fn from_env() -> Self {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL").expect("SEKAI_TEST_POSTGRES_URL");
        let ca = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT").expect("SEKAI_TEST_POSTGRES_CA_CERT");
        Self {
            config: postgres::Config::from_str(&url).unwrap(),
            ca_pem: std::fs::read_to_string(ca).unwrap(),
        }
    }

    fn admin(&self) -> postgres::Client {
        let tls = native_tls::TlsConnector::builder()
            .add_root_certificate(
                native_tls::Certificate::from_pem(self.ca_pem.as_bytes()).unwrap(),
            )
            .build()
            .unwrap();
        let mut config = self.config.clone();
        config.ssl_mode(postgres::config::SslMode::Require);
        config.connect(MakeTlsConnector::new(tls)).unwrap()
    }

    fn host(&self) -> String {
        match &self.config.get_hosts()[0] {
            Host::Tcp(host) => host.clone(),
            #[allow(unreachable_patterns)]
            _ => panic!("a TCP host"),
        }
    }

    fn settings(&self, slot: &str, publication: &str) -> Settings {
        Settings {
            server_name: self.host(),
            user: self.config.get_user().unwrap().to_owned(),
            database: self.config.get_dbname().unwrap().to_owned(),
            ca_pem: Some(self.ca_pem.clone()),
            slot: slot.into(),
            publication: publication.into(),
            resume_lsn: 0,
            max_commits: 10,
        }
    }

    fn password(&self) -> String {
        String::from_utf8(self.config.get_password().unwrap().to_vec()).unwrap()
    }

    /// A session as the runtime opens it: dialed here, then handed over.
    fn session(&self, settings: &Settings, password: &str) -> Result<pg::Session, Refusal> {
        let port = self.config.get_ports().first().copied().unwrap_or(5432);
        let socket = TcpStream::connect((self.host().as_str(), port)).unwrap();
        pg::connect(socket, settings, password)
    }

    /// One `changes` page; retried while the previous page's session still
    /// holds the slot on the server.
    fn page(&self, settings: &Settings) -> Vec<Line> {
        for _ in 0..50 {
            let mut out = Vec::new();
            let mut session = self.session(settings, &self.password()).unwrap();
            match pg::changes(&mut session, settings, &mut out) {
                Err(Refusal("slot_in_use")) => std::thread::sleep(Duration::from_millis(100)),
                result => {
                    result.unwrap();
                    return String::from_utf8(out)
                        .unwrap()
                        .lines()
                        .map(|line| Line::parse(line).unwrap())
                        .collect();
                }
            }
        }
        panic!("the slot stayed in use");
    }

    fn drop_slot(&self, slot: &str) {
        let mut admin = self.admin();
        for _ in 0..50 {
            let dropped = admin.execute(
                "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots \
                 WHERE slot_name = $1 AND NOT active",
                &[&slot],
            );
            let remaining: i64 = admin
                .query_one(
                    "SELECT count(*) FROM pg_replication_slots WHERE slot_name = $1",
                    &[&slot],
                )
                .unwrap()
                .get(0);
            if dropped.is_ok() && remaining == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("slot {slot} was not dropped");
    }
}

fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("{prefix}_{}_{nanos}", std::process::id())
}

/// A password made at run time, unique to the process and the call, so no
/// credential is a literal in the source.
fn test_password() -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!(
        "{}-{}-{nanos}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL with wal_level=logical; run through scripts/postgres-conformance.sh"]
fn postgres_check_names_what_the_database_lacks_before_reading_data() {
    let server = Server::from_env();
    let publication = unique("cc_check_pub");
    let role = unique("cc_check_role");
    let role_password = test_password();
    // The server stores only the SCRAM verifier, never the password itself.
    let verifier = postgres_protocol::password::scram_sha_256(role_password.as_bytes());
    let mut admin = server.admin();
    admin
        .batch_execute(&format!(
            "CREATE PUBLICATION {publication}; \
             CREATE ROLE {role} LOGIN PASSWORD '{verifier}'"
        ))
        .unwrap();
    let check = |settings: &Settings, password: &str| {
        let mut session = server.session(settings, password)?;
        pg::check(&mut session, settings)
    };

    let ready = server.settings("cc_unused", &publication);
    assert_eq!(check(&ready, &server.password()), Ok(()));
    assert_eq!(
        check(
            &server.settings("cc_unused", "cc_no_such_pub"),
            &server.password()
        ),
        Err(Refusal("publication_missing"))
    );
    let mut unprivileged = ready.clone();
    unprivileged.user = role.clone();
    assert!(matches!(
        server.session(&unprivileged, &role_password),
        Err(Refusal("replication_permission_missing"))
    ));
    assert!(matches!(
        server.session(&unprivileged, &format!("{role_password}-other")),
        Err(Refusal("auth_failed"))
    ));
    // A certificate that does not name the server stops before the
    // credential is sent.
    let mut misnamed = ready.clone();
    misnamed.server_name = "not-this-server.invalid".into();
    assert!(matches!(
        server.session(&misnamed, &server.password()),
        Err(Refusal("tls_handshake_failed"))
    ));
    let mut untrusted = ready;
    untrusted.ca_pem = None;
    assert!(matches!(
        server.session(&untrusted, &server.password()),
        Err(Refusal("tls_handshake_failed"))
    ));

    admin
        .batch_execute(&format!("DROP PUBLICATION {publication}; DROP ROLE {role}"))
        .unwrap();
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL with wal_level=logical; run through scripts/postgres-conformance.sh"]
fn postgres_changes_page_through_committed_transactions_once() {
    let server = Server::from_env();
    let table = unique("cc_items");
    let publication = unique("cc_pub");
    let slot = unique("cc_slot");
    let mut admin = server.admin();
    admin
        .batch_execute(&format!(
            "CREATE TABLE {table} (id int PRIMARY KEY, name text); \
             CREATE PUBLICATION {publication} FOR TABLE {table}"
        ))
        .unwrap();
    let mut settings = server.settings(&slot, &publication);

    // The first page creates the missing slot and finds nothing yet.
    let first = server.page(&settings);
    let [Line::SlotCreated { consistent_lsn }, Line::CaughtUp { .. }] = first.as_slice() else {
        panic!("{first:?}");
    };
    admin
        .batch_execute(&format!(
            "BEGIN; INSERT INTO {table} VALUES (1, 'a'), (2, NULL); COMMIT; \
             UPDATE {table} SET name = 'b' WHERE id = 1"
        ))
        .unwrap();

    // One transaction per page here: the page stops at its commit.
    settings.resume_lsn = *consistent_lsn;
    settings.max_commits = 1;
    let inserts = server.page(&settings);
    let relation = format!("public.{table}");
    let [
        Line::Change {
            relation: first_relation,
            row: first_row,
            ..
        },
        Line::Change {
            row: second_row, ..
        },
        Line::Commit { end_lsn, .. },
    ] = inserts.as_slice()
    else {
        panic!("{inserts:?}");
    };
    assert_eq!(first_relation, &relation);
    assert_eq!(first_row["name"].as_deref(), Some("a"));
    assert_eq!(second_row["name"], None);

    // Resuming after that commit reads only the next transaction.
    settings.resume_lsn = *end_lsn;
    settings.max_commits = 10;
    let update = server.page(&settings);
    let [
        Line::Change { row, .. },
        Line::Commit {
            end_lsn: last_end, ..
        },
        Line::CaughtUp { .. },
    ] = update.as_slice()
    else {
        panic!("{update:?}");
    };
    assert_eq!(row["name"].as_deref(), Some("b"));

    // Nothing is read twice.
    settings.resume_lsn = *last_end;
    let rest = server.page(&settings);
    assert!(
        matches!(rest.as_slice(), [Line::CaughtUp { .. }]),
        "{rest:?}"
    );

    server.drop_slot(&slot);
    admin
        .batch_execute(&format!(
            "DROP PUBLICATION {publication}; DROP TABLE {table}"
        ))
        .unwrap();
}

/// The real child, sandboxed, checks the database over the socket this test
/// dialed and hands over, the way the runtime starts it. Linux only; the
/// PostgreSQL conformance job runs it.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL with wal_level=logical; run through scripts/postgres-conformance.sh"]
fn postgres_check_runs_in_the_sandboxed_child_on_the_inherited_socket() {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let server = Server::from_env();
    let publication = unique("cc_child_pub");
    let mut admin = server.admin();
    admin
        .batch_execute(&format!("CREATE PUBLICATION {publication}"))
        .unwrap();
    let child = env!("CARGO_BIN_EXE_sekai-change-capture");
    let run = |publication: &str| {
        let port = server.config.get_ports().first().copied().unwrap_or(5432);
        let socket = TcpStream::connect((server.host().as_str(), port)).unwrap();
        let fd = socket.as_raw_fd();
        let start = serde_json::json!({
            "credential": server.password(),
            "read_paths": [child, "/etc/ssl", "/usr/lib/ssl"],
            "postgres": {
                "server_name": server.host(),
                "user": server.config.get_user().unwrap(),
                "database": server.config.get_dbname().unwrap(),
                "ca_pem": server.ca_pem,
                "slot": "cc_unused",
                "publication": publication,
            },
        });
        let mut command = Command::new(child);
        command
            .args(["check", "--socket-fd", &fd.to_string()])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        // SAFETY: fcntl is async-signal-safe and touches no parent memory.
        unsafe {
            command.pre_exec(move || match libc::fcntl(fd, libc::F_SETFD, 0) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            });
        }
        let mut process = command.spawn().unwrap();
        drop(socket);
        let mut stdin = process.stdin.take().unwrap();
        stdin.write_all(start.to_string().as_bytes()).unwrap();
        drop(stdin);
        let output = process.wait_with_output().unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(&server.password()));
        (output.status.code(), text)
    };

    let (code, text) = run(&publication);
    assert_eq!(code, Some(sekai_change_capture::EXIT_OK), "{text}");
    assert_eq!(Line::parse(text.trim()).unwrap(), Line::Checked);
    let (code, text) = run("cc_no_such_pub");
    assert_eq!(code, Some(sekai_change_capture::EXIT_REFUSED), "{text}");
    assert_eq!(
        Line::parse(text.trim()).unwrap(),
        Line::Refused {
            reason: "publication_missing".into()
        }
    );

    admin
        .batch_execute(&format!("DROP PUBLICATION {publication}"))
        .unwrap();
}
