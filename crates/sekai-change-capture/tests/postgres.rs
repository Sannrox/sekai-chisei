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
            snapshot_lsn: 0,
            snapshot_after: None,
            max_rows: 0,
            // As the runtime runs it once the plane records the slot.
            slot_recorded: true,
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
        self.try_page(settings).unwrap()
    }

    /// [`Server::page`], keeping a refusal for the caller.
    fn try_page(&self, settings: &Settings) -> Result<Vec<Line>, Refusal> {
        self.run(settings, pg::changes)
    }

    /// One `snapshot` page, keeping a refusal for the caller.
    fn snapshot(&self, settings: &Settings) -> Result<Vec<Line>, Refusal> {
        self.run(settings, pg::snapshot)
    }

    /// Runs `mode` once, retried while a previous session holds the slot,
    /// without the retained-log lines, which [`Server::run_measured`]
    /// keeps.
    fn run(
        &self,
        settings: &Settings,
        mode: fn(&mut pg::Session, &Settings, &mut Vec<u8>) -> Result<(), Refusal>,
    ) -> Result<Vec<Line>, Refusal> {
        let mut lines = self.run_measured(settings, mode)?;
        lines.retain(|line| !matches!(line, Line::RetainedLog { .. }));
        Ok(lines)
    }

    /// [`Server::run`] with every line.
    fn run_measured(
        &self,
        settings: &Settings,
        mode: fn(&mut pg::Session, &Settings, &mut Vec<u8>) -> Result<(), Refusal>,
    ) -> Result<Vec<Line>, Refusal> {
        for _ in 0..50 {
            let mut out = Vec::new();
            let mut session = self.session(settings, &self.password()).unwrap();
            match mode(&mut session, settings, &mut out) {
                Err(Refusal("slot_in_use")) => std::thread::sleep(Duration::from_millis(100)),
                result => {
                    result?;
                    return Ok(String::from_utf8(out)
                        .unwrap()
                        .lines()
                        .map(|line| Line::parse(line).unwrap())
                        .collect());
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
    let table = unique("cc_check_items");
    let publication = unique("cc_check_pub");
    let empty = unique("cc_check_empty");
    let role = unique("cc_check_role");
    let role_password = test_password();
    // The server stores only the SCRAM verifier, never the password itself.
    let verifier = postgres_protocol::password::scram_sha_256(role_password.as_bytes());
    let mut admin = server.admin();
    admin
        .batch_execute(&format!(
            "CREATE TABLE {table} (id int PRIMARY KEY); \
             CREATE PUBLICATION {publication} FOR TABLE {table}; \
             CREATE PUBLICATION {empty}; \
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
        check(&server.settings("cc_unused", &empty), &server.password()),
        Err(Refusal("publication_not_one_table"))
    );
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
        .batch_execute(&format!(
            "DROP PUBLICATION {publication}; DROP PUBLICATION {empty}; \
             DROP TABLE {table}; DROP ROLE {role}"
        ))
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

    // The slot now confirms `last_end`: resuming before it would skip the
    // update, and a slot gone after the first commit is never re-created.
    settings.resume_lsn = *end_lsn;
    assert_eq!(server.try_page(&settings), Err(Refusal("slot_ahead")));
    let mut vanished = settings.clone();
    vanished.slot = unique("cc_gone");
    vanished.resume_lsn = *last_end;
    assert_eq!(server.try_page(&vanished), Err(Refusal("slot_missing")));

    server.drop_slot(&slot);
    admin
        .batch_execute(&format!(
            "DROP PUBLICATION {publication}; DROP TABLE {table}"
        ))
        .unwrap();
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL with wal_level=logical; run through scripts/postgres-conformance.sh"]
fn postgres_snapshot_pages_read_the_table_in_key_order_after_the_slot() {
    let server = Server::from_env();
    let table = unique("cc_snap_items");
    let publication = unique("cc_snap_pub");
    let empty = unique("cc_snap_empty");
    let empty_publication = unique("cc_snap_empty_pub");
    let slot = unique("cc_snap_slot");
    let mut admin = server.admin();
    admin
        .batch_execute(&format!(
            "CREATE TABLE {table} (id int, name text, flag boolean, PRIMARY KEY (id) INCLUDE (name)); \
             INSERT INTO {table} SELECT n, 'r' || n, n % 2 = 0 FROM generate_series(1, 5) n; \
             CREATE TABLE {table}_child () INHERITS ({table}); \
             INSERT INTO {table}_child VALUES (3, 'child', true); \
             CREATE PUBLICATION {publication} FOR TABLE ONLY {table}; \
             CREATE TABLE {empty} (id int PRIMARY KEY); \
             CREATE PUBLICATION {empty_publication} FOR TABLE {empty}"
        ))
        .unwrap();
    let mut settings = server.settings(&slot, &publication);
    settings.max_rows = 2;
    let ids = |lines: &[Line]| -> Vec<String> {
        lines
            .iter()
            .filter_map(|line| match line {
                Line::Row { key, .. } | Line::Gone { key } => key["id"].clone(),
                _ => None,
            })
            .collect()
    };

    // The first page creates the slot and reads after its position.
    let first = server.snapshot(&settings).unwrap();
    let [
        Line::SlotCreated { consistent_lsn },
        Line::SnapshotAt { lsn },
        Line::Row { key, row },
        Line::Row { .. },
        Line::SnapshotEnd { complete: false },
    ] = first.as_slice()
    else {
        panic!("{first:?}");
    };
    assert_eq!(consistent_lsn, lsn);
    assert_eq!(ids(&first), ["1", "2"]);
    // A covering index's included columns are not part of the identity.
    assert_eq!(key.keys().collect::<Vec<_>>(), ["id"]);
    // Values in the server's own text form, as the feed streams them.
    assert_eq!(row["flag"].as_deref(), Some("f"));

    settings.snapshot_lsn = *lsn;
    settings.snapshot_after = Some(vec!["2".into()]);
    let second = server.snapshot(&settings).unwrap();
    // The unpublished inheritance child's row 3 is not read.
    assert_eq!(ids(&second), ["3", "4"]);
    assert_eq!(second.last(), Some(&Line::SnapshotEnd { complete: false }));

    // Rows after the last key vanished: the page carries that key again,
    // as gone once it is deleted too, and completes.
    admin
        .batch_execute(&format!("DELETE FROM {table} WHERE id >= 5"))
        .unwrap();
    settings.snapshot_after = Some(vec!["4".into()]);
    let again = server.snapshot(&settings).unwrap();
    assert!(
        matches!(
            again.as_slice(),
            [
                Line::SnapshotAt { .. },
                Line::Row { .. },
                Line::SnapshotEnd { complete: true }
            ]
        ),
        "{again:?}"
    );
    admin
        .batch_execute(&format!("DELETE FROM {table} WHERE id = 4"))
        .unwrap();
    let gone = server.snapshot(&settings).unwrap();
    assert!(
        matches!(
            gone.as_slice(),
            [
                Line::SnapshotAt { .. },
                Line::Gone { .. },
                Line::SnapshotEnd { complete: true }
            ]
        ),
        "{gone:?}"
    );
    assert_eq!(ids(&gone), ["4"]);

    // A slot confirmed past the snapshot's position would skip changes.
    let mut behind = settings.clone();
    behind.snapshot_lsn = lsn - 1;
    assert_eq!(server.snapshot(&behind), Err(Refusal("slot_ahead")));

    // An empty table cannot finish a snapshot.
    let mut nothing = server.settings(&unique("cc_snap_none"), &empty_publication);
    nothing.max_rows = 2;
    assert_eq!(server.snapshot(&nothing), Err(Refusal("table_empty")));

    server.drop_slot(&slot);
    server.drop_slot(&nothing.slot);
    admin
        .batch_execute(&format!(
            "DROP PUBLICATION {publication}; DROP PUBLICATION {empty_publication}; \
             DROP TABLE {table} CASCADE; DROP TABLE {empty}"
        ))
        .unwrap();
}

/// A new snapshot creates only a slot the plane records (#3083): it names
/// a missing unrecorded slot and creates nothing, refuses an existing
/// unrecorded one, and measures the log a slot retains on every page.
#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL with wal_level=logical; run through scripts/postgres-conformance.sh"]
fn postgres_snapshot_creates_only_a_recorded_slot_and_measures_its_log() {
    let server = Server::from_env();
    let table = unique("cc_rec_items");
    let publication = unique("cc_rec_pub");
    let slot = unique("cc_rec_slot");
    let mut admin = server.admin();
    admin
        .batch_execute(&format!(
            "CREATE TABLE {table} (id int PRIMARY KEY); INSERT INTO {table} VALUES (1); \
             CREATE PUBLICATION {publication} FOR TABLE {table}"
        ))
        .unwrap();
    let slots = |admin: &mut postgres::Client| -> i64 {
        admin
            .query_one(
                "SELECT count(*) FROM pg_replication_slots WHERE slot_name = $1",
                &[&slot],
            )
            .unwrap()
            .get(0)
    };
    let mut settings = server.settings(&slot, &publication);
    settings.max_rows = 10;
    settings.slot_recorded = false;
    assert_eq!(server.snapshot(&settings), Ok(vec![Line::SlotMissing]));
    assert_eq!(slots(&mut admin), 0, "an unrecorded slot is never created");

    settings.slot_recorded = true;
    let created = server.run_measured(&settings, pg::snapshot).unwrap();
    let [
        Line::SlotCreated { .. },
        Line::RetainedLog { bytes, wal_status },
        Line::SnapshotAt { .. },
        Line::Row { .. },
        Line::SnapshotEnd { complete: true },
    ] = created.as_slice()
    else {
        panic!("{created:?}");
    };
    assert!(*bytes >= 0);
    assert_eq!(wal_status, "reserved");

    // The same slot, existing but no longer recorded, is refused and left
    // in place.
    settings.slot_recorded = false;
    assert_eq!(
        server.snapshot(&settings),
        Err(Refusal("slot_ahead_of_snapshot"))
    );
    assert_eq!(slots(&mut admin), 1);

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
    let table = unique("cc_child_items");
    let publication = unique("cc_child_pub");
    let mut admin = server.admin();
    admin
        .batch_execute(&format!(
            "CREATE TABLE {table} (id int PRIMARY KEY); \
             CREATE PUBLICATION {publication} FOR TABLE {table}"
        ))
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
        .batch_execute(&format!(
            "DROP PUBLICATION {publication}; DROP TABLE {table}"
        ))
        .unwrap();
}
