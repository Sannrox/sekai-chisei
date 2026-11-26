//! `sekai-change-capture <mode> --socket-fd <fd>`; see the library docs.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::FromRawFd;
use std::process::ExitCode;

use sekai_change_capture::output::Line;
use sekai_change_capture::{
    EXIT_BROKEN, EXIT_OK, EXIT_REFUSED, EXIT_UNAVAILABLE, EXIT_USAGE, MAX_START_BYTES, Start,
    parse_args, pg, sandbox, self_test,
};

fn main() -> ExitCode {
    ExitCode::from(run() as u8)
}

fn run() -> i32 {
    let Some((mode, socket_fd)) = parse_args(std::env::args().skip(1)) else {
        return EXIT_USAGE;
    };
    let mut bytes = Vec::new();
    if std::io::stdin()
        .take(MAX_START_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return EXIT_USAGE;
    }
    let Some(start) = Start::parse(&bytes) else {
        return EXIT_USAGE;
    };
    drop(bytes);
    let capture = match (mode.as_str(), &start.postgres) {
        ("self-test", _) => None,
        ("check" | "changes" | "snapshot", Some(settings)) => Some(settings.clone()),
        _ => return EXIT_USAGE,
    };
    if let Err(reason) = sandbox::enter(socket_fd, &start.read_paths) {
        report(&match capture {
            None => self_test::unavailable(reason.0),
            Some(_) => serde_json::json!({ "kind": "unavailable", "reason": reason.0 }),
        });
        return EXIT_UNAVAILABLE;
    }
    if !sandbox::is_connected_socket(socket_fd) {
        return EXIT_USAGE;
    }
    let Some(settings) = capture else {
        let (report_value, held) = self_test::run(socket_fd, &start.credential, &start.read_paths);
        report(&report_value);
        return if held { EXIT_OK } else { EXIT_BROKEN };
    };
    // SAFETY: the descriptor is the connected socket the runtime handed
    // over, checked above; nothing else in this process owns it.
    let socket = unsafe { TcpStream::from_raw_fd(socket_fd) };
    let mut stdout = std::io::stdout().lock();
    let outcome = pg::connect(socket, &settings, &start.credential).and_then(|mut session| {
        match mode.as_str() {
            "check" => pg::check(&mut session, &settings).map(|()| Some(Line::Checked)),
            "snapshot" => pg::snapshot(&mut session, &settings, &mut stdout).map(|()| None),
            _ => pg::changes(&mut session, &settings, &mut stdout).map(|()| None),
        }
    });
    drop(start);
    let line = match outcome {
        Ok(line) => line,
        Err(pg::Refusal(reason)) => Some(Line::Refused {
            reason: reason.to_owned(),
        }),
    };
    let refused = matches!(line, Some(Line::Refused { .. }));
    if let Some(text) = line.and_then(|line| line.encode().ok()) {
        let _ = stdout.write_all(text.as_bytes());
        let _ = stdout.flush();
    }
    if refused { EXIT_REFUSED } else { EXIT_OK }
}

fn report(value: &serde_json::Value) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{value}");
}
