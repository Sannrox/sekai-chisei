//! `sekai-change-capture <mode> --socket-fd <fd>`; see the library docs.

use std::io::{Read, Write};
use std::process::ExitCode;

use sekai_change_capture::{
    EXIT_BROKEN, EXIT_OK, EXIT_UNAVAILABLE, EXIT_USAGE, MAX_START_BYTES, Start, parse_args,
    sandbox, self_test,
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
    if mode != "self-test" {
        return EXIT_USAGE;
    }
    if let Err(reason) = sandbox::enter(socket_fd, &start.read_paths) {
        report(&self_test::unavailable(reason.0));
        return EXIT_UNAVAILABLE;
    }
    if !sandbox::is_connected_socket(socket_fd) {
        return EXIT_USAGE;
    }
    let (report_value, held) = self_test::run(socket_fd, &start.credential, &start.read_paths);
    report(&report_value);
    if held { EXIT_OK } else { EXIT_BROKEN }
}

fn report(value: &serde_json::Value) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{value}");
}
