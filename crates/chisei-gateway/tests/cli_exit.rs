//! Early-exit commands return without serving. Telemetry flush is the `run`
//! wrapper in `main`; these cases prove the printed outcome is unchanged.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

fn gateway(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chisei-gateway"))
        .args(args)
        .env_clear()
        .output()
        .expect("spawn chisei-gateway")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn early_exit_paths_keep_their_codes_and_messages() {
    let report = gateway(&["report", "--help"]);
    assert!(report.status.success(), "{report:?}");
    assert!(
        stdout(&report).contains("Usage: chisei-gateway report"),
        "{}",
        stdout(&report)
    );

    let refresh = gateway(&["refresh", "--help"]);
    assert!(refresh.status.success(), "{refresh:?}");
    assert!(
        stdout(&refresh).contains("Usage: chisei-gateway refresh"),
        "{}",
        stdout(&refresh)
    );

    let unknown = gateway(&["not-a-command"]);
    assert!(!unknown.status.success(), "{unknown:?}");
    assert!(
        stderr(&unknown).contains("unknown chisei-gateway command"),
        "{}",
        stderr(&unknown)
    );

    let config = gateway(&[]);
    assert!(!config.status.success(), "{config:?}");
    assert!(
        stderr(&config).contains("a configured provider API key is required"),
        "{}",
        stderr(&config)
    );
}

fn refresh_against(url: &str) -> (Output, Duration) {
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_chisei-gateway"))
        .args(["refresh", "--url", url])
        .env_clear()
        .env("LLM_HTTP_CONNECT_TIMEOUT_SECS", "1")
        .env("LLM_HTTP_REQUEST_TIMEOUT_SECS", "1")
        .output()
        .expect("spawn chisei-gateway refresh");
    (output, started.elapsed())
}

#[test]
fn refresh_against_a_listener_that_never_responds_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind silent listener");
    let addr = listener.local_addr().expect("silent listener addr");
    let _hold = std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            std::mem::forget(stream);
        }
    });

    let (output, elapsed) = refresh_against(&format!("http://{addr}"));
    assert!(!output.status.success(), "{output:?}");
    let err = stderr(&output);
    let lowered = err.to_ascii_lowercase();
    assert!(
        lowered.contains("timedout")
            || lowered.contains("timed out")
            || lowered.contains("timeout"),
        "expected a timeout error, got {err}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "refresh hung for {elapsed:?} instead of giving up within the request timeout"
    );
}

#[test]
fn refresh_against_a_responsive_endpoint_succeeds() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind refresh listener");
    let addr = listener.local_addr().expect("refresh listener addr");
    let _hold = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = "{\"refreshed\":true}";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let (output, _) = refresh_against(&format!("http://{addr}"));
    assert!(output.status.success(), "{output:?}");
    assert!(
        stdout(&output).contains("{\"refreshed\":true}"),
        "{}",
        stdout(&output)
    );
}
