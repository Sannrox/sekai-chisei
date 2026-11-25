//! The worker binary speaks the protocol in the library's documentation.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], input: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sekai-object-parser"))
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn rows_go_to_stdout_one_object_per_line() {
    let (code, stdout, _) = run(&["csv", "10"], b"id,n\n1,a\n2,b\n");
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        "{\"id\":\"1\",\"n\":\"a\"}\n{\"id\":\"2\",\"n\":\"b\"}\n"
    );
}

#[test]
fn a_refusal_exits_2_with_its_reason_and_no_rows() {
    for (args, input, reason) in [
        (&["csv", "1"][..], &b"id\n1\n2\n"[..], "too_many_rows"),
        (&["parquet", "10"], b"not parquet", "malformed"),
        (&["xml", "10"], b"<a/>", "malformed"),
    ] {
        let (code, stdout, stderr) = run(args, input);
        assert_eq!((code, stdout.as_str(), stderr.trim()), (2, "", reason));
    }
}
