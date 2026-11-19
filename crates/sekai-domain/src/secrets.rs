use std::error::Error;

/// Resolve a secret from the local environment or, when compiled with the
/// `secret-command` feature, by passing an opaque reference to a configured
/// secrets-manager adapter. Direct environment values intentionally take
/// precedence to preserve the local-development workflow.
pub fn resolve_optional(
    value_env: &str,
    reference_env: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    select_secret(
        nonempty_env(value_env),
        nonempty_env(reference_env),
        resolve_reference,
    )
}

fn select_secret<F>(
    direct: Option<String>,
    reference: Option<String>,
    resolver: F,
) -> Result<Option<String>, Box<dyn Error>>
where
    F: FnOnce(&str) -> Result<String, Box<dyn Error>>,
{
    match (direct, reference) {
        (Some(value), _) => Ok(Some(value)),
        (None, Some(reference)) => resolver(&reference).map(Some),
        (None, None) => Ok(None),
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// How long `CHISEI_SECRET_COMMAND` may run before it is killed, so a command
/// blocked on a prompt or an unreachable backend cannot hang startup.
#[cfg(any(feature = "secret-command", test))]
const SECRET_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Bytes of a failing command's stderr kept in the error. Stdout carries the
/// secret and is never reported.
#[cfg(any(feature = "secret-command", test))]
const STDERR_SUMMARY_BYTES: usize = 512;

#[cfg(feature = "secret-command")]
fn resolve_reference(reference: &str) -> Result<String, Box<dyn Error>> {
    let command = nonempty_env("CHISEI_SECRET_COMMAND")
        .ok_or("CHISEI_SECRET_COMMAND is required when a secret reference is configured")?;
    run_secret_command(&command, reference, SECRET_COMMAND_TIMEOUT)
}

/// Run `command reference`, killing it after `timeout`, and return its
/// trimmed stdout.
#[cfg(any(feature = "secret-command", test))]
fn run_secret_command(
    command: &str,
    reference: &str,
    timeout: std::time::Duration,
) -> Result<String, Box<dyn Error>> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut child = Command::new(command)
        .arg(reference)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Drain both pipes concurrently so a chatty command cannot block on a
    // full pipe while we wait for it to exit.
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = drain(child.stdout.take().map(|pipe| Box::new(pipe) as _));
    let stderr = drain(child.stderr.take().map(|pipe| Box::new(pipe) as _));
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "secret command did not exit within {}s and was killed",
                timeout.as_secs_f32()
            )
            .into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let stdout = stdout
        .join()
        .map_err(|_| "secret command stdout reader failed")?;
    let stderr = stderr
        .join()
        .map_err(|_| "secret command stderr reader failed")?;
    if !status.success() {
        let summary = String::from_utf8_lossy(&stderr[..stderr.len().min(STDERR_SUMMARY_BYTES)])
            .trim()
            .to_string();
        return Err(
            format!("secret command failed for reference with status {status}: {summary}").into(),
        );
    }
    let value = String::from_utf8(stdout)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err("secret command returned an empty value".into());
    }
    Ok(value)
}

#[cfg(not(feature = "secret-command"))]
fn resolve_reference(_reference: &str) -> Result<String, Box<dyn Error>> {
    Err("secret references require building with --features secret-command".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_secret_takes_precedence_without_resolving_reference() {
        let result = select_secret(
            Some("local-value".to_string()),
            Some("kms://provider/key".to_string()),
            |_| panic!("reference must not be resolved"),
        )
        .unwrap();
        assert_eq!(result.as_deref(), Some("local-value"));
    }

    #[test]
    fn opaque_reference_is_passed_to_adapter() {
        let result = select_secret(None, Some("kms://provider/key".to_string()), |reference| {
            assert_eq!(reference, "kms://provider/key");
            Ok("resolved-value".to_string())
        })
        .unwrap();
        assert_eq!(result.as_deref(), Some("resolved-value"));
    }

    /// Write an executable shell script into a directory unique to this
    /// process and test, so parallel runs never share it.
    #[cfg(unix)]
    fn script(name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "sekai-secret-command-{}-{name}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("adapter.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn secret_command_returns_its_trimmed_value() {
        let adapter = script("ok", r#"printf '  value-for-%s \n' "$1""#);
        let value =
            run_secret_command(adapter.to_str().unwrap(), "ref-1", SECRET_COMMAND_TIMEOUT).unwrap();
        assert_eq!(value, "value-for-ref-1");
    }

    #[cfg(unix)]
    #[test]
    fn a_hung_secret_command_is_killed_at_the_deadline() {
        let adapter = script("hang", "exec sleep 30");
        let started = std::time::Instant::now();
        let error = run_secret_command(
            adapter.to_str().unwrap(),
            "ref-1",
            std::time::Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(error.to_string().contains("did not exit"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_secret_command_reports_bounded_stderr_but_never_stdout() {
        let adapter = script(
            "fail",
            "printf 'leaked-secret'\nprintf 'backend unreachable' >&2\nhead -c 4000 /dev/zero | tr '\\0' x >&2\nexit 3",
        );
        let error = run_secret_command(adapter.to_str().unwrap(), "ref-1", SECRET_COMMAND_TIMEOUT)
            .unwrap_err()
            .to_string();
        assert!(error.contains("backend unreachable"), "{error}");
        assert!(error.contains('3'), "{error}");
        assert!(!error.contains("leaked-secret"), "{error}");
        assert!(error.len() < 700, "{}", error.len());
    }
}
