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

#[cfg(feature = "secret-command")]
fn resolve_reference(reference: &str) -> Result<String, Box<dyn Error>> {
    use std::process::Command;

    let command = nonempty_env("CHISEI_SECRET_COMMAND")
        .ok_or("CHISEI_SECRET_COMMAND is required when a secret reference is configured")?;
    let output = Command::new(&command).arg(reference).output()?;
    if !output.status.success() {
        return Err(format!(
            "secret command failed for reference with status {}",
            output.status
        )
        .into());
    }
    let value = String::from_utf8(output.stdout)?;
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
}
