//! Argument helpers shared by the root crate's command-line modules.

/// Returns the value after the flag at `index`. An absent value, an empty
/// value, or a following `--flag` is refused with `<flag> requires a value`,
/// so `--name --json` never takes `--json` as the name.
pub(crate) fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .filter(|value| !value.is_empty() && !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::require_value;

    #[test]
    fn refuses_a_missing_empty_or_flag_value() {
        let args = |raw: &[&str]| raw.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            require_value(&args(&["--name", "orders"]), 0, "--name"),
            Ok("orders".to_string())
        );
        assert_eq!(
            require_value(&args(&["--limit", "-5"]), 0, "--limit"),
            Ok("-5".to_string())
        );
        for raw in [&["--name"][..], &["--name", ""], &["--name", "--json"]] {
            assert_eq!(
                require_value(&args(raw), 0, "--name"),
                Err("--name requires a value".to_string()),
                "{raw:?}"
            );
        }
    }
}
