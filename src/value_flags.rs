//! Strict `--flag value` validation for operator CLIs whose options all take a
//! value. A misspelled flag must fail instead of leaving a field at its
//! default, which can widen what a write applies to (#2618).

/// Accepts `args` only when it is a sequence of `--flag value` pairs naming
/// each of `known` at most once, with no value that itself looks like a flag.
/// Errors name the offending argument.
pub fn check_value_flags(args: &[String], known: &[&str]) -> Result<(), String> {
    let mut seen: Vec<&str> = Vec::new();
    let mut pairs = args.chunks(2);
    for pair in &mut pairs {
        let name = pair[0].as_str();
        if !known.contains(&name) {
            return Err(format!("unknown option {name}"));
        }
        if seen.contains(&name) {
            return Err(format!("{name} was given more than once"));
        }
        match pair.get(1) {
            Some(value) if !value.starts_with("--") => {}
            _ => return Err(format!("{name} requires a value")),
        }
        seen.push(name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn accepts_known_pairs_and_names_the_offending_argument() {
        let known = ["--digest", "--reason"];
        assert!(check_value_flags(&args(&["--reason", "r", "--digest", "d"]), &known).is_ok());
        assert!(check_value_flags(&[], &known).is_ok());
        assert_eq!(
            check_value_flags(&args(&["--digets", "d"]), &known).unwrap_err(),
            "unknown option --digets"
        );
        assert_eq!(
            check_value_flags(&args(&["--reason", "a", "--reason", "b"]), &known).unwrap_err(),
            "--reason was given more than once"
        );
        assert_eq!(
            check_value_flags(&args(&["--reason", "--digest", "d"]), &known).unwrap_err(),
            "--reason requires a value"
        );
        assert_eq!(
            check_value_flags(&args(&["--digest"]), &known).unwrap_err(),
            "--digest requires a value"
        );
    }
}
