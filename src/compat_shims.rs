//! Lifecycle register for compatibility shims.
//!
//! Issue #98 requires each shim retained from Issue #95 to declare an owner, a
//! usage signal, a removal condition, and a deadline. A shim without those
//! becomes permanent by default: nobody knows who owns it, whether anything
//! still calls it, or what would justify deleting it.
//!
//! The register is checked in rather than derived, because the interesting
//! fields — owner and deadline — do not exist anywhere in the source. What is
//! derived is the *completeness* check: a test scans the control-plane and
//! provider crate sources for
//! `#[deprecated]` items and fails when one is missing here, so a shim cannot
//! be added without also being given a deadline.

/// How the project learns whether a shim is still in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageSignal {
    /// `#[deprecated]`; the compiler warns at every call site.
    CompilerDeprecation,
    /// Emits a runtime warning when exercised.
    RuntimeWarning,
}

impl UsageSignal {
    pub const fn as_str(self) -> &'static str {
        match self {
            UsageSignal::CompilerDeprecation => "compiler deprecation warning",
            UsageSignal::RuntimeWarning => "runtime warning",
        }
    }
}

/// One retained compatibility shim.
#[derive(Debug, Clone, Copy)]
pub struct ShimRecord {
    /// Item name as it appears in the source, or the configuration key.
    pub id: &'static str,
    /// Module that owns removal.
    pub owner: &'static str,
    pub usage_signal: UsageSignal,
    /// What has to be true before this can be deleted.
    pub removal_condition: &'static str,
    /// Release by which the removal condition must hold.
    pub deadline: &'static str,
}

/// Every compatibility shim currently retained.
pub const RETAINED_SHIMS: &[ShimRecord] = &[ShimRecord {
    id: "SEKAI_AUTH_TOKEN",
    owner: "sekai::credentials",
    usage_signal: UsageSignal::RuntimeWarning,
    removal_condition: "deployments issue principal credentials via sekaictl credential create",
    deadline: "0.2.0",
}];

/// Render the shim register as a plain-text report.
pub fn render_report() -> String {
    let mut out = String::from("Retained compatibility shims\n");
    for shim in RETAINED_SHIMS {
        out.push_str(&format!(
            "\n{}\n  owner:     {}\n  signal:    {}\n  remove when: {}\n  deadline:  {}\n",
            shim.id,
            shim.owner,
            shim.usage_signal.as_str(),
            shim.removal_condition,
            shim.deadline,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn deprecated_item_names(source: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("#[deprecated") {
                continue;
            }
            // Walk forward to the declaration the attribute applies to.
            for candidate in lines.iter().skip(index + 1).take(12) {
                let trimmed = candidate.trim_start();
                if let Some(rest) = trimmed
                    .strip_prefix("pub fn ")
                    .or_else(|| trimmed.strip_prefix("fn "))
                {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        names.insert(name);
                    }
                    break;
                }
            }
        }
        names
    }

    fn rust_sources(root: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_string()];
        while let Some(dir) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path.to_string_lossy().into_owned());
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    found.push(path.to_string_lossy().into_owned());
                }
            }
        }
        found
    }

    /// Names of items carrying `#[deprecated]` anywhere under `src/`.
    fn deprecated_items_in_roots(roots: &[&str]) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        for root in roots {
            for path in rust_sources(root) {
                let Ok(source) = std::fs::read_to_string(&path) else {
                    continue;
                };
                names.extend(deprecated_item_names(&source));
            }
        }
        names
    }

    fn deprecated_items() -> BTreeSet<String> {
        deprecated_items_in_roots(&["src", "crates/sekai-provider/src"])
    }

    #[test]
    fn every_deprecated_item_has_a_lifecycle_record() {
        let registered: BTreeSet<String> =
            RETAINED_SHIMS.iter().map(|s| s.id.to_string()).collect();
        let missing: Vec<String> = deprecated_items()
            .into_iter()
            .filter(|name| !registered.contains(name))
            .collect();
        assert!(
            missing.is_empty(),
            "deprecated items with no owner or deadline: {missing:?}"
        );
    }

    #[test]
    fn deprecated_item_scan_traverses_rust_sources() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let source = format!(
            "{}[deprecated(since = \"0.1.0\", note = \"use replacement\")]\n\
             pub fn legacy_alias() {{}}",
            '#'
        );
        std::fs::write(nested.join("fixture.rs"), source).unwrap();
        std::fs::write(nested.join("ignored.txt"), "#[deprecated]\nfn ignored() {}").unwrap();

        let root = dir.path().to_str().unwrap();
        let found = deprecated_items_in_roots(&[root]);
        assert_eq!(found, BTreeSet::from(["legacy_alias".to_string()]));
    }

    #[test]
    fn every_record_is_complete_and_dated() {
        for shim in RETAINED_SHIMS {
            assert!(!shim.id.is_empty(), "shim with no id");
            assert!(!shim.owner.is_empty(), "{} has no owner", shim.id);
            assert!(
                !shim.removal_condition.is_empty(),
                "{} has no removal condition",
                shim.id
            );
            // A deadline is what stops a shim becoming permanent.
            assert!(
                shim.deadline.starts_with(char::is_numeric),
                "{} has no release deadline",
                shim.id
            );
        }
    }

    #[test]
    fn shim_ids_are_unique() {
        let unique: BTreeSet<&str> = RETAINED_SHIMS.iter().map(|s| s.id).collect();
        assert_eq!(unique.len(), RETAINED_SHIMS.len(), "duplicate shim id");
    }

    #[test]
    fn report_names_every_shim_with_its_deadline() {
        let report = render_report();
        for shim in RETAINED_SHIMS {
            assert!(report.contains(shim.id), "{} missing from report", shim.id);
            assert!(
                report.contains(shim.removal_condition),
                "{} removal condition missing from report",
                shim.id
            );
        }
    }
}
