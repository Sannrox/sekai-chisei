//! sekaictl admin access unmarked list/apply (#1399).

use crate::combined_stores::CombinedStoreLayout;
use crate::config::Config;
use crate::db::store::SekaiStore;
use crate::domain::{ListFilter, Object};
use crate::sekai::markings::{
    self, UnmarkedObjectReport, apply_default_marking, unmarked_object_report,
};
use serde::Serialize;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    concat!(
        "Usage: sekaictl admin access unmarked list --namespace <name>\n",
        "       sekaictl admin access unmarked apply --namespace <name> --marking <token>"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnmarkedCommand {
    List { namespace: String },
    Apply { namespace: String, marking: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnmarkedListReport {
    pub namespace: String,
    pub unmarked: Vec<UnmarkedObjectReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnmarkedApplyReport {
    pub namespace: String,
    pub marking: String,
    pub applied: Vec<UnmarkedObjectReport>,
}

pub fn parse_unmarked_command<I>(args: I) -> Result<UnmarkedCommand, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let command = args.next().ok_or_else(|| usage().to_string())?;
    let remaining: Vec<String> = args.collect();
    match command.as_str() {
        "list" => {
            let flags = take_flags(&remaining, "list", &["--namespace"])?;
            Ok(UnmarkedCommand::List {
                namespace: require_flag(&flags, "list", "--namespace")?,
            })
        }
        "apply" => {
            let flags = take_flags(&remaining, "apply", &["--namespace", "--marking"])?;
            Ok(UnmarkedCommand::Apply {
                namespace: require_flag(&flags, "apply", "--namespace")?,
                marking: require_flag(&flags, "apply", "--marking")?,
            })
        }
        other => Err(format!("unknown unmarked command {other:?}")),
    }
}

pub fn run_unmarked_command(args: Vec<String>) -> Result<(), BoxErr> {
    if args.is_empty() {
        println!("{}", usage());
        return Ok(());
    }
    match parse_unmarked_command(args)? {
        UnmarkedCommand::List { namespace } => {
            let store = open_sekai_store()?;
            let report = list_unmarked(&store, &namespace)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        UnmarkedCommand::Apply { namespace, marking } => {
            let store = open_sekai_store()?;
            let report = apply_unmarked(&store, &namespace, &marking)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
    }
}

pub fn list_unmarked(store: &SekaiStore, namespace: &str) -> Result<UnmarkedListReport, String> {
    let namespace = require_namespace(namespace)?;
    Ok(UnmarkedListReport {
        namespace: namespace.to_string(),
        unmarked: list_namespace_objects(store, namespace)?
            .iter()
            .filter_map(unmarked_object_report)
            .collect(),
    })
}

pub fn apply_unmarked(
    store: &SekaiStore,
    namespace: &str,
    marking: &str,
) -> Result<UnmarkedApplyReport, String> {
    let namespace = require_namespace(namespace)?;
    let token = markings::parse_classification(marking)?
        .as_str()
        .to_string();
    let mut applied = Vec::new();
    for mut object in list_namespace_objects(store, namespace)? {
        let Some(report) = unmarked_object_report(&object) else {
            continue;
        };
        if apply_default_marking(&mut object, &token)? {
            store.update_object(&object)?;
            applied.push(report);
        }
    }
    Ok(UnmarkedApplyReport {
        namespace: namespace.to_string(),
        marking: token,
        applied,
    })
}

fn open_sekai_store() -> Result<SekaiStore, BoxErr> {
    let cfg = Config::from_env();
    let layout = CombinedStoreLayout::from_env(&cfg.db_path).map_err(std::io::Error::other)?;
    Ok(layout.handles().0)
}

fn list_namespace_objects(store: &SekaiStore, namespace: &str) -> Result<Vec<Object>, String> {
    store.list_objects(&ListFilter {
        namespace: Some(namespace.to_string()),
        ..Default::default()
    })
}

fn require_namespace(namespace: &str) -> Result<&str, String> {
    let namespace = namespace.trim();
    if namespace.is_empty() {
        return Err("namespace must not be empty".into());
    }
    Ok(namespace)
}

fn take_flags(
    args: &[String],
    command: &str,
    allowed: &[&str],
) -> Result<Vec<(String, String)>, String> {
    let mut flags = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        if !flag.starts_with("--") || !allowed.contains(&flag.as_str()) {
            return Err(format!("unknown unmarked {command} option {flag}"));
        }
        let value = args
            .get(i + 1)
            .cloned()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        if flags.iter().any(|(name, _)| name == flag) {
            return Err(format!("{flag} specified more than once"));
        }
        flags.push((flag.clone(), value));
        i += 2;
    }
    Ok(flags)
}

fn require_flag(flags: &[(String, String)], command: &str, flag: &str) -> Result<String, String> {
    let value = flags
        .iter()
        .find(|(name, _)| name == flag)
        .map(|(_, value)| value.clone())
        .ok_or_else(|| format!("unmarked {command} requires {flag}"))?;
    if value.trim().is_empty() {
        return Err(format!("{flag} must not be empty"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::store::SekaiStore;
    use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
    use std::collections::HashMap;

    fn object(id: &str, namespace: &str, marking: Option<&str>) -> Object {
        let mut properties = HashMap::new();
        if let Some(marking) = marking {
            properties.insert(OBJECT_CLASSIFICATION_PROPERTY.into(), marking.into());
        }
        Object {
            id: id.into(),
            kind: "artifact".into(),
            name: id.into(),
            namespace: namespace.into(),
            external_id: format!("artifact:{id}"),
            properties,
            created: 0,
            updated: 0,
        }
    }

    #[test]
    fn parse_list_and_apply_require_namespace_and_marking() {
        assert_eq!(
            parse_unmarked_command(["list".into(), "--namespace".into(), "ns".into()]).unwrap(),
            UnmarkedCommand::List {
                namespace: "ns".into()
            }
        );
        assert_eq!(
            parse_unmarked_command([
                "apply".into(),
                "--namespace".into(),
                "ns".into(),
                "--marking".into(),
                "internal".into(),
            ])
            .unwrap(),
            UnmarkedCommand::Apply {
                namespace: "ns".into(),
                marking: "internal".into(),
            }
        );
        assert!(parse_unmarked_command(["list".into()]).is_err());
        assert!(
            parse_unmarked_command(["apply".into(), "--namespace".into(), "ns".into()]).is_err()
        );
    }

    #[test]
    fn list_and_apply_drive_the_store_namespace() {
        let store = SekaiStore::memory();
        store.create_object(&object("open", "ns", None)).unwrap();
        store
            .create_object(&object("marked", "ns", Some("confidential")))
            .unwrap();
        store
            .create_object(&object("other", "other", None))
            .unwrap();

        let listed = list_unmarked(&store, "ns").unwrap();
        assert_eq!(
            listed
                .unmarked
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            vec!["open"]
        );

        let applied = apply_unmarked(&store, "ns", "internal").unwrap();
        assert_eq!(applied.marking, "internal");
        assert_eq!(
            applied
                .applied
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            vec!["open"]
        );
        assert_eq!(
            store
                .get_object("open")
                .unwrap()
                .unwrap()
                .properties
                .get(OBJECT_CLASSIFICATION_PROPERTY)
                .map(String::as_str),
            Some("internal")
        );
        assert_eq!(
            store
                .get_object("marked")
                .unwrap()
                .unwrap()
                .properties
                .get(OBJECT_CLASSIFICATION_PROPERTY)
                .map(String::as_str),
            Some("confidential")
        );
        assert!(list_unmarked(&store, "ns").unwrap().unmarked.is_empty());
        assert_eq!(
            apply_unmarked(&store, "ns", "not-a-marking").unwrap_err(),
            "unknown classification marking: not-a-marking"
        );
    }
}
