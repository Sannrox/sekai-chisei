//! sekaictl admin geospatial query commands (#680).

use crate::config::Config;
use crate::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use crate::sekai::geospatial::{self, query_geospatial};
use chrono::Utc;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin geospatial query --namespace <ns> --property <name> --operator <point|distance|contains|intersects> --geometry <json> [--kind <kind>] [--max-distance-m <meters>] [--limit <n>] [--offset <n>] [--actor <principal>]"
}

pub async fn run_geospatial_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("query") => query(parse_query(&args[1..])?).await,
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

struct QueryConfig {
    namespace: String,
    kind: Option<String>,
    property: String,
    operator: String,
    geometry: String,
    max_distance_m: Option<f64>,
    limit: i32,
    offset: i32,
    actor: String,
}

async fn open_db() -> Result<std::sync::Arc<crate::db::runtime_db::RuntimeDb>, BoxErr> {
    let cfg = Config::from_env();
    let backend = RuntimeBackend::initialize(RuntimeBackendConfig::from_env(&cfg.db_path)?)?;
    Ok(backend.database())
}

async fn query(config: QueryConfig) -> Result<(), BoxErr> {
    let db = open_db().await?;
    let query = geospatial::parse_geospatial_query(
        &config.namespace,
        config.kind.as_deref(),
        &config.property,
        &config.operator,
        &config.geometry,
        config.max_distance_m,
        config.limit,
        config.offset,
    )
    .map_err(std::io::Error::other)?;
    let page = query_geospatial(
        db.as_ref(),
        &config.actor,
        &query,
        Utc::now().timestamp_millis(),
    )
    .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&page)?);
    Ok(())
}

fn require_value(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_query(args: &[String]) -> Result<QueryConfig, String> {
    let mut namespace = None;
    let mut kind = None;
    let mut property = None;
    let mut operator = None;
    let mut geometry = None;
    let mut max_distance_m = None;
    let mut limit = 0;
    let mut offset = 0;
    let mut actor = "operator".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--namespace" => {
                namespace = Some(require_value(args, i, "--namespace")?);
                i += 2;
            }
            "--kind" => {
                kind = Some(require_value(args, i, "--kind")?);
                i += 2;
            }
            "--property" => {
                property = Some(require_value(args, i, "--property")?);
                i += 2;
            }
            "--operator" => {
                operator = Some(require_value(args, i, "--operator")?);
                i += 2;
            }
            "--geometry" => {
                geometry = Some(require_value(args, i, "--geometry")?);
                i += 2;
            }
            "--max-distance-m" => {
                let raw = require_value(args, i, "--max-distance-m")?;
                max_distance_m = Some(
                    raw.parse()
                        .map_err(|_| "--max-distance-m must be a number".to_string())?,
                );
                i += 2;
            }
            "--limit" => {
                let raw = require_value(args, i, "--limit")?;
                limit = raw
                    .parse()
                    .map_err(|_| "--limit must be an integer".to_string())?;
                i += 2;
            }
            "--offset" => {
                let raw = require_value(args, i, "--offset")?;
                offset = raw
                    .parse()
                    .map_err(|_| "--offset must be an integer".to_string())?;
                i += 2;
            }
            "--actor" => {
                actor = require_value(args, i, "--actor")?;
                i += 2;
            }
            other => return Err(format!("unknown query option {other}")),
        }
    }
    Ok(QueryConfig {
        namespace: namespace.ok_or("--namespace is required")?,
        kind,
        property: property.ok_or("--property is required")?,
        operator: operator.ok_or("--operator is required")?,
        geometry: geometry.ok_or("--geometry is required")?,
        max_distance_m,
        limit,
        offset,
        actor,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_query;

    #[test]
    fn parses_a_distance_query() {
        let config = parse_query(&[
            "--namespace".into(),
            "sites".into(),
            "--property".into(),
            "location".into(),
            "--operator".into(),
            "distance".into(),
            "--geometry".into(),
            r#"{"type":"sekai.geospatial-value/v1"}"#.into(),
            "--max-distance-m".into(),
            "1500".into(),
            "--kind".into(),
            "site".into(),
        ])
        .unwrap();
        assert_eq!(config.namespace, "sites");
        assert_eq!(config.kind.as_deref(), Some("site"));
        assert_eq!(config.max_distance_m, Some(1500.0));
        assert_eq!(config.actor, "operator");
    }
}
