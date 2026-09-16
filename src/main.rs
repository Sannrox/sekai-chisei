use sekai_chisei::config::Config;
use sekai_chisei::grpc::ServicePlane;
use sekai_chisei::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env();
    if let Some(mode) = std::env::args().nth(1)
        && mode == "gateway-report"
    {
        return run_gateway_report(&config);
    }
    sekai_chisei::server::boot(ServicePlane::from_env())
}

fn run_gateway_report(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    if !args.iter().any(|arg| arg == "--egress") {
        return Err("gateway-report currently requires --egress".into());
    }

    let format = arg_value(&args, "--format").unwrap_or("csv");
    let after = arg_value(&args, "--after")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    let limit = arg_value(&args, "--limit")
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(500);

    let backend_config =
        RuntimeBackendConfig::from_env(&config.db_path).map_err(std::io::Error::other)?;
    let backend = RuntimeBackend::initialize(backend_config).map_err(std::io::Error::other)?;
    let db = backend.database();
    let rows = sekai_chisei::gateway_report::egress_rows(&db, after, limit)?;

    match format {
        "html" => println!(
            "{}",
            sekai_chisei::gateway_report::render_egress_html(&rows)
        ),
        "csv" => print!("{}", sekai_chisei::gateway_report::render_egress_csv(&rows)),
        other => return Err(format!("unsupported report format {other:?}").into()),
    }
    Ok(())
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}
