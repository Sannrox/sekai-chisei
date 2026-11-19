use chisei_provider::cost_estimate::{
    CostEstimateConfig, estimate_cost, pricing_from_env, render_estimate, usage as estimate_usage,
};
use sekai_admin_client::client::connect_sekai;
use sekai_admin_client::gateway_report::{GatewayReportConfig, report_usage, run_report};
use sekai_admin_client::gateway_setup::{
    GatewaySetupConfig, key_usage, run_gateway_key_command, run_setup, usage as setup_usage,
};
use sekai_proto::sekai::GetProvenanceReportRequest;
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekaictl::credential_cli::{
    CredentialCommand, create_credential, list_credentials, parse_credential_command,
    revoke_credential, rotate_credential, usage as credential_usage,
};
use sekaictl::launch::{LaunchConfig, run_launch, usage as launch_usage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_root_usage();
        return Ok(());
    }
    if args.len() == 1 && (args[0] == "--version" || args[0] == "-V") {
        println!(
            "sekaictl {} ({})",
            env!("CARGO_PKG_VERSION"),
            sekai_obs::build_info::GIT_VERSION
        );
        return Ok(());
    }
    if args[0] == "admin"
        && (args.len() == 1
            || args
                .get(1)
                .is_some_and(|arg| arg == "--help" || arg == "-h"))
    {
        print_admin_usage();
        return Ok(());
    }
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        print_root_usage();
        return Ok(());
    }
    let is_admin_path = args[0] == "admin";
    if !is_admin_path && let Some(help) = removed_alias_help(&args[0]) {
        eprintln!("{help}");
        std::process::exit(2);
    }
    let has_help = help_requested(&args);
    if is_admin_path && has_help && expand_admin_args(args.clone()).is_err() {
        print_admin_usage();
        return Ok(());
    }
    args = expand_admin_args(args).map_err(|error| {
        print_admin_usage();
        std::io::Error::other(error)
    })?;
    if (has_help && !handles_own_help(&args)) || (is_admin_path && args.len() == 1) {
        if let Some(usage) = expert_usage(&args[0]) {
            println!("{usage}");
        } else {
            print_root_usage();
        }
        return Ok(());
    }

    match args[0].as_str() {
        "credential" => run_credential_command(args.into_iter().skip(1).collect()).await,
        "unmarked" => {
            sekaictl::unmarked_cli::run_unmarked_command(args.into_iter().skip(1).collect())
        }
        "gateway" => run_gateway_command(args.into_iter().skip(1).collect()).await,
        "action" => {
            sekaictl::action_cli::run_action_command(args.into_iter().skip(1).collect()).await
        }
        "budget" => {
            sekaictl::budget_cli::run_budget_command(args.into_iter().skip(1).collect()).await
        }
        "attest" => {
            sekaictl::attest_cli::run_attest_command(args.into_iter().skip(1).collect()).await
        }
        "compliance" => {
            sekaictl::compliance_cli::run_compliance_command(args.into_iter().skip(1).collect())
                .await
        }
        "audit" => {
            sekaictl::audit_export_cli::run_audit_command(args.into_iter().skip(1).collect()).await
        }
        "receipts" => {
            sekaictl::receipt_chain_cli::run_receipts_command(args.into_iter().skip(1).collect())
                .await
        }
        "probes" => {
            sekaictl::probe_cli::run_probes_command(args.into_iter().skip(1).collect()).await
        }
        "federation" => {
            sekaictl::federation_cli::run_federation_command(args.into_iter().skip(1).collect())
                .await
        }
        "network" => {
            sekaictl::federation_network_cli::run_network_command(
                args.into_iter().skip(1).collect(),
            )
            .await
        }
        "workflow" => {
            sekaictl::workflow_action_cli::run_workflow_command(args.into_iter().skip(1).collect())
                .await
        }
        "connectors" => {
            sekaictl::connector_certification_cli::run_connectors_command(
                args.into_iter().skip(1).collect(),
            )
            .await
        }
        "warehouse" => {
            sekaictl::warehouse_projection_cli::run_warehouse_command(
                args.into_iter().skip(1).collect(),
            )
            .await
        }
        "lakehouse" => {
            sekaictl::lakehouse_snapshot_cli::run_lakehouse_command(
                args.into_iter().skip(1).collect(),
            )
            .await
        }
        "providers" => {
            sekaictl::model_platform_cli::run_providers_command(args.into_iter().skip(1).collect())
                .await
        }
        "model-review" => {
            sekaictl::model_review_cli::run_model_review_command(args.into_iter().skip(1).collect())
                .await
        }
        "model-release-evidence" => {
            sekaictl::model_release_evidence_cli::run_model_release_evidence_command(
                args.into_iter().skip(1).collect(),
            )
            .await
        }
        "autonomy" => {
            sekaictl::autonomous_envelope_cli::run_autonomy_command(
                args.into_iter().skip(1).collect(),
            )
            .await
        }
        "learning" => {
            sekaictl::learning_cli::run_learning_command(args.into_iter().skip(1).collect()).await
        }
        "geospatial" => {
            sekaictl::geospatial_cli::run_geospatial_command(args.into_iter().skip(1).collect())
                .await
        }
        "transform" => {
            sekaictl::transform_cli::run_transform_command(args.into_iter().skip(1).collect()).await
        }
        "quality" => {
            sekaictl::quality_cli::run_quality_command(args.into_iter().skip(1).collect()).await
        }
        "store" => {
            chisei_core::store_relocate::run_store_command(args.into_iter().skip(1).collect())
        }
        "retention" => {
            sekaictl::retention_cli::run_retention_command(args.into_iter().skip(1).collect())
        }
        "sync" => {
            sekaictl::source_webhook_cli::run_sync_command(args.into_iter().skip(1).collect()).await
        }
        "tables" => {
            sekaictl::open_table_cli::run_tables_command(args.into_iter().skip(1).collect()).await
        }
        "streams" => {
            sekaictl::event_stream_cli::run_streams_command(args.into_iter().skip(1).collect())
                .await
        }
        "documents" => {
            sekaictl::document_cli::run_documents_command(args.into_iter().skip(1).collect()).await
        }
        "images" => {
            sekaictl::image_cli::run_images_command(args.into_iter().skip(1).collect()).await
        }
        "sdk-packages" => {
            sekaictl::client_package_cli::run_sdk_packages_command(
                args.into_iter().skip(1).collect(),
            )
            .await
        }
        "compatibility" => {
            sekaictl::compatibility_cli::run_compatibility_command(
                args.into_iter().skip(1).collect(),
            )
            .await
        }
        "packages" => {
            sekaictl::capability_package_cli::run_packages_command(
                args.into_iter().skip(1).collect(),
            )
            .await
        }
        "receipt" => {
            sekaictl::receipt_cli::run_receipt_command(args.into_iter().skip(1).collect()).await
        }
        "replay" => match args.get(1).map(String::as_str) {
            Some("export") => {
                let config =
                    sekaictl::replay_cli::ReplayExportConfig::from_args(args.into_iter().skip(2))
                        .map_err(std::io::Error::other)?;
                sekaictl::replay_cli::run_export(config).await
            }
            _ => Err(std::io::Error::other(sekaictl::replay_cli::usage()).into()),
        },
        "report" => {
            sekaictl::report_cli::run_report_command(args.into_iter().skip(1).collect()).await
        }
        "inbox" => {
            sekaictl::launch::load_local_env();
            sekaictl::inbox_cli::run_inbox_command(args.into_iter().skip(1).collect()).await
        }
        "models" => {
            let config =
                sekaictl::models_cli::ModelsListConfig::from_args(args.into_iter().skip(1))
                    .map_err(std::io::Error::other)?;
            print!("{}", sekaictl::models_cli::run_models_list(config).await?);
            Ok(())
        }
        "gunshi" => match args.get(1).map(String::as_str) {
            Some("recommend") => {
                let config =
                    sekaictl::gunshi_cli::RecommendConfig::from_args(args.into_iter().skip(2))
                        .map_err(std::io::Error::other)?;
                let output = config.output.clone();
                sekaictl::gunshi_cli::run_recommend(config)?;
                println!("created {}", output.display());
                Ok(())
            }
            _ => Err(std::io::Error::other(sekaictl::gunshi_cli::usage()).into()),
        },
        "governed-subject" => {
            sekaictl::governed_subject_cli::run(args.into_iter().skip(1).collect()).await
        }
        "evaluation-plan" => {
            match sekaictl::evaluation_plan_cli::run(args.into_iter().skip(1).collect()).await {
                Ok(()) => Ok(()),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(error.exit_code());
                }
            }
        }
        "team" => match args.get(1).map(String::as_str) {
            Some("join") => {
                let config =
                    sekaictl::team_cli::TeamJoinConfig::from_env_and_args(args.into_iter().skip(2))
                        .map_err(std::io::Error::other)?;
                let bundle = sekaictl::team_cli::run_team_join(config)
                    .await
                    .map_err(std::io::Error::other)?;
                println!("{}", serde_json::to_string_pretty(&bundle)?);
                Ok(())
            }
            Some("weekly-report") => {
                let config = sekaictl::weekly_report_cli::WeeklyReportConfig::from_args(
                    args.into_iter().skip(2),
                )
                .map_err(std::io::Error::other)?;
                let output = config.output.clone();
                sekaictl::weekly_report_cli::run_weekly_report(config).await?;
                println!("created {}", output.display());
                Ok(())
            }
            _ => Err(std::io::Error::other(format!(
                "{}\n  {}",
                sekaictl::team_cli::usage(),
                sekaictl::weekly_report_cli::usage()
            ))
            .into()),
        },
        "estimate" => {
            sekaictl::launch::load_local_env();
            let config = CostEstimateConfig::from_args(args.into_iter().skip(1))
                .map_err(std::io::Error::other)?;
            let pricing = pricing_from_env().map_err(std::io::Error::other)?;
            let estimate = estimate_cost(&config, &pricing).map_err(std::io::Error::other)?;
            println!("{}", render_estimate(&config, &estimate));
            Ok(())
        }
        "launch" => {
            sekaictl::launch::load_local_env();
            let config = LaunchConfig::from_env_and_args(args.into_iter().skip(1))
                .map_err(std::io::Error::other)?;
            run_launch(config).await
        }
        "doctor" => {
            sekaictl::launch::load_local_env();
            let agent = args.get(1).map(String::as_str);
            if args.len() > 2 {
                return Err(std::io::Error::other(
                    "usage: sekaictl doctor [codex-app|claude-code]",
                )
                .into());
            }
            let checks = sekaictl::onboarding::run_doctor(agent);
            print!("{}", sekaictl::onboarding::render_doctor(&checks));
            if checks
                .iter()
                .any(|check| check.status == sekaictl::onboarding::CheckStatus::Failed)
            {
                return Err(std::io::Error::other("doctor found blocking failures").into());
            }
            Ok(())
        }
        "smoke" => {
            sekaictl::launch::load_local_env();
            let model = args.get(1).map(String::as_str).unwrap_or("gpt-5.5");
            if args.len() > 2 {
                return Err(std::io::Error::other("usage: sekaictl smoke [model]").into());
            }
            print!(
                "{}",
                sekaictl::onboarding::run_smoke(model)
                    .await
                    .map_err(std::io::Error::other)?
            );
            Ok(())
        }
        "provenance" => {
            sekaictl::launch::load_local_env();
            let work_unit = args.get(1).ok_or_else(|| {
                std::io::Error::other("usage: sekaictl admin assurance provenance <work-unit>")
            })?;
            let target = std::env::var("CHISEI_GRPC_URL")
                .or_else(|_| std::env::var("SEKAI_SOCKET"))
                .unwrap_or_else(|_| "./data/sekai.sock".into());
            let channel = connect_sekai(&target).await?;
            let report = SekaiServiceClient::new(channel)
                .get_provenance_report(GetProvenanceReportRequest {
                    work_unit_id: work_unit.clone(),
                })
                .await?
                .into_inner();
            print!("{}", report.report);
            Ok(())
        }
        "ontology" => match args.get(1).map(String::as_str) {
            Some("inspect") => {
                sekaictl::launch::load_local_env();
                let config = sekaictl::ontology_inspect::InspectConfig::from_env_and_args(
                    args.into_iter().skip(2),
                )
                .map_err(std::io::Error::other)?;
                let output = config.output.clone();
                sekaictl::ontology_inspect::run_inspect(config).await?;
                println!("created {}", output.display());
                Ok(())
            }
            Some(
                "apply" | "export" | "import" | "draft" | "seed" | "run" | "first-run" | "context"
                | "expand" | "explain" | "lint",
            ) => {
                sekaictl::launch::load_local_env();
                sekaictl::ontology_product_cli::run_ontology_product_command(
                    args.into_iter().skip(1).collect(),
                )
                .await
            }
            _ => Err(std::io::Error::other(sekaictl::ontology_product_cli::usage()).into()),
        },
        other => {
            eprintln!("unknown command {other:?}");
            print_root_usage();
            Err(std::io::Error::other("unknown command").into())
        }
    }
}

fn expand_admin_args(mut args: Vec<String>) -> Result<Vec<String>, String> {
    if args.first().map(String::as_str) != Some("admin") {
        return Ok(args);
    }

    let replacement = match (
        args.get(1).map(String::as_str),
        args.get(2).map(String::as_str),
    ) {
        (Some("access"), Some("credential")) => ("credential", 3),
        (Some("access"), Some("unmarked")) => ("unmarked", 3),
        (Some("access"), Some("team")) => ("team", 3),
        (Some("gateway"), _) => ("gateway", 2),
        (Some("governance"), Some("action")) => ("action", 3),
        (Some("governance"), Some("budget")) => ("budget", 3),
        (Some("governance"), Some("gunshi")) => ("gunshi", 3),
        (Some("governance"), Some("subject")) => ("governed-subject", 3),
        (Some("evaluation"), Some("plan")) => ("evaluation-plan", 3),
        (Some("assurance"), Some("attest")) => ("attest", 3),
        (Some("assurance"), Some("compliance")) => ("compliance", 3),
        (Some("assurance"), Some("receipts")) => ("receipts", 3),
        (Some("assurance"), Some("audit")) => ("audit", 3),
        (Some("assurance"), Some("probes")) => ("probes", 3),
        (Some("assurance"), Some("provenance")) => ("provenance", 3),
        (Some("assurance"), Some("replay")) => ("replay", 3),
        (Some("federation"), _) => ("federation", 2),
        (Some("network"), _) => ("network", 2),
        (Some("learning"), _) => ("learning", 2),
        (Some("geospatial"), _) => ("geospatial", 2),
        (Some("transform"), _) => ("transform", 2),
        (Some("quality"), _) => ("quality", 2),
        (Some("sync"), _) => ("sync", 2),
        (Some("tables"), _) => ("tables", 2),
        (Some("streams"), _) => ("streams", 2),
        (Some("documents"), _) => ("documents", 2),
        (Some("images"), _) => ("images", 2),
        (Some("sdk-packages"), _) => ("sdk-packages", 2),
        (Some("compatibility"), _) => ("compatibility", 2),
        (Some("packages"), _) => ("packages", 2),
        (Some("workflow"), _) => ("workflow", 2),
        (Some("connectors"), _) => ("connectors", 2),
        (Some("warehouse"), _) => ("warehouse", 2),
        (Some("lakehouse"), _) => ("lakehouse", 2),
        (Some("providers"), _) => ("providers", 2),
        (Some("model-review"), _) => ("model-review", 2),
        (Some("model-release-evidence"), _) => ("model-release-evidence", 2),
        (Some("autonomy"), _) => ("autonomy", 2),
        (Some("store"), _) => ("store", 2),
        (Some("retention"), _) => ("retention", 2),
        _ => return Err("unknown admin command".to_string()),
    };

    let mut expanded = vec![replacement.0.to_string()];
    expanded.extend(args.drain(replacement.1..));
    Ok(expanded)
}

async fn run_credential_command(
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if args.is_empty() {
        println!("{}", credential_usage());
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", credential_usage());
        return Ok(());
    }

    let command = parse_credential_command(args)?;
    match command {
        CredentialCommand::Create { principal } => {
            let token = create_credential(&principal)
                .await
                .map_err(std::io::Error::other)?;
            println!("{}", token);
        }
        CredentialCommand::Rotate { principal } => {
            let token = rotate_credential(&principal)
                .await
                .map_err(std::io::Error::other)?;
            println!("{}", token);
        }
        CredentialCommand::Revoke { principal } => {
            revoke_credential(&principal)
                .await
                .map_err(std::io::Error::other)?;
        }
        CredentialCommand::BulkCreate { principals } => {
            for principal in principals {
                let token = create_credential(&principal)
                    .await
                    .map_err(std::io::Error::other)?;
                println!("{principal}\t{token}");
            }
        }
        CredentialCommand::BulkRotate { principals } => {
            for principal in principals {
                let token = rotate_credential(&principal)
                    .await
                    .map_err(std::io::Error::other)?;
                println!("{principal}\t{token}");
            }
        }
        CredentialCommand::BulkRevoke { principals } => {
            for principal in principals {
                revoke_credential(&principal)
                    .await
                    .map_err(std::io::Error::other)?;
                println!("{principal}\trevoked");
            }
        }
        CredentialCommand::List => {
            let credentials = list_credentials().await.map_err(std::io::Error::other)?;
            println!("principal\tstatus\tcreated\trotated_at");
            for credential in credentials {
                println!(
                    "{}\t{}\t{}\t{}",
                    credential.principal,
                    credential.status,
                    credential.created,
                    credential.rotated_at
                );
            }
        }
        _ => return Err("unsupported credential command".into()),
    }

    Ok(())
}

async fn run_gateway_command(
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if args.is_empty() {
        print_gateway_usage();
        return Ok(());
    }
    if args[0] == "key" {
        // `gateway key` prints its own usage for help anywhere in its
        // arguments, so `key create --help` never runs a create.
        if help_requested(&args[1..]) {
            println!("{}", key_usage());
            return Ok(());
        }
        return run_gateway_key_command(args.into_iter().skip(1)).await;
    }
    if help_requested(&args) {
        print_gateway_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "setup" => {
            let config = GatewaySetupConfig::from_env_and_args(args.into_iter().skip(1))
                .map_err(std::io::Error::other)?;
            run_setup(config).await
        }
        "report" => {
            let config = GatewayReportConfig::from_env_and_args(args.into_iter().skip(1))
                .map_err(std::io::Error::other)?;
            run_report(config).await
        }
        other => {
            eprintln!("unknown gateway command {other:?}");
            print_gateway_usage();
            Err(std::io::Error::other("unknown gateway command").into())
        }
    }
}

fn print_root_usage() {
    println!(
        "Usage: sekaictl [--version] <ontology|launch|doctor|smoke|models|estimate|receipt|report|inbox|admin> ...\n"
    );
    println!("Product loop (ontology-first):");
    println!("  {}", sekaictl::ontology_product_cli::usage());
    println!("  {}", sekaictl::ontology_inspect::usage());
    println!("\nLaunch commands:");
    println!("  {}", launch_usage());
    println!("\nDiagnostics:\n  sekaictl doctor [codex-app|claude-code]");
    println!("\nFirst governed operation (model smoke):\n  sekaictl smoke [model]");
    println!("\nCost estimate:");
    println!("  {}", estimate_usage());
    println!("\nOperation receipt:\n  {}", sekaictl::receipt_cli::usage());
    println!("\nOperation report:\n  {}", sekaictl::report_cli::usage());
    println!(
        "\nDecisions waiting on you:\n  {}",
        sekaictl::inbox_cli::usage()
    );
    println!("\nModel commands:\n  {}", sekaictl::models_cli::USAGE);
    println!("\nExpert administration:\n  sekaictl admin --help");
}

fn print_admin_usage() {
    println!(
        "Usage: sekaictl admin <access|gateway|governance|evaluation|assurance|federation> ...\n\
         \n\
         Access:\n\
           sekaictl admin access credential ...\n\
           sekaictl admin access unmarked ...\n\
           sekaictl admin access team ...\n\
         \n\
         Gateway:\n\
           sekaictl admin gateway ...\n\
         \n\
         Governance:\n\
           sekaictl admin governance <action|budget|gunshi|subject> ...\n\
         \n\
         Evaluation:\n\
           sekaictl admin evaluation plan ...\n\
         \n\
         Assurance:\n\
           sekaictl admin assurance <attest|audit|compliance|provenance|replay|receipts|probes> ...\n\
         \n\
         Federation:\n\
           sekaictl admin federation ...\n\
         \n\
         Learning:\n\
           sekaictl admin learning ...\n\
         \n\
         Geospatial:\n\
           sekaictl admin geospatial ...\n\
         \n\
         Transforms:\n\
           sekaictl admin transform ...\n\
         \n\
         Quality:\n\
           sekaictl admin quality ...\n\
         \n\
         Sync:\n\
           sekaictl admin sync ...\n\
         \n\
         Tables:\n\
           sekaictl admin tables ...\n\
         \n\
         Streams:\n\
           sekaictl admin streams ...\n\
         \n\
         Documents:\n\
           sekaictl admin documents ...\n\
         \n\
         Images:\n\
           sekaictl admin images ...\n\
         \n\
         SDK packages:\n\
           sekaictl admin sdk-packages ...\n\
         \n\
         Compatibility:\n\
           sekaictl admin compatibility ...\n\
         \n\
         Capability packages:\n\
           sekaictl admin packages ...\n\
         \n\
         Network:\n\
           sekaictl admin network ...\n\
         \n\
         Workflow:\n\
           sekaictl admin workflow ...\n\
         \n\
         Connectors:\n\
           sekaictl admin connectors ...\n\
         \n\
         Warehouse:\n\
           sekaictl admin warehouse ...\n\
         \n\
         Lakehouse:\n\
           sekaictl admin lakehouse ...\n\
         \n\
         Providers:\n\
           sekaictl admin providers ...\n\
         \n\
         Model review:\n\
           sekaictl admin model-review ...\n\
         \n\
         Model-release evidence:\n\
           sekaictl admin model-release-evidence ...\n\
         \n\
         Autonomy:\n\
           sekaictl admin autonomy ...\n\
         \n\
         Store:\n\
           sekaictl admin store relocate ...\n\
           sekaictl admin store restamp ...\n\
           sekaictl admin store migrate-object-log ...\n\
         \n\
         Retention:\n\
           sekaictl admin retention status\n\
           sekaictl admin retention dry-run\n\
           sekaictl admin retention run\n\
           sekaictl admin retention policy list\n\
           sekaictl admin retention policy set --dataset <name> --days <n>\n\
           sekaictl admin retention policy delete --dataset <name>"
    );
}

/// Whether the arguments ask for help. Scanning stops at `--`, so a `--help`
/// after it is passed through as a value.
fn help_requested(args: &[String]) -> bool {
    args.iter()
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--help" || arg == "-h")
}

/// Whether the dispatched command prints a more specific usage than its
/// top-level expert usage, so `main` must hand the help request through.
fn handles_own_help(args: &[String]) -> bool {
    args.first().is_some_and(|command| command == "gateway")
        && args.get(1).is_some_and(|sub| sub == "key")
}

fn expert_usage(command: &str) -> Option<String> {
    match command {
        "credential" => Some(credential_usage().to_string()),
        "unmarked" => Some(sekaictl::unmarked_cli::usage().to_string()),
        "gateway" => Some(gateway_usage()),
        "action" => Some(sekaictl::action_cli::usage().to_string()),
        "budget" => Some(sekaictl::budget_cli::usage().to_string()),
        "inbox" => Some(sekaictl::inbox_cli::usage().to_string()),
        "gunshi" => Some(sekaictl::gunshi_cli::usage().to_string()),
        "governed-subject" => Some(sekaictl::governed_subject_cli::usage().to_string()),
        "evaluation-plan" => Some(sekaictl::evaluation_plan_cli::usage().to_string()),
        "attest" => Some(sekaictl::attest_cli::usage().to_string()),
        "compliance" => Some(sekaictl::compliance_cli::usage().to_string()),
        "receipts" => Some(sekaictl::receipt_chain_cli::usage().to_string()),
        "audit" => Some(sekaictl::audit_export_cli::usage().to_string()),
        "probes" => Some(sekaictl::probe_cli::usage().to_string()),
        "provenance" => Some("usage: sekaictl admin assurance provenance <work-unit>".to_string()),
        "replay" => Some(sekaictl::replay_cli::usage().to_string()),
        "team" => Some(format!(
            "{}\n  {}",
            sekaictl::team_cli::usage(),
            sekaictl::weekly_report_cli::usage()
        )),
        "federation" => Some(sekaictl::federation_cli::usage().to_string()),
        "learning" => Some(sekaictl::learning_cli::usage().to_string()),
        "geospatial" => Some(sekaictl::geospatial_cli::usage().to_string()),
        "transform" => Some(sekaictl::transform_cli::usage().to_string()),
        "quality" => Some(sekaictl::quality_cli::usage().to_string()),
        "sync" => Some(sekaictl::source_webhook_cli::usage().to_string()),
        "tables" => Some(sekaictl::open_table_cli::usage().to_string()),
        "streams" => Some(sekaictl::event_stream_cli::usage().to_string()),
        "documents" => Some(sekaictl::document_cli::usage().to_string()),
        "images" => Some(sekaictl::image_cli::usage().to_string()),
        "sdk-packages" => Some(sekaictl::client_package_cli::usage().to_string()),
        "compatibility" => Some(sekaictl::compatibility_cli::usage().to_string()),
        "packages" => Some(sekaictl::capability_package_cli::usage().to_string()),
        "network" => Some(sekaictl::federation_network_cli::usage().to_string()),
        "workflow" => Some(sekaictl::workflow_action_cli::usage().to_string()),
        "connectors" => Some(sekaictl::connector_certification_cli::usage().to_string()),
        "warehouse" => Some(sekaictl::warehouse_projection_cli::usage().to_string()),
        "lakehouse" => Some(sekaictl::lakehouse_snapshot_cli::usage().to_string()),
        "providers" => Some(sekaictl::model_platform_cli::usage().to_string()),
        "model-review" => Some(sekaictl::model_review_cli::usage().to_string()),
        "model-release-evidence" => Some(sekaictl::model_release_evidence_cli::usage().to_string()),
        "autonomy" => Some(sekaictl::autonomous_envelope_cli::usage().to_string()),
        "store" => Some(chisei_core::store_relocate::usage().to_string()),
        "retention" => Some(sekaictl::retention_cli::usage().to_string()),
        _ => None,
    }
}

fn canonical_admin_path(command: &str) -> Option<&'static str> {
    match command {
        "credential" => Some("admin access credential"),
        "team" => Some("admin access team"),
        "gateway" => Some("admin gateway"),
        "action" => Some("admin governance action"),
        "gunshi" => Some("admin governance gunshi"),
        "governed-subject" => Some("admin governance subject"),
        "evaluation-plan" => Some("admin evaluation plan"),
        "attest" => Some("admin assurance attest"),
        "compliance" => Some("admin assurance compliance"),
        "provenance" => Some("admin assurance provenance"),
        "replay" => Some("admin assurance replay"),
        "federation" => Some("admin federation"),
        "sync" => Some("admin sync"),
        "tables" => Some("admin tables"),
        "streams" => Some("admin streams"),
        "documents" => Some("admin documents"),
        "images" => Some("admin images"),
        "sdk-packages" => Some("admin sdk-packages"),
        "compatibility" => Some("admin compatibility"),
        "packages" => Some("admin packages"),
        "network" => Some("admin network"),
        "workflow" => Some("admin workflow"),
        "connectors" => Some("admin connectors"),
        "warehouse" => Some("admin warehouse"),
        "lakehouse" => Some("admin lakehouse"),
        "providers" => Some("admin providers"),
        "model-review" => Some("admin model-review"),
        "model-release-evidence" => Some("admin model-release-evidence"),
        "autonomy" => Some("admin autonomy"),
        _ => None,
    }
}

fn removed_alias_help(command: &str) -> Option<String> {
    canonical_admin_path(command).map(|canonical| {
        format!("`sekaictl {command}` was removed in 0.2.0; use `sekaictl {canonical}`")
    })
}

fn print_gateway_usage() {
    println!("{}", gateway_usage());
}

fn gateway_usage() -> String {
    format!(
        "Usage: sekaictl admin gateway setup|key|report ...\n\n{}\n\n{}\n\n{}",
        setup_usage(),
        key_usage(),
        report_usage()
    )
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_admin_path, expand_admin_args, expert_usage, handles_own_help, help_requested,
        removed_alias_help,
    };

    fn strings(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn help_after_double_dash_is_a_value() {
        assert!(help_requested(&strings(&["gateway", "--help"])));
        assert!(help_requested(&strings(&[
            "gateway", "key", "create", "-h"
        ])));
        assert!(!help_requested(&strings(&[
            "action", "submit", "--", "--help"
        ])));
    }

    #[test]
    fn only_gateway_key_takes_over_its_help() {
        assert!(handles_own_help(&strings(&["gateway", "key", "--help"])));
        assert!(!handles_own_help(&strings(&["gateway", "--help"])));
        assert!(!handles_own_help(&strings(&["credential", "--help"])));
    }

    #[test]
    fn expands_every_canonical_admin_path_to_the_existing_dispatcher() {
        for (canonical, expected) in [
            (vec!["access", "credential"], "credential"),
            (vec!["access", "unmarked"], "unmarked"),
            (vec!["access", "team"], "team"),
            (vec!["gateway"], "gateway"),
            (vec!["governance", "action"], "action"),
            (vec!["governance", "budget"], "budget"),
            (vec!["governance", "gunshi"], "gunshi"),
            (vec!["governance", "subject"], "governed-subject"),
            (vec!["evaluation", "plan"], "evaluation-plan"),
            (vec!["assurance", "attest"], "attest"),
            (vec!["assurance", "compliance"], "compliance"),
            (vec!["assurance", "receipts"], "receipts"),
            (vec!["assurance", "audit"], "audit"),
            (vec!["assurance", "probes"], "probes"),
            (vec!["assurance", "provenance"], "provenance"),
            (vec!["assurance", "replay"], "replay"),
            (vec!["federation"], "federation"),
            (vec!["learning"], "learning"),
            (vec!["geospatial"], "geospatial"),
            (vec!["transform"], "transform"),
            (vec!["quality"], "quality"),
            (vec!["sync"], "sync"),
            (vec!["tables"], "tables"),
            (vec!["streams"], "streams"),
            (vec!["documents"], "documents"),
            (vec!["images"], "images"),
            (vec!["sdk-packages"], "sdk-packages"),
            (vec!["compatibility"], "compatibility"),
            (vec!["packages"], "packages"),
            (vec!["network"], "network"),
            (vec!["workflow"], "workflow"),
            (vec!["connectors"], "connectors"),
            (vec!["warehouse"], "warehouse"),
            (vec!["lakehouse"], "lakehouse"),
            (vec!["providers"], "providers"),
            (vec!["autonomy"], "autonomy"),
            (vec!["store"], "store"),
        ] {
            let mut args = vec!["admin".to_string()];
            args.extend(canonical.into_iter().map(str::to_string));
            args.push("sentinel".to_string());
            assert_eq!(
                expand_admin_args(args).unwrap(),
                vec![expected.to_string(), "sentinel".to_string()]
            );
        }
    }

    #[test]
    fn rejects_incomplete_or_unknown_admin_paths() {
        for args in [
            vec!["admin"],
            vec!["admin", "access"],
            vec!["admin", "governance", "unknown"],
            vec!["admin", "assurance", "unknown"],
        ] {
            assert!(expand_admin_args(args.into_iter().map(str::to_string).collect()).is_err());
        }
    }

    #[test]
    fn every_admin_target_has_command_specific_help() {
        for command in [
            "credential",
            "unmarked",
            "team",
            "gateway",
            "action",
            "budget",
            "gunshi",
            "governed-subject",
            "evaluation-plan",
            "attest",
            "compliance",
            "receipts",
            "audit",
            "provenance",
            "replay",
            "federation",
            "learning",
            "geospatial",
            "transform",
            "quality",
            "sync",
            "tables",
            "streams",
            "documents",
            "images",
            "sdk-packages",
            "compatibility",
            "packages",
            "network",
            "workflow",
            "connectors",
            "warehouse",
            "lakehouse",
            "providers",
            "autonomy",
            "store",
        ] {
            let usage = expert_usage(command).unwrap();
            assert!(usage.contains("sekaictl admin "));
            assert!(!usage.contains(&format!("sekaictl {command}")));
        }
    }

    #[test]
    fn every_removed_alias_names_its_canonical_replacement_and_core_commands_do_not() {
        for (alias, canonical) in [
            ("credential", "admin access credential"),
            ("team", "admin access team"),
            ("gateway", "admin gateway"),
            ("action", "admin governance action"),
            ("gunshi", "admin governance gunshi"),
            ("governed-subject", "admin governance subject"),
            ("evaluation-plan", "admin evaluation plan"),
            ("attest", "admin assurance attest"),
            ("compliance", "admin assurance compliance"),
            ("provenance", "admin assurance provenance"),
            ("replay", "admin assurance replay"),
            ("federation", "admin federation"),
        ] {
            assert_eq!(canonical_admin_path(alias), Some(canonical));
            assert_eq!(
                removed_alias_help(alias).unwrap(),
                format!("`sekaictl {alias}` was removed in 0.2.0; use `sekaictl {canonical}`")
            );
        }
        for core in [
            "ontology", "launch", "doctor", "smoke", "models", "estimate", "receipt", "report",
            "admin",
        ] {
            assert_eq!(canonical_admin_path(core), None);
            assert_eq!(removed_alias_help(core), None);
        }
    }
}
