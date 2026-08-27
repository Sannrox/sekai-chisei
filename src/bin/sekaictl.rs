use sekai_chisei::cost_estimate::{
    CostEstimateConfig, estimate_cost, pricing_from_env, render_estimate, usage as estimate_usage,
};
use sekai_chisei::credential_cli::{
    CredentialCommand, create_credential, list_credentials, parse_credential_command,
    revoke_credential, rotate_credential, usage as credential_usage,
};
use sekai_chisei::gateway_report::{GatewayReportConfig, report_usage, run_report};
use sekai_chisei::gateway_setup::{
    GatewaySetupConfig, key_usage, run_gateway_key_command, run_setup, usage as setup_usage,
};
use sekai_chisei::grpc::client::connect_sekai;
use sekai_chisei::grpc::pb::sekai::GetProvenanceReportRequest;
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::launch::{LaunchConfig, run_launch, usage as launch_usage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_root_usage();
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
    let has_help = args.iter().any(|arg| arg == "--help" || arg == "-h");
    if is_admin_path && has_help && expand_admin_args(args.clone()).is_err() {
        print_admin_usage();
        return Ok(());
    }
    args = expand_admin_args(args).map_err(|error| {
        print_admin_usage();
        std::io::Error::other(error)
    })?;
    if has_help || (is_admin_path && args.len() == 1) {
        if let Some(usage) = expert_usage(&args[0]) {
            println!("{usage}");
        } else {
            print_root_usage();
        }
        return Ok(());
    }

    match args[0].as_str() {
        "credential" => run_credential_command(args.into_iter().skip(1).collect()).await,
        "gateway" => run_gateway_command(args.into_iter().skip(1).collect()).await,
        "action" => {
            sekai_chisei::action_cli::run_action_command(args.into_iter().skip(1).collect()).await
        }
        "attest" => {
            sekai_chisei::attest_cli::run_attest_command(args.into_iter().skip(1).collect()).await
        }
        "compliance" => {
            sekai_chisei::compliance_cli::run_compliance_command(args.into_iter().skip(1).collect())
                .await
        }
        "federation" => {
            sekai_chisei::federation_cli::run_federation_command(args.into_iter().skip(1).collect())
                .await
        }
        "learning" => {
            sekai_chisei::learning_cli::run_learning_command(args.into_iter().skip(1).collect())
                .await
        }
        "geospatial" => {
            sekai_chisei::geospatial_cli::run_geospatial_command(args.into_iter().skip(1).collect())
                .await
        }
        "quality" => {
            sekai_chisei::quality_cli::run_quality_command(args.into_iter().skip(1).collect()).await
        }
        "sync" => {
            sekai_chisei::source_webhook_cli::run_sync_command(args.into_iter().skip(1).collect())
                .await
        }
        "tables" => {
            sekai_chisei::open_table_cli::run_tables_command(args.into_iter().skip(1).collect())
                .await
        }
        "streams" => {
            sekai_chisei::event_stream_cli::run_streams_command(args.into_iter().skip(1).collect())
                .await
        }
        "documents" => {
            sekai_chisei::document_cli::run_documents_command(args.into_iter().skip(1).collect())
                .await
        }
        "receipt" => {
            sekai_chisei::receipt_cli::run_receipt_command(args.into_iter().skip(1).collect()).await
        }
        "replay" => match args.get(1).map(String::as_str) {
            Some("export") => {
                let config = sekai_chisei::replay_cli::ReplayExportConfig::from_args(
                    args.into_iter().skip(2),
                )
                .map_err(std::io::Error::other)?;
                sekai_chisei::replay_cli::run_export(config).await
            }
            _ => Err(std::io::Error::other(sekai_chisei::replay_cli::usage()).into()),
        },
        "report" => {
            sekai_chisei::report_cli::run_report_command(args.into_iter().skip(1).collect()).await
        }
        "memory" => {
            sekai_chisei::memory_cli::run_memory_command(args.into_iter().skip(1).collect()).await
        }
        "models" => {
            let config =
                sekai_chisei::models_cli::ModelsListConfig::from_args(args.into_iter().skip(1))
                    .map_err(std::io::Error::other)?;
            print!(
                "{}",
                sekai_chisei::models_cli::run_models_list(config).await?
            );
            Ok(())
        }
        "gunshi" => match args.get(1).map(String::as_str) {
            Some("recommend") => {
                let config =
                    sekai_chisei::gunshi_cli::RecommendConfig::from_args(args.into_iter().skip(2))
                        .map_err(std::io::Error::other)?;
                let output = config.output.clone();
                sekai_chisei::gunshi_cli::run_recommend(config)?;
                println!("created {}", output.display());
                Ok(())
            }
            Some("issue") => {
                let config =
                    sekai_chisei::gunshi_cli::RecommendConfig::from_args(args.into_iter().skip(2))
                        .map_err(std::io::Error::other)?;
                let output = config.output.clone();
                sekai_chisei::gunshi_cli::issue_recommendations(config).await?;
                println!("created {}", output.display());
                Ok(())
            }
            Some("scorecard") => {
                let namespace = sekai_chisei::gunshi_cli::scorecard_namespace(&args[2..])
                    .map_err(std::io::Error::other)?;
                let scorecard = sekai_chisei::gunshi_cli::get_scorecard(namespace).await?;
                println!("{}", serde_json::to_string_pretty(&scorecard)?);
                Ok(())
            }
            Some("allocation-status") => {
                let namespace = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--namespace")
                    .map_err(std::io::Error::other)?;
                let status = sekai_chisei::gunshi_cli::get_allocation_status(namespace).await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            Some("install-baseline") => {
                let namespace = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--namespace")
                    .map_err(std::io::Error::other)?;
                let snapshot = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--snapshot")
                    .map_err(std::io::Error::other)?;
                let gate = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--gate")
                    .map_err(std::io::Error::other)?;
                let status = sekai_chisei::gunshi_cli::install_baseline(
                    namespace,
                    snapshot.into(),
                    gate.into(),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            Some("promote") => {
                let namespace = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--namespace")
                    .map_err(std::io::Error::other)?;
                let candidate = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--candidate")
                    .map_err(std::io::Error::other)?;
                let baseline =
                    sekai_chisei::gunshi_cli::require_flag(&args[2..], "--baseline-eval")
                        .map_err(std::io::Error::other)?;
                let candidate_eval =
                    sekai_chisei::gunshi_cli::require_flag(&args[2..], "--candidate-eval")
                        .map_err(std::io::Error::other)?;
                let expected =
                    sekai_chisei::gunshi_cli::require_flag(&args[2..], "--expected-revision")
                        .map_err(std::io::Error::other)?;
                let status = sekai_chisei::gunshi_cli::promote_policy(
                    namespace,
                    candidate.into(),
                    baseline.into(),
                    candidate_eval.into(),
                    expected,
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            Some("rollback") => {
                let namespace = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--namespace")
                    .map_err(std::io::Error::other)?;
                let expected =
                    sekai_chisei::gunshi_cli::require_flag(&args[2..], "--expected-revision")
                        .map_err(std::io::Error::other)?;
                let reason = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--reason")
                    .map_err(std::io::Error::other)?;
                let status =
                    sekai_chisei::gunshi_cli::rollback_policy(namespace, expected, reason).await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            Some("auto-opt-in") => {
                let namespace = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--namespace")
                    .map_err(std::io::Error::other)?;
                let expected =
                    sekai_chisei::gunshi_cli::require_flag(&args[2..], "--expected-revision")
                        .map_err(std::io::Error::other)?;
                let opt_in = !args[2..].iter().any(|arg| arg == "--off");
                let status =
                    sekai_chisei::gunshi_cli::set_auto_opt_in(namespace, opt_in, expected).await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            Some("kill-switch") => {
                let namespace = sekai_chisei::gunshi_cli::require_flag(&args[2..], "--namespace")
                    .map_err(std::io::Error::other)?;
                let clear = args[2..].iter().any(|arg| arg == "--clear");
                let reason = if clear {
                    String::new()
                } else {
                    sekai_chisei::gunshi_cli::require_flag(&args[2..], "--reason")
                        .map_err(std::io::Error::other)?
                };
                let status =
                    sekai_chisei::gunshi_cli::set_kill_switch(namespace, !clear, reason).await?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                Ok(())
            }
            _ => Err(std::io::Error::other(sekai_chisei::gunshi_cli::usage()).into()),
        },
        "governed-subject" => {
            sekai_chisei::governed_subject_cli::run(args.into_iter().skip(1).collect()).await
        }
        "evaluation-plan" => {
            match sekai_chisei::evaluation_plan_cli::run(args.into_iter().skip(1).collect()).await {
                Ok(()) => Ok(()),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(error.exit_code());
                }
            }
        }
        "lookup-first-gate" => {
            match sekai_chisei::lookup_gate_cli::run(args.into_iter().skip(1).collect()).await {
                Ok(()) => Ok(()),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(error.exit_code());
                }
            }
        }
        "team" => match args.get(1).map(String::as_str) {
            Some("join") => {
                let config = sekai_chisei::team_cli::TeamJoinConfig::from_env_and_args(
                    args.into_iter().skip(2),
                )
                .map_err(std::io::Error::other)?;
                let bundle = sekai_chisei::team_cli::run_team_join(config)
                    .await
                    .map_err(std::io::Error::other)?;
                println!("{}", serde_json::to_string_pretty(&bundle)?);
                Ok(())
            }
            Some("weekly-report") => {
                let config = sekai_chisei::weekly_report_cli::WeeklyReportConfig::from_args(
                    args.into_iter().skip(2),
                )
                .map_err(std::io::Error::other)?;
                let output = config.output.clone();
                sekai_chisei::weekly_report_cli::run_weekly_report(config).await?;
                println!("created {}", output.display());
                Ok(())
            }
            _ => Err(std::io::Error::other(format!(
                "{}\n  {}",
                sekai_chisei::team_cli::usage(),
                sekai_chisei::weekly_report_cli::usage()
            ))
            .into()),
        },
        "estimate" => {
            sekai_chisei::launch::load_local_env();
            let config = CostEstimateConfig::from_args(args.into_iter().skip(1))
                .map_err(std::io::Error::other)?;
            let pricing = pricing_from_env().map_err(std::io::Error::other)?;
            let estimate = estimate_cost(&config, &pricing).map_err(std::io::Error::other)?;
            println!("{}", render_estimate(&config, &estimate));
            Ok(())
        }
        "launch" => {
            sekai_chisei::launch::load_local_env();
            let config = LaunchConfig::from_env_and_args(args.into_iter().skip(1))
                .map_err(std::io::Error::other)?;
            run_launch(config).await
        }
        "doctor" => {
            sekai_chisei::launch::load_local_env();
            let agent = args.get(1).map(String::as_str);
            if args.len() > 2 {
                return Err(std::io::Error::other(
                    "usage: sekaictl doctor [codex-app|claude-code]",
                )
                .into());
            }
            let checks = sekai_chisei::onboarding::run_doctor(agent);
            print!("{}", sekai_chisei::onboarding::render_doctor(&checks));
            if checks
                .iter()
                .any(|check| check.status == sekai_chisei::onboarding::CheckStatus::Failed)
            {
                return Err(std::io::Error::other("doctor found blocking failures").into());
            }
            Ok(())
        }
        "smoke" => {
            sekai_chisei::launch::load_local_env();
            let model = args.get(1).map(String::as_str).unwrap_or("gpt-5.5");
            if args.len() > 2 {
                return Err(std::io::Error::other("usage: sekaictl smoke [model]").into());
            }
            print!(
                "{}",
                sekai_chisei::onboarding::run_smoke(model)
                    .await
                    .map_err(std::io::Error::other)?
            );
            Ok(())
        }
        "provenance" => {
            sekai_chisei::launch::load_local_env();
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
                sekai_chisei::launch::load_local_env();
                let config = sekai_chisei::ontology_inspect::InspectConfig::from_env_and_args(
                    args.into_iter().skip(2),
                )
                .map_err(std::io::Error::other)?;
                let output = config.output.clone();
                sekai_chisei::ontology_inspect::run_inspect(config).await?;
                println!("created {}", output.display());
                Ok(())
            }
            Some("apply" | "seed" | "run" | "first-run") => {
                sekai_chisei::launch::load_local_env();
                sekai_chisei::ontology_product_cli::run_ontology_product_command(
                    args.into_iter().skip(1).collect(),
                )
                .await
            }
            _ => Err(std::io::Error::other(sekai_chisei::ontology_product_cli::usage()).into()),
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
        (Some("access"), Some("team")) => ("team", 3),
        (Some("gateway"), _) => ("gateway", 2),
        (Some("governance"), Some("action")) => ("action", 3),
        (Some("governance"), Some("memory")) => ("memory", 3),
        (Some("governance"), Some("gunshi")) => ("gunshi", 3),
        (Some("governance"), Some("subject")) => ("governed-subject", 3),
        (Some("evaluation"), Some("plan")) => ("evaluation-plan", 3),
        (Some("evaluation"), Some("lookup-first-gate")) => ("lookup-first-gate", 3),
        (Some("assurance"), Some("attest")) => ("attest", 3),
        (Some("assurance"), Some("compliance")) => ("compliance", 3),
        (Some("assurance"), Some("provenance")) => ("provenance", 3),
        (Some("assurance"), Some("replay")) => ("replay", 3),
        (Some("federation"), _) => ("federation", 2),
        (Some("learning"), _) => ("learning", 2),
        (Some("geospatial"), _) => ("geospatial", 2),
        (Some("quality"), _) => ("quality", 2),
        (Some("sync"), _) => ("sync", 2),
        (Some("tables"), _) => ("tables", 2),
        (Some("streams"), _) => ("streams", 2),
        (Some("documents"), _) => ("documents", 2),
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
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_gateway_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "setup" => {
            let config = GatewaySetupConfig::from_env_and_args(args.into_iter().skip(1))
                .map_err(std::io::Error::other)?;
            run_setup(config).await
        }
        "key" => {
            if args
                .get(1)
                .is_some_and(|arg| arg == "--help" || arg == "-h")
            {
                println!("{}", key_usage());
                return Ok(());
            }
            run_gateway_key_command(args.into_iter().skip(1)).await
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
        "Usage: sekaictl <ontology|launch|doctor|smoke|models|estimate|receipt|report|admin> ...\n"
    );
    println!("Product loop (ontology-first):");
    println!("  {}", sekai_chisei::ontology_product_cli::usage());
    println!("  {}", sekai_chisei::ontology_inspect::usage());
    println!("\nLaunch commands:");
    println!("  {}", launch_usage());
    println!("\nDiagnostics:\n  sekaictl doctor [codex-app|claude-code]");
    println!("\nFirst governed operation (model smoke):\n  sekaictl smoke [model]");
    println!("\nCost estimate:");
    println!("  {}", estimate_usage());
    println!(
        "\nOperation receipt:\n  {}",
        sekai_chisei::receipt_cli::usage()
    );
    println!(
        "\nOperation report:\n  {}",
        sekai_chisei::report_cli::usage()
    );
    println!("\nModel commands:\n  {}", sekai_chisei::models_cli::USAGE);
    println!("\nExpert administration:\n  sekaictl admin --help");
}

fn print_admin_usage() {
    println!(
        "Usage: sekaictl admin <access|gateway|governance|evaluation|assurance|federation> ...\n\
         \n\
         Access:\n\
           sekaictl admin access credential ...\n\
           sekaictl admin access team ...\n\
         \n\
         Gateway:\n\
           sekaictl admin gateway ...\n\
         \n\
         Governance:\n\
           sekaictl admin governance <action|memory|gunshi|subject> ...\n\
         \n\
         Evaluation:\n\
           sekaictl admin evaluation plan ...\n\
           sekaictl admin evaluation lookup-first-gate ...\n\
         \n\
         Assurance:\n\
           sekaictl admin assurance <attest|compliance|provenance|replay> ...\n\
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
           sekaictl admin documents ..."
    );
}

fn expert_usage(command: &str) -> Option<String> {
    match command {
        "credential" => Some(credential_usage().to_string()),
        "gateway" => Some(gateway_usage()),
        "action" => Some(sekai_chisei::action_cli::usage().to_string()),
        "memory" => Some(sekai_chisei::memory_cli::usage().to_string()),
        "gunshi" => Some(sekai_chisei::gunshi_cli::usage().to_string()),
        "governed-subject" => Some(sekai_chisei::governed_subject_cli::usage().to_string()),
        "evaluation-plan" => Some(sekai_chisei::evaluation_plan_cli::usage().to_string()),
        "lookup-first-gate" => Some(sekai_chisei::lookup_gate_cli::usage().to_string()),
        "attest" => Some(sekai_chisei::attest_cli::usage().to_string()),
        "compliance" => Some(sekai_chisei::compliance_cli::usage().to_string()),
        "provenance" => Some("usage: sekaictl admin assurance provenance <work-unit>".to_string()),
        "replay" => Some(sekai_chisei::replay_cli::usage().to_string()),
        "team" => Some(format!(
            "{}\n  {}",
            sekai_chisei::team_cli::usage(),
            sekai_chisei::weekly_report_cli::usage()
        )),
        "federation" => Some(sekai_chisei::federation_cli::usage().to_string()),
        "learning" => Some(sekai_chisei::learning_cli::usage().to_string()),
        "geospatial" => Some(sekai_chisei::geospatial_cli::usage().to_string()),
        "quality" => Some(sekai_chisei::quality_cli::usage().to_string()),
        "sync" => Some(sekai_chisei::source_webhook_cli::usage().to_string()),
        "tables" => Some(sekai_chisei::open_table_cli::usage().to_string()),
        "streams" => Some(sekai_chisei::event_stream_cli::usage().to_string()),
        "documents" => Some(sekai_chisei::document_cli::usage().to_string()),
        _ => None,
    }
}

fn canonical_admin_path(command: &str) -> Option<&'static str> {
    match command {
        "credential" => Some("admin access credential"),
        "team" => Some("admin access team"),
        "gateway" => Some("admin gateway"),
        "action" => Some("admin governance action"),
        "memory" => Some("admin governance memory"),
        "gunshi" => Some("admin governance gunshi"),
        "governed-subject" => Some("admin governance subject"),
        "evaluation-plan" => Some("admin evaluation plan"),
        "lookup-first-gate" => Some("admin evaluation lookup-first-gate"),
        "attest" => Some("admin assurance attest"),
        "compliance" => Some("admin assurance compliance"),
        "provenance" => Some("admin assurance provenance"),
        "replay" => Some("admin assurance replay"),
        "federation" => Some("admin federation"),
        "sync" => Some("admin sync"),
        "tables" => Some("admin tables"),
        "streams" => Some("admin streams"),
        "documents" => Some("admin documents"),
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
    use super::{canonical_admin_path, expand_admin_args, expert_usage, removed_alias_help};

    #[test]
    fn expands_every_canonical_admin_path_to_the_existing_dispatcher() {
        for (canonical, expected) in [
            (vec!["access", "credential"], "credential"),
            (vec!["access", "team"], "team"),
            (vec!["gateway"], "gateway"),
            (vec!["governance", "action"], "action"),
            (vec!["governance", "memory"], "memory"),
            (vec!["governance", "gunshi"], "gunshi"),
            (vec!["governance", "subject"], "governed-subject"),
            (vec!["evaluation", "plan"], "evaluation-plan"),
            (vec!["evaluation", "lookup-first-gate"], "lookup-first-gate"),
            (vec!["assurance", "attest"], "attest"),
            (vec!["assurance", "compliance"], "compliance"),
            (vec!["assurance", "provenance"], "provenance"),
            (vec!["assurance", "replay"], "replay"),
            (vec!["federation"], "federation"),
            (vec!["learning"], "learning"),
            (vec!["geospatial"], "geospatial"),
            (vec!["quality"], "quality"),
            (vec!["sync"], "sync"),
            (vec!["tables"], "tables"),
            (vec!["streams"], "streams"),
            (vec!["documents"], "documents"),
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
            "team",
            "gateway",
            "action",
            "memory",
            "gunshi",
            "governed-subject",
            "evaluation-plan",
            "lookup-first-gate",
            "attest",
            "compliance",
            "provenance",
            "replay",
            "federation",
            "learning",
            "geospatial",
            "quality",
            "sync",
            "tables",
            "streams",
            "documents",
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
            ("memory", "admin governance memory"),
            ("gunshi", "admin governance gunshi"),
            ("governed-subject", "admin governance subject"),
            ("evaluation-plan", "admin evaluation plan"),
            ("lookup-first-gate", "admin evaluation lookup-first-gate"),
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
