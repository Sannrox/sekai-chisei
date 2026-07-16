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
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_root_usage();
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
        "receipt" => {
            sekai_chisei::receipt_cli::run_receipt_command(args.into_iter().skip(1).collect()).await
        }
        "report" => {
            sekai_chisei::report_cli::run_report_command(args.into_iter().skip(1).collect()).await
        }
        "memory" => {
            sekai_chisei::memory_cli::run_memory_command(args.into_iter().skip(1).collect()).await
        }
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
            let work_unit = args
                .get(1)
                .ok_or_else(|| std::io::Error::other("usage: sekaictl provenance <work-unit>"))?;
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
        other => {
            eprintln!("unknown command {other:?}");
            print_root_usage();
            Err(std::io::Error::other("unknown command").into())
        }
    }
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
        "Usage: sekaictl <credential|gateway|launch|doctor|smoke|action|attest|estimate|provenance|receipt|report|memory> ...\n"
    );
    println!("Credential commands:");
    println!("  {}", credential_usage());
    println!("\nGateway commands:");
    println!("  sekaictl gateway setup [...]");
    println!("  sekaictl gateway key [create|list|rotate|revoke] [...]");
    println!("  sekaictl gateway report [...]");
    println!("\nLaunch commands:");
    println!("  {}", launch_usage());
    println!("\nDiagnostics:\n  sekaictl doctor [codex-app|claude-code]");
    println!("\nFirst governed operation:\n  sekaictl smoke [model]");
    println!("\nCost estimate:");
    println!("  {}", estimate_usage());
    println!("\nGoverned action commands:");
    println!("{}", sekai_chisei::action_cli::usage());
    println!(
        "\nAttestation commands:\n  {}",
        sekai_chisei::attest_cli::usage()
    );
    println!("\nProvenance report:\n  sekaictl provenance <work-unit>");
    println!(
        "\nOperation receipt:\n  {}",
        sekai_chisei::receipt_cli::usage()
    );
    println!(
        "\nOperation report:\n  {}",
        sekai_chisei::report_cli::usage()
    );
    println!(
        "\nMemory commands:\n  {}",
        sekai_chisei::memory_cli::usage()
    );
}

fn print_gateway_usage() {
    println!("Usage: sekaictl gateway setup|key|report ...");
    println!("\n{}", setup_usage());
    println!("\n{}", key_usage());
    println!("\n{}", report_usage());
}
