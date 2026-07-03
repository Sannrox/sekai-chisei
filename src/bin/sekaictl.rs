use sekai_chisei::credential_cli::{
    CredentialCommand, create_credential, list_credentials, parse_credential_command,
    revoke_credential, rotate_credential, usage as credential_usage,
};
use sekai_chisei::gateway_report::{GatewayReportConfig, report_usage, run_report};
use sekai_chisei::gateway_setup::{
    GatewaySetupConfig, key_usage, run_gateway_key_command, run_setup, usage as setup_usage,
};

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
            let token = create_credential(&principal).map_err(std::io::Error::other)?;
            println!("{}", token);
        }
        CredentialCommand::Rotate { principal } => {
            let token = rotate_credential(&principal).map_err(std::io::Error::other)?;
            println!("{}", token);
        }
        CredentialCommand::Revoke { principal } => {
            revoke_credential(&principal).map_err(std::io::Error::other)?;
        }
        CredentialCommand::List => {
            let credentials = list_credentials().map_err(std::io::Error::other)?;
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
    println!("Usage: sekaictl <credential|gateway> ...\n");
    println!("Credential commands:");
    println!("  {}", credential_usage());
    println!("\nGateway commands:");
    println!("  sekaictl gateway setup [...]");
    println!("  sekaictl gateway key [create|list|rotate|revoke] [...]");
    println!("  sekaictl gateway report [...]");
}

fn print_gateway_usage() {
    println!("Usage: sekaictl gateway setup|key|report ...");
    println!("\n{}", setup_usage());
    println!("\n{}", key_usage());
    println!("\n{}", report_usage());
}
