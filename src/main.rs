use sekai_chisei::config::Config;
use sekai_chisei::plane::ProcessPlane;
use std::process::ExitCode;

const USAGE: &str = "usage: sekai-chisei [gateway-report --egress [--format csv|html] [--after N] [--limit N]]\n\n\
With no argument, starts the combined control plane.";

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    // Match the mode explicitly so a typo never starts a server.
    match std::env::args().nth(1).as_deref() {
        None => sekai_chisei::control_plane::run(ProcessPlane::Combined)?,
        Some("gateway-report") => {
            sekai_chisei::control_plane::run_gateway_report(&Config::from_env())?
        }
        Some("--help" | "-h") => println!("{USAGE}"),
        Some(other) => {
            eprintln!("sekai-chisei: unknown argument {other:?}\n\n{USAGE}");
            return Ok(ExitCode::from(2));
        }
    }
    Ok(ExitCode::SUCCESS)
}
