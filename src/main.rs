use sekai_chisei::config::Config;
use sekai_chisei::plane::ProcessPlane;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env();
    if let Some(mode) = std::env::args().nth(1)
        && mode == "gateway-report"
    {
        return sekai_chisei::control_plane::run_gateway_report(&config);
    }
    sekai_chisei::control_plane::run(ProcessPlane::Combined)
}
