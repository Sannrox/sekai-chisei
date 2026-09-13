//! sekaictl admin compatibility commands (#873).

use crate::compatibility_matrix::{self, CompatibilityMatrix};
use std::path::PathBuf;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub fn usage() -> &'static str {
    "sekaictl admin compatibility generate [--root <dir>] [--out <file>]\n  sekaictl admin compatibility check --matrix <file> --consumer <dir>"
}

pub async fn run_compatibility_command(args: Vec<String>) -> Result<(), BoxErr> {
    match args.first().map(String::as_str) {
        Some("generate") => generate(parse_generate(&args[1..])?),
        Some("check") => check(parse_check(&args[1..])?),
        _ => Err(std::io::Error::other(usage()).into()),
    }
}

struct GenerateConfig {
    root: PathBuf,
    out: PathBuf,
}

struct CheckConfig {
    matrix: PathBuf,
    consumer: PathBuf,
}

fn generate(config: GenerateConfig) -> Result<(), BoxErr> {
    let matrix =
        CompatibilityMatrix::from_workspace(&config.root).map_err(std::io::Error::other)?;
    compatibility_matrix::write_matrix(&config.out, &matrix).map_err(std::io::Error::other)?;
    println!("{}", config.out.display());
    Ok(())
}

fn check(config: CheckConfig) -> Result<(), BoxErr> {
    let matrix = CompatibilityMatrix::from_path(&config.matrix).map_err(std::io::Error::other)?;
    let result = compatibility_matrix::check_consumer(&matrix, &config.consumer)
        .map_err(std::io::Error::other)?;
    println!("{}", result.report());
    if result.is_on_matrix() {
        Ok(())
    } else {
        Err(std::io::Error::other(result.summary).into())
    }
}

fn parse_generate(args: &[String]) -> Result<GenerateConfig, BoxErr> {
    let mut root = PathBuf::from(".");
    let mut out = PathBuf::from("compatibility.json");
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--root" => {
                root = PathBuf::from(required_value(args, index, "--root")?);
                index += 2;
            }
            "--out" => {
                out = PathBuf::from(required_value(args, index, "--out")?);
                index += 2;
            }
            other => {
                return Err(std::io::Error::other(format!("unknown argument {other}")).into());
            }
        }
    }
    Ok(GenerateConfig { root, out })
}

fn parse_check(args: &[String]) -> Result<CheckConfig, BoxErr> {
    let mut matrix = None;
    let mut consumer = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--matrix" => {
                matrix = Some(PathBuf::from(required_value(args, index, "--matrix")?));
                index += 2;
            }
            "--consumer" => {
                consumer = Some(PathBuf::from(required_value(args, index, "--consumer")?));
                index += 2;
            }
            other => {
                return Err(std::io::Error::other(format!("unknown argument {other}")).into());
            }
        }
    }
    Ok(CheckConfig {
        matrix: matrix.ok_or_else(|| std::io::Error::other(usage()))?,
        consumer: consumer.ok_or_else(|| std::io::Error::other(usage()))?,
    })
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, BoxErr> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| std::io::Error::other(format!("{flag} requires a value")).into())
}
