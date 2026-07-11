use std::collections::HashMap;

use crate::gateway::{ModelPricing, parse_pricing_table};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostEstimateConfig {
    pub model: String,
    pub context_tokens: i64,
    pub turns: i64,
    pub output_tokens_per_turn: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostEstimate {
    pub low_usd_micros: i64,
    pub high_usd_micros: i64,
    pub low_output_tokens: i64,
    pub high_output_tokens: i64,
}

impl CostEstimateConfig {
    pub fn from_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut model = None;
        let mut context_tokens = None;
        let mut turns = 1;
        let mut output_tokens_per_turn = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--model" => model = Some(next_arg(&mut args, &arg)?),
                "--context-tokens" | "--prompt-tokens" => {
                    context_tokens = Some(parse_positive(&next_arg(&mut args, &arg)?, &arg)?)
                }
                "--turns" => turns = parse_positive(&next_arg(&mut args, &arg)?, &arg)?,
                "--output-tokens" => {
                    output_tokens_per_turn =
                        Some(parse_positive(&next_arg(&mut args, &arg)?, &arg)?)
                }
                "--help" | "-h" => return Err(usage()),
                other => return Err(format!("unknown argument {other:?}\n\n{}", usage())),
            }
        }
        Ok(Self {
            model: model.ok_or_else(|| format!("missing --model\n\n{}", usage()))?,
            context_tokens: context_tokens
                .ok_or_else(|| format!("missing --context-tokens\n\n{}", usage()))?,
            turns,
            output_tokens_per_turn,
        })
    }
}

pub fn pricing_from_env() -> Result<HashMap<String, ModelPricing>, String> {
    let spec = std::env::var("CHISEI_GATEWAY_PRICING")
        .or_else(|_| std::env::var("GATEWAY_PRICING"))
        .unwrap_or_default();
    parse_pricing_table(&spec).map_err(|error| error.to_string())
}

pub fn estimate_cost(
    config: &CostEstimateConfig,
    pricing: &HashMap<String, ModelPricing>,
) -> Result<CostEstimate, String> {
    let rates = pricing.get(&config.model).ok_or_else(|| {
        format!(
            "no pricing configured for {:?}; add it to CHISEI_GATEWAY_PRICING",
            config.model
        )
    })?;
    if config.context_tokens <= 0 || config.turns <= 0 {
        return Err("context tokens and turns must be positive".to_string());
    }
    let (low_output_per_turn, high_output_per_turn) = match config.output_tokens_per_turn {
        Some(output) if output > 0 => (
            output.saturating_mul(80) / 100,
            output.saturating_mul(120) / 100,
        ),
        Some(_) => return Err("output tokens must be positive".to_string()),
        None => (
            (config.context_tokens / 10).max(1),
            (config.context_tokens / 2).max(1),
        ),
    };
    let input_tokens = config
        .context_tokens
        .checked_mul(config.turns)
        .ok_or_else(|| "input token estimate is too large".to_string())?;
    let low_output_tokens = low_output_per_turn
        .checked_mul(config.turns)
        .ok_or_else(|| "output token estimate is too large".to_string())?;
    let high_output_tokens = high_output_per_turn
        .checked_mul(config.turns)
        .ok_or_else(|| "output token estimate is too large".to_string())?;
    Ok(CostEstimate {
        low_usd_micros: projected_cost(input_tokens, low_output_tokens, rates)?,
        high_usd_micros: projected_cost(input_tokens, high_output_tokens, rates)?,
        low_output_tokens,
        high_output_tokens,
    })
}

pub fn render_estimate(config: &CostEstimateConfig, estimate: &CostEstimate) -> String {
    format!(
        "estimated cost for {}: ${}–${} ({} context tokens × {} turns; {}–{} output tokens total)",
        config.model,
        format_usd(estimate.low_usd_micros),
        format_usd(estimate.high_usd_micros),
        config.context_tokens,
        config.turns,
        estimate.low_output_tokens,
        estimate.high_output_tokens,
    )
}

pub fn usage() -> String {
    "Usage: sekaictl estimate --model <model> --context-tokens <tokens> [--turns <count>] [--output-tokens <per-turn>]".to_string()
}

fn projected_cost(input: i64, output: i64, pricing: &ModelPricing) -> Result<i64, String> {
    let cost = i128::from(input)
        .checked_mul(i128::from(pricing.input_usd_micros_per_million))
        .and_then(|input_cost| {
            i128::from(output)
                .checked_mul(i128::from(pricing.output_usd_micros_per_million))
                .and_then(|output_cost| input_cost.checked_add(output_cost))
        })
        .and_then(|cost| cost.checked_div(1_000_000))
        .ok_or_else(|| "cost estimate is too large".to_string())?;
    i64::try_from(cost).map_err(|_| "cost estimate is too large".to_string())
}

fn format_usd(micros: i64) -> String {
    format!("{}.{:06}", micros / 1_000_000, (micros % 1_000_000).abs())
}

fn parse_positive(value: &str, flag: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{flag} must be a positive integer"))
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_is_a_range_when_output_is_unknown() {
        let pricing = parse_pricing_table("model-x=2:10").unwrap();
        let config = CostEstimateConfig {
            model: "model-x".to_string(),
            context_tokens: 10_000,
            turns: 2,
            output_tokens_per_turn: None,
        };
        let estimate = estimate_cost(&config, &pricing).unwrap();
        assert_eq!(estimate.low_usd_micros, 60_000);
        assert_eq!(estimate.high_usd_micros, 140_000);
        assert!(render_estimate(&config, &estimate).contains("$0.060000–$0.140000"));
    }

    #[test]
    fn parses_required_estimate_inputs() {
        let config = CostEstimateConfig::from_args([
            "--model".to_string(),
            "model-x".to_string(),
            "--context-tokens".to_string(),
            "12000".to_string(),
            "--turns".to_string(),
            "3".to_string(),
        ])
        .unwrap();
        assert_eq!(config.context_tokens, 12_000);
        assert_eq!(config.turns, 3);
    }
}
