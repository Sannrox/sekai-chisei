//! The governed series read (ADR 0161, ADR 0171, #3472): the samples of one
//! series in a time range, returned raw or downsampled into fixed-width
//! buckets.
//!
//! Samples are rows of a governed dataset with the columns
//! [`SERIES_ID_COLUMN`], [`TIMESTAMP_COLUMN`] (milliseconds) and
//! [`VALUE_COLUMN`] (a finite float). The stores scan one series over the
//! `(dataset_id, series_id, timestamp)` index and stop past
//! [`MAX_SCANNED_SAMPLES`], so a read never returns a partial series.

/// Column holding the series id an object's `series` property names.
pub const SERIES_ID_COLUMN: &str = "series_id";
/// Column holding the sample time in milliseconds.
pub const TIMESTAMP_COLUMN: &str = "timestamp";
/// Column holding the sample value.
pub const VALUE_COLUMN: &str = "value";
/// The columns a samples dataset must have, and a reader must be able to read.
pub const SAMPLE_COLUMNS: [&str; 3] = [SERIES_ID_COLUMN, TIMESTAMP_COLUMN, VALUE_COLUMN];

/// Most points one read returns; a larger target is lowered to this.
pub const MAX_TARGET_POINTS: u32 = 10_000;
/// Most samples one read scans; a range holding more is refused.
pub const MAX_SCANNED_SAMPLES: usize = 1_000_000;

/// Refusal prefix of a range holding more than [`MAX_SCANNED_SAMPLES`].
pub const REFUSAL_SCAN_CAP: &str = "series_scan_cap_exceeded";
/// Refusal prefix of a quarantined samples dataset.
pub const REFUSAL_QUARANTINED: &str = "series_dataset_quarantined";
/// Error prefix of a stored sample whose timestamp or value does not parse.
pub const ERROR_INVALID_SAMPLE: &str = "series_sample_invalid";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub timestamp_ms: i64,
    pub value: f64,
}

/// One fixed-width bucket of samples, `[start_ms, start_ms + width)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bucket {
    pub start_ms: i64,
    pub count: u64,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
}

/// What a store scan of one series found.
#[derive(Debug, Clone, PartialEq)]
pub enum SeriesScan {
    /// The samples in the range, oldest first.
    Samples(Vec<Sample>),
    /// The range holds more than [`MAX_SCANNED_SAMPLES`] samples.
    OverScanCap,
    /// The samples dataset is quarantined; its rows are not served.
    Quarantined,
}

/// A series read's answer: the samples as stored, or buckets, never both.
#[derive(Debug, Clone, PartialEq)]
pub enum SeriesPoints {
    Raw(Vec<Sample>),
    Buckets { width_ms: i64, buckets: Vec<Bucket> },
}

/// Parses one stored row's timestamp and value cells.
pub fn parse_sample(timestamp: &str, value: &str) -> Result<Sample, String> {
    let timestamp_ms = timestamp
        .parse::<i64>()
        .map_err(|_| format!("{ERROR_INVALID_SAMPLE}: timestamp {timestamp:?}"))?;
    let value = value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
        .ok_or_else(|| format!("{ERROR_INVALID_SAMPLE}: value {value:?}"))?;
    Ok(Sample {
        timestamp_ms,
        value,
    })
}

/// Fits `samples` (oldest first, all in `[start_ms, end_ms)`) to at most
/// `target` points: the samples themselves when they fit, else one bucket per
/// non-empty slice of `ceil((end_ms - start_ms) / target)` milliseconds.
pub fn downsample(samples: Vec<Sample>, start_ms: i64, end_ms: i64, target: u32) -> SeriesPoints {
    let target = target.clamp(1, MAX_TARGET_POINTS);
    if samples.len() <= target as usize {
        return SeriesPoints::Raw(samples);
    }
    let span = end_ms.saturating_sub(start_ms).max(1);
    let target = i64::from(target);
    let width_ms = (span / target + i64::from(span % target != 0)).max(1);
    let mut buckets: Vec<Bucket> = Vec::new();
    let mut sum = 0.0;
    for sample in samples {
        // i128, so a range spanning most of i64 cannot overflow.
        let offset = (i128::from(sample.timestamp_ms) - i128::from(start_ms))
            / i128::from(width_ms)
            * i128::from(width_ms);
        let start = (i128::from(start_ms) + offset) as i64;
        match buckets.last_mut() {
            Some(bucket) if bucket.start_ms == start => {
                bucket.count += 1;
                bucket.min = bucket.min.min(sample.value);
                bucket.max = bucket.max.max(sample.value);
                sum += sample.value;
            }
            _ => {
                if let Some(bucket) = buckets.last_mut() {
                    bucket.mean = sum / bucket.count as f64;
                }
                sum = sample.value;
                buckets.push(Bucket {
                    start_ms: start,
                    count: 1,
                    min: sample.value,
                    max: sample.value,
                    mean: 0.0,
                });
            }
        }
    }
    if let Some(bucket) = buckets.last_mut() {
        bucket.mean = sum / bucket.count as f64;
    }
    SeriesPoints::Buckets { width_ms, buckets }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples(points: &[(i64, f64)]) -> Vec<Sample> {
        points
            .iter()
            .map(|&(timestamp_ms, value)| Sample {
                timestamp_ms,
                value,
            })
            .collect()
    }

    #[test]
    fn a_range_within_the_target_returns_its_samples() {
        let raw = samples(&[(0, 1.0), (5, 2.0)]);
        assert_eq!(downsample(raw.clone(), 0, 10, 2), SeriesPoints::Raw(raw));
    }

    #[test]
    fn a_larger_range_buckets_into_at_most_the_target_and_keeps_spikes() {
        // 10 samples over [0, 100) into 3 buckets of 34 ms.
        let raw = samples(&[
            (0, 1.0),
            (10, 3.0),
            (20, 2.0),
            (33, 100.0),
            (34, 4.0),
            (50, 6.0),
            (67, 5.0),
            (68, -7.0),
            (80, 1.0),
            (99, 3.0),
        ]);
        let SeriesPoints::Buckets { width_ms, buckets } = downsample(raw, 0, 100, 3) else {
            panic!("expected buckets");
        };
        assert_eq!(width_ms, 34);
        assert_eq!(
            buckets,
            vec![
                Bucket {
                    start_ms: 0,
                    count: 4,
                    min: 1.0,
                    max: 100.0,
                    mean: 26.5
                },
                Bucket {
                    start_ms: 34,
                    count: 3,
                    min: 4.0,
                    max: 6.0,
                    mean: 5.0
                },
                Bucket {
                    start_ms: 68,
                    count: 3,
                    min: -7.0,
                    max: 3.0,
                    mean: -1.0
                },
            ]
        );
    }

    #[test]
    fn a_stored_sample_must_be_an_integer_time_and_a_finite_value() {
        assert_eq!(
            parse_sample("12", "1.5").unwrap(),
            Sample {
                timestamp_ms: 12,
                value: 1.5
            }
        );
        for (timestamp, value) in [("12abc", "1"), ("12", "NaN"), ("12", "inf"), ("", "1")] {
            assert!(
                parse_sample(timestamp, value)
                    .unwrap_err()
                    .starts_with(ERROR_INVALID_SAMPLE)
            );
        }
    }
}
