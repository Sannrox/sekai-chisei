//! `ReadObjectSeries` (experimental, #3472, ADR 0171): one object's series,
//! raw or bucketed.
//!
//! Access is the conjunction of two reads. The object is read through
//! `GetObject`'s path, so visibility, markings, purpose and property
//! redaction match it, and the `series` property must survive that read.
//! The samples dataset is then authorized as a dataset read, with every
//! sample column readable and released to the caller's egress. A refusal on
//! the dataset side never depends on its rows.

use super::rpc_data::authorize_series_dataset;
use super::*;
use crate::sekai::series::{
    self, MAX_SCANNED_SAMPLES, REFUSAL_QUARANTINED, REFUSAL_SCAN_CAP, SeriesPoints, SeriesScan,
};

impl SekaiServiceImpl {
    pub(super) async fn read_object_series_rpc(
        &self,
        req: Request<ReadObjectSeriesRequest>,
    ) -> Result<Response<ReadObjectSeriesResponse>, Status> {
        let service = self.clone();
        self.spawn_db(move || service.read_object_series_blocking(req))
            .await
    }

    fn read_object_series_blocking(
        &self,
        req: Request<ReadObjectSeriesRequest>,
    ) -> Result<Response<ReadObjectSeriesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let (metadata, extensions, input) = req.into_parts();
        if input.target_points == 0 {
            return Err(Status::invalid_argument("target_points must be at least 1"));
        }
        if input.start_ms >= input.end_ms {
            return Err(Status::invalid_argument("start_ms must be below end_ms"));
        }
        let visible = self
            .get_visible_object_blocking(Request::from_parts(
                metadata,
                extensions,
                GetObjectRequest {
                    id: input.object_id,
                },
            ))?
            .into_inner()
            .object
            .ok_or_else(|| Status::not_found("not found"))?;
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        let property = schema
            .get(&visible.kind)
            .and_then(|object_type| {
                object_type
                    .properties
                    .iter()
                    .find(|property| property.name == input.property)
            })
            .filter(|property| property.prop_type == schema::PropertyType::Series)
            .ok_or_else(|| Status::invalid_argument("property is not a series"))?;
        // A property the caller may not read is absent from the visible
        // object, exactly like an unset one.
        let series_id = visible
            .properties
            .get(&input.property)
            .filter(|series_id| !series_id.is_empty())
            .ok_or_else(|| Status::not_found("series not found"))?;
        let dataset = authorize_series_dataset(
            self,
            &principals,
            tenant_context.as_ref(),
            &property.series_dataset,
        )?;
        let disclosure = self.egress_disclosure(&principals, tenant_context.as_ref());
        for name in series::SAMPLE_COLUMNS {
            let column = dataset
                .columns
                .iter()
                .find(|column| column.name == name)
                .ok_or_else(|| {
                    Status::failed_precondition(format!("samples dataset has no {name} column"))
                })?;
            if !disclosure.releases(&column.classification) {
                return Err(Status::permission_denied("series dataset access denied"));
            }
        }
        let scan = self
            .db
            .runtime()
            .series_samples(
                &dataset.id,
                series_id,
                input.start_ms,
                input.end_ms,
                MAX_SCANNED_SAMPLES,
            )
            .map_err(Status::failed_precondition)?;
        let samples = match scan {
            SeriesScan::Samples(samples) => samples,
            SeriesScan::OverScanCap => {
                return Err(Status::failed_precondition(format!(
                    "{REFUSAL_SCAN_CAP}: the range holds more than {MAX_SCANNED_SAMPLES} samples; narrow it"
                )));
            }
            SeriesScan::Quarantined => {
                return Err(Status::failed_precondition(format!(
                    "{REFUSAL_QUARANTINED}: the samples dataset is quarantined"
                )));
            }
        };
        let response =
            match series::downsample(samples, input.start_ms, input.end_ms, input.target_points) {
                SeriesPoints::Raw(samples) => ReadObjectSeriesResponse {
                    samples: samples
                        .into_iter()
                        .map(|sample| SeriesSample {
                            timestamp_ms: sample.timestamp_ms,
                            value: sample.value,
                        })
                        .collect(),
                    ..Default::default()
                },
                SeriesPoints::Buckets { width_ms, buckets } => ReadObjectSeriesResponse {
                    buckets: buckets
                        .into_iter()
                        .map(|bucket| SeriesBucket {
                            start_ms: bucket.start_ms,
                            count: bucket.count,
                            min: bucket.min,
                            max: bucket.max,
                            mean: bucket.mean,
                        })
                        .collect(),
                    bucket_width_ms: width_ms,
                    ..Default::default()
                },
            };
        Ok(Response::new(response))
    }
}
