//! Embedding catch-up (#1581, ADR 0117): follows the Sekai object-change feed
//! and writes the Sekai embedding index, under the Chisei egress policy that
//! decides which properties may reach an external model route.

use crate::chisei::egress::{filter_property_with_schema, new_record};
use crate::chisei::object_schema::ObjectType;
use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::classification_lattice::{ClassificationLattice, union_input_marking_tokens};
use crate::sekai::embedding_index::{
    CHANGE_PAGE, EmbeddingCatchUpReport, EmbeddingCheckpoint, EmbeddingError, EmbeddingRebuild,
    EmbeddingSource, EmbeddingSpec, EmbeddingStore, ObjectEmbeddings, StoredEmbeddingSpec,
    chunk_text, sha_hex, source_text,
};
use crate::sekai::markings::object_marking_token;
use crate::sekai::object_change_subscription::CommittedObjectMutation;
use chisei_provider::embedding::Embedder;
use futures_util::future::BoxFuture;
use std::collections::BTreeSet;

const REBUILD_PAGE: i64 = 500;

/// How long a rebuild's last write holds off scheduled catch-up on other
/// instances. A rebuild refreshes it with every object it writes; one that
/// stopped is taken over after it lapses.
pub const REBUILD_LEASE_MS: i64 = 5 * 60 * 1000;

/// One model call never outlives half a lease, whatever the route's own
/// timeout, so a rebuild renews its lease before it can lapse.
const EMBED_CALL_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(REBUILD_LEASE_MS as u64 / 2);

/// Policy an object is embedded under: its kind's schema (property
/// classifications for egress) and the namespace marking lattice.
struct Governance<'a> {
    schema: Option<&'a ObjectType>,
    lattice: Option<&'a ClassificationLattice>,
}

/// Bring the spec's vectors up to date with the object-change feed.
///
/// `admit` is the model-review admission for the embedder's route (the same
/// review state as other model calls); a refusal embeds nothing. A failure
/// leaves the checkpoint where it was, so the next call retries. Every write
/// is fenced on the spec revision, so a concurrent catch-up for the same spec
/// fails with [`EmbeddingError::Conflict`] instead of interleaving.
pub async fn catch_up_embeddings(
    db: &RuntimeDb,
    spec: &EmbeddingSpec,
    embedder: &dyn Embedder,
    admit: &(dyn Fn(&str) -> Result<(), String> + Sync),
    now_ms: i64,
) -> Result<EmbeddingCatchUpReport, EmbeddingError> {
    catch_up_from(db, spec, embedder, admit, now_ms, None).await
}

/// [`catch_up_embeddings`], refused when `listed_revision` is set and the
/// checkpoint has moved past it: the spec was put or deleted since it was
/// listed. Every later write is fenced on the revision read here.
pub async fn catch_up_from(
    db: &RuntimeDb,
    spec: &EmbeddingSpec,
    embedder: &dyn Embedder,
    admit: &(dyn Fn(&str) -> Result<(), String> + Sync),
    now_ms: i64,
    listed_revision: Option<i64>,
) -> Result<EmbeddingCatchUpReport, EmbeddingError> {
    spec.validate()?;
    admit(embedder.model()).map_err(EmbeddingError::Refused)?;
    let digest = spec.digest(embedder.model(), embedder.model_version());
    let namespace = spec.namespace.as_str();
    let checkpoint = db.embedding_checkpoint(namespace, &spec.id)?;
    if let Some(listed) = listed_revision {
        if listed
            != checkpoint
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.revision)
        {
            return Err(EmbeddingError::Conflict(
                "embedding spec changed since it was listed".into(),
            ));
        }
        // A rebuild clears the digest until it completes. While its lease
        // holds, another instance leaves it alone instead of restarting it.
        if checkpoint.as_ref().is_some_and(|checkpoint| {
            checkpoint.spec_digest.is_empty()
                && checkpoint.updated_at_ms > 0
                && now_ms.saturating_sub(checkpoint.updated_at_ms) < REBUILD_LEASE_MS
        }) {
            return Err(EmbeddingError::Conflict(
                "embedding rebuild in progress on another instance".into(),
            ));
        }
    }
    let checkpoint = match checkpoint {
        Some(checkpoint) if checkpoint.spec_digest == digest => checkpoint,
        previous => {
            let revision = previous
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.revision);
            let from = previous.map(|checkpoint| checkpoint.spec_digest);
            return rebuild(db, spec, embedder, &digest, from, revision, now_ms).await;
        }
    };
    // Generation before the feed: mutations after this read are in the feed
    // but not counted, so coverage can only be overstated toward safety.
    let generation = db.namespace_object_generation(namespace)?;
    let mut pending = db.list_committed_object_mutations_after(
        namespace,
        checkpoint.last_change_rowid,
        CHANGE_PAGE,
    )?;
    let more = pending.len() as i32 == CHANGE_PAGE;
    // One mutation writes one contiguous change row per field, all with its
    // timestamp. A full page may end inside a mutation: leave that mutation
    // whole for the next call so no mutation is counted twice.
    let mutation_key = |mutation: &CommittedObjectMutation| {
        (mutation.change.object_id.clone(), mutation.change.timestamp)
    };
    let mut split = false;
    if more && let Some(last) = pending.last().map(mutation_key) {
        let keep = pending.len()
            - pending
                .iter()
                .rev()
                .take_while(|mutation| mutation_key(mutation) == last)
                .count();
        if keep > 0 {
            pending.truncate(keep);
        } else {
            // One mutation larger than a page: consume it but acknowledge no
            // generation, which can only cause an extra rebuild.
            split = true;
        }
    }
    let covered = if split {
        0
    } else {
        pending
            .iter()
            .map(mutation_key)
            .collect::<BTreeSet<_>>()
            .len() as u64
    };
    let acknowledged = (checkpoint.last_generation + covered).min(generation);
    if !more && acknowledged < generation {
        // Mutations were purged from the feed before we read them: only a
        // rebuild closes that gap.
        return rebuild(
            db,
            spec,
            embedder,
            &digest,
            Some(digest.clone()),
            checkpoint.revision,
            now_ms,
        )
        .await;
    }
    let mut report = EmbeddingCatchUpReport {
        consumed_changes: pending.len() as i64,
        more,
        lag_ms: pending
            .iter()
            .map(|mutation| now_ms.saturating_sub(mutation.change.timestamp))
            .max()
            .unwrap_or(0),
        ..Default::default()
    };
    let mut revision = checkpoint.revision;
    let mut seen = BTreeSet::new();
    let mut last_rowid = checkpoint.last_change_rowid;
    let schema = db.get_object_type(&spec.object_kind)?;
    let lattice = db.get_classification_lattice(namespace)?;
    let governance = Governance {
        schema: schema.as_ref(),
        lattice: lattice.as_ref(),
    };
    for mutation in &pending {
        let object_id = &mutation.change.object_id;
        last_rowid = last_rowid.max(mutation.seq);
        if !seen.insert(object_id.clone()) {
            continue;
        }
        match db.get_object(object_id)? {
            Some(object) if object.namespace == namespace && object.kind == spec.object_kind => {
                report.chunks_embedded += embed_object(
                    db,
                    spec,
                    embedder,
                    &governance,
                    &object,
                    &mut revision,
                    &|| now_ms,
                    false,
                )
                .await?;
                report.objects += 1;
            }
            _ => {
                revision =
                    db.delete_embedding_object(namespace, &spec.id, object_id, revision, now_ms)?
            }
        }
    }
    db.store_embedding_checkpoint(
        namespace,
        &spec.id,
        &EmbeddingCheckpoint {
            spec_digest: digest,
            last_change_rowid: last_rowid,
            last_generation: acknowledged,
            revision,
            updated_at_ms: 0,
        },
        now_ms,
    )?;
    crate::obs::metrics::set_embedding_index_lag_ms(report.lag_ms.max(0) as u64);
    Ok(report)
}

/// One stored spec and how its catch-up in a pass ended.
pub type StoredSpecOutcome = (
    StoredEmbeddingSpec,
    Result<EmbeddingCatchUpReport, EmbeddingError>,
);

/// One pass over every stored spec (#1609): one catch-up call each, fenced
/// on the revision the spec was listed at. `route` admits each spec's
/// catalog route and returns its embedder; admission is its job, so catch-up
/// gets no second gate. A spec that fails is reported and retried on the
/// next pass; it does not stop the others. Replicas may run passes at once,
/// and a spec put or deleted during a pass is fenced out: the loser sees
/// [`EmbeddingError::Conflict`]. Run another pass while a report has `more`.
pub async fn catch_up_stored_specs<Route, Admitted>(
    db: &RuntimeDb,
    route: Route,
    now_ms: &(dyn Fn() -> i64 + Sync),
) -> Result<Vec<StoredSpecOutcome>, String>
where
    Route: Fn(StoredEmbeddingSpec) -> Admitted,
    Admitted: std::future::Future<Output = Result<Box<dyn Embedder>, EmbeddingError>>,
{
    let mut outcomes = Vec::new();
    for stored in db.list_embedding_specs(None)? {
        let outcome = match route(stored.clone()).await {
            Ok(embedder) => {
                catch_up_from(
                    db,
                    &stored.spec,
                    embedder.as_ref(),
                    &|_| Ok(()),
                    now_ms(),
                    Some(stored.revision),
                )
                .await
            }
            Err(error) => Err(error),
        };
        outcomes.push((stored, outcome));
    }
    Ok(outcomes)
}

/// Admits a stored spec's model route and returns its embedder. Combined
/// mode builds one from the Chisei route catalog; scheduled catch-up and
/// query embedding share it.
pub type EmbeddingRoute = std::sync::Arc<
    dyn Fn(StoredEmbeddingSpec) -> BoxFuture<'static, Result<Box<dyn Embedder>, EmbeddingError>>
        + Send
        + Sync,
>;

/// A query embedded for one stored spec.
#[derive(Debug, Clone, PartialEq)]
pub struct QueryVector {
    /// The spec whose chunks the vector is compared with.
    pub spec_id: String,
    /// The index's spec digest the query was embedded for. A caller re-reads
    /// the checkpoint after loading vectors: a rebuild clears the digest
    /// until it completes, so a changed digest means unlike vectors.
    pub spec_digest: String,
    pub vector: Vec<f32>,
    /// Age of the oldest namespace object change the spec's index has not
    /// consumed; 0 when caught up. Changes to other kinds count too, so it
    /// can only overstate.
    pub lag_ms: i64,
}

/// Embeds a search query for a stored spec (#1681, #1582), through the
/// same admitted route `route` returns for indexing. The route must produce
/// the vectors the index holds: its model and version give the indexed spec
/// digest, or the query is refused. An external route is refused when a
/// source property of the spec is classified restricted, as for indexing;
/// the text then passes the route's screen before it is sent.
pub async fn embed_query<Route, Admitted>(
    db: &RuntimeDb,
    stored: StoredEmbeddingSpec,
    text: &str,
    route: Route,
    now_ms: i64,
) -> Result<QueryVector, EmbeddingError>
where
    Route: Fn(StoredEmbeddingSpec) -> Admitted,
    Admitted: std::future::Future<Output = Result<Box<dyn Embedder>, EmbeddingError>>,
{
    let spec = stored.spec.clone();
    let namespace = spec.namespace.as_str();
    let embedder = route(stored).await?;
    let digest = spec.digest(embedder.model(), embedder.model_version());
    let checkpoint = match db.embedding_checkpoint(namespace, &spec.id)? {
        Some(checkpoint) if checkpoint.spec_digest == digest => checkpoint,
        _ => {
            return Err(EmbeddingError::Refused(
                "the route's model or version does not match the indexed vectors".into(),
            ));
        }
    };
    if embedder.external() {
        let schema = db.get_object_type(&spec.object_kind)?;
        if let Some(property) = spec.properties.iter().find(|name| {
            schema
                .as_ref()
                .and_then(|schema| schema.properties.iter().find(|p| &p.name == *name))
                .is_some_and(|p| {
                    crate::sekai::schema::is_restricted_property_classification(&p.classification)
                })
        }) {
            return Err(EmbeddingError::Refused(format!(
                "property `{property}` may not leave the deployment; query embedding needs a self-hosted route"
            )));
        }
    }
    embedder.screen(text).map_err(EmbeddingError::Refused)?;
    let mut vectors = tokio::time::timeout(EMBED_CALL_TIMEOUT, embedder.embed(&[text.to_string()]))
        .await
        .map_err(|_| EmbeddingError::Model("embedding call timed out".into()))?
        .map_err(EmbeddingError::Model)?;
    let lag_ms = db
        .list_committed_object_mutations_after(namespace, checkpoint.last_change_rowid, 1)?
        .first()
        .map_or(0, |mutation| {
            now_ms.saturating_sub(mutation.change.timestamp)
        });
    match vectors.pop() {
        Some(vector) if vectors.is_empty() && vector.len() == spec.dimension => Ok(QueryVector {
            spec_id: spec.id,
            spec_digest: digest,
            vector,
            lag_ms,
        }),
        _ => Err(EmbeddingError::Model(format!(
            "model {} did not return one vector of dimension {}",
            embedder.model(),
            spec.dimension
        ))),
    }
}

async fn rebuild(
    db: &RuntimeDb,
    spec: &EmbeddingSpec,
    embedder: &dyn Embedder,
    digest: &str,
    from: Option<String>,
    revision: i64,
    now_ms: i64,
) -> Result<EmbeddingCatchUpReport, EmbeddingError> {
    let namespace = spec.namespace.as_str();
    // Generation before position: a mutation between the two reads is then
    // replayed from the feed but never credited twice, so coverage can only
    // be undercounted, which at worst causes an extra rebuild. Changes landing
    // during the rebuild are replayed after it.
    let generation = db.namespace_object_generation(namespace)?;
    let watermark = db.object_change_watermark(namespace)?;
    // Writes are stamped with elapsed time, so each one renews the lease.
    let started = std::time::Instant::now();
    let clock = move || now_ms.saturating_add(started.elapsed().as_millis() as i64);
    let mut revision = db.reset_embedding_spec(namespace, &spec.id, revision, now_ms)?;
    let schema = db.get_object_type(&spec.object_kind)?;
    let lattice = db.get_classification_lattice(namespace)?;
    let governance = Governance {
        schema: schema.as_ref(),
        lattice: lattice.as_ref(),
    };
    let mut report = EmbeddingCatchUpReport {
        rebuilt: true,
        ..Default::default()
    };
    // Keyset pages by id: a deletion during the rebuild cannot shift an
    // unchanged object out of the walk.
    let mut after = String::new();
    loop {
        let ids = db.embedding_source_ids(namespace, &spec.object_kind, &after, REBUILD_PAGE)?;
        for id in &ids {
            // Recheck namespace and kind: the object may have changed since
            // the id page was read, and its schema decides egress.
            if let Some(object) = db
                .get_object(id)?
                .filter(|object| object.namespace == namespace && object.kind == spec.object_kind)
            {
                report.chunks_embedded += embed_object(
                    db,
                    spec,
                    embedder,
                    &governance,
                    &object,
                    &mut revision,
                    &clock,
                    true,
                )
                .await?;
                report.objects += 1;
            }
        }
        match ids.last() {
            Some(last) if ids.len() as i64 == REBUILD_PAGE => after = last.clone(),
            _ => break,
        }
    }
    db.complete_embedding_rebuild(
        namespace,
        &spec.id,
        &EmbeddingRebuild {
            from_digest: from.unwrap_or_default(),
            to_digest: digest.to_string(),
            objects: report.objects,
            rebuilt_at_ms: now_ms,
        },
        &EmbeddingCheckpoint {
            spec_digest: digest.to_string(),
            last_change_rowid: watermark,
            last_generation: generation,
            revision,
            updated_at_ms: 0,
        },
        now_ms,
    )?;
    Ok(report)
}

/// Embed the chunks of `object` whose text changed. Returns how many were
/// sent to the model.
#[allow(clippy::too_many_arguments)]
async fn embed_object(
    db: &RuntimeDb,
    spec: &EmbeddingSpec,
    embedder: &dyn Embedder,
    governance: &Governance<'_>,
    object: &Object,
    revision: &mut i64,
    clock: &(dyn Fn() -> i64 + Sync),
    renew_lease: bool,
) -> Result<i64, EmbeddingError> {
    if embedder.external() {
        // Same rule as other model context: a property leaves the deployment
        // only when its classification and the object's egress list allow it.
        let mut record = new_record(object);
        for property in &spec.properties {
            if object
                .properties
                .get(property)
                .is_some_and(|v| !v.is_empty())
                && filter_property_with_schema(
                    object,
                    property,
                    governance.schema,
                    &mut record,
                    true,
                )
                .is_none()
            {
                return Err(EmbeddingError::Refused(format!(
                    "object {} property `{property}` may not leave the deployment; \
                     embedding needs a self-hosted route",
                    object.id
                )));
            }
        }
    }
    // Join the marking before any model call: an unknown token fails closed
    // without sending text anywhere.
    let (_, marking) =
        union_input_marking_tokens(governance.lattice, [object_marking_token(object)])
            .map_err(EmbeddingError::Refused)?;
    let text = source_text(spec, object);
    let chunks = chunk_text(&text, spec.chunk_chars);
    let stored = db.embedding_chunk_digests(&spec.namespace, &spec.id, &object.id)?;
    let changed: Vec<(u32, String, String)> = chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| (index as u32, sha_hex(chunk), chunk.clone()))
        .filter(|(index, digest, _)| stored.get(*index as usize) != Some(digest))
        .collect();
    if !changed.is_empty() {
        embedder.screen(&text).map_err(EmbeddingError::Refused)?;
    }
    let mut embedded = Vec::with_capacity(changed.len());
    for (index, batch) in changed.chunks(spec.batch_size).enumerate() {
        // A rebuild renews its lease before every further model call, so a
        // large object never outlives it.
        if renew_lease && index > 0 {
            *revision = db.store_embedding_checkpoint(
                &spec.namespace,
                &spec.id,
                &EmbeddingCheckpoint {
                    revision: *revision,
                    ..EmbeddingCheckpoint::default()
                },
                clock(),
            )?;
        }
        let texts: Vec<String> = batch.iter().map(|(_, _, text)| text.clone()).collect();
        let vectors = tokio::time::timeout(EMBED_CALL_TIMEOUT, embedder.embed(&texts))
            .await
            .map_err(|_| EmbeddingError::Model("embedding call timed out".into()))?
            .map_err(EmbeddingError::Model)?;
        if vectors.len() != batch.len() || vectors.iter().any(|v| v.len() != spec.dimension) {
            return Err(EmbeddingError::Model(format!(
                "model {} returned vectors that do not match {} texts of dimension {}",
                embedder.model(),
                batch.len(),
                spec.dimension
            )));
        }
        embedded.extend(
            batch
                .iter()
                .zip(vectors)
                .map(|((index, digest, _), vector)| (*index, digest.clone(), vector)),
        );
    }
    let source = EmbeddingSource {
        source_digest: sha_hex(&text),
        model: embedder.model().to_string(),
        model_version: embedder.model_version().to_string(),
        marking,
        classifications: spec
            .properties
            .iter()
            .map(|property| {
                let class = governance
                    .schema
                    .and_then(|schema| schema.properties.iter().find(|p| &p.name == property))
                    .map(|p| p.classification.as_str())
                    .filter(|class| !class.is_empty())
                    .unwrap_or("public");
                format!("{property}={class}")
            })
            .collect(),
    };
    *revision = db.write_embedding_object(
        &spec.namespace,
        &spec.id,
        &ObjectEmbeddings {
            object_id: &object.id,
            source: &source,
            chunks: &embedded,
            keep: chunks.len() as u32,
        },
        *revision,
        clock(),
    )?;
    Ok(embedded.len() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::object_schema::{PropertyDef, PropertyType};
    use async_trait::async_trait;
    use chisei_provider::embedding::HashEmbedder;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NS: &str = "ops";

    fn postgres_runtime() -> (crate::db::postgres::ScratchDatabase, RuntimeDb) {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        (scratch, db)
    }

    fn spec() -> EmbeddingSpec {
        EmbeddingSpec {
            id: "notes".into(),
            namespace: NS.into(),
            object_kind: "note".into(),
            properties: vec!["body".into(), "title".into()],
            chunk_chars: 8,
            dimension: 4,
            batch_size: 2,
        }
    }

    fn property(name: &str, classification: &str) -> PropertyDef {
        PropertyDef {
            name: name.into(),
            prop_type: PropertyType::String,
            required: false,
            description: String::new(),
            enum_values: Vec::new(),
            link_kind: String::new(),
            compute_expr: String::new(),
            classification: classification.into(),
            struct_fields: Vec::new(),
        }
    }

    fn note(id: &str, body: &str, title: &str) -> Object {
        Object {
            id: id.into(),
            kind: "note".into(),
            name: id.into(),
            namespace: NS.into(),
            external_id: String::new(),
            properties: [
                ("body", body),
                ("title", title),
                ("access_marking", "internal"),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect(),
            created: 1,
            updated: 1,
        }
    }

    /// Counts calls and can claim to be an external route.
    struct Counting {
        inner: HashEmbedder,
        external: bool,
        calls: AtomicUsize,
    }

    impl Counting {
        fn new(version: &str, external: bool) -> Self {
            Self {
                inner: HashEmbedder::new("embed-test", version, 4),
                external,
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl Embedder for Counting {
        fn model(&self) -> &str {
            self.inner.model()
        }
        fn model_version(&self) -> &str {
            self.inner.model_version()
        }
        fn external(&self) -> bool {
            self.external
        }
        async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
            self.calls.fetch_add(texts.len(), Ordering::SeqCst);
            self.inner.embed(texts).await
        }
    }

    /// Edit the stored object so the update carries its current revision.
    fn retitle(db: &RuntimeDb, id: &str, title: &str) {
        let mut object = db.get_object(id).unwrap().unwrap();
        object.properties.insert("title".into(), title.into());
        object.updated += 1;
        db.update_object_with_audit(&object, "test").unwrap();
    }

    fn admit_all(_: &str) -> Result<(), String> {
        Ok(())
    }

    async fn exercise(db: &RuntimeDb) {
        db.upsert_object_type(&ObjectType {
            kind: "note".into(),
            description: String::new(),
            properties: vec![property("body", "sensitive"), property("title", "public")],
            is_builtin: false,
            implements: Vec::new(),
        })
        .unwrap();
        // "body: " + 26 letters + "\ntitle: draft" = 45 chars, 6 chunks of 8.
        let body = "abcdefghijklmnopqrstuvwxyz";
        db.create_object_with_audit(&note("n1", body, "draft"), "test")
            .unwrap();
        let spec = spec();
        let local = Counting::new("v1", false);

        // First run builds and records the rebuild.
        let first = catch_up_embeddings(db, &spec, &local, &admit_all, 1_000)
            .await
            .unwrap();
        assert!(first.rebuilt);
        let chunks = db.embedding_chunks(NS, &spec.id).unwrap();
        assert_eq!(chunks.len(), 6);
        let tags = &chunks[0].source;
        assert_eq!(
            (tags.model.as_str(), tags.model_version.as_str()),
            ("embed-test", "v1")
        );
        assert_eq!(tags.marking.as_deref(), Some("internal"));
        assert_eq!(tags.classifications, vec!["body=sensitive", "title=public"]);
        assert!(chunks.iter().all(|chunk| chunk.vector.len() == 4));

        // An edit to the title re-embeds only the last chunk.
        let calls = local.calls.load(Ordering::SeqCst);
        retitle(db, "n1", "final");
        let edit = catch_up_embeddings(db, &spec, &local, &admit_all, 2_000)
            .await
            .unwrap();
        assert!(!edit.rebuilt);
        assert_eq!(edit.chunks_embedded, 1);
        assert_eq!(local.calls.load(Ordering::SeqCst) - calls, 1);
        let after = db.embedding_chunks(NS, &spec.id).unwrap();
        assert_eq!(after.len(), 6);
        assert_eq!(after[0].vector, chunks[0].vector);
        assert_ne!(after[5].vector, chunks[5].vector);

        // A model version change is a tracked rebuild.
        let v2 = Counting::new("v2", false);
        let rebuilt = catch_up_embeddings(db, &spec, &v2, &admit_all, 3_000)
            .await
            .unwrap();
        assert!(rebuilt.rebuilt);
        let rebuilds = db.embedding_rebuilds(NS, &spec.id).unwrap();
        assert_eq!(rebuilds.len(), 2);
        assert_eq!(rebuilds[1].from_digest, spec.digest("embed-test", "v1"));
        assert_eq!(rebuilds[1].to_digest, spec.digest("embed-test", "v2"));
        assert_eq!(rebuilds[1].objects, 1);
        assert!(
            db.embedding_chunks(NS, &spec.id)
                .unwrap()
                .iter()
                .all(|chunk| chunk.source.model_version == "v2")
        );

        // A sensitive source property refuses an external route before any call.
        let external = Counting::new("v2", true);
        retitle(db, "n1", "again");
        let refused = catch_up_embeddings(db, &spec, &external, &admit_all, 4_000).await;
        assert!(
            matches!(refused, Err(EmbeddingError::Refused(_))),
            "{refused:?}"
        );
        assert_eq!(external.calls.load(Ordering::SeqCst), 0);

        // Model review refusal embeds nothing.
        let denied =
            catch_up_embeddings(db, &spec, &v2, &|_| Err("route not enabled".into()), 5_000).await;
        assert!(matches!(denied, Err(EmbeddingError::Refused(_))));

        // Deleting the object removes its vectors.
        db.delete_object_with_audit("n1", "test").unwrap();
        catch_up_embeddings(db, &spec, &v2, &admit_all, 6_000)
            .await
            .unwrap();
        assert!(db.embedding_chunks(NS, &spec.id).unwrap().is_empty());
    }

    async fn exercise_feed_gap_rebuilds(db: &RuntimeDb) {
        use crate::db::search_index::SearchIndexStore;
        let spec = spec();
        let local = Counting::new("v1", false);
        db.create_object_with_audit(&note("g1", "first", "one"), "test")
            .unwrap();
        catch_up_embeddings(db, &spec, &local, &admit_all, 1_000)
            .await
            .unwrap();
        // g1's edit is purged from the feed; a newer change to g2 remains.
        retitle(db, "g1", "two");
        db.purge_object_changes_for_object_for_test("g1").unwrap();
        db.create_object_with_audit(&note("g2", "second", "one"), "test")
            .unwrap();
        let report = catch_up_embeddings(db, &spec, &local, &admit_all, 2_000)
            .await
            .unwrap();
        assert!(report.rebuilt, "{report:?}");
        let ids: BTreeSet<_> = db
            .embedding_chunks(NS, &spec.id)
            .unwrap()
            .into_iter()
            .map(|chunk| chunk.object_id)
            .collect();
        assert_eq!(ids, BTreeSet::from(["g1".to_string(), "g2".to_string()]));
    }

    async fn exercise_stale_revision_is_refused(db: &RuntimeDb) {
        let spec = spec();
        db.create_object_with_audit(&note("r1", "text", "one"), "test")
            .unwrap();
        catch_up_embeddings(db, &spec, &Counting::new("v1", false), &admit_all, 1_000)
            .await
            .unwrap();
        let stale = db.embedding_checkpoint(NS, &spec.id).unwrap().unwrap();
        // Another catch-up moves the revision on.
        db.delete_embedding_object(NS, &spec.id, "r1", stale.revision, 2_000)
            .unwrap();
        let refused = db.delete_embedding_object(NS, &spec.id, "r1", stale.revision, 3_000);
        assert_eq!(
            refused.map_err(EmbeddingError::from),
            Err(EmbeddingError::Conflict(
                crate::sekai::embedding_index::EMBEDDING_REVISION_CONFLICT.into()
            ))
        );
        let checkpoint = db.store_embedding_checkpoint(NS, &spec.id, &stale, 4_000);
        assert!(checkpoint.is_err());
    }

    /// Deletes `victim` the first time it is asked to embed.
    struct DeletingOnce<'a> {
        db: &'a RuntimeDb,
        victim: &'a str,
        inner: HashEmbedder,
        done: AtomicUsize,
    }

    #[async_trait]
    impl Embedder for DeletingOnce<'_> {
        fn model(&self) -> &str {
            self.inner.model()
        }
        fn model_version(&self) -> &str {
            self.inner.model_version()
        }
        fn external(&self) -> bool {
            false
        }
        async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
            if self.done.fetch_add(1, Ordering::SeqCst) == 0 {
                self.db.delete_object_with_audit(self.victim, "test")?;
            }
            self.inner.embed(texts).await
        }
    }

    async fn exercise_rebuild_survives_deletes(db: &RuntimeDb) {
        let count = REBUILD_PAGE as usize + 1;
        for index in 0..count {
            db.create_object_with_audit(&note(&format!("k{index:04}"), "x", "y"), "test")
                .unwrap();
        }
        let spec = EmbeddingSpec {
            chunk_chars: 1000,
            batch_size: 64,
            ..spec()
        };
        let embedder = DeletingOnce {
            db,
            victim: "k0001",
            inner: HashEmbedder::new("embed-test", "v1", 4),
            done: AtomicUsize::new(0),
        };
        catch_up_embeddings(db, &spec, &embedder, &admit_all, 1_000)
            .await
            .unwrap();
        let ids: BTreeSet<_> = db
            .embedding_chunks(NS, &spec.id)
            .unwrap()
            .into_iter()
            .map(|chunk| chunk.object_id)
            .collect();
        // The object past the first page is embedded although an earlier one
        // vanished mid-walk.
        assert!(
            ids.contains(&format!("k{:04}", count - 1)),
            "{} ids",
            ids.len()
        );
        assert!(!ids.contains("k0001"));
    }

    async fn exercise_interrupted_rebuild_is_redone(db: &RuntimeDb) {
        let spec = spec();
        let v1 = Counting::new("v1", false);
        db.create_object_with_audit(&note("c1", "text", "one"), "test")
            .unwrap();
        catch_up_embeddings(db, &spec, &v1, &admit_all, 1_000)
            .await
            .unwrap();
        // A v2 rebuild resets the index and dies before finishing.
        let current = db.embedding_checkpoint(NS, &spec.id).unwrap().unwrap();
        db.reset_embedding_spec(NS, &spec.id, current.revision, 2_000)
            .unwrap();
        // A v1 worker must not trust the empty index.
        let report = catch_up_embeddings(db, &spec, &v1, &admit_all, 3_000)
            .await
            .unwrap();
        assert!(report.rebuilt);
        assert!(!db.embedding_chunks(NS, &spec.id).unwrap().is_empty());
    }

    #[tokio::test]
    async fn namespace_lattice_tokens_mark_vectors() {
        use crate::sekai::classification_lattice::{
            CLASSIFICATION_LATTICE_VERSION, ClassificationLattice,
        };
        let db = RuntimeDb::memory();
        db.put_classification_lattice(
            &ClassificationLattice {
                contract_version: CLASSIFICATION_LATTICE_VERSION.into(),
                namespace: NS.into(),
                tokens: vec!["open".into(), "compartment-a".into()],
                parents: std::collections::BTreeMap::new(),
                incomparable: Vec::new(),
            },
            "root",
            10,
        )
        .unwrap();
        let mut object = note("m1", "text", "one");
        object
            .properties
            .insert("access_marking".into(), "compartment-a".into());
        db.create_object_with_audit(&object, "test").unwrap();
        catch_up_embeddings(&db, &spec(), &Counting::new("v1", false), &admit_all, 1_000)
            .await
            .unwrap();
        let chunks = db.embedding_chunks(NS, "notes").unwrap();
        assert!(!chunks.is_empty());
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.source.marking.as_deref() == Some("compartment-a"))
        );
    }

    #[tokio::test]
    async fn interrupted_rebuild_is_redone() {
        exercise_interrupted_rebuild_is_redone(&RuntimeDb::memory()).await;
    }

    #[tokio::test]
    async fn feed_gap_behind_newer_changes_rebuilds() {
        exercise_feed_gap_rebuilds(&RuntimeDb::memory()).await;
    }

    #[tokio::test]
    async fn stale_revision_is_refused() {
        exercise_stale_revision_is_refused(&RuntimeDb::memory()).await;
    }

    #[tokio::test]
    async fn rebuild_survives_deletes_during_the_walk() {
        exercise_rebuild_survives_deletes(&RuntimeDb::memory()).await;
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_fencing_gap_and_keyset() {
        let (_scratch, db) = postgres_runtime();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            exercise_feed_gap_rebuilds(&db).await;
            exercise_stale_revision_is_refused(&db).await;
            exercise_rebuild_survives_deletes(&db).await;
            exercise_interrupted_rebuild_is_redone(&db).await;
        });
    }

    #[tokio::test]
    async fn embeddings_follow_edits_rebuilds_and_governance() {
        exercise(&RuntimeDb::memory()).await;
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_embeddings_follow_edits_rebuilds_and_governance() {
        // The scratch database drops outside the runtime: its synchronous
        // client cannot shut down inside one.
        let (_scratch, db) = postgres_runtime();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise(&db));
    }

    /// An OpenAI-compatible embeddings endpoint on a loopback port that
    /// counts the texts it embeds.
    async fn embeddings_route(hits: std::sync::Arc<AtomicUsize>) -> String {
        use axum::{Json, Router, routing::post};
        let app = Router::new().route(
            "/v1/embeddings",
            post(move |Json(body): Json<serde_json::Value>| {
                let hits = hits.clone();
                async move {
                    let inputs = body["input"].as_array().cloned().unwrap_or_default();
                    hits.fetch_add(inputs.len(), Ordering::SeqCst);
                    let data = inputs
                        .iter()
                        .enumerate()
                        .map(|(index, _)| {
                            serde_json::json!({"index": index, "embedding": [0.1, 0.2, 0.3, 0.4]})
                        })
                        .collect::<Vec<_>>();
                    Json(serde_json::json!({ "data": data }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        origin
    }

    async fn exercise_stored_specs(db: &RuntimeDb) {
        use chisei_provider::llm::openai::OpenAiEmbedder;
        db.upsert_object_type(&ObjectType {
            kind: "note".into(),
            description: String::new(),
            properties: vec![property("body", "sensitive"), property("title", "public")],
            is_builtin: false,
            implements: Vec::new(),
        })
        .unwrap();
        db.create_object_with_audit(&note("s1", "stored spec body", "draft"), "test")
            .unwrap();
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let origin = embeddings_route(hits.clone()).await;
        let model = "hosted.local/embed-small";
        let mut stored = StoredEmbeddingSpec {
            spec: spec(),
            model: model.into(),
            updated_by: "admin".into(),
            updated_at_ms: 1,
            revision: 0,
        };
        db.put_embedding_spec(&stored).unwrap();
        let route = |external: bool| {
            let origin = origin.clone();
            move |stored: StoredEmbeddingSpec| {
                let embedder = Box::new(OpenAiEmbedder::new(
                    "",
                    &origin,
                    &stored.model,
                    "embed-small",
                    "",
                    external,
                )) as Box<dyn Embedder>;
                async move { Ok(embedder) }
            }
        };
        let local = route(false);
        let now = || 1_000;

        // A local route embeds the namespace from the stored spec.
        let outcomes = catch_up_stored_specs(db, &local, &now).await.unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].1.as_ref().unwrap().rebuilt, "{outcomes:?}");
        let chunks = db.embedding_chunks(NS, "notes").unwrap();
        assert!(!chunks.is_empty());
        assert!(chunks.iter().all(|chunk| chunk.source.model == model));

        // Changing the stored spec is a recorded rebuild.
        stored.spec.chunk_chars = 16;
        db.put_embedding_spec(&stored).unwrap();
        catch_up_stored_specs(db, &local, &now).await.unwrap()[0]
            .1
            .as_ref()
            .unwrap();
        let rebuilds = db.embedding_rebuilds(NS, "notes").unwrap();
        assert_eq!(rebuilds.len(), 2);
        assert_eq!(rebuilds[1].to_digest, stored.spec.digest(model, ""));

        // An external route refuses the sensitive body before any call.
        retitle(db, "s1", "final");
        let before = hits.load(Ordering::SeqCst);
        let external = route(true);
        let refused = catch_up_stored_specs(db, &external, &now).await.unwrap();
        assert!(
            matches!(refused[0].1, Err(EmbeddingError::Refused(_))),
            "{refused:?}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), before);

        // Deleting the spec removes its vectors and history.
        assert!(db.delete_embedding_spec(NS, "notes").unwrap());
        assert!(db.list_embedding_specs(Some(NS)).unwrap().is_empty());
        assert!(db.embedding_chunks(NS, "notes").unwrap().is_empty());
        assert!(db.embedding_rebuilds(NS, "notes").unwrap().is_empty());
        assert_eq!(
            db.embedding_checkpoint(NS, "notes")
                .unwrap()
                .unwrap()
                .spec_digest,
            ""
        );

        // A catch-up for a listing taken before a delete or a put writes
        // nothing; the next listing catches up.
        db.put_embedding_spec(&stored).unwrap();
        let listed = db.list_embedding_specs(Some(NS)).unwrap().remove(0);
        let hash = HashEmbedder::new(model, "", 4);
        let late = |listed: StoredEmbeddingSpec| {
            let hash = hash.clone();
            async move {
                catch_up_from(
                    db,
                    &listed.spec,
                    &hash,
                    &admit_all,
                    7_000,
                    Some(listed.revision),
                )
                .await
            }
        };
        assert!(db.delete_embedding_spec(NS, "notes").unwrap());
        let deleted = late(listed.clone()).await;
        assert!(
            matches!(deleted, Err(EmbeddingError::Conflict(_))),
            "{deleted:?}"
        );
        assert!(db.embedding_chunks(NS, "notes").unwrap().is_empty());
        db.put_embedding_spec(&stored).unwrap();
        let replaced = late(listed).await;
        assert!(
            matches!(replaced, Err(EmbeddingError::Conflict(_))),
            "{replaced:?}"
        );
        assert!(db.embedding_chunks(NS, "notes").unwrap().is_empty());
        let revived = catch_up_stored_specs(db, &local, &now).await.unwrap();
        assert!(revived[0].1.as_ref().unwrap().rebuilt);

        // A rebuild another instance is running holds off scheduled
        // catch-up until its lease lapses; then this instance takes over.
        let current = db.embedding_checkpoint(NS, "notes").unwrap().unwrap();
        db.reset_embedding_spec(NS, "notes", current.revision, 50_000)
            .unwrap();
        let listed = db.list_embedding_specs(Some(NS)).unwrap().remove(0);
        let scheduled = |now_ms| {
            catch_up_from(
                db,
                &listed.spec,
                &hash,
                &admit_all,
                now_ms,
                Some(listed.revision),
            )
        };
        let held = scheduled(51_000).await;
        assert!(matches!(held, Err(EmbeddingError::Conflict(_))), "{held:?}");
        let taken = scheduled(50_000 + REBUILD_LEASE_MS).await.unwrap();
        assert!(taken.rebuilt);
    }

    #[tokio::test]
    async fn stored_specs_embed_through_a_route_and_rebuild_on_change() {
        exercise_stored_specs(&RuntimeDb::memory()).await;
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_stored_specs_embed_through_a_route_and_rebuild_on_change() {
        let (_scratch, db) = postgres_runtime();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise_stored_specs(&db));
    }

    /// Refuses any source text holding `needle`, like a payload leak rule.
    struct Screening {
        inner: Counting,
        needle: &'static str,
    }

    #[async_trait]
    impl Embedder for Screening {
        fn model(&self) -> &str {
            self.inner.model()
        }
        fn model_version(&self) -> &str {
            self.inner.model_version()
        }
        fn external(&self) -> bool {
            false
        }
        fn screen(&self, text: &str) -> Result<(), String> {
            if text.contains(self.needle) {
                Err("blocked by payload rule".into())
            } else {
                Ok(())
            }
        }
        async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
            self.inner.embed(texts).await
        }
    }

    #[tokio::test]
    async fn whole_source_text_is_screened_before_any_chunk_is_sent() {
        let db = RuntimeDb::memory();
        // 8-character chunks split "body: tok-secret-42" across chunk boundaries.
        db.create_object_with_audit(&note("leak", "tok-secret-42", "t"), "test")
            .unwrap();
        let screening = Screening {
            inner: Counting::new("v1", false),
            needle: "tok-secret-42",
        };
        let refused = catch_up_embeddings(&db, &spec(), &screening, &admit_all, 1_000).await;
        assert!(
            matches!(refused, Err(EmbeddingError::Refused(_))),
            "{refused:?}"
        );
        assert_eq!(screening.inner.calls.load(Ordering::SeqCst), 0);
    }

    async fn exercise_query_embedding(db: &RuntimeDb) {
        db.upsert_object_type(&ObjectType {
            kind: "note".into(),
            description: String::new(),
            properties: vec![property("body", "sensitive"), property("title", "public")],
            is_builtin: false,
            implements: Vec::new(),
        })
        .unwrap();
        db.create_object_with_audit(&note("q1", "quarterly", "plan"), "test")
            .unwrap();
        let mut spec = spec();
        // One chunk per object, so a query of the same text matches it.
        spec.chunk_chars = 1_000;
        db.put_embedding_spec(&StoredEmbeddingSpec {
            spec: spec.clone(),
            model: "embed-test".into(),
            updated_by: "admin".into(),
            updated_at_ms: 1,
            revision: 0,
        })
        .unwrap();
        let route = |version: &'static str, external: bool| {
            move |_: StoredEmbeddingSpec| async move {
                Ok(Box::new(Counting::new(version, external)) as Box<dyn Embedder>)
            }
        };
        catch_up_stored_specs(db, route("v1", false), &|| 1_000)
            .await
            .unwrap();
        let stored = db.embedding_chunks(NS, &spec.id).unwrap();
        let text = "body: quarterly\ntitle: plan";

        let listed = db.list_embedding_specs(Some(NS)).unwrap().remove(0);
        // The same route embeds the query as the index embedded the object.
        let query = embed_query(db, listed.clone(), text, route("v1", false), 2_000)
            .await
            .unwrap();
        assert_eq!(query.vector, stored[0].vector);
        assert_eq!(
            (query.spec_id.as_str(), query.lag_ms),
            (spec.id.as_str(), 0)
        );

        // Another model version would compare unlike vectors.
        let other = embed_query(db, listed.clone(), text, route("v2", false), 2_000).await;
        assert!(
            matches!(other, Err(EmbeddingError::Refused(_))),
            "{other:?}"
        );

        // An external route refuses a spec with a sensitive source property.
        let external = embed_query(db, listed, text, route("v1", true), 2_000).await;
        assert!(
            matches!(external, Err(EmbeddingError::Refused(_))),
            "{external:?}"
        );
    }

    #[tokio::test]
    async fn query_embedding_matches_the_index_and_refuses_other_routes() {
        exercise_query_embedding(&RuntimeDb::memory()).await;
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_query_embedding_matches_the_index_and_refuses_other_routes() {
        let (_scratch, db) = postgres_runtime();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise_query_embedding(&db));
    }
}
