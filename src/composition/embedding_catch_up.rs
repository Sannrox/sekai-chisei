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
    EmbeddingSource, EmbeddingSpec, EmbeddingStore, ObjectEmbeddings, chunk_text, sha_hex,
    source_text,
};
use crate::sekai::markings::object_marking_token;
use crate::sekai::object_change_subscription::CommittedObjectMutation;
use chisei_provider::embedding::Embedder;
use std::collections::BTreeSet;

const REBUILD_PAGE: i64 = 500;

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
    admit: &dyn Fn(&str) -> Result<(), String>,
    now_ms: i64,
) -> Result<EmbeddingCatchUpReport, EmbeddingError> {
    spec.validate()?;
    admit(embedder.model()).map_err(EmbeddingError::Refused)?;
    let digest = spec.digest(embedder.model(), embedder.model_version());
    let namespace = spec.namespace.as_str();
    let checkpoint = db.embedding_checkpoint(namespace, &spec.id)?;
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
                    now_ms,
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
        },
        now_ms,
    )?;
    crate::obs::metrics::set_embedding_index_lag_ms(report.lag_ms.max(0) as u64);
    Ok(report)
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
                    now_ms,
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
        },
        now_ms,
    )?;
    Ok(report)
}

/// Embed the chunks of `object` whose text changed. Returns how many were
/// sent to the model.
async fn embed_object(
    db: &RuntimeDb,
    spec: &EmbeddingSpec,
    embedder: &dyn Embedder,
    governance: &Governance<'_>,
    object: &Object,
    revision: &mut i64,
    now_ms: i64,
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
    let mut embedded = Vec::with_capacity(changed.len());
    for batch in changed.chunks(spec.batch_size) {
        let texts: Vec<String> = batch.iter().map(|(_, _, text)| text.clone()).collect();
        let vectors = embedder
            .embed(&texts)
            .await
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
        now_ms,
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
}
