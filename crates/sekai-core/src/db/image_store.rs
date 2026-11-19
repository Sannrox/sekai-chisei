//! SQLite persistence for governed images, renditions, and annotations (#696).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::image::{
    GovernedImage, IMAGE_UNAVAILABLE, ImageAnnotation, ImageRendition, require_attachable,
};

impl SekaiDb {
    pub fn put_governed_image(&self, image: &GovernedImage) -> Result<(), String> {
        let json = serde_json::to_string(image)
            .map_err(|error| format!("encode governed image: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        // A tombstone is final: re-putting the image does not revive it.
        if load_image(&tx, &image.namespace, &image.image_id)?
            .is_some_and(|stored| stored.deleted_at_ms != 0)
        {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_images
                    (namespace, image_id, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, image_id) DO UPDATE SET
                    record_json = excluded.record_json
                 WHERE sekai_governed_images.owner = excluded.owner",
                params![image.namespace, image.image_id, image.owner, json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Insert `image` unless its id is taken, in one write transaction.
    /// Returns `None` when this call stored it, or the record that already
    /// holds the id, untouched, so concurrent admissions cannot overwrite
    /// each other (#2717).
    pub fn insert_governed_image(
        &self,
        image: &GovernedImage,
    ) -> Result<Option<GovernedImage>, String> {
        let json = serde_json::to_string(image)
            .map_err(|error| format!("encode governed image: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let inserted = tx
            .execute(
                "INSERT INTO sekai_governed_images
                    (namespace, image_id, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, image_id) DO NOTHING",
                params![image.namespace, image.image_id, image.owner, json],
            )
            .map_err(|error| error.to_string())?;
        let existing = if inserted == 0 {
            let current: String = tx
                .query_row(
                    "SELECT record_json FROM sekai_governed_images
                     WHERE namespace = ?1 AND image_id = ?2",
                    params![image.namespace, image.image_id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            Some(
                serde_json::from_str(&current)
                    .map_err(|error| format!("decode governed image: {error}"))?,
            )
        } else {
            None
        };
        tx.commit().map_err(|error| error.to_string())?;
        Ok(existing)
    }

    /// Read-modify-write of one image in a single write transaction, so a check made
    /// by `update` (hold, deletion, expiry) still holds when its result is stored.
    /// Writing a deleted image also drops its renditions and annotations in the same
    /// transaction (#2717).
    pub fn update_governed_image(
        &self,
        namespace: &str,
        image_id: &str,
        update: impl FnOnce(GovernedImage) -> Result<GovernedImage, String>,
    ) -> Result<GovernedImage, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current: String = tx
            .query_row(
                "SELECT record_json FROM sekai_governed_images
                 WHERE namespace = ?1 AND image_id = ?2",
                params![namespace, image_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or(IMAGE_UNAVAILABLE)?;
        let current: GovernedImage = serde_json::from_str(&current)
            .map_err(|error| format!("decode governed image: {error}"))?;
        let owner = current.owner.clone();
        let next = update(current)?;
        if next.namespace != namespace || next.image_id != image_id || next.owner != owner {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        let json = serde_json::to_string(&next)
            .map_err(|error| format!("encode governed image: {error}"))?;
        tx.execute(
            "UPDATE sekai_governed_images SET record_json = ?3
             WHERE namespace = ?1 AND image_id = ?2",
            params![namespace, image_id, json],
        )
        .map_err(|error| error.to_string())?;
        if next.deleted_at_ms != 0 {
            tx.execute(
                "DELETE FROM sekai_governed_image_renditions
                 WHERE namespace = ?1 AND image_id = ?2",
                params![namespace, image_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "DELETE FROM sekai_governed_image_annotations
                 WHERE namespace = ?1 AND image_id = ?2",
                params![namespace, image_id],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(next)
    }

    pub fn get_governed_image(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Option<GovernedImage>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_governed_images
                 WHERE namespace = ?1 AND image_id = ?2",
                params![namespace, image_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode governed image: {error}"))
        })
        .transpose()
    }

    pub fn put_governed_image_rendition(&self, rendition: &ImageRendition) -> Result<(), String> {
        let json = serde_json::to_string(rendition)
            .map_err(|error| format!("encode governed image rendition: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let parent =
            load_image(&tx, &rendition.namespace, &rendition.image_id)?.ok_or(IMAGE_UNAVAILABLE)?;
        require_attachable(&parent, &rendition.parent_content_digest)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_image_renditions
                    (namespace, image_id, rendition_id, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, image_id, rendition_id) DO UPDATE SET
                    record_json = excluded.record_json
                 WHERE sekai_governed_image_renditions.namespace = excluded.namespace
                   AND sekai_governed_image_renditions.image_id = excluded.image_id",
                params![
                    rendition.namespace,
                    rendition.image_id,
                    rendition.rendition_id,
                    json
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn list_governed_image_renditions(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Vec<ImageRendition>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_governed_image_renditions
                 WHERE namespace = ?1 AND image_id = ?2
                 ORDER BY rendition_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, image_id], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut renditions = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            renditions.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode governed image rendition: {error}"))?,
            );
        }
        Ok(renditions)
    }

    pub fn tombstone_governed_image(&self, image: &GovernedImage) -> Result<(), String> {
        let json = serde_json::to_string(image)
            .map_err(|error| format!("encode governed image: {error}"))?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_images
                    (namespace, image_id, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, image_id) DO UPDATE SET
                    record_json = excluded.record_json
                 WHERE sekai_governed_images.owner = excluded.owner",
                params![image.namespace, image.image_id, image.owner, json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        tx.execute(
            "DELETE FROM sekai_governed_image_renditions
             WHERE namespace = ?1 AND image_id = ?2",
            params![image.namespace, image.image_id],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_governed_image_annotations
             WHERE namespace = ?1 AND image_id = ?2",
            params![image.namespace, image.image_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn put_governed_image_annotation(
        &self,
        annotation: &ImageAnnotation,
    ) -> Result<(), String> {
        let json = serde_json::to_string(annotation)
            .map_err(|error| format!("encode governed image annotation: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let parent = load_image(&tx, &annotation.namespace, &annotation.image_id)?
            .ok_or(IMAGE_UNAVAILABLE)?;
        require_attachable(&parent, &annotation.parent_content_digest)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_image_annotations
                    (namespace, image_id, annotation_id, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, image_id, annotation_id) DO UPDATE SET
                    record_json = excluded.record_json
                 WHERE sekai_governed_image_annotations.namespace = excluded.namespace
                   AND sekai_governed_image_annotations.image_id = excluded.image_id",
                params![
                    annotation.namespace,
                    annotation.image_id,
                    annotation.annotation_id,
                    json
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn list_governed_image_annotations(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Vec<ImageAnnotation>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT record_json FROM sekai_governed_image_annotations
                 WHERE namespace = ?1 AND image_id = ?2
                 ORDER BY annotation_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, image_id], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut annotations = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            annotations.push(
                serde_json::from_str(&json)
                    .map_err(|error| format!("decode governed image annotation: {error}"))?,
            );
        }
        Ok(annotations)
    }
}

/// The stored image `namespace`/`image_id`, if any.
fn load_image(
    conn: &rusqlite::Connection,
    namespace: &str,
    image_id: &str,
) -> Result<Option<GovernedImage>, String> {
    conn.query_row(
        "SELECT record_json FROM sekai_governed_images
         WHERE namespace = ?1 AND image_id = ?2",
        params![namespace, image_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|error| error.to_string())?
    .map(|json| {
        serde_json::from_str(&json).map_err(|error| format!("decode governed image: {error}"))
    })
    .transpose()
}
