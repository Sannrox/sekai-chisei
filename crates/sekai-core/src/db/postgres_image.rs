//! PostgreSQL persistence for governed images, renditions, and annotations (#1479).

use postgres::GenericClient;

use crate::db::postgres::{PostgresDb, advisory_lock_key};
use crate::sekai::image::{GovernedImage, IMAGE_UNAVAILABLE, ImageAnnotation, ImageRendition};

impl PostgresDb {
    pub fn put_governed_image(&self, image: &GovernedImage) -> Result<(), String> {
        let json = serde_json::to_string(image)
            .map_err(|error| format!("encode governed image: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_image(&mut tx, &image.namespace, &image.image_id)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_images
                    (namespace, image_id, owner, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, image_id) DO UPDATE SET
                    record_json = EXCLUDED.record_json
                 WHERE sekai_governed_images.owner = EXCLUDED.owner",
                &[&image.namespace, &image.image_id, &image.owner, &json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_governed_image(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Option<GovernedImage>, String> {
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_governed_images
                 WHERE namespace = $1 AND image_id = $2",
                &[&namespace, &image_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_image(&row.get::<_, String>(0)))
            .transpose()
    }

    pub fn put_governed_image_rendition(&self, rendition: &ImageRendition) -> Result<(), String> {
        let json = serde_json::to_string(rendition)
            .map_err(|error| format!("encode governed image rendition: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_image(&mut tx, &rendition.namespace, &rendition.image_id)?;
        require_parent(&mut tx, &rendition.namespace, &rendition.image_id)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_image_renditions
                    (namespace, image_id, rendition_id, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, image_id, rendition_id) DO UPDATE SET
                    record_json = EXCLUDED.record_json
                 WHERE sekai_governed_image_renditions.namespace = EXCLUDED.namespace
                   AND sekai_governed_image_renditions.image_id = EXCLUDED.image_id",
                &[
                    &rendition.namespace,
                    &rendition.image_id,
                    &rendition.rendition_id,
                    &json,
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
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_governed_image_renditions
                 WHERE namespace = $1 AND image_id = $2
                 ORDER BY rendition_id",
                &[&namespace, &image_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_rendition(&row.get::<_, String>(0)))
            .collect()
    }

    pub fn tombstone_governed_image(&self, image: &GovernedImage) -> Result<(), String> {
        let json = serde_json::to_string(image)
            .map_err(|error| format!("encode governed image: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_image(&mut tx, &image.namespace, &image.image_id)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_images
                    (namespace, image_id, owner, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, image_id) DO UPDATE SET
                    record_json = EXCLUDED.record_json
                 WHERE sekai_governed_images.owner = EXCLUDED.owner",
                &[&image.namespace, &image.image_id, &image.owner, &json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(IMAGE_UNAVAILABLE.into());
        }
        tx.execute(
            "DELETE FROM sekai_governed_image_renditions
             WHERE namespace = $1 AND image_id = $2",
            &[&image.namespace, &image.image_id],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_governed_image_annotations
             WHERE namespace = $1 AND image_id = $2",
            &[&image.namespace, &image.image_id],
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_image(&mut tx, &annotation.namespace, &annotation.image_id)?;
        require_parent(&mut tx, &annotation.namespace, &annotation.image_id)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_governed_image_annotations
                    (namespace, image_id, annotation_id, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, image_id, annotation_id) DO UPDATE SET
                    record_json = EXCLUDED.record_json
                 WHERE sekai_governed_image_annotations.namespace = EXCLUDED.namespace
                   AND sekai_governed_image_annotations.image_id = EXCLUDED.image_id",
                &[
                    &annotation.namespace,
                    &annotation.image_id,
                    &annotation.annotation_id,
                    &json,
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
        self.connection()?
            .query(
                "SELECT record_json FROM sekai_governed_image_annotations
                 WHERE namespace = $1 AND image_id = $2
                 ORDER BY annotation_id",
                &[&namespace, &image_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| decode_annotation(&row.get::<_, String>(0)))
            .collect()
    }
}

fn lock_image(
    client: &mut impl GenericClient,
    namespace: &str,
    image_id: &str,
) -> Result<(), String> {
    let lock_key = advisory_lock_key(&["governed_image", namespace, image_id]);
    client
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn require_parent(
    client: &mut impl GenericClient,
    namespace: &str,
    image_id: &str,
) -> Result<(), String> {
    let parent = client
        .query_opt(
            "SELECT record_json FROM sekai_governed_images
             WHERE namespace = $1 AND image_id = $2",
            &[&namespace, &image_id],
        )
        .map_err(|error| error.to_string())?;
    if parent.is_none() {
        return Err(IMAGE_UNAVAILABLE.into());
    }
    Ok(())
}

fn decode_image(json: &str) -> Result<GovernedImage, String> {
    serde_json::from_str(json).map_err(|error| format!("decode governed image: {error}"))
}

fn decode_rendition(json: &str) -> Result<ImageRendition, String> {
    serde_json::from_str(json).map_err(|error| format!("decode governed image rendition: {error}"))
}

fn decode_annotation(json: &str) -> Result<ImageAnnotation, String> {
    serde_json::from_str(json).map_err(|error| format!("decode governed image annotation: {error}"))
}
