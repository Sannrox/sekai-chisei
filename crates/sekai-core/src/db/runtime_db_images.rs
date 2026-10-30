//! Dual-backend community-store dispatch for images.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn put_governed_image(
        &self,
        image: &crate::sekai::image::GovernedImage,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_image(image),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.put_governed_image(image)),
        }
    }

    pub fn get_governed_image(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Option<crate::sekai::image::GovernedImage>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_image(namespace, image_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_governed_image(namespace, image_id))
            }
        }
    }

    pub fn put_governed_image_rendition(
        &self,
        rendition: &crate::sekai::image::ImageRendition,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_image_rendition(rendition),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_governed_image_rendition(rendition))
            }
        }
    }

    pub fn list_governed_image_renditions(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Vec<crate::sekai::image::ImageRendition>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_image_renditions(namespace, image_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_image_renditions(namespace, image_id)
            }),
        }
    }

    pub fn tombstone_governed_image(
        &self,
        image: &crate::sekai::image::GovernedImage,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.tombstone_governed_image(image),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.tombstone_governed_image(image))
            }
        }
    }

    pub fn put_governed_image_annotation(
        &self,
        annotation: &crate::sekai::image::ImageAnnotation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_governed_image_annotation(annotation),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_governed_image_annotation(annotation))
            }
        }
    }

    pub fn list_governed_image_annotations(
        &self,
        namespace: &str,
        image_id: &str,
    ) -> Result<Vec<crate::sekai::image::ImageAnnotation>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_image_annotations(namespace, image_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_image_annotations(namespace, image_id)
            }),
        }
    }
}
