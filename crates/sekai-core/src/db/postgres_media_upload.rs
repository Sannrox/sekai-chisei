//! PostgreSQL storage for media uploads (#1623). Same tables and semantics
//! as SQLite (`crates/sekai-core/src/db/media_upload.rs`); appends lock the session row, so
//! two instances never store a chunk at the same offset.

use crate::db::postgres::PostgresDb;
use crate::sekai::media_upload::{
    MediaError, MediaUpload, MediaUploadRequest, assemble, check_append,
};

const UPLOAD_COLUMNS: &str = "SELECT upload_id, namespace, uploader, idempotency_key, size_bytes,
    sha256, media_type, file_name, access_marking, received_bytes, attempt, object_id,
    created_at_ms, updated_at_ms FROM sekai_media_uploads WHERE upload_id = $1";

fn storage(error: impl ToString) -> MediaError {
    MediaError::Storage(error.to_string())
}

fn upload_row(row: &postgres::Row) -> MediaUpload {
    MediaUpload {
        upload_id: row.get(0),
        request: MediaUploadRequest {
            namespace: row.get(1),
            uploader: row.get(2),
            idempotency_key: row.get(3),
            size_bytes: row.get::<_, i64>(4) as u64,
            sha256: row.get(5),
            media_type: row.get(6),
            file_name: row.get(7),
            access_marking: row.get(8),
        },
        received_bytes: row.get::<_, i64>(9) as u64,
        attempt: row.get::<_, i64>(10) as u64,
        object_id: row.get(11),
        created_at_ms: row.get(12),
        updated_at_ms: row.get(13),
    }
}

impl PostgresDb {
    pub fn begin_media_upload(
        &self,
        request: &MediaUploadRequest,
        now_ms: i64,
    ) -> Result<MediaUpload, MediaError> {
        let upload_id = request.upload_id();
        let mut connection = self.connection().map_err(storage)?;
        connection
            .execute(
                "INSERT INTO sekai_media_uploads (upload_id, namespace, uploader, idempotency_key,
                     size_bytes, sha256, media_type, file_name, access_marking, received_bytes,
                     attempt, object_id, created_at_ms, updated_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, 0, NULL, $10, $10)
                 ON CONFLICT (upload_id) DO NOTHING",
                &[
                    &upload_id,
                    &request.namespace,
                    &request.uploader,
                    &request.idempotency_key,
                    &(request.size_bytes as i64),
                    &request.sha256,
                    &request.media_type,
                    &request.file_name,
                    &request.access_marking,
                    &now_ms,
                ],
            )
            .map_err(storage)?;
        let stored = upload_row(
            &connection
                .query_one(UPLOAD_COLUMNS, &[&upload_id])
                .map_err(storage)?,
        );
        if &stored.request == request {
            Ok(stored)
        } else {
            Err(MediaError::Conflict)
        }
    }

    pub fn get_media_upload(&self, upload_id: &str) -> Result<Option<MediaUpload>, MediaError> {
        Ok(self
            .connection()
            .map_err(storage)?
            .query_opt(UPLOAD_COLUMNS, &[&upload_id])
            .map_err(storage)?
            .as_ref()
            .map(upload_row))
    }

    pub fn append_media_chunk(
        &self,
        upload_id: &str,
        offset: u64,
        data: &[u8],
        now_ms: i64,
    ) -> Result<MediaUpload, MediaError> {
        let mut connection = self.connection().map_err(storage)?;
        let mut tx = connection.transaction().map_err(storage)?;
        let upload = tx
            .query_opt(&format!("{UPLOAD_COLUMNS} FOR UPDATE"), &[&upload_id])
            .map_err(storage)?
            .as_ref()
            .map(upload_row)
            .ok_or(MediaError::NotFound)?;
        if !check_append(&upload, offset, data.len())? {
            return Ok(upload);
        }
        tx.execute(
            "INSERT INTO sekai_media_chunks (upload_id, offset_bytes, data) VALUES ($1, $2, $3)",
            &[&upload_id, &(offset as i64), &data],
        )
        .map_err(storage)?;
        tx.execute(
            "UPDATE sekai_media_uploads SET received_bytes = $2, updated_at_ms = $3
             WHERE upload_id = $1",
            &[&upload_id, &((offset + data.len() as u64) as i64), &now_ms],
        )
        .map_err(storage)?;
        let updated = upload_row(
            &tx.query_one(UPLOAD_COLUMNS, &[&upload_id])
                .map_err(storage)?,
        );
        tx.commit().map_err(storage)?;
        Ok(updated)
    }

    pub fn read_media_bytes(
        &self,
        upload_id: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, MediaError> {
        let chunks = self
            .connection()
            .map_err(storage)?
            .query(
                "SELECT offset_bytes, data FROM sekai_media_chunks
                 WHERE upload_id = $1 AND offset_bytes < $3
                   AND offset_bytes + octet_length(data) > $2
                 ORDER BY offset_bytes",
                &[
                    &upload_id,
                    &(offset as i64),
                    &((offset + len as u64) as i64),
                ],
            )
            .map_err(storage)?
            .into_iter()
            .map(|row| (row.get::<_, i64>(0) as u64, row.get::<_, Vec<u8>>(1)))
            .collect();
        Ok(assemble(chunks, offset, len))
    }

    pub fn reset_media_upload(
        &self,
        upload_id: &str,
        attempt: u64,
        now_ms: i64,
    ) -> Result<(), MediaError> {
        let mut connection = self.connection().map_err(storage)?;
        let mut tx = connection.transaction().map_err(storage)?;
        let reset = tx
            .execute(
                "UPDATE sekai_media_uploads
                 SET received_bytes = 0, attempt = attempt + 1, updated_at_ms = $2
                 WHERE upload_id = $1 AND object_id IS NULL AND attempt = $3",
                &[&upload_id, &now_ms, &(attempt as i64)],
            )
            .map_err(storage)?;
        if reset == 0 {
            return Err(MediaError::Changed);
        }
        tx.execute(
            "DELETE FROM sekai_media_chunks WHERE upload_id = $1",
            &[&upload_id],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    pub fn finish_media_upload(
        &self,
        upload_id: &str,
        object_id: &str,
        attempt: u64,
        now_ms: i64,
    ) -> Result<MediaUpload, MediaError> {
        let mut connection = self.connection().map_err(storage)?;
        let finished = connection
            .execute(
                "UPDATE sekai_media_uploads SET object_id = $2, updated_at_ms = $3
                 WHERE upload_id = $1 AND (object_id = $2 OR (object_id IS NULL
                   AND attempt = $4 AND received_bytes = size_bytes))",
                &[&upload_id, &object_id, &now_ms, &(attempt as i64)],
            )
            .map_err(storage)?;
        let upload = connection
            .query_opt(UPLOAD_COLUMNS, &[&upload_id])
            .map_err(storage)?
            .as_ref()
            .map(upload_row)
            .ok_or(MediaError::NotFound)?;
        if finished == 0 {
            return Err(MediaError::Changed);
        }
        Ok(upload)
    }
}
