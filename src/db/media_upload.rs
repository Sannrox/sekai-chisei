//! SQLite storage for media uploads (#1623), and the backend dispatch.
//! Bytes are stored as the chunks that arrived, keyed by their offset.

use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::media_upload::{
    MediaError, MediaUpload, MediaUploadRequest, assemble, check_append,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sekai_media_uploads (
    upload_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    uploader TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    file_name TEXT NOT NULL,
    access_marking TEXT NOT NULL,
    received_bytes INTEGER NOT NULL,
    attempt INTEGER NOT NULL,
    object_id TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sekai_media_chunks (
    upload_id TEXT NOT NULL,
    offset_bytes INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (upload_id, offset_bytes)
);
";

const UPLOAD_COLUMNS: &str = "SELECT upload_id, namespace, uploader, idempotency_key, size_bytes,
    sha256, media_type, file_name, access_marking, received_bytes, attempt, object_id,
    created_at_ms, updated_at_ms FROM sekai_media_uploads WHERE upload_id = ?1";

fn storage(error: impl ToString) -> MediaError {
    MediaError::Storage(error.to_string())
}

fn upload_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MediaUpload> {
    Ok(MediaUpload {
        upload_id: row.get(0)?,
        request: MediaUploadRequest {
            namespace: row.get(1)?,
            uploader: row.get(2)?,
            idempotency_key: row.get(3)?,
            size_bytes: row.get::<_, i64>(4)? as u64,
            sha256: row.get(5)?,
            media_type: row.get(6)?,
            file_name: row.get(7)?,
            access_marking: row.get(8)?,
        },
        received_bytes: row.get::<_, i64>(9)? as u64,
        attempt: row.get::<_, i64>(10)? as u64,
        object_id: row.get(11)?,
        created_at_ms: row.get(12)?,
        updated_at_ms: row.get(13)?,
    })
}

impl SekaiDb {
    pub(crate) fn migrate_media_uploads(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(SCHEMA)
            .map_err(|error| error.to_string())
    }

    fn begin_media_upload(
        &self,
        request: &MediaUploadRequest,
        now_ms: i64,
    ) -> Result<MediaUpload, MediaError> {
        let upload_id = request.upload_id();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let stored = tx
            .query_row(UPLOAD_COLUMNS, params![upload_id], upload_row)
            .optional()
            .map_err(storage)?;
        if let Some(stored) = stored {
            return if &stored.request == request {
                Ok(stored)
            } else {
                Err(MediaError::Conflict)
            };
        }
        tx.execute(
            "INSERT INTO sekai_media_uploads (upload_id, namespace, uploader, idempotency_key,
                 size_bytes, sha256, media_type, file_name, access_marking, received_bytes,
                 attempt, object_id, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, 0, NULL, ?10, ?10)",
            params![
                upload_id,
                request.namespace,
                request.uploader,
                request.idempotency_key,
                request.size_bytes as i64,
                request.sha256,
                request.media_type,
                request.file_name,
                request.access_marking,
                now_ms,
            ],
        )
        .map_err(storage)?;
        let created = tx
            .query_row(UPLOAD_COLUMNS, params![upload_id], upload_row)
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(created)
    }

    fn get_media_upload(&self, upload_id: &str) -> Result<Option<MediaUpload>, MediaError> {
        self.conn()
            .query_row(UPLOAD_COLUMNS, params![upload_id], upload_row)
            .optional()
            .map_err(storage)
    }

    fn append_media_chunk(
        &self,
        upload_id: &str,
        offset: u64,
        data: &[u8],
        now_ms: i64,
    ) -> Result<MediaUpload, MediaError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let upload = tx
            .query_row(UPLOAD_COLUMNS, params![upload_id], upload_row)
            .optional()
            .map_err(storage)?
            .ok_or(MediaError::NotFound)?;
        if !check_append(&upload, offset, data.len())? {
            return Ok(upload);
        }
        tx.execute(
            "INSERT INTO sekai_media_chunks (upload_id, offset_bytes, data) VALUES (?1, ?2, ?3)",
            params![upload_id, offset as i64, data],
        )
        .map_err(storage)?;
        tx.execute(
            "UPDATE sekai_media_uploads SET received_bytes = ?2, updated_at_ms = ?3
             WHERE upload_id = ?1",
            params![upload_id, (offset + data.len() as u64) as i64, now_ms],
        )
        .map_err(storage)?;
        let updated = tx
            .query_row(UPLOAD_COLUMNS, params![upload_id], upload_row)
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(updated)
    }

    fn read_media_bytes(
        &self,
        upload_id: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, MediaError> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT offset_bytes, data FROM sekai_media_chunks
                 WHERE upload_id = ?1 AND offset_bytes < ?3 AND offset_bytes + length(data) > ?2
                 ORDER BY offset_bytes",
            )
            .map_err(storage)?;
        let chunks = statement
            .query_map(
                params![upload_id, offset as i64, (offset + len as u64) as i64],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage)?;
        Ok(assemble(chunks, offset, len))
    }

    fn reset_media_upload(
        &self,
        upload_id: &str,
        attempt: u64,
        now_ms: i64,
    ) -> Result<(), MediaError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let reset = tx
            .execute(
                "UPDATE sekai_media_uploads
                 SET received_bytes = 0, attempt = attempt + 1, updated_at_ms = ?2
                 WHERE upload_id = ?1 AND object_id IS NULL AND attempt = ?3",
                params![upload_id, now_ms, attempt as i64],
            )
            .map_err(storage)?;
        if reset == 0 {
            return Err(MediaError::Changed);
        }
        tx.execute(
            "DELETE FROM sekai_media_chunks WHERE upload_id = ?1",
            params![upload_id],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    fn finish_media_upload(
        &self,
        upload_id: &str,
        object_id: &str,
        attempt: u64,
        now_ms: i64,
    ) -> Result<MediaUpload, MediaError> {
        let conn = self.conn();
        let finished = conn
            .execute(
                "UPDATE sekai_media_uploads SET object_id = ?2, updated_at_ms = ?3
                 WHERE upload_id = ?1 AND (object_id = ?2 OR (object_id IS NULL
                   AND attempt = ?4 AND received_bytes = size_bytes))",
                params![upload_id, object_id, now_ms, attempt as i64],
            )
            .map_err(storage)?;
        let upload = conn
            .query_row(UPLOAD_COLUMNS, params![upload_id], upload_row)
            .optional()
            .map_err(storage)?
            .ok_or(MediaError::NotFound)?;
        if finished == 0 {
            return Err(MediaError::Changed);
        }
        Ok(upload)
    }
}

impl RuntimeDb {
    /// Open the session the request names, or return the stored one when it
    /// declares the same file. Another declaration under the key conflicts.
    pub fn begin_media_upload(
        &self,
        request: &MediaUploadRequest,
        now_ms: i64,
    ) -> Result<MediaUpload, MediaError> {
        match self {
            Self::Sqlite(db) => db.begin_media_upload(request, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.begin_media_upload(request, now_ms))
            }
        }
    }

    pub fn get_media_upload(&self, upload_id: &str) -> Result<Option<MediaUpload>, MediaError> {
        match self {
            Self::Sqlite(db) => db.get_media_upload(upload_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_media_upload(upload_id))
            }
        }
    }

    /// Store a chunk at `offset`, which must be where the upload stands. A
    /// chunk the session already holds is a retry and changes nothing.
    pub fn append_media_chunk(
        &self,
        upload_id: &str,
        offset: u64,
        data: &[u8],
        now_ms: i64,
    ) -> Result<MediaUpload, MediaError> {
        match self {
            Self::Sqlite(db) => db.append_media_chunk(upload_id, offset, data, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.append_media_chunk(upload_id, offset, data, now_ms)
            }),
        }
    }

    /// Up to `len` stored bytes from `offset`.
    pub fn read_media_bytes(
        &self,
        upload_id: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, MediaError> {
        match self {
            Self::Sqlite(db) => db.read_media_bytes(upload_id, offset, len),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.read_media_bytes(upload_id, offset, len))
            }
        }
    }

    /// Drop the received bytes of an unfinished upload so it can be sent
    /// again, if it is still at `attempt`; otherwise `Changed`.
    pub fn reset_media_upload(
        &self,
        upload_id: &str,
        attempt: u64,
        now_ms: i64,
    ) -> Result<(), MediaError> {
        match self {
            Self::Sqlite(db) => db.reset_media_upload(upload_id, attempt, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reset_media_upload(upload_id, attempt, now_ms)
            }),
        }
    }

    /// Record the object a fully received upload became, if it is still at
    /// `attempt`. Recording the same object again is a no-op.
    pub fn finish_media_upload(
        &self,
        upload_id: &str,
        object_id: &str,
        attempt: u64,
        now_ms: i64,
    ) -> Result<MediaUpload, MediaError> {
        match self {
            Self::Sqlite(db) => db.finish_media_upload(upload_id, object_id, attempt, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.finish_media_upload(upload_id, object_id, attempt, now_ms)
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::media_upload::hex;
    use sha2::{Digest, Sha256};

    #[test]
    fn a_stale_completion_cannot_reset_or_finish_a_newer_attempt() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let request = MediaUploadRequest {
            namespace: "field".into(),
            uploader: "alice".into(),
            idempotency_key: "k".into(),
            size_bytes: 3,
            sha256: hex(&Sha256::digest(b"abc")),
            media_type: "image/png".into(),
            file_name: String::new(),
            access_marking: String::new(),
        };
        let upload = db.begin_media_upload(&request, 1).unwrap();
        db.append_media_chunk(&upload.upload_id, 0, b"abx", 2)
            .unwrap();
        // Two completions hashed attempt 0; the first resets it.
        db.reset_media_upload(&upload.upload_id, 0, 3).unwrap();
        db.append_media_chunk(&upload.upload_id, 0, b"abc", 4)
            .unwrap();
        assert_eq!(
            db.reset_media_upload(&upload.upload_id, 0, 5),
            Err(MediaError::Changed)
        );
        assert_eq!(
            db.finish_media_upload(&upload.upload_id, "media-x", 0, 5)
                .unwrap_err(),
            MediaError::Changed
        );
        let current = db.get_media_upload(&upload.upload_id).unwrap().unwrap();
        assert_eq!((current.attempt, current.received_bytes), (1, 3));
        assert_eq!(
            db.read_media_bytes(&upload.upload_id, 0, 3).unwrap(),
            b"abc"
        );
        let finished = db
            .finish_media_upload(&upload.upload_id, "media-x", 1, 6)
            .unwrap();
        assert_eq!(finished.object_id.as_deref(), Some("media-x"));
        // Finishing again with the same object is a no-op at any attempt.
        db.finish_media_upload(&upload.upload_id, "media-x", 0, 7)
            .unwrap();
        // A different declaration under the same key conflicts.
        let other = MediaUploadRequest {
            size_bytes: 4,
            ..request
        };
        assert_eq!(db.begin_media_upload(&other, 8), Err(MediaError::Conflict));
    }
}
