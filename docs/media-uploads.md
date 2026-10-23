# Media uploads

Experimental (`SEKAI_EXPERIMENTAL_RPCS=1`). Design: [ADR 0123](decisions/0123-governed-media-uploads.md).

A client uploads a file in chunks and gets a media reference,
`sekai-media:<object id>`. The reference can be an Action parameter or a
`media` property value.

1. `BeginMediaUpload` with the namespace, an idempotency key, `size_bytes`
   (at most 64 MiB), the lowercase hex `sha256`, `media_type`
   (`image/jpeg`), an optional `file_name` and an optional
   `access_marking`. The response gives `upload_id` and `received_bytes`.
2. `UploadMediaChunk` with `offset = received_bytes` and up to 1 MiB of
   `data`, until `received_bytes == size_bytes`. After an interruption,
   `GetMediaUpload` (or a repeated begin with the same key) tells where to
   continue. Resending a chunk the upload already holds is safe.
3. `CompleteMediaUpload` checks the SHA-256 of the received bytes. A
   mismatch is refused with `INVALID_ARGUMENT`, and the bytes are dropped,
   so the file can be sent again from offset 0. A match returns
   `complete: true` and the `media_reference`.

Repeating the begin with the same key and the same declaration returns the
same upload, and after completion the same reference.

`ReadMedia` returns up to 1 MiB from `offset`, with the size, SHA-256,
media type, file name and marking. The file is a `media_attachment` object
in the namespace, so it is read under the object read checks: namespace
role, tenant scope, grants, marking and object security policy. Other
callers get `NOT_FOUND`. Only the uploader sees or continues a session.
Every write needs namespace write access and clearance for the marking,
and is stopped by a write freeze.
