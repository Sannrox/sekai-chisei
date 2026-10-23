# ADR 0123: Media uploads become governed objects

- Status: accepted
- Date: 2026-10-23
- Issue: #1623

## Context

Clients capture photos and files offline and upload them later. The file
must be governed like the objects it belongs to. The upload must survive
an interrupted connection, and the result must be a media reference that
an Action parameter or a media property can hold.

## Decision

1. **A session per idempotency key.** `BeginMediaUpload` declares the size
   (at most 64 MiB), the SHA-256, the media type, a file name and an access
   marking. The upload id derives from the namespace, the uploader and the
   key. A repeated begin with the same declaration returns the same session,
   and once complete the same reference. A different declaration under the
   key is `ALREADY_EXISTS`.
2. **Chunks append at the received offset.** `UploadMediaChunk` stores up
   to 1 MiB at `received_bytes`. A chunk the session already holds is a
   retry and changes nothing. Any other offset is refused with the offset
   to continue from. Sessions and chunks are durable rows in both backends,
   so any instance can continue an upload another one started.
3. **Completion checks the checksum, then creates an object.**
   `CompleteMediaUpload` hashes the stored bytes. On a mismatch it is
   refused and the bytes are dropped, so the file can be sent again. A
   session attempt counter fences the drop and the finish, so a delayed
   completion never acts on bytes sent after it hashed. On a
   match it creates a `media_attachment` object with the upload's marking,
   fenced on the object policy generation read before authorizing it. The reference is
   `sekai-media:<object id>`. The object id derives from the upload, so a
   crash after the create is finished by completing again.
4. **The file is governed by its object.** `media_attachment` is a
   reserved kind: generic object RPCs and Action mutations never create,
   change or read it. `ReadMedia` applies the object read checks: namespace
   role, tenant and collaboration scope, grants, marking and object
   security policy. A caller who fails one gets `NOT_FOUND`.
5. **Writes need the right to create the object.** Begin, every chunk and
   completion check namespace write, write freezes, the marking's validity,
   that the uploader's clearance covers it, the create ACL, property and
   value write grants, and the object security policy. A session is
   visible only to its uploader, while it may still read the namespace.
   Metadata in `ReadMedia` is projected as a read of the object, so a
   property the reader may not see comes back empty.

## Consequences

- An object security activation in a namespace with uploads needs a
  `media_attachment` policy, as for any instantiated kind.
- Bytes live in the Sekai database. The 64 MiB cap keeps that bounded;
  larger media need an external store behind the same RPCs.
- Unfinished sessions are kept. Expiring them is follow-up work.

## Rejected alternatives

- A separate media ACL: it would drift from object grants and policy.
- Trusting the client checksum without hashing the stored bytes.
- Storing files on the server's disk: another instance could not continue
  the upload.
