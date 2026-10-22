# Object comments

Comment threads on objects, with mentions and a resolved state. Experimental:
the RPCs need `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo
feature (see [rpc-maturity.md](rpc-maturity.md)).

| RPC | Who | Does |
| --- | --- | --- |
| `CreateObjectComment` | a reader of the object (and of `property`, when set) | adds a comment; the object must be in a namespace, and every mentioned principal must be able to read the object and property |
| `UpdateObjectComment` | the author for `body` and `mentions`; any reader to resolve or reopen | replaces the fields given; `expected_updated_at_ms` must match the stored comment |
| `ListObjectComments` | a reader of the object | the visible comments, oldest first; `total` counts resolved ones too |
| `ListCommentMentions` | a reader of the namespace | comments in the namespace that mention the caller, on objects the caller can still read |

## Visibility follows the object

- A caller who cannot read the object gets `NOT_FOUND`, the same as for a
  missing object: no comments, no count, no mentions.
- A comment on a property is visible only while the property is. A missing
  property and a hidden one answer alike.
- When a comment is written, the properties whose values its body quotes
  (values of four characters or more) are recorded with a digest of each
  value, judged only against what the writer can see; a guess at a hidden
  value is never matched. A reader gets the body only if they can see every
  quoted property with the same value now, otherwise the whole body is
  redacted. Edits keep earlier quotes, so redaction never loosens. The
  author always sees their own text.
- Mentioned principals are checked as themselves, not under the sender's
  authenticated context, and again under their own context whenever they
  list their mentions.
  With the enterprise extension installed, a recipient's access depends on
  their own tenant context, so mentions are refused with
  `FAILED_PRECONDITION` for now.
- Losing read access to the object, or the object being deleted, hides its
  comments and their mentions.

## Storage and audit

A comment is a reserved governance object (`object_comment`). It lives
outside every namespace, as action policies do, so it never blocks object
security activation; generic object reads and writes cannot see or change
it. Each write goes through the audited object path: the object change log
records the creation (author and time) and every later change with its old
and new values, in the same transaction as the write. With the comment's
current values that is its whole history, and `receipt_id` is the id of the
latest entry. Edits use the stored `updated_at_ms` as a precondition, so a
stale writer fails with `FAILED_PRECONDITION`. One request reads at most
10,000 comments.

Not yet covered: comment events on object-change subscriptions, and
retention and subject erasure for comments.
