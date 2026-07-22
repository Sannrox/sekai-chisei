# Generation-fenced leases

Sekai exposes namespace-scoped leases for coordinating one active owner of a
logical key. Acquire returns both a monotonically increasing `generation` and
a unique `fencing_token`. Release keeps the key and its audit history, so a
later acquire creates a new generation rather than reusing an object identity.

Use a unique `request_id` for each intended operation and reuse it unchanged
after an ambiguous transport failure. Reusing it with different input is an
error. Refresh and release require the active fencing token. Expired leases are
not implicitly replaced: takeover requires the exact token and expiry observed
by the caller, and the server decides whether that expiry has passed using its
own clock.

`GetLease` returns the current active or released record to principals with
namespace read access. Contenders use it to observe the exact token and expiry
required by takeover after an owner crash. The fencing token is not a bearer
credential: every mutation still requires namespace write authorization, and
the server verifies that the token names the active generation.

The control plane prevents an old generation from changing current lease state,
but it cannot stop work that has already left the control plane. Clients must
persist the returned generation with their durable attempt and pass it to every
downstream mutation executor. Each executor must remember the highest
generation accepted for the protected resource and reject commands carrying a
lower generation. A fencing token alone is sufficient for Sekai RPCs; the
monotonic generation is the downstream ordering primitive.

Lease transitions and retry results are stored durably with the active record.
Acquire, refresh, release, and takeover are committed atomically with their
transition audit entry. The current server persistence path is SQLite; the
partial PostgreSQL interfaces do not yet implement this API.
