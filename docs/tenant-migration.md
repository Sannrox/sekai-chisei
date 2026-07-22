# Migrating legacy SQLite tenant state

The community SQLite runtime no longer creates or serves tenant state. Startup
fails before normal migrations when it finds populated legacy tenant lifecycle,
membership, namespace-ownership, request, or tenant-bound credential records.
The check is read-only: it does not delete, rewrite, or disable those records.

Before upgrading a database that contains tenant state:

1. Stop every writer and make a verified backup of the SQLite database and its
   WAL/SHM files.
2. Keep the previous compatible binary available for export and rollback.
3. Export tenant records, memberships, namespace ownership, tenant credentials,
   and their audit provenance using the enterprise migration tooling for the
   target PostgreSQL distribution.
4. Validate the PostgreSQL import and enterprise authorization conformance
   before directing traffic to it.
5. Start this community runtime only with a tenant-free SQLite database. Do not
   delete legacy tables merely to bypass the startup guard.

There is no automatic downgrade or destructive cleanup path. Credential
secrets must be rotated through the target enterprise system rather than copied
into logs or ad-hoc export files.
