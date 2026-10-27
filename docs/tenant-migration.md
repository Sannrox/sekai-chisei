# Migrating legacy tenant state

Sekai owns no tenant, membership, tenant-credential, OIDC or OAuth state on any
backend (ADR 0099). Tenant authority comes from the identity extension an
enterprise assembly installs, on SQLite or PostgreSQL. Neither runtime creates
or serves tenant state. Startup fails before normal migrations when it finds
populated legacy tenant lifecycle, membership, namespace-ownership, request,
or tenant-bound credential records. The check is read-only: it does not
delete, rewrite, or disable those records.

On PostgreSQL, a store whose legacy tenant tables are empty drops them at
migration 120 (`drop_legacy_tenant_state`). Their earlier migrations stay in
the recorded history. The `tenant_id` column of `sekai_principal_credentials`
remains, holding only the empty value.

Before upgrading a database that contains tenant state:

1. Stop every writer and make a verified backup of the SQLite database and its
   WAL/SHM files.
2. Keep the previous compatible binary available for export and rollback.
3. Export tenant records, memberships, namespace ownership, tenant credentials,
   and their audit provenance into the identity extension's own store, using
   its migration tooling.
4. Validate the import and the extension's authorization conformance before
   directing traffic to it.
5. Start this version only with a tenant-free database. Do not delete legacy
   rows merely to bypass the startup guard.

There is no automatic downgrade or destructive cleanup path. Credential
secrets must be rotated through the target enterprise system rather than copied
into logs or ad-hoc export files.
