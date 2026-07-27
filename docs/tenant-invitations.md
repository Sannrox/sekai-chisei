# Tenant invitation authorization hooks (#121)

Backend-neutral invitation authorization for adding a human to a tenant without
sharing a service credential. Storage, email delivery, and OIDC sessions remain
enterprise-owned.

## Contract

| Piece | Role |
| --- | --- |
| `MemoryInvitationHooks` | Deterministic create/inspect/accept/revoke + audit |
| `MembershipDirectory` | Membership writes and last-owner checks |
| `InvitationView` | Public inspection without raw secret |
| `invitation_token_url` | Adapter-facing token URL helper |

Version: `sekai.tenant-invitation/v1`.

## Rules

- Secrets are **hashed at rest**; raw secret is returned only once at create.
- Expired, revoked, reused, wrong-tenant, and role-mismatch invitations fail.
- Acceptance binds to the authenticated human subject; retry is idempotent for
  the same subject (exactly one membership).
- Last-owner invariant blocks demotion/removal of the sole owner.
- Audit events never contain invitation secrets.

## Non-goals

Public self-signup, domain auto-join, community SQLite invitation tables.
