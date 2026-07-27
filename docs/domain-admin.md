# Domain-administration contracts (#125)

Governed facade for tenant administrators over Sekai Chisei domain resources
(credentials, quotas, entitlements, invitations, usage). Tenant lifecycle and
product catalogs stay with the external enterprise authority.

## Version

`sekai.domain-admin/v1` (`DomainAdminSurface`)

## Authorization matrix

| Action | Owner | Admin | Member | Billing viewer |
| --- | --- | --- | --- | --- |
| Profile / entitlement view | ✓ | ✓ | ✓ | ✓ |
| Usage summary | ✓ | ✓ | ✓ | ✓ |
| Configure quotas | ✓ | ✓ | | |
| Provider credential rotate | ✓ | ✓ | | |
| Create invitation | ✓ | ✓ | | |

Cross-tenant identifiers fail closed (`CrossTenant`).

## Audit

Every mutation and privileged read appends `DomainAdminAudit` with actor,
tenant, action, target, and result — never secrets.

## Composition

Builds on #118 credentials, #119 quotas, #121 invitations, #122 usage ledger,
#123 entitlements.
