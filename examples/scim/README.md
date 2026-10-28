# SCIM public consumer

Build with `pnpm --filter @arkenivajs/example-scim build`, then run `pnpm --filter @arkenivajs/example-scim test`. The consumer imports public package exports and uses actual signed bearer tokens, an owned JWKS endpoint and real HTTP, HTTPS and HTTP/2 sockets. OpenSSL generates disposable private certificates in a protected temporary directory; tests remove them afterward.

`createExampleService(settings)` delegates to the public SCIM factory. Supply actual authentication and independent trusted authority, then register concrete providers before handling requests. HTTP integration uses `scimPlugin` on the existing API listener and `/scim/v2`. See the [package guide](../../packages/security-scim/README.md) for scopes, authority actions and limits.

The memory fixture is explicitly test-only and rejected by production configuration. Durable provisioning requires an application-owned shared provider such as the [PostgreSQL reference](../postgres/scim.md), with immutable external identity mapping and explicit privileged membership policy.

Tests cover CRUD, discovery, native schema/filter/PATCH behavior, ETags, tenant provenance, forbidden privileges, malformed inputs, deadlines, TLS identity verification and listener lifecycle. Local controls do not establish third-party certification.
