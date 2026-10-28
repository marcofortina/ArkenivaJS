# ArkenivaJS

Modular ESM libraries for Node.js and TypeScript backend services. Packages expose typed contracts and explicit integrations without installing unrelated database drivers.

This workspace is private and under development. No npm packages have been published. Use Node.js 24 for development; supported runtime tests also cover Node.js 22 and 26.

Install the pinned package manager and verify the workspace:

```sh
npm install --global corepack@0.36.0
corepack enable
pnpm install --frozen-lockfile
pnpm verify
```

The verification command checks formatting, lint, an explicit build, types, unit and contract tests, coverage and an ESM smoke. The lockfile records exact dependency resolution.

Read the [API reference](docs/api.md) and run the [configuration example](examples/configuration/README.md) for a complete introduction to typed configuration and isolated lifecycle management.

The [observability example](examples/observability/README.md) demonstrates contextual JSON logging, safe errors, native process snapshots and resource cleanup without external services.

Use the [foundation measurement tool](tools/benchmark/README.md) to repeat exploratory local component benchmarks and inspect their measurement limits.

Run the [typed HTTP example](examples/hello-http/README.md) for a Fastify service with OpenAPI, a bounded outbound client and a real curl/SIGTERM check.

Run the [PostgreSQL orders example](examples/postgres/README.md) against a disposable
TLS server for exact numeric values, named binds, transactions and rollback.

The [MySQL orders example](examples/mysql/README.md) verifies the same business
operations with InnoDB, exact values and explicit handling of DDL commit semantics.

Use the [MariaDB orders example](examples/mariadb/README.md) for its independent
native driver, bigint result values and explicit JSON transport conversion.

The [Oracle exact-number consumer](examples/oracle/README.md) demonstrates named
binds and lossless JSON DTOs. Oracle is contract-tested with mocks; live
compatibility remains unverified and real execution requires explicit opt-in.

The [Redis cache consumer](examples/redis/README.md) demonstrates scoped UTF-8
values, actual NX outcomes, millisecond expiration, exact counters and cleanup.

The [etcd configuration consumer](examples/etcd/README.md) demonstrates raw bytes,
exact revisions, CAS contention, resumable watches and explicitly renewed leases.

The [MongoDB customer consumer](examples/mongodb/README.md) demonstrates native
BSON, exact JSON conversion, modified counts, bounded aggregation and owned
session transactions with verified commit and rollback.

The [JSON cache consumer](examples/cache/README.md) demonstrates checked values,
finite expiration, actual deletion outcomes and explicit business DTO validation.

The [health service](examples/health/README.md) demonstrates process liveness,
safe HTTP readiness, optional actual Redis probes and graceful shutdown.

The [Core NATS consumer](examples/messaging/README.md) demonstrates checked JSON,
correlation, explicit handler error policy and truthful acknowledgment semantics.

Follow the [developer learning path](docs/learning-path.md) for executable
projects and independent verification with packed public artifacts.

The experimental [cryptography example](examples/cryptography/README.md) covers
verified HTTPS secret retrieval, versioned authenticated encryption, HMAC,
Ed25519 signatures and explicit key rotation with disposable test material.

The optional [X.509 adapter](packages/security-x509/README.md) separates bounded
certificate inspection from explicit chain and revocation verification, with
native TLS and CRL tests using ephemeral certificates.
The [certificate example](examples/certificates/README.md) demonstrates the full
flow, including revocation and cleanup, against packed public artifacts.

The optional [API key service](packages/security-apikey/README.md) provides
scoped credentials with independent runtime authorization and shared atomic
state. Its [PostgreSQL guide](examples/postgres/api-keys.md) verifies signed
OIDC administration, tenant isolation, concurrent rotation and revocation.

The optional [session service](packages/security-sessions/README.md) provides
opaque server-side credentials, atomic renewal and shared revocation epochs.
Its [PostgreSQL guide](examples/postgres/sessions.md) verifies current account
policy, original authentication metadata and signed logout boundaries.

The optional [password service](packages/security-password/README.md) uses bounded
native Argon2id, breach-policy hooks and one-use recovery credentials. Its
[PostgreSQL guide](examples/postgres/passwords.md) verifies atomic password
replacement and session invalidation through the application-owned transaction port.

The optional [magic-link service](packages/security-magiclink/README.md) adds
short-lived single-use credentials with runtime account authorization. Its
[PostgreSQL HTTPS guide](examples/postgres/magiclinks.md) verifies scanner-safe
GETs, explicit POST confirmation and redemption across independent processes.

The optional [HTTP reverse proxy](packages/proxy/README.md) adds fixed-upstream
streaming with connect-time address policy, runtime authentication and header
isolation. Its [HTTPS consumer](examples/proxy/README.md) verifies real TLS,
rewrites, byte counts and rejection of spoofed identity headers.

The optional [realtime adapter](packages/realtime/README.md) adds authenticated
WebSocket/SSE streams, bounded queues and shared NATS/Redis delivery. Its
[HTTPS/WSS consumer](examples/realtime/README.md) exercises native protocols and
the [PostgreSQL source](examples/postgres/realtime.md) demonstrates persistent replay.

The optional [SAML Service Provider](packages/security-saml/README.md) adds signed
Redirect/POST login and controlled logout with shared replay protection. Its
[HTTPS form example](examples/saml/README.md) and [SQL mapping example](examples/postgres/saml.md)
keep browser correlation and local tenant authorization explicit.

The [identifier utility](packages/data-identifiers/README.md) uses native UUIDv4
and the approved UUID library for UUIDv7, with strict version/canonical policy.
The [utilities example](examples/utilities/README.md) runs without external services.
The [validation utility](packages/data-validation/README.md) adds explicit email,
URL, IP and UUID policies and startup-compiled Ajv schemas with bounded JSON input.
The [time utility](packages/data-time/README.md) delegates calendar and DST behavior
to Temporal, with explicit IANA zones, locale formatting and disambiguation policy.
The [CSV adapter](packages/data-csv/README.md) streams UTF-8 records through the
approved native codecs with explicit headers, bounds and cancellation.
The [DNS utility](packages/dns/README.md) isolates named native resolvers from OS
lookup semantics. Its [loopback example](examples/dns/README.md) tests actual DNS records.

The optional [LDAP adapter](packages/security-ldap/README.md) adds verified LDAPS,
mandatory STARTTLS, native bound filters, isolated password binds and bounded
paged/group searches. Its [consumer](examples/ldap/README.md) runs against an
owned OpenLDAP fixture and checks actual SDK diagnostic privacy.

The optional [outgoing OAuth client](packages/security-oauth-client/README.md)
uses the native OIDC SDK for PKCE grants and shared encrypted refresh state.
The [PostgreSQL consumer](examples/postgres/oauth-client.md) verifies signed
local authorization independently of outgoing provider grants.

The optional [XLSX adapter](packages/data-xlsx/README.md) reads typed worksheets
and writes native streaming workbooks with controlled styles, formula policies
and finite process ownership. Its [consumer](examples/xlsx/README.md) verifies
two-sheet roundtrips and actual SDK diagnostic privacy.

The optional [PDF adapter](packages/documents-pdf/README.md) composes the native
document engines for searchable text, inspection and protected rewriting. Its
[consumer](examples/pdf/README.md) verifies page composition and private SDK metrics.

The optional [SFTP and SSH adapter](packages/sftp/README.md) pins named remote
servers, streams bounded files and proves supported atomic renames. Its
[consumer](examples/sftp/README.md) runs against owned OpenSSH infrastructure.

The optional [gRPC adapter](packages/grpc/README.md) provides mTLS-protected unary,
server-streaming and native bidirectional workflows with verified signed tenant
assertions. Its [standalone consumer](examples/grpc/README.md) uses real local PKI,
JWT signatures and native protobuf codecs.

## License

SPDX-License-Identifier: AGPL-3.0-or-later

Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

ArkenivaJS is licensed under the GNU Affero General Public License, version 3
or later. See [LICENSE](LICENSE) for the full text. Upstream components retain
their own licenses and attributions; see the notices for
[Redis](packages/database-redis/THIRD_PARTY_NOTICES.md),
[etcd](packages/database-etcd/THIRD_PARTY_NOTICES.md),
[MongoDB](packages/database-mongodb/THIRD_PARTY_NOTICES.md) and
[messaging](packages/messaging/THIRD_PARTY_NOTICES.md).

The [native socket servers](packages/socket/README.md) add managed TCP, TLS, UDP and Unix listeners. The [executable example](examples/socket/README.md) uses real owned loopback clients.
