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
