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
