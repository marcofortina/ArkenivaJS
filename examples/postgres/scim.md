# Shared PostgreSQL SCIM provider

`createPostgresScimProvider(sql, auth, connection, schema, kind)` uses the existing SQL pool and authentication owner. It verifies tenant context runtime provenance and binds ownership to verified issuer, provisioning subject and tenant. User and Group resources share the caller-owned table. Pools and schemas remain application-owned.

`createPostgresScimTables` is disposable fixture DDL requiring `ARKENIVA_POSTGRES_DISPOSABLE=1` and an owned `security_` schema with 24 hexadecimal suffix characters. Production applications must supply their own migrations and ownership policy.

Mutations use a PostgreSQL transaction and owner-scoped advisory lock. ETag predicates, external identity uniqueness, create retry mapping, username uniqueness and group-reference checks execute within that boundary. Independent processes racing one ETag produce one successful write and one precondition failure. Unchanged replacement preserves the version. Deletion retains a tombstone and immutable retry mapping; deleted records are not returned.

The example rejects privilege-bearing roles, entitlements and initial passwords. Members must reference owned User/Group records; bounded graph checks reject membership cycles and deletion of referenced members. Review this explicit policy against the application's actual privilege model.

The reference bounds each owner's live resources to 1000 and combined JSON bodies to 2 MiB. Each body is limited to 128 KiB and the shared plain-data copier's structural bounds. Reads check aggregate limits before fetching bodies; writes check prospective limits under the lock. Exceeding a bound is an explicit error. Native schemas, schema-aware filters, sorting and PATCH execute through the pinned SDK.

Build with `pnpm --filter @arkenivajs/example-postgres build`. With the existing disposable PostgreSQL TLS fixture configured, run `node --test examples/postgres/dist-test/integration/scim.integration.test.js examples/postgres/dist-test/integration/scim-process.integration.test.js`. Tests use actual signed identities, independent pools/processes, cross-tenant denial, idempotent retries, atomic preconditions, native membership replacement and late acknowledgement reconciliation. Cancellation cannot undo a committed database transaction; reconcile an uncertain response through the immutable external identity mapping.
