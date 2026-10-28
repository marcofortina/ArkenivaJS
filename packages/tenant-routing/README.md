# @arkenivajs/tenant-routing

Optional tenant operation routing contracts and startup file registry provider.
The package exposes readonly public types, version constants, resource defaults
and an administrative capability identity. The routing factory is not yet exposed.
This package does not register its own listener.

The internal startup validator checks bounded strict JSON, duplicate decoded
keys, referential integrity, route collisions and offline operation schemas.
Content checksums use the upstream RFC 8785 implementation over the four content
fields, preserving array order and excluding activation metadata. Loaded objects
are copied and deeply frozen before use. Provider I/O and durable activation
history checks belong to the provider layer.

`tenantRegistryFileProvider({ absolutePath, maxBytes })` defaults to `production`.
It requires a regular root-owned file with mode 0600/0640 (or read-only
equivalents), no hard links, no symbolic-link path components, and root-owned
parent directories that are not writable by group or others. The file must be
outside every deployment static directory: supply their absolute paths through
`publicRoots`. The operator remains responsible for declaring every served root.
Use a direct immutable deployment file; symlink-based ConfigMap layouts require
an operator-controlled copy to such a file before startup.

`environment: 'development' | 'test'` permits application-owned deployment paths;
the private file mode, size, regular-file, link and public-root checks still apply.
The environment is fixed server configuration, never request data. Explicit
`maxBytes` is bounded to 1..134217728 bytes. Invalid or zero operation timeouts
fail before file I/O; omitted timeouts use 30 seconds.

The provider returns independent frozen snapshots. Repeated startup loads are
rejected immediately when another load is in progress, with no waiting queue. A timed-out load keeps
ownership until its physical work settles, and cannot publish a late result.
It checks at most 10000 distinct revision IDs per provider instance, rejects
changed content under an existing ID and decreasing/conflicting generations,
and permits rollback to an old body under a higher generation.

Optional `activationCheckpoint.accept` provides durable cross-process admission.
Its scope is `file:` plus SHA-256 of the captured absolute deployment path; use a
consistent path and a deployment-specific checkpoint authority across pods.
Provider errors fail closed. Without a durable checkpoint, the operator's
deployment admission process must enforce history across recreated processes;
a stateless file alone cannot detect every rollback. Application requests use
the startup snapshot and do not call this provider per request.

`tenantRegistrySqlProvider({ sql, connectionName, storageKey, storagePrefixes })`
uses the existing application `SqlProvider` after its named pool is ready. There
is no independent client, pool, global application lookup or default-connection
fallback. `storagePrefixes` is a trusted startup allowlist mapping logical keys
to lowercase table prefixes, optionally qualified by one schema. Without a
catalog, only `storageKey: 'tenant_registry'` is registered, using the same prefix.
Unknown keys or unsafe identifiers fail before I/O. Values remain SQL bindings.

The operator provisions `<prefix>_snapshot` with `revision_key` (unique text),
`content_checksum` (71-character string) and `body` (UTF-8 JSON text). `body`
contains exactly `schemaVersion`, `operations`, `implementations` and `bindings`.
Use text rather than a pre-parsed JSON value so duplicate keys remain detectable.
`<prefix>_active` contains one row keyed by `registry_key = 'active'`, with
`activation_generation` (positive BIGINT), `revision_key` and `activated_at` (UTC).
Promote the pointer atomically using an expected-generation comparison; protect
snapshot rows against updates and deletion through database permissions/triggers.
The provider performs no schema creation, migration or administrative writes.

One joined select inside an existing-provider transaction reads pointer and body
consistently. Its server-side byte guard avoids transferring a body above 8 MiB;
the complete reconstructed snapshot also passes the exact UTF-8 size limit.
The initial portable statement uses `OCTET_LENGTH` and text columns, as supported
by PostgreSQL, MySQL and MariaDB. Other engines require compatible SQL/storage
semantics and are not implicitly claimed verified. PostgreSQL integration
exercises real immutable rows, concurrent pointer promotion and named pools.
Both providers accept optional durable activation checkpoints; SQL scopes hash
the captured connection name, storage key and prefix. They do not read registry
tables during application request dispatch.

Active registry content uses schema 1.1.0. Immutable content revisions and
monotonic activation generations are separate. SQL options require the existing
application SqlProvider, and HTTP implementations separate request/response
transformers and trusted service credentials. Activation is startup-only.

Capability limits count authorized visible entries in one requesting principal's
response, with default 1000 and integer range 1..5000. Discovery never grants
execution permission, and an over-limit response must fail rather than truncate.
Tenant provenance, scopes, assurance and field-independent operation policy
remain runtime obligations of the forthcoming provider and dispatcher layers.
