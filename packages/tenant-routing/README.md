# @arkenivajs/tenant-routing

Optional tenant operation routing contracts and startup file registry provider.
The package exposes readonly public types, version constants, resource defaults
and an administrative capability identity. The SQL provider and routing factory
are not yet exposed. This package does not register its own listener.

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
serialized by immediate rejection, with no waiting queue. A timed-out load keeps
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

Active registry content uses schema 1.1.0. Immutable content revisions and
monotonic activation generations are separate. SQL options require the existing
application SqlProvider, and HTTP implementations separate request/response
transformers and trusted service credentials. Activation is startup-only.

Capability limits count authorized visible entries in one requesting principal's
response, with default 1000 and integer range 1..5000. Discovery never grants
execution permission, and an over-limit response must fail rather than truncate.
Tenant provenance, scopes, assurance and field-independent operation policy
remain runtime obligations of the forthcoming provider and dispatcher layers.
