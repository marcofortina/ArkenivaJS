# @arkenivajs/tenant-routing

Optional tenant operation routing with immutable startup registries.
The package exposes readonly public types, version constants, resource defaults
and an administrative capability identity. `tenantRoutingPlugin` registers local
JSON operations and capability discovery on the existing listener. Fixed HTTP
implementations reuse the proxy package's native Undici transport and destination
policy without creating another listener or forwarding inbound credentials.

The internal startup validator checks bounded strict JSON, duplicate decoded
keys, referential integrity, route collisions and offline operation schemas.
Content checksums use the upstream RFC 8785 implementation over the four content
fields, preserving array order and excluding activation metadata. Loaded objects
are copied and deeply frozen before use. Provider I/O and durable activation
history checks belong to the provider layer.

Configured registry, SQL, activation, credential, event and authentication methods
retain their original callback and receiver without reading callable `bind`,
`name` or `length` properties. Later method replacement cannot change captured
callbacks. Existing descriptor, proxy and bounded prototype checks remain in force.

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
The dispatcher verifies tenant provenance, scopes, assurance and the configured
operation policy at runtime.

## Local dispatch

Register `tenantRoutingPlugin` with a trusted registry provider, an installed
handler catalog, `activation: 'startup'` and a mandatory `authorize` callback.
The application needs its existing API and authentication plugins. Declared SQL
adapters initialize before the routing loader; inject their already configured
`SqlProvider` into the SQL registry after it becomes available. No additional
listener, database pool or per-request registry load is created.

Each request verifies its bearer assertion and live tenant provenance using the
application authentication service. Binding lookup is exact; disabled/missing
bindings return 404. Scopes, optional issuer-owned assurance and `authorize`
must all succeed before a concurrency permit is acquired. Failed authorization
returns 403. A full operation rejects immediately with 503, without a queue.
An instance also bounds outstanding request/discovery scopes to 1024, including
pending authentication work, to prevent unbounded retained contexts.
Concurrency counts the same logical operation across tenants in one instance;
it is not a distributed quota. Timed-out or disconnected work retains its permit
until the actual handler promise settles. Handlers must observe `context.signal`.

Input is finite strict UTF-8 JSON with duplicate and unsafe-property rejection.
Native Ajv validators do not coerce inputs or fetch schemas remotely. The copied
request context and normalized response are frozen; output shape and exact
encoded byte limits apply before transmission. Invalid input returns 400,
invalid output 502, failed implementations 503 and expired operations 504,
with fixed safe messages. Existing HTTP/HTTPS transport hooks still apply.

The default discovery route is `GET /api/tenant/capabilities`. It uses the same
snapshot and rechecks each operation's authorization, scopes and assurance.
It accepts no tenant selector, omits disabled/hidden/denied entries, sorts by
operation ID and emits `Cache-Control: private, no-store` with
`Vary: Authorization`. Exceeding `maxCapabilities` returns 503
`EK_TCAP_LIMIT_EXCEEDED`, with no truncated success response.

Resolve the administrative service with `TENANT_ROUTING_CAPABILITY` after READY.
Its `api.resolve` inspects exact bindings but does not grant execution permission;
it and `capabilities.list` still reject forged, copied or foreign-authority tenant
objects. Methods become unavailable during drain/after close. Registry and
catalog edits take effect only in a newly initialized application instance.

A cached verified tenant or administrative resolution does not cache permission.
Each capability listing and HTTP operation applies the current trusted assurance
policy. A downgrade or assurance-provider failure hides protected capabilities
and prevents handler execution. Client assurance and tenant headers cannot restore
permission; other tenants retain their independently authorized access.

## Approved HTTP implementations

Install an `approvedUpstreams` catalog with fixed canonical origins, explicit
hostname and CIDR allowlists, positive connection timeouts and
`allowRedirects: false`. Production requires HTTPS. Loopback, unspecified,
link-local and known metadata destinations are rejected outside the explicit
test environment, including addresses returned by connect-time DNS resolution.
Every DNS answer must pass the destination policy. Optional `tlsCaFile` adds a
bounded deployment CA bundle; native TLS still verifies certificate identity.

An HTTP implementation references only an installed `upstreamKey`, literal
`upstreamPath`, method and named transforms. Unknown destinations or transforms
fail startup. `requestTransformerKey` receives the validated public payload and
verified request context. GET results become bounded flat query parameters;
other methods send bounded JSON and retain the validated public query.
`responseTransformerKey` normalizes the upstream JSON before the public response
schema is checked. Legacy `transformerKey` and `transformers` remain response-only
aliases and cannot be supplied alongside their replacement fields.

Outgoing requests contain fixed JSON media headers and, when configured, a
separate service credential. They never copy the caller's authorization, cookies
or diagnostic tenant headers. `serviceAuth` requires HTTPS and a server-installed
`credentialProvider`; returned credentials must match the fixed audience and
exact scope set, have a valid future UTC expiry and contain a valid Bearer/Basic
header. The native request is cancelled if its credential expires in flight.
The target service must independently authenticate that credential.

Redirects and non-success status codes fail with safe 503 errors. Responses must
be bounded UTF-8 JSON without duplicate or unsafe keys; invalid media, JSON,
transformed values or normalized schemas return safe 502 contract errors.
Operation cancellation and deadlines cover credential lookup, transforms and
native I/O. Unfinished work retains its concurrency permit until it settles;
application shutdown destroys every owned transport pool.

## Routing diagnostics

When the application installs telemetry, the dispatcher records separate
monotonic durations for startup registry validation, immutable lookup,
authorization, implementation work, upstream network I/O and the public
operation. These durations overlap and must not be added together. Request,
match and rejection counters use fixed kind/outcome/match categories; tenant IDs,
request IDs, operation IDs, revision IDs and partner addresses are never metric
dimensions. Operation timing ends at the HTTP result, while implementation
timing retains the physical lifetime of unfinished application work.

Authorized requests create an HTTP server span and a selected-operation child.
Only bounded W3C trace headers supply diagnostic parentage. The private child
contains verified tenant, logical operation, implementation, revision and
activation generation; protect collector access and retention accordingly.
Bodies, concrete request paths, credentials, upstream URLs and baggage are not
exported. Exporter errors cannot replace an outcome, repeat a handler or relax
authorization.

When root metering is enabled, install the existing metering plugin. Each verified
request reaching a logical operation records an `http.request` parent and, after
authorization/admission, a child named by the logical operation ID. The existing
meter independently verifies tenant provenance. Capacity/export failures do not
repeat a handler or bypass operation policy; a rejected tenant fails closed.

The parent counts `http.requests` and observed entity bytes. The logical child
counts `tenant.routing.operations`; database or other installed adapters inherit
that child scope. HTTP implementations additionally record native client request
count, elapsed milliseconds and observed upstream response bytes under the
existing `http.client.*` quantities. These client bytes are distinct from the
parent's server response bytes. Incomplete upstream bodies mark byte quality as
missing rather than claiming a complete measurement.

The HTTP parent closes at response completion. Unfinished timed-out work retains
its child session until physical settlement and reports an unknown execution
outcome. Private exporter queues, drop counters and permanent loss reporting are
owned by the existing meter. No revision, implementation, URL, payload or monetary
field is appended to technical metering event v1.

## Supplementary routing events

`eventExporter` opts into independent event 1.0.0 batches. Its borrowed
`export(events, { signal, timeoutMs })` transport acknowledges the entire
immutable batch by resolving. The application owns that transport's client and
lifecycle; the dispatcher owns only event admission, queueing and cancellation.
Without this option no supplementary events or export queue are created.
The immutable production schema is published separately as
`@arkenivajs/tenant-routing/event-schema` (`TENANT_ROUTING_EVENT_SCHEMA_V1`).
Native Ajv validates every event before queue admission.

Events contain a native random UUID, server request ID, verified tenant, logical
operation ID, selected implementation kind/ID, registry revision/generation,
monotonic duration, status and quality. A valid current trace ID supplies optional
correlation. Join technical usage through request/trace IDs; event `operationId`
is the logical registry identity. Payloads, URLs, credentials and monetary fields
are forbidden. Protect exporter access and retention for private identity data.

One event is completed for each selected operation, including denied/failed
attempts. Completion waits for physical operation settlement; a public timeout
or disconnect keeps an unknown outcome and explicit incomplete quality even if
the handler later returns. Unmatched or unauthenticated requests do not invent a
tenant or implementation event. Capability discovery does not execute an
operation and produces no selected-operation event.

The queue bounds retained events, including the active batch, to 1024 entries
and 4 MiB of encoded data/reserved metadata. Individual events have an 8064-byte
admission bound with reserved loss-metadata space; batches contain at most 100
events. One physical export runs at a time, with a five-second deadline and no
automatic retry. A timed-out uncooperative exporter retains admission until it
settles; late success never acknowledges previously failed delivery. Exporters
must observe the signal and implement any independent durable deduplication
using the event ID.

`service.events.stats()` reports queued/in-flight/exported/dropped counts and
failed exports. The same losses have bounded telemetry counters. Later batches
declare prior stream loss in quality rather than claiming complete history.
`service.events.flush(options?)` is bounded and reports accumulated loss; graceful
drain also flushes and preserves a typed cleanup failure after event loss.
Forced cleanup aborts exports and explicitly drops undelivered queued events.

## Offline deployment validation

The installed package provides:

```sh
pnpm exec arkenivajs-tenant-registry validate --file /run/config/tenant-registry.json
```

It uses the same bounded private-file provider, strict JSON/schema and reference
validation, offline operation-schema compiler and RFC 8785 checksum checks. It
starts no application, listener or database pool and executes no registry code.
Successful output contains only version/revision/generation and operation/binding
counts. Exit codes are 0 for valid/help, 1 for file/registry/cancellation failure,
and 2 for invalid command syntax. Error messages do not include paths or contents.

Production ownership rules apply by default. A controlled development/test
fixture may explicitly use `--environment development` or `--environment test`;
private file modes and link checks remain mandatory. `--max-bytes` accepts an
integer from 1 to 134217728, defaulting to 8388608. Repeat `--public-root` for all
served deployment directories. Invalid or duplicate singleton flags are rejected.

Offline validation checks declarative references within the snapshot. Actual
startup additionally checks deployed handlers, transforms, approved upstreams
and listener collisions. A one-shot CLI cannot prove historical activation
admission across recreated processes; retain the operator's audited promotion
history or durable checkpoint authority. Registry edits still require restart.

The [tenant quote example](../../examples/tenant-routing/README.md) exercises this
command, actual signed identities and HTTPS, separate application processes,
registry-only onboarding, implementation swaps, new operations and a controlled
higher-generation rollback. It also runs against independently packed packages.

## Integration gates

`pnpm --filter @arkenivajs/tenant-routing test:integration:http` exercises real
HTTP/HTTPS/HTTP2 routing, capability isolation, approved upstreams and observations.
`test:integration:postgres` requires the existing explicitly disposable verified
PostgreSQL fixture environment and tests immutable rows, atomic activation and
normal pool startup. CI runs it against PostgreSQL 17/18 on all supported Nodes.

Production file admission is tested as an unprivileged process on an explicitly
disposable Linux VM/runner. `test/fixtures/file.py` prepares root-owned fixtures
through passwordless sudo, launches `test:integration:file` without privileges,
then removes only its nonce-marked deployment directory. Its four admission-guard
tests run before allocation. The wrapper rejects execution without
`ARKENIVA_TENANT_FILE_DISPOSABLE=1`; use it only on that disposable runner. It
installs no packages and starts no daemon. Normal developer HTTP tests need no
privileged operations or external service.
