# Foundation API reference

ArkenivaJS packages are ESM-only. Import their documented package entry points after building the workspace. Application instances do not share a mutable singleton. The following runtime APIs are available in the current packages.

## Errors and core composition

`KitError({code, message, cause?, retryable?, details?})` extends Error. Its developer message and original cause stay internal. `code` belongs to the exported `ErrorCode` union; invalid JavaScript constructor arguments reject with TypeError. `retryable` defaults to false. `details` contains immutable finite primitive metadata. `toSafeJSON()` and JSON serialization expose only a stable code and a fixed safe message; optional request correlation never exposes a cause or stack.

`createApplication(options): Promise<Application>` validates `service.name`, SemVer `service.version` and the development/test/production environment. It checks declared plugins and requested capabilities before opening resources. It never binds a port. Missing or cyclic dependencies use `EK_PLUGIN_DEPENDENCY`; duplicates use `EK_PLUGIN_DUPLICATE`; malformed options use `EK_CONFIG_INVALID`.

`Application.start(): Promise<void>` follows dependency order, shares concurrent startup, and returns immediately once READY. Failure rolls back initialized plugins in reverse order with the primary error retained as cause. `Application.stop({timeoutMs?}): Promise<void>` closes initialized plugins once, continues after cleanup failures and rejects with sanitized aggregate metadata. Its default is `DEFAULT_SHUTDOWN_TIMEOUT_MS`, exactly 30,000 ms. CLOSED is terminal; repeated stop calls are harmless. Starting a closed or draining application rejects with `EK_LIFECYCLE_STATE`.

`Plugin` has a stable id/version, optional dependency ids, a read-only capability set and init/close hooks. `PluginContext.provide(symbol, instance)` registers during initialization; `require<T>(symbol)` enforces explicit provider dependencies. `COMPONENTS` contains the built-in service keys. `APPLICATION_SIGNAL` exposes cooperative startup cancellation. A hook must clean its own partially acquired resources if it rejects. Late successful initialization is closed after cancellation; uncooperative JavaScript cannot be forcibly terminated.

A core-only application exposes validated configuration and lifecycle. Required component accessors throw `EK_UNSUPPORTED_CAPABILITY` until the matching adapter is installed. Optional auth/cache/messaging/Redis/etcd/Mongo accessors return undefined when absent. Type-only ports do not claim an operational HTTP, security, database, telemetry, health or metering service.

## Configuration

`createConfig<T>(options): Promise<ConfigService<T>>` belongs to `@arkenivajs/config`. Required options are a strict JSON Schema and an approved existing workspace. Optional inputs are `defaults`, one `yamlFile` or `yamlText`, explicit `environmentFields`, an environment map and `runtime`. Precedence increases in that order. File inputs must be regular files within the approved workspace and at most one MiB. Aliases, duplicate keys and unknown mappings reject. Numbers use complete finite numeric syntax; booleans accept literal true/false only. Strings are never evaluated.

`secrets` maps paths to provider reference names. The optional `secretProvider(reference, options)` resolves paths not supplied by explicit environment mappings. Secret values are prohibited in defaults, YAML and runtime objects. Provider paths are automatically redacted. Empty provider results use `EK_CONFIG_MISSING`. Loading accepts `signal` and positive integer `timeoutMs`, default 30,000 ms; cancellation and deadlines use `EK_ABORTED` and `EK_TIMEOUT`.

| Service operation | Behavior                                                                            |
| ----------------- | ----------------------------------------------------------------------------------- |
| `get(key)`        | Return the declared top-level value or undefined; nested objects are deeply frozen. |
| `require(key)`    | Return a non-null value or throw `EK_CONFIG_MISSING` naming the key.                |
| `has(key)`        | Report presence; an explicitly nullable value is present.                           |
| `snapshot()`      | Return a deeply immutable redacted display view.                                    |
| `reload(updates)` | Validate and preflight a merged generation before one atomic swap.                  |

Reload permits only `dynamicPaths`. Credentials, secret paths, database definitions and security policy require reconstruction. Side-effect-free `preflight(next, previous)` validation is bounded by `preflightTimeoutMs` (default 30,000 ms). Failed or timed-out validation returns `EK_CONFIG_RELOAD_REJECTED`, retains earlier generations and releases the reload queue. `configPlugin(service)` installs a validated service into an application.

Optional synchronous `onDiagnostic(event)` routes safe override/reload audit metadata into a caller-owned sink. The default is JSON on standard error; a throwing sink falls back there. Only fixed event/source names and top-level key counts are emitted after validation/commit, excluding paths and values. Rejected changes have no applied event. The support entry point exports `ConfigurationDiagnostic` and `reportConfigurationDiagnostic` for adapters using this same convention.

## Adapter support entry point

`@arkenivajs/core/support` supplies `ConfigStore<T>`, `StoreOptions<T>`, strict `compileSchema`, safe `copyData`/`freezeData`/`mergeData`/`redactData`, and `within(work, options)`. These shared primitives preserve one error identity without package dependency cycles. Data copying rejects cycles, accessors, unsafe prototype keys, unsupported values and excessive nesting. Merge replaces arrays and explicit null rather than interpreting null as deletion. `within` defaults to 30,000 ms, requires positive integer milliseconds, and removes its timer and abort listener on every outcome.

See the [configuration example](../examples/configuration/README.md) for complete commands, expected output, errors and cleanup.

## Structured logging

`@arkenivajs/logging` exports the `Logger`, `LogLevel` and `LogFields` contracts, `createLogger(options)` and `loggingPlugin(options?)`. The factory returns `ManagedLogger`: the six severity methods, `child`, `setLevel`, `flush`, an isolated asynchronous `run` scope, immutable `stats` and idempotent `close`. See the [logging reference and runnable sequence](../packages/logging/README.md) for default limits, redaction controls, write acknowledgement and transport ownership.

## Process diagnostics

`@arkenivajs/diagnostics` exports `Diagnostics`, `ProcessSnapshot`, `createDiagnostics(options?)`, `diagnosticsPlugin(options?)` and immutable `DIAGNOSTIC_SOURCES`. The managed collector adds idempotent `close()` to the normative snapshot interface. Measurements are native process CPU/memory and optional event-loop observations; absent samples stay omitted. See the [diagnostics reference](../packages/diagnostics/README.md) for units, source, interval, defaults and cleanup.

## Outbound HTTP

`@arkenivajs/http` exports `OutboundHttpClient`, `createHttpClient(options)`, `httpPlugin(options)` and `DEFAULT_HTTP_TIMEOUT_MS=10000`. The managed client adds `close` and transport statistics. Destinations require exact origins and connection-time DNS validation; response bodies, connection count, deadline and retries are bounded. See the [HTTP client reference](../packages/http/README.md) for argument policies, cancellation, trace/service identity hooks and observed-byte coverage.

## HTTP server

`@arkenivajs/api` exports the typed route contracts, `createApi(options)` and `apiPlugin(options?)`. Registration precedes startup, and activation follows resource initialization. Schemas are mandatory, middleware stages preserve authentication, OpenAPI is deterministic 3.1, and shutdown drains inbound work before downstream resources close. See the [server reference](../packages/api/README.md) and [runnable HTTP guide](../examples/hello-http/README.md).

## Identity and trusted tenant context

`@arkenivajs/security` exports `createAuthService`, `securityPlugin` and the public authentication types. Signature, issuer, audience, time, type and scope checks precede tenant attribution. Runtime provenance rejects cloned or foreign identity/context objects. See the [security reference](../packages/security/README.md) and [executable tenant guide](../examples/oidc-tenants/README.md).

## Shared MFA trust and storage contracts

The following type-only ports are exported by `@arkenivajs/core` and re-exported
by `@arkenivajs/security`. They introduce no runtime factor implementation or
database dependency. Persistent adapters and the optional TOTP/WebAuthn services
remain under development; these interfaces alone do not enable MFA.

`MfaSubjectContext` contains `issuer`, `subject`, `primarySessionId`,
`authenticatedAt` and an optional verified `tenant`. A trusted server-side
session authority resolves those values. Structural assignability is not
authentication: factor implementations must validate ownership, issuer, session
binding and freshness at runtime. `MfaManagementAuthorization` binds a recent
authority decision to `enroll`, `replace`, `disable`, `recovery-codes` or `revoke`.

`MfaChallengeRecord` binds one opaque ID/digest to its factor ceremony purpose,
issuer and optional subject/tenant/session/RP. Its timestamps are UTC ISO strings.
`MfaStateStore.createChallenge(record, options?)` inserts once and rejects
duplicates; `claimChallenge({id,purpose,issuer,subject?,tenantId?,primarySessionId?,rpId?,now}, options?)`
atomically consumes the exact unexpired match or returns `null`.
`discardChallenge(id, options?)` removes a challenge. Every method is asynchronous.
Separate reads and deletes cannot satisfy the single-use contract.

`MfaRateLimitStore.checkAndRecord({scopeKey,operation,maxAttempts,windowMs,nowMs}, options?)`
atomically returns `{allowed,retryAfterMs?}` across instances. Window and retry
durations are integer milliseconds. An unavailable limiter must fail closed.

`MfaEvidence` describes a short-lived verified `totp`, `recovery-code` or
`webauthn` result. `MfaEvidenceRecord` additionally requires issuer and primary
session binding, with optional tenant. `MfaEvidenceStore.recordOnce(record, options?)`
persists once; `consume({evidenceId,issuer,subject,tenantId?,primarySessionId,now}, options?)`
atomically returns the matching unexpired record or `null`. The application
session authority consumes it internally before upgrading assurance. These
values are never browser bearer credentials and do not issue a cookie or JWT.

`MfaSecretProtector.seal(bytes, {issuer,subject,tenantId?}, options?)` returns a
`MfaSealedSecret` with `keyId`, `ciphertext`, `nonce` and `tag`; `open(envelope,
binding, options?)` authenticates the same binding before returning bytes. Use a
reviewed AEAD/KMS provider, versioned keys and fresh nonces. Secret material must
never appear in logs, traces, errors or metering.

The [PostgreSQL state reference](../examples/postgres/mfa-shared-state.md)
implements the challenge, shared limiter and single-use evidence ports in an
explicitly disposable application example, with separate-process consumption
and quota-contention tests. Evidence retains consumed tombstones to prevent
re-recording after use. Actual factor verification and session issuance remain
separate responsibilities.

Store/provider calls accept the existing `OperationOptions` cancellation and
deadline contract. Persistence outages or uncertain outcomes must use safe
storage failures, never success evidence. Actual multi-instance atomicity,
outage handling and encryption require independent implementation tests.

The optional [TOTP package](../packages/security-totp/README.md) exports
`createTotpService(options)` and its lifecycle/storage types. Its explicit
application authority resolves ownership and authorizes sensitive management.
The service uses upstream TOTP verification, durable generation-bound replay CAS,
external-key HMAC-SHA256 recovery and persisted single-use assurance evidence.
It does not issue a session; production requires independently verified providers.

## Metrics and tracing

`@arkenivajs/telemetry` exports `createTelemetry`, `telemetryPlugin`, `DURATION_BUCKETS_SECONDS` and the public telemetry port. Providers and W3C async context are instance-owned; no process-global SDK is replaced. Metric labels and series, span queues and exporter deadlines are bounded. See the [telemetry reference](../packages/telemetry/README.md) for modes, units, sampling, resource metadata and actual collector integration. The [distributed guide](../examples/distributed-tracing/README.md) runs two HTTP hops with correlated logs and measured process quantities.

The [metering reference](../packages/metering/README.md) and [verified tenant metering example](../examples/metering/README.md) cover independent events, failure/pressure semantics and automatic request scopes.

## SQL, PostgreSQL, MySQL and MariaDB

`@arkenivajs/database` provides the bounded named-bind compiler and application-owned
SQL coordination. Install `postgresPlugin()` from `@arkenivajs/database-postgres`
and configure named root database definitions to use `app.sql` queries and pinned
transactions. See the [SQL reference](../packages/database/README.md),
[PostgreSQL reference](../packages/database-postgres/README.md) and
[executable orders guide](../examples/postgres/README.md) for limits, precision,
TLS, cancellation, unknown commit outcomes and native instrumentation coverage.

Install `mysqlPlugin()` from `@arkenivajs/database-mysql` for root definitions with
`driver: 'mysql'`. Its Promise pools use bounded prepared streams and verified DNS
TLS, preserve bigint/decimal/temporal precision, and never replay statements or
callbacks. MySQL DDL may implicitly commit: the adapter reports that outcome rather
than promising rollback. See the [MySQL reference](../packages/database-mysql/README.md)
and [runnable MySQL orders example](../examples/mysql/README.md).

`mariadbPlugin()` from `@arkenivajs/database-mariadb` owns separate native Promise
pools for `driver: 'mariadb'`. Its bigint results, awaited release, CA/IP/DNS policy
and MariaDB error codes are verified independently. See the
[MariaDB reference](../packages/database-mariadb/README.md) and
[runnable MariaDB consumer](../examples/mariadb/README.md).

`oraclePlugin({ mode: 'thin' })` from `@arkenivajs/database-oracle` registers
independent native Oracle pools. Its named binds, exact NUMBER text, bounded
ResultSets, native LOB ownership and optional process-wide Thick mode are described
in the [Oracle reference](../packages/database-oracle/README.md).
**Oracle adapter contract-tested with mocks; live compatibility not verified**.

## etcd key-value resources

`etcdPlugin()` from `@arkenivajs/database-etcd` installs `app.etcd` for one root
database definition. The provider exposes raw bytes, exact bigint metadata,
atomic compare-and-swap, closable watch iteration and explicitly renewed owned
leases. Its native handle is the actual `Etcd3` SDK instance. See the
[etcd reference](../packages/database-etcd/README.md) and
[executable consumer](../examples/etcd/README.md) for mTLS/ACL configuration,
bounded recovery, unknown write outcomes and resource cleanup.

## Redis

`redisPlugin()` from `@arkenivajs/database-redis` installs a separate
`RedisProvider` for the explicitly configured root database definition.
`get`, `set`, `del`, `increment` and `publish` retain native Redis semantics;
`set` reports whether NX/expiration options were accepted, and a publication's
subscriber count does not imply durable delivery. `native()` is an explicit
escape hatch with reduced portable validation/measurement coverage. See the
[Redis reference](../packages/database-redis/README.md) and
[executable consumer](../examples/redis/README.md).

## MongoDB documents

`mongodbPlugin()` from `@arkenivajs/database-mongodb` installs `app.mongo`.
The portable document port exposes bounded `findOne`, `findMany`, `insertOne`,
`updateOne`, `deleteOne`, `aggregate` and `withTransaction`. Actual native
BSON/session semantics are retained; application DTOs must explicitly convert
ObjectId, Decimal128 and int64 before JSON output. A transaction requires a
replica set and is never blindly replayed. See the
[MongoDB reference](../packages/database-mongodb/README.md) and
[customer consumer](../examples/mongodb/README.md).

## Checked JSON cache

`cachePlugin(options?)` from `@arkenivajs/cache` wraps an explicitly installed
Redis provider. `get<T>` returns checked JSON or null; `set<T>` captures data
before submission and accepts a positive millisecond TTL; `delete` returns
whether a value was actually removed. The default TTL is 30,000 ms. Schema
bounds reject unsupported data instead of executing custom serialization.
`tenantCache(cache, verifier, context)` binds keys to an application-verified
tenant and rejects attempts to address another namespace. See the
[cache reference](../packages/cache/README.md) and
[complete example](../examples/cache/README.md).

## Health and readiness

`healthPlugin(options?)` from `@arkenivajs/health` installs `app.health`.
`live()` reports local process liveness. `ready()` checks bounded dependency
probes and returns safe failing names; concurrent requests share probe work.
Timed-out native probes remain owned until their actual settlement. HTTP
`/readyz` returns 503 for unavailable dependencies while `/livez` can remain 200.
See the [health reference](../packages/health/README.md) and
[HTTP/Redis readiness service](../examples/health/README.md).

## Optional Core NATS messaging

`messagingPlugin(options)` and `createNatsBus(options, operation?)` from
`@arkenivajs/messaging` require verified TLS, scoped credentials and an explicit
asynchronous error policy. `publish<T>` captures checked JSON and returns a
UUID plus `acknowledged:false` for Core NATS. A successful communication round
trip is not proof of durable storage or subscriber acceptance. Interrupted
submitted publications can have an unknown outcome and are not replayed.
`subscribe<T>` returns an idempotently closable subscription; handler errors
reach the configured policy. Background consumers never receive trusted tenant
state from wire JSON and must establish their own metering authority.
See the [messaging reference](../packages/messaging/README.md),
[strict package compatibility check](../packages/messaging/compat/README.md)
and [executable consumer](../examples/messaging/README.md).

## Generated declarations and distributable artifacts

`pnpm docs:build` renders the complete exported symbol/type reference from
actual package sources and checks local documentation links. Its output is
`.build/api/index.html`. Package-specific references above describe behavior,
limits, defaults, errors, cancellation and measurement coverage beyond the
signatures. `pnpm test:packed:examples` separately installs real package archives
in a private temporary consumer, recompiles example source/tests against those
public declarations and executes their suites. See the
[learning path](learning-path.md) for prerequisites and live examples.
