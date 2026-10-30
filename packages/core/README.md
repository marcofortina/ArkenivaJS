# @arkenivajs/core

Typed foundations for modular ESM applications. `KitError` preserves the developer message and original `cause` internally. Call `toSafeJSON()` at external boundaries; it returns a stable error code and a fixed safe message. JSON serialization uses the same safe envelope. Stack traces, raw messages and details never enter that envelope.

Public defaults are shared literal constants: `DEFAULT_SHUTDOWN_TIMEOUT_MS=30000`,
`DEFAULT_HTTP_TIMEOUT_MS=10000`, `DEFAULT_SQL_TIMEOUT_MS=15000`,
`DEFAULT_POOL_ACQUIRE_TIMEOUT_MS=5000`, `DEFAULT_METER_QUEUE_CAPACITY=10000`, and
`METER_EVENT_SCHEMA_VERSION='1.0.0'`. Adapter entry points also expose their relevant
constants. Changing a default requires an explicit compatibility review.

```ts
import { KitError } from '@arkenivajs/core';

const error = new KitError({
  code: 'EK_TIMEOUT',
  message: 'The internal operation exceeded its deadline',
  retryable: false,
});
const response = error.toSafeJSON();
```

`retryable` defaults to false and never authorizes automatic replay. Error details are immutable primitive metadata. Native causes may contain sensitive data and must remain within trusted components.

`ErrorCode` includes the approved optional security, protocol, data and tenant
categories. Recognizing an error identifier does not install its adapter or enable
an optional feature. All categories retain the same fixed safe JSON message;
unknown identifiers and spelling variants are rejected at runtime.

The documented `@arkenivajs/core/support` integration entry point provides `ConfigStore`, `compileSchema`, `copyData`, `freezeData`, `mergeData`, `redactData` and `within`. These primitives let adapters share one validated data model and error identity without circular package dependencies. They perform no I/O at import.

`copyData` rejects executable accessors, custom object prototypes and proxies,
including nested arrays and revoked proxies, before invoking their hooks.

`ConfigStore<T>(initial, {schema, dynamicPaths?, secretPaths?, preflight?})` validates strict JSON Schema without coercion. Getters and snapshots are deeply immutable; snapshots redact known secret names and explicit secret paths. `reload` merges, validates and preflights a new generation before one atomic swap. Failed reloads retain the previous generation and reject with `EK_CONFIG_RELOAD_REJECTED`. Preflight functions must be side-effect-free. Static data, credentials and security policy require reconstruction.

`within(work, {signal?, timeoutMs?})` bounds a promise with `EK_ABORTED` or `EK_TIMEOUT`; timeout defaults to 30,000 ms and must be a positive integer. It removes its listener and timer on every outcome. The work callback must cooperate with cancellation to terminate its own resources.

Operation options use own data fields on plain records. Proxy options are rejected
before reflection or callback execution; cancellation requires an actual native signal.

Long deadlines use bounded native timer intervals against a monotonic clock, preserving the requested duration beyond Node's single-timer limit.

Plugin metadata must use data properties. Lifecycle and health callbacks are captured
once with their original receiver; later replacement and custom `bind`, `call` or
`apply` properties cannot substitute another callback. Accessors, proxy metadata
and proxy lifecycle callbacks fail configuration validation before resources open.

`createApplication(options)` validates service metadata and requested capabilities before opening resources. `start()` shares a pending initialization promise, follows plugin dependencies and rolls back initialized resources in reverse order. `stop({timeoutMs})` uses a shared deadline, continues after close failures and becomes harmless once CLOSED. Startup failure preserves the primary cause and counts cleanup failures.

Use `COMPONENTS` with plugin `provide` and `require` to install explicit services. Duplicate registrations fail; a consumer must declare the provider's plugin id in `dependencies`. The registry freezes after initialization. `APPLICATION_SIGNAL` provides cooperative startup cancellation. Hooks must release partially acquired resources on rejection; late successful hooks are closed even after cancellation. JavaScript cannot forcibly terminate arbitrary uncooperative code.

`app.resolve<T>(key: symbol)` returns an explicitly installed service; a missing
symbol throws `EK_UNSUPPORTED_CAPABILITY`. `app.tryResolve<T>(key)` returns
`undefined` for absence. Both require a started application, or the current
plugin's active dependency-aware initialization/activation context. That context
is local to one application, propagates across awaits and expires when its hook
finishes. Duplicate capability registration reaches startup callers as
`EK_PLUGIN_DUPLICATE` and preserves the original cause.

After READY, admitted drain work may resolve remaining dependencies until their
owner releases them. CREATED, cancelled startup and CLOSED reject with
`EK_LIFECYCLE_STATE`; stopping an application that never reached READY grants no
lookup admission. Primitive symbol identity selects a service, with no implicit
module loading or string-name fallback. See the
[configured capability example](../../examples/configuration/README.md).

A core-only application has lifecycle and validated configuration. Required accessors for absent adapters throw `EK_UNSUPPORTED_CAPABILITY`, while optional accessors return undefined. HTTP, database, security, telemetry, health and metering implementations are separate integrations. The type-only ports describe their application-facing contracts and do not open or simulate those services.

Reload preflight is bounded by `preflightTimeoutMs` (default 30,000 ms). A hung or failed preflight leaves the active generation unchanged and releases the serialized reload queue; late preflight completion cannot commit.

Store options accept synchronous `onDiagnostic(event)` for committed reload audit events. The default sink writes bounded JSON metadata to standard error. `ConfigurationDiagnostic` and `reportConfigurationDiagnostic` are available from the support entry point for configuration adapters; events contain only a fixed event name, source and top-level key count. No values or paths are logged, and a failing custom sink cannot reverse the committed generation.

Adapters that expose configuration facades before startup may implement `ComposablePlugin` from the support entry point. Its optional `PREPARE_PLUGIN` hook returns bindings for its declared built-in capabilities after application validation. This phase must be resource-free: no connection, timer, collector or listener. Each application receives independent facades even when a factory is reused. `context.state()` reports lifecycle state without exposing another plugin's registry.

The optional `ACTIVATE_PLUGIN` hook runs after every ordinary `init` hook; inbound API adapters activate last so routes and resource checks finish before listener binding. Activation failures follow the same reverse cleanup as startup failure. Hooks must honor `APPLICATION_SIGNAL`. The normative `Plugin` init/close shape and explicit dependency access remain unchanged.

`SEMVER_PATTERN` from the support entry point shares strict service/plugin version validation with adapters.

Optional `DRAIN_PLUGIN` hooks stop inbound work before any downstream resource closes. They share the shutdown deadline; a failed drain is collected while reverse-order `close` still runs for every initialized plugin. Listener adapters use this phase to finish requests while database/client dependencies remain available.

Adapter authors can use `instrumentOperation(telemetry,name,attributes,work,onFailure)` from the support entry point. It invokes business work at most once, preserves its original value/exception even when a diagnostic provider fails, and reports instrumentation failures through a protected synchronous callback. It does not retry business operations. Providers must still honor their own bounded lifecycle; use the application operation signal for cancellable business work.

Root `security.assuranceResolver` is executable, immutable trust policy. Construction captures the callback separately from validated configuration data and exposes it only through immutable plugin options. Configuration getters, serialized snapshots and reloads do not carry executable callbacks; security changes require application reconstruction. Other functions or accessors in configuration remain invalid. Assurance policy startup failures retain `EK_MFA_POLICY` after owned resources are cleaned up.

Adapters can declare pure synchronous metadata factories through `SUPPORT_PLUGINS` in the composition SPI. The kernel resolves each factory identity once per application after root data validates, then applies the normal duplicate id/capability checks, dependency ordering, preparation and reverse cleanup. The requesting plugin must explicitly list each returned support id in `dependencies`; the extension grants no access to undeclared providers. It allows a group of SQL drivers to share one application-owned coordinator while retaining zero-argument driver factories and one `app.sql` facade. It performs no native-driver discovery and must not open resources in the support factory. Support graphs are bounded; asynchronous or malformed factories fail before initialization. Distinct factories returning the same id are conflicts, rather than permission to overwrite a provider. No mutable process-global service registry is needed.

`ComposablePlugin.health(context, operation)` is an optional readonly owner probe.
The kernel orders a declared health collector after all probe owners, including
expanded support plugins. Only the health capability can require the immutable
`HEALTH_PROBES` list from the support entry point. Each callback invokes its
owner's captured hook with that owner's original scoped context; it grants no
access to foreign component values. Callback results must be boolean, and late
results from stopped owners reject. Neither `HEALTH_PROBES` nor
`APPLICATION_SIGNAL` can be overwritten by a plugin. The separate
health integration owns probe deadlines and readiness policy.

The adapter support SPI also exposes `validateServerTlsFiles` and the lazy
`withServerTls` loader, shared by explicit HTTPS and raw TLS owners. Validation
captures file references without reading them. The loader reads bounded regular
files, validates certificate dates and native OpenSSL context compatibility, and
clears temporary certificate/key/CA buffers after the trusted callback constructs
its native context. Importing core or its support entry does not load TLS material
or open a listener.

`captureAbortSignal` in the support SPI captures a validated native signal and
rejects structural lookalikes or shadowed cancellation hooks. `within` snapshots
its options, checks cancellation before invoking queued work, and checks its
monotonic deadline again before acknowledging success. A timeout cannot preempt
synchronous JavaScript or roll back a side effect that already occurred.
