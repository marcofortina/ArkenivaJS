# @arkenivajs/health

Optional bounded dependency readiness for an application. Importing the package
opens no listener, timer, transport or database connection. Install the actual
database plugins explicitly; health never installs a driver or simulates a
successful backend response.

```ts
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { apiPlugin } from '@arkenivajs/api';
import { redisPlugin } from '@arkenivajs/database-redis';
import { healthPlugin } from '@arkenivajs/health';

const app = await createApplication({
  service: { name: 'orders', version: '1.0.0', environment: 'production' },
  http: { host: '127.0.0.1', port: 8080 },
  databases: { values: { driver: 'redis', connectionStringEnv: 'REDIS_URL' } },
  plugins: [loggingPlugin(), apiPlugin(), redisPlugin(), healthPlugin()],
});
await app.start();
// Arrange application shutdown through app.stop() on SIGTERM/SIGINT.
```

Use the Redis adapter's [verified TLS and scoped account policy](../database-redis/README.md).

## Readiness and liveness

`app.health.live()` returns `{status: 'live'}` locally. It never queries an
external dependency. `app.health.ready()` returns `{status: 'ready', failing: []}`
only after startup, while the application remains READY and every registered
probe confirms readiness. Failure returns `status: 'not_ready'` and bounded
configured check names. Lifecycle failure uses the reserved name `application`.
Retained facades remain not ready after closure; late probe success cannot
restore readiness during drain.

Database plugins expose optional readonly SPI hooks. The kernel explicitly
orders health after their owners, including recursive support plugins, and
captures each callback with its original scoped context. The health collector
receives immutable kernel callbacks, without permission to read a foreign
plugin's private components. Other plugins cannot replace this kernel metadata.
Public database facades remain unavailable before application activation.

SQL hooks ping every configured pool. Redis sends PING; etcd performs an
authorized scoped read; MongoDB performs an authorized bounded collection read.
These checks use the owned native clients on each probe. They do not cache an
initial connected flag. MongoDB topology capability validation remains part of
the adapter's startup. Normal dependency failure produces not ready; original
errors remain internal startup causes, outside public HTTP responses.

With the API plugin installed, `/readyz` consumes the optional declared health
owner and returns HTTP 200 or 503 with only `{status: 'ready' | 'not_ready'}`.
It checks lifecycle again after awaiting dependency evidence. `/livez` stays
local HTTP 200 while the event loop and listener can answer. Both routes are
excluded from business OpenAPI paths. Restrict these endpoints to trusted
deployment probes; they do not replace business authentication or authorization.
Without health installed, HTTP readiness still checks the application lifecycle.
Startup probes must pass before the API listener activates.

## Custom checks and budgets

`healthPlugin({checks, dependencies, timeoutMs})` accepts named callbacks
`check(context, operation)`. Declare every custom dependency's plugin ID in
`dependencies`. Use already initialized private resources exposed by that
dependency; public application facades still require READY. An optional
`ComposablePlugin.health(context, operation)` hook is preferable for an owner
checking its own resources. Returning exactly boolean true confirms readiness;
false, rejection, malformed evidence, cancellation and timeout fail closed.

Names use lowercase ASCII letters, digits, dots and hyphens, start with a
letter and contain at most 96 characters. Automatic names are `plugin.<id>`.
Names must be unique across custom and automatic checks; `application` is
reserved. There are at most 32 checks in total. Combined metadata and deadlines
are validated before any resource initializes. Use static diagnostic names,
never tenant identities, request input or credentials.

The default per-check budget is 1,000 ms; positive integer values up to 5,000 ms
are supported. Checks run concurrently and receive both `timeoutMs` and an
owned `AbortSignal`. Concurrent readiness callers share a probe batch. A timed
out callback remains reserved until its actual promise settles; no overlapping
retry of that check starts in the meantime. Probes perform no background polling
and never retry mutations. An uncooperative callback can keep its slot occupied,
but cannot create an unbounded queue of new probes.

Shutdown aborts probe signals and drains owned promises for up to five seconds.
A failed drain is reported as `EK_HEALTH_NOT_READY` with internal
`details.cleanupFailed=true`; cleanup continues through the application kernel.
Failed health startup also cleans up its own partial work. JavaScript cannot
forcibly terminate arbitrary callback code; callbacks must honor cancellation
and retain ownership of any native work continuing after a logical timeout.
Health never closes another plugin's client.

The standalone `createHealthRegistry(options)` exposes the same `live`/`ready`
contract plus explicit `start()`, `close()` and numeric `stats()`. Its optional
`isReady` predicate must confirm application lifecycle; exceptions fail closed.
An empty registry confirms only local lifecycle and makes no backend claim.

Standalone `createApi({health, readinessTimeoutMs})` accepts an explicit health
registry. HTTP readiness defaults to a separate 2,000 ms response budget, with
a maximum of 10,000 ms. It shares one pending registry call across concurrent
requests and retains that call after logical timeout until settlement. Registry
ownership and cleanup stay with its caller. Application `apiPlugin` obtains
health through an explicit support dependency instead of accepting a foreign
registry in plugin options.

## Observations and verification

Optional `health.ready.duration` histograms measure a completed probe batch in
seconds. Failure warnings contain only a count. Numeric stats report pending
checks, failed checks and observer failures. Failed diagnostic sinks cannot
turn dependency failure into success or replace an established result. No
probe invents server CPU, wire bytes or tenant attribution. Native adapters
retain their own measured operation accounting; health adds no duplicate charge.

Tests enforce 95% line and branch coverage, including startup rollback,
uncooperative callbacks, cancellation, concurrency, captured contexts, drain,
safe HTTP responses and capacity validation. The live Redis test pauses actual
encrypted replies through a loopback relay to verify HTTP 503, independent
liveness and recovery. Every other mandatory native adapter has a real scoped
health-hook integration test. Oracle is contract-tested with mocks; live
compatibility is not verified.

Run `pnpm coverage:health` with the
[disposable Redis fixture environment](../database-redis/test/fixtures/README.md).
Missing fixture authorization is an error rather than a skipped integration.
