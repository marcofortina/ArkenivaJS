# @arkenivajs/database-redis

Optional Redis key-value support using the actual **redis 6.3.0** client.
Import and application creation open no socket. Startup validates one explicit
database definition, connects and authenticates a PING before activating `app.redis`.
Redis operations remain separate from SQL.

```ts
import { createApplication } from '@arkenivajs/core';
import { redisPlugin } from '@arkenivajs/database-redis';

const app = await createApplication({
  service: { name: 'cache-reader', version: '1.0.0', environment: 'production' },
  plugins: [redisPlugin()],
  databases: { cache: { driver: 'redis', connectionStringEnv: 'REDIS_URL' } },
});
await app.start();
try {
  const accepted = await app.redis!.set('orders:42', '{"id":42}', {
    ttlMs: 5000,
    onlyIfAbsent: true,
  });
  console.log(accepted, await app.redis!.get('orders:42'));
} finally {
  await app.stop();
}
```

## Configuration and isolation

`REDIS_URL` is an explicit URL such as
`rediss://application:password@redis.example:6379/0?prefix=tenant-a:`.
Percent-encode credentials and query values. Username and password are required;
the database index defaults to zero. The only query options are `prefix` and
`sslca`. Unknown or duplicate options, fragments, SQL pool options and multiple
Redis definitions reject. URLs are bounded to 64 KiB.

Production and remote connections require TLS with certificate and hostname/IP
verification, TLS 1.2 minimum and explicit system trust roots. `sslca` accepts an
absolute path to a regular, nonempty CA bundle of at most 1 MiB, captured during
startup. No insecure verification option exists. Plain `redis://` is accepted
only on development/test loopback addresses, including IPv6 loopback.

The optional namespace is empty or at most 128 ASCII characters ending in `:`;
letters, digits, colon, underscore and hyphen are allowed. It is prepended to
portable keys and channels. A prefix organizes keys; **server ACLs enforce tenant
isolation**. Assign a separate least-privileged account and key/channel patterns
to each trust domain. A shared native client retains its account's authority.
Never derive a trusted tenant prefix from unverified request input.

Portable permissions include PING, SET, DEL, PUBLISH, EVAL, EVAL_RO, STRLEN, GET
and INCRBY. Native examples/tests additionally use narrowly scoped hash,
transaction, subscription and introspection commands. The disposable fixture's
control account is for fault tests only; it is never an application account.

## Portable values and results

| Operation                                                 | Result and bounds                                                                                                  |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `get(key, options?)`                                      | Exact UTF-8 text or `null`; empty strings and a leading BOM are preserved. Invalid UTF-8 rejects.                  |
| `set(key, value, { ttlMs?, onlyIfAbsent?, ...options }?)` | `true` for an acknowledged SET; `false` only for an unmet NX condition. TTL is positive safe integer milliseconds. |
| `del(keys, options?)`                                     | Actual nonnegative deleted count; an empty array returns zero without a request. At most 1,000 keys.               |
| `increment(key, amount = 1, options?)`                    | Exact safe integer result; amount, stored integer and result must fit ±9,007,199,254,740,991.                      |
| `publish(channel, message, options?)`                     | Actual nonnegative subscriber count; this does not acknowledge downstream processing.                              |

Keys/channels are nonempty valid UTF-8, at most 1,024 bytes before the namespace,
and contain no NUL/CR/LF. Values/messages are valid UTF-8 of at most 1 MiB.
Identifier and value limits reject before command submission. Input key arrays
and mutable option fields are captured before asynchronous work.

GET uses an atomic read-only Lua `STRLEN`/`GET` script to reject oversized stored
values before transfer. Increment uses an atomic Lua validation and INCRBY;
invalid, noncanonical, fractional or unsafe stored integers reject **before
mutation**, preserving the value and its TTL. Its integer reply is decoded as
text, checked exactly with bigint and then converted to number, avoiding native
numeric decoder rounding at the safe-integer boundary. Redis 7+ EVAL_RO is
required; the exact tested server is listed below. Arbitrary server modules,
cluster routing and Sentinel are not qualified by this adapter's tests.

Redis expiry is eventual from the caller's perspective. Pub/Sub is ephemeral,
with no durable delivery guarantee. Use a durable messaging adapter for durable
consumer processing.

## Deadlines, reconnect and shutdown

Each call accepts a positive safe integer `timeoutMs` and an `AbortSignal`.
The monotonic total deadline defaults to **15,000 ms**; socket connect timeout is
5,000 ms. Portable pending attempts and the native command queue are bounded to 128. Overload and offline calls fail before submission. Native maintenance
redirects and the offline queue are disabled.

Reconnect retries only transport establishment, at most five retries with bounded
100–1,099 ms exponential delay/jitter. Authentication and certificate trust
errors stop reconnect. Failed application commands and callbacks are never
replayed. A cancelled, timed-out or disconnected submitted write may have reached
Redis: its error carries `details.outcome='unknown'`, `retryable=false`.
Reconcile with application idempotency policy before any retry. Acknowledged
server errors retain their known failure outcome.

Shutdown aborts owned operations, destroys the application socket and observes
pending/startup promises with a 5-second cleanup budget. Late startup completion
is closed. Retained portable facades reject after closure. Cleanup failures are
surfaced rather than reported as successful release.

## Native ownership and diagnostics

`app.redis!.native()` returns the actual `RedisClientType` from node-redis. Use
it for hashes, pipelines, MULTI/WATCH, binary data or subscriptions. Native calls
do not apply portable prefixes, bounds, conversion, deadlines or instrumentation.
Supply the configured namespace yourself; server ACLs continue to apply. For
large exact integer replies, use the SDK's `withTypeMapping` with
`RESP_TYPES.NUMBER: String` and validate the decimal text explicitly.

Pub/Sub needs a separately owned `client.duplicate()`: attach its error listener,
connect, subscribe, then explicitly unsubscribe and destroy it in `finally`
before application shutdown. The application does not own independently created
duplicates. Native MULTI/EXEC and WATCH retain SDK/server behavior; there is no
portable transaction callback or automatic transaction replay.

Each submitted portable call records one `db.query` attempt. Optional framework
CLIENT spans contain bounded operation/system names; OTel
`db.client.operation.duration` is seconds and managed meter scopes record
`db.client.elapsed` in milliseconds. No server CPU, I/O or wire-byte counts are
invented. Quality reports `driver_bytes_unavailable`; obtaining a native handle
inside a managed scope marks `not_instrumented`. Diagnostic failures cannot
replay work or replace an established native outcome. Keys, values, credentials
and raw server messages are absent from default diagnostic fields; private error
causes retain the original exception for explicit developer inspection.

The SDK itself publishes Node diagnostics channels. Externally installed
node-redis auto-instrumentation/subscribers can collect keys, Lua arguments and
Pub/Sub payloads independently of this adapter. Exclude this client from host
auto-instrumentation or apply an independently reviewed redaction policy. The
framework neither subscribes to these channels nor changes global subscribers or
the process-wide OTel provider. Do not enable duplicate native and framework DB
spans. No client-side cache or optional xxhash native addon is configured.

## Verification and compatibility

See the [disposable TLS/ACL fixture](test/fixtures/README.md). Unit and contract
tests run without a server. Explicit live tests require authorized disposable
endpoints; missing environment is a failure, not a skipped pass. The live suite
uses targeted disconnects, temporary server pauses and scoped keys, so it must
run against its own dedicated server without concurrent integration jobs.

| Driver      | Server       | Node                        | Platform                           | Verified scope/date                                                                                                     |
| ----------- | ------------ | --------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| redis 6.3.0 | Redis 8.10.2 | 22.23.4 / 24.22.1 / 26.12.1 | Linux x86-64, QEMU isolated server | 2026-10-25: TLS/ACL, text/NX/TTL, exact counters, DEL, Pub/Sub, native hash/MULTI, reconnect, cancellation and shutdown |

Other Node versions require their own successful live matrix. Redis
module availability in the server image is not evidence that those modules were
tested. SDK packages are pinned and MIT licensed; see
[third-party notices](THIRD_PARTY_NOTICES.md) for the adapted Apache-2.0 code and
optional OTel peer. The Redis server image is a separate test prerequisite and is
not included in the product's npm package.

With an optional health collector installed, the plugin performs a fresh
readonly native readiness probe through its owned client and bounded operation
scope. Health runs after owner initialization, before inbound listeners activate;
public provider facades still require application READY. Scoped hook integration
tests use the actual authenticated disposable server and reject stale callbacks
and pre-aborted operations. Health never closes the native owner's client.
