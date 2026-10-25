# @arkenivajs/cache

Optional schema-checked JSON convenience cache backed by the explicitly
installed `@arkenivajs/database-redis` provider. The module opens no socket and
installs no database driver implicitly. Redis owns the actual transport,
authentication, TLS, native cancellation and backend metering.

```ts
import { createApplication } from '@arkenivajs/core';
import { redisPlugin } from '@arkenivajs/database-redis';
import { cachePlugin } from '@arkenivajs/cache';

const app = await createApplication({
  service: { name: 'customer-cache', version: '1.0.0', environment: 'production' },
  plugins: [redisPlugin(), cachePlugin()],
  databases: { values: { driver: 'redis', connectionStringEnv: 'REDIS_URL' } },
});
await app.start();
try {
  await app.cache!.set('trusted-producer:customer:42', { name: 'Ada' }, { ttlMs: 30000 });
  const row = await app.cache!.get<{ name: string }>('trusted-producer:customer:42');
  console.log(row?.name);
  console.log(await app.cache!.delete('trusted-producer:customer:42'));
} finally {
  await app.stop();
}
```

Use the Redis adapter's [verified TLS and scoped ACL configuration](../database-redis/README.md).
The cache plugin depends on the declared owner `database-redis` by default;
`redisDependency` selects another explicit plugin ID providing the same port.
Namespaces and TTL policy are captured at factory creation, validated before
remote initialization and isolated for each application. A retained facade
rejects before activation and after closure.

## JSON, keys and expiration

The default namespace is `cache:v1:`. An explicit `namespace` accepts 1–128 ASCII
letters, digits, colons, underscores and hyphens. It is prepended to portable
keys, separately from the Redis adapter's authorized native prefix. Keys must
be nonempty valid UTF-8, at most 2,048 bytes, without NUL/CR/LF. A tenant facade
adds its own namespace within that bound. Namespaces organize data; Redis server
ACLs enforce account authority.

`set<T>` captures data before asynchronous submission and resolves only after
backend acceptance. Every stored value is a JSON envelope with
`schemaVersion: 1` and `value`, checked against the module's recursive JSON
Schema with unknown envelope fields rejected. Supported values are finite
JSON numbers, strings, booleans, null, dense arrays and plain records. Business
DTO validation remains the application's responsibility; generic `T` does not
create a runtime business schema. Decode uses ordinary JSON data and never
constructs a class from tags.

Values reject undefined, bigint, non-finite numbers, functions, custom classes,
serializers, accessors, symbols, unsafe prototype keys, cycles and sparse or
named-property arrays. Traversal is bounded to 64 levels, 50,000 nodes, 10,000
array items and 10,000 record properties. Cumulative bytes are checked before
cloning/stringification; the final encoded envelope must fit 1 MiB. Structural
and byte bounds can reject a value before its final encoding is allocated.
Corrupt or incompatible stored envelopes fail with `EK_BACKEND_UNAVAILABLE`;
they are not treated as misses, evicted or silently replaced.

`get<T>` returns a fresh deserialized value or `null` for an absent/expired key.
Stored JSON null and a miss both return null under the public contract. `delete`
returns whether the backend actually removed the key. There is no local cache
fallback and no automatic write replay.

Expiration defaults to **30,000 ms**. A per-call `ttlMs` must be a positive safe
integer. To explicitly opt into non-expiring entries, construct the cache with
`defaultTtlMs: null`; this policy should not be used for tenant-sensitive data
without a reviewed expiration/invalidation strategy. A positive per-call TTL
still overrides that factory policy.

## Verified tenant facade

Create a facade from the current request's verified context and the managed
authentication service that owns its provenance:

```ts
import { tenantCache } from '@arkenivajs/cache';
import type { ManagedAuthService } from '@arkenivajs/security';

const customers = tenantCache(app.cache!, app.auth! as ManagedAuthService, context.auth!);
await customers.set('customer:' + context.params.id, { name: 'Ada' }, { ttlMs: 30000 });
const customer = await customers.get<{ name: string }>('customer:' + context.params.id);
```

The verifier must be trusted application configuration. Never accept it or a
tenant context from request JSON, headers or route parameters. The facade
captures an unambiguous UTF-8/base64url tenant namespace and checks provenance
again before each backend access. Qualified `tenant:` keys are rejected rather
than interpreted as another tenant's authority. Logical keys passed to one
facade cannot select a different tenant namespace. Closing the owning
authentication service invalidates its contexts. Construct request-scoped
facades after normal token expiry, scope and authorization checks; this helper
does not independently reverify a bearer token or install a Redis ACL policy.

## Budgets, ownership and observations

Calls accept a positive safe-integer `timeoutMs` and `AbortSignal`; the default
budget is 15 seconds and admission is bounded to 128 attempts. A logical timeout
or cancellation never authorizes write replay. If native acceptance is not yet
known, interrupted mutations report `details.outcome='unknown'`. Reservations
remain held until the Redis port's submitted promise settles. Its native
provider independently owns and bounds any later transport settlement.
Acknowledged work is preserved if a diagnostic wrapper subsequently fails or
times out. Delayed diagnostic callbacks cannot submit work after cancellation.

`createRedisCache(redis, options)` provides the same behavior as a standalone
`ManagedCache`, with `close()` and bounded numeric `stats()`. Close stops its
facade and drains its own calls within five seconds. It does not close the
application's Redis provider. Application plugin shutdown closes the cache
before Redis. Closing one application does not close another client's cache.

Optional `cache.get`, `cache.set` and `cache.delete` spans enclose actual backend
calls. Cache duration histograms use seconds and include backend completion.
The actual Redis provider records one `db.query` and elapsed milliseconds in
managed tenant metering; the convenience wrapper does not double-count those
calls. Metering remains active with tracing disabled. Wire bytes, server CPU,
I/O and cache serialization CPU are not fabricated. Cache keys, values and
tenant identifiers are absent from default cache diagnostics. Observation
failures cannot replay work or replace an established backend result.

## Verification

The suite enforces 95% line/branch coverage and tests strict JSON, TTL policy,
128-call admission, cancellation, delayed diagnostics, lifecycle and tenant
authority. Live tests use the [disposable Redis VM/CI fixture](../database-redis/test/fixtures/README.md)
and require its explicit environment; they do not skip missing configuration.
Real JWT signatures, two actual Redis tenant namespaces and persisted JSONL
metering verify isolation and independent accounting with tracing disabled.

| Redis driver | Server                                    | Node                        | Platform                            | Verified date |
| ------------ | ----------------------------------------- | --------------------------- | ----------------------------------- | ------------- |
| redis 6.3.0  | Redis 8.10.2, verified TLS and scoped ACL | 22.23.4 / 24.22.1 / 26.12.1 | Linux x64; Ubuntu 24.04 QEMU server | 2026-10-25    |

Run `pnpm --filter @arkenivajs/cache coverage` with the fixture's private
environment. This module ships no in-memory adapter and makes no live claim
for an alternative cache backend.

The [executable consumer](../../examples/cache/README.md) verifies JSON DTOs,
actual deletion outcomes and native expiration with explicit fixture opt-in.
