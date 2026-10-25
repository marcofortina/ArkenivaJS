# Redis-backed JSON cache consumer

An executable trusted-producer example using `@arkenivajs/cache` and the actual
Redis adapter. It writes a bounded schema-checked JSON value with an explicit
TTL, validates the application's customer DTO, verifies deletion results
true/false and waits for a short native Redis expiration. Random owned keys are
removed before application shutdown; cleanup errors remain visible.

Run against the [private Redis VM/CI fixture](../../packages/database-redis/test/fixtures/README.md):

```sh
pnpm build
pnpm --filter @arkenivajs/example-cache test
python3 packages/database-redis/test/fixtures/run.py /private/runtime/redis-fixture/environment.json pnpm --filter @arkenivajs/example-cache test:integration
python3 packages/database-redis/test/fixtures/run.py /private/runtime/redis-fixture/environment.json pnpm --filter @arkenivajs/example-cache start
```

The environment requires `ARKENIVA_REDIS_DISPOSABLE=1` and an explicit verified
`ARKENIVA_REDIS_URL`. The CLI prints a JSON DTO containing `customer-42`, `Ada`,
`removed: true`, `removedAgain: false` and `expired: true`, without internal
document fields or private native errors.

The example owns its local producer namespace. For authenticated HTTP requests,
use the cache module's [verified tenant facade](../../packages/cache/README.md#verified-tenant-facade)
with the current request's verified context and application-owned authentication
service. Its live integration suite exercises actual JWT signatures, tenant
isolation and independent metering with tracing off. Names from unverified
headers or route parameters cannot establish tenant authority.
