# Redis cache consumer

This executable guide uses the [Redis adapter](../../packages/database-redis/README.md)
on an explicitly disposable server. It writes only random owned keys under the
configured ACL namespace, verifies missing values, JSON text, NX true/false,
eventual millisecond expiration, exact integer increments and actual deletion
counts. It deletes its keys and closes the application in `finally`.

Use the adapter's [private TLS/ACL fixture](../../packages/database-redis/test/fixtures/README.md)
inside a dedicated VM or ephemeral CI runner. After the fixture is healthy:

```sh
pnpm build
pnpm --filter @arkenivajs/example-redis test
python3 packages/database-redis/test/fixtures/run.py /private/runtime/redis-fixture/environment.json pnpm --filter @arkenivajs/example-redis test:integration
python3 packages/database-redis/test/fixtures/run.py /private/runtime/redis-fixture/environment.json pnpm --filter @arkenivajs/example-redis start
```

The CLI requires `ARKENIVA_REDIS_DISPOSABLE=1` and `ARKENIVA_REDIS_URL`; import and
offline unit tests do not connect. Output is a JSON DTO with string order fields,
the actual NX outcomes, counter 3 and deleted count 2. A 200 ms TTL is checked
eventually within a bounded 3-second budget rather than treating expiration as an
exact delivery clock. Public failures use safe error JSON, without URL, cause or
stack serialization.

In a real service, `cacheOrder` receives `app.redis` and an application-controlled
key. Authorize a verified tenant and assign a server-enforced ACL namespace first.
An NX rejection is normal contention and returns false; it is never fabricated as
success. A transport failure after a submitted write may have an unknown outcome;
the example does not retry it. Durable business events require durable messaging,
since Redis Pub/Sub subscriber counts do not prove message processing.
