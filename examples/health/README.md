# Health and readiness service

An executable HTTP service with explicit startup, safe liveness/readiness and
SIGTERM/SIGINT cleanup. The default mode has no backend and confirms only local
application lifecycle. The optional Redis mode installs the actual Redis
adapter and requires its explicit disposable fixture authorization.

```sh
pnpm build
pnpm --filter @arkenivajs/example-health test
ARKENIVAJS_PORT=8080 pnpm --filter @arkenivajs/example-health start
curl --fail http://127.0.0.1:8080/livez
curl --fail http://127.0.0.1:8080/readyz
```

Stop with SIGTERM or Ctrl-C. The listener drains before dependency cleanup.
The readiness body contains only status; it never exposes dependency names,
native messages, credentials or topology.

Use the [private Redis fixture](../../packages/database-redis/test/fixtures/README.md)
for actual dependency readiness:

```sh
python3 packages/database-redis/test/fixtures/run.py /private/runtime/redis-fixture/environment.json pnpm --filter @arkenivajs/example-health test:integration
python3 packages/database-redis/test/fixtures/run.py /private/runtime/redis-fixture/environment.json pnpm --filter @arkenivajs/example-health start --redis
```

`--redis` is explicit opt-in; fixture URLs are never printed. A failed authenticated
probe prevents the listener from starting. At runtime, a failed probe returns
HTTP 503 from readiness while liveness remains independent. The
[health package guide](../../packages/health/README.md) describes timeouts,
coalescing, cancellation, native owner scope and custom checks. Restrict probe
routes to trusted deployment infrastructure.
