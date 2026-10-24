# Typed HTTP service and outbound client

Prerequisites: Node.js 24, the pinned pnpm version and `curl` for the CLI verification. No external database or credential is needed. From the workspace root:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-hello-http start
```

In a second terminal:

```sh
curl -fsS http://127.0.0.1:8080/hello/Ada
curl -fsS http://127.0.0.1:8080/proxy/Ada
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/readyz
```

The first two calls return `{"greeting":"Hello Ada"}`. The proxy route calls the typed outbound client against an explicitly permitted local origin. It forwards the handler's cancellation signal. The health endpoints return `live` and `ready` status objects without dependency internals. An unknown path returns a 404 safe error envelope; malformed requests return `EK_HTTP_VALIDATION` without exposing submitted values. The OpenAPI 3.1 document is available through `app.api.openApiDocument()` after startup.

Route registration occurs before `app.start()`. The API plugin prepares a facade, resource initialization completes, and the listener activates last. During shutdown, inbound requests drain while the outbound agent is still available. Stop the CLI with SIGINT or SIGTERM; it closes the listener and owned agent and flushes Pino logs.

Set another valid port explicitly:

```sh
ARKENIVAJS_PORT=8081 pnpm --filter @arkenivajs/example-hello-http start
pnpm --filter @arkenivajs/example-hello-http test
```

Ports outside 1–65535, malformed environment values and unknown `ARKENIVAJS_*` mappings fail before listening. If the port is occupied, startup reports a safe error and rolls back initialized resources. Select a free port instead of stopping unrelated services. Tests reserve ephemeral ports, execute both routes, check access logs and OpenAPI, run actual curl against the built CLI and verify SIGTERM termination.

`allowPrivateNetwork:true` is used solely for this isolated loopback example. Keep the explicit origin allowlist. Public deployment requires ingress TLS and declared authentication policies; these example routes explicitly use `auth.required:false`. Trace and request identifiers provide correlation and never authorize a tenant. See the [API guide](../../packages/api/README.md) and [outbound client reference](../../packages/http/README.md) for limits and failure semantics.
