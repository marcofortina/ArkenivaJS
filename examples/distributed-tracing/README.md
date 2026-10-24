# Distributed HTTP tracing and process metrics

Prerequisites: Node.js 24, the pinned pnpm version, and the disposable OTel collector. Run Docker inside a disposable VM if you want to keep container services off the development host. The collector fixture is digest-pinned, read-only and resource-bounded. No OIDC token or database is needed for these explicitly public diagnostic routes.

From the workspace root, on the disposable Docker host:

```sh
docker compose -f packages/telemetry/test/fixtures/compose.yaml up -d
pnpm install --frozen-lockfile
pnpm build
ARKENIVAJS_OTLP_ENDPOINT=http://127.0.0.1:4318 pnpm --filter @arkenivajs/example-distributed-tracing start
docker compose -f packages/telemetry/test/fixtures/compose.yaml logs --no-color collector
docker compose -f packages/telemetry/test/fixtures/compose.yaml down
```

If Docker is inside a separate VM, run only the compose commands there and forward its collector port to a loopback port on the development host. Set `ARKENIVAJS_OTLP_ENDPOINT` to that forwarded origin when starting the CLI. Keep diagnostic logs and evidence outside the checkout. The [collector integration instructions](../../packages/telemetry/README.md) include exact trace/resource checks.

An explicit endpoint override emits a safe configuration diagnostic on stderr with source and key count only. Expected stdout includes safe access logs and a final JSON object with `value:"ok"` and matching `traceId`/`downstreamTraceId` hexadecimal values. They change each run. Collector output contains parent and child service resource metadata, two server spans, one outbound client span, request durations in seconds, observed response bytes and active-request state. Handler logs carry the same trace id plus independently assigned request ids. `pnpm --filter @arkenivajs/example-distributed-tracing test` executes the source flow and built CLI against an HTTP capture receiver; the dedicated CI collector job also runs the CLI against the actual collector.

Two application instances run in one Node process and communicate over separate loopback sockets. Each owns independent SDK providers and async context; no global provider is replaced. The HTTP hop serializes W3C context and the destination extracts it independently. Separate processes, containers and pods use the same protocol; this example does not claim process or tenant resource isolation.

The source explicitly declares `telemetry` dependencies for both API and HTTP plugins and declares the finite route-template metric labels. Server middleware and handler spans run inside the scoped context; the client injects trace headers from its own child span. Health probes are excluded from business request metrics. Caller baggage is ignored and never creates a tenant context. These public routes cannot access tenant-owned data; destination services that do so require their own audience-bound access token verification, as shown in the [tenant guide](../oidc-tenants/README.md).

The example records actual differences between cumulative process CPU snapshots and an instantaneous RSS/ELU sample. CPU includes the process's combined application and instrumentation work, including both application instances. RSS is one shared process measurement. These observations are not exact request CPU/RAM, tenant attribution, TCP egress or a performance comparison. Response byte histograms count observed logical payloads with `server.response`/`client.response` roles; they exclude request bodies, protocol headers and TLS/IP overhead.

Unavailable collectors produce typed export failure/deadline errors; the CLI exits unsuccessfully and closes owned resources. Existing business responses remain valid when diagnostic hooks fail, and the adapters never replay writes because telemetry failed. Invalid or metadata-service endpoints reject before application listeners bind. Port reservations are temporary; if a selected port becomes occupied, retry with available local resources rather than stopping another service.

Shutdown closes the parent application before releasing its downstream service, drains each listener, closes outbound agents, flushes SDK exporters and logger buffers and stops diagnostics. Always stop the collector fixture after the example, including after a failure. Production uses verified HTTPS and trusted workload metadata; the loopback plaintext opt-in belongs only to this disposable test.
