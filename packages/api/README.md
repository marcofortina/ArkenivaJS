# @arkenivajs/api

Fastify routing through `ApiServer`, with `RouteDefinition`, `RouteContext`, `RouteHandler` and `ApiMiddleware`. `createApi(options)` creates a standalone managed server; `apiPlugin(options?)` exposes `app.api` before startup and binds its configured listener after every plugin initializes. Application composition explicitly includes a logging plugin. No module import binds a port.

`get/post/put/patch/delete(path, definition)` register before startup. Every definition supplies request schemas as applicable, a mandatory response schema, an explicit `auth:{required:boolean,scopes?}` and a handler. Params/query/body validate without coercion or inserted defaults. Response validation is enabled by default; `validateResponses:false` opts out of the explicit response check while retaining the serialization schema. Invalid handler output produces a safe internal error rather than returning confidential extra fields. Duplicate route patterns, reserved health paths and malformed definitions reject before listening. Use the native Fastify handle for advanced routing outside these portability guarantees.

Request context includes a fresh server-owned UUID request id, immutable params/query/body/headers, a cooperative AbortSignal and an optional verified tenant. Caller headers cannot replace the request id. Protected routes require an authentication provider at startup; public routes never receive a trusted tenant automatically. Declare the security plugin in `apiPlugin({dependencies:['security']})` when using application authentication. The security provider verifies identity, scopes and tenant before either middleware stage. Headers, tokens, full claims and payloads are excluded from framework access logs.

`registerMiddleware('postAuthentication'|'preHandler', fn)` executes FIFO within each stage. Middleware must await `next()` exactly once or throw a typed error. Silent short-circuit and repeated continuation reject; neither stage can bypass authentication or schema validation. Registration freezes when startup begins.

Defaults are loopback host, port 8080, a 30,000 ms request/handler deadline and one MiB body bound. Port zero explicitly requests an ephemeral port and is permitted only in the test environment. Standalone `tls:{key,cert}` retains native HTTPS with TLS 1.2 minimum; application-level file-based HTTPS is described below. Bind public interfaces explicitly and provide the deployment network policy.

`start(options?)` performs schema setup and listener activation; `address()` returns the actual origin. `openApiDocument()` returns a deeply immutable OpenAPI 3.1 document after successful startup, sorted deterministically by paths and methods. `/livez` and `/readyz` are internal operational routes; readiness returns 503 while work is disabled and includes no dependency details. They are omitted from the business API document. `native()` returns the Fastify instance and can bypass adapter validation or instrumentation; consumers own tests for raw extensions.

`close(options?)` rejects new work, drains active handlers and aborts remaining work at deadline. Client disconnect and handler timeout abort the context signal. Closed resources use `EK_RESOURCE_CLOSED`; late registration uses `EK_LIFECYCLE_STATE`; invalid setup uses `EK_CONFIG_INVALID`; missing auth uses `EK_PLUGIN_DEPENDENCY`. Failure to bind uses `EK_HTTP_LISTEN`. Uncooperative handlers cannot retain active sockets after bounded shutdown.

HTTP errors use `{error:{code,message,requestId}}`, excluding native cause, stack and developer message. Validation maps to 400, missing/invalid identity to 401, scope/tenant denial to 403, unknown routes to 404, rate limit to 429, request timeout/abort to 408, an explicitly upstream timeout to 504, backend/readiness failure to 503 and other errors to 500.

`stats()` reports completed, failed, active and observer-failure counts. Optional synchronous `onObservation` receives method, route template, status, monotonic duration and serialized response byte count where observed. It contains no raw URL or tenant label. Request transport bytes and streamed response bytes remain unavailable here. Client disconnects finalize bookkeeping as failures without inventing an HTTP response status. Optional native logger context scoping correlates logs from a handler when the supplied logger supports it.

Tests use real loopback sockets and Fastify injection to verify every verb, schema rejection, safe errors, auth boundaries, middleware order, cancellation, client disconnect, graceful drain, bounded close and application composition.

Optional `telemetry` supplies the abstract core port without importing an SDK. In applications, declare `telemetry` in `apiPlugin` dependencies when root telemetry is configured, and register finite route templates in the telemetry label policy. The adapter exports server/handler spans, observed request duration, serialized response bytes and active requests; health probes are excluded from business measurements. `server.response` identifies logical response-body bytes, not inbound request or TCP bytes. Scoped W3C extraction and logger trace correlation use optional contextual controls when provided. Diagnostic failures increment observer failures and preserve the business callback result without replay.

Protected routes may declare `auth.assurance:'single-factor' | 'mfa' | 'phishing-resistant'`. Any declared assurance requires a trusted resolver: startup fails with `EK_MFA_POLICY` before listener binding when the managed auth provider's `hasAssurancePolicy()` check is absent, false or fails. Unauthenticated routes cannot declare assurance. Unknown authorization fields reject registration. After bearer verification and exact scope checks, the server calls `requireAssurance` before tenant derivation, middleware or the handler. Missing authentication returns 401; insufficient verified assurance returns 403. OpenAPI exposes the requirement as `x-arkenivajs-assurance`.

MFA verification errors use opaque envelopes: invalid proof 401, inadequate assurance 403, replay/enrollment/credential or counter conflict 409, expiration 410, rate limiting 429 and unavailable durable state/crypto 503. `EK_MFA_RATE_LIMIT` may carry internal `retryAfterMs` as a positive integer up to one day; the response exposes only rounded-up integer seconds in `Retry-After`. Invalid delay metadata is omitted. No account/factor details or raw proof appear in responses.

Optional `meter` supplies an independent usage port with managed `run`/`markMissing` scope controls. Root metering requires an explicit `metering` plugin dependency. Trusted sessions begin only after all authorization checks, cover middleware and handler work and finish once after response serialization or client disconnect. Public/health/unauthenticated requests never acquire a tenant meter. HEAD/204/304 have zero body bytes; unknown body sizes remain unavailable. Export/queue failure is observable without replaying business work. See the [metering example](../../examples/metering/README.md).

## Dependency readiness

With an explicit health plugin installed, API composition declares a support
dependency on its owner. Startup health checks finish before listener activation.
`/readyz` returns 503 on unhealthy, malformed, rejected or timed out evidence and
rechecks lifecycle after awaiting it. Its body contains only status. `/livez`
remains a local process response; neither route is a business OpenAPI endpoint.
Without a health owner, readiness checks application lifecycle alone.

Standalone `createApi` accepts an optional `health: HealthRegistry` and a positive
integer `readinessTimeoutMs` (default 2000, maximum 10000). Concurrent requests
share one pending registry call, retained until actual settlement even after a
logical timeout. Registry cleanup remains the caller's responsibility. Application
`apiPlugin` obtains health from its declared owner instead of accepting a foreign
registry. Probe endpoints should be limited to trusted deployment infrastructure.

## TLS material validation

The internal file adapter accepts the shared `ServerTlsFiles` shape and reads at
most 1 MiB per regular file. It checks PEM certificate validity and uses Node TLS
to validate encrypted keys and certificate/key matching. Explicit mounted-secret
symlinks are supported. Private keys and passphrases are excluded from safe errors,
and temporary buffers are cleared after native context construction.

This helper is not a package-root export. Application configuration selects it
through `http.protocol:'https'` with `tls.certificateFile` and `tls.privateKeyFile`.
The file references are validated before activation and loaded at `app.start()`;
invalid material fails startup without an HTTP fallback.

## Application HTTP/HTTPS selection

`http:{host,port}` and `http:{protocol:'http',host,port}` both select plain HTTP.
TLS fields and HTTP/2 flags are forbidden on plain HTTP. If `http` is omitted,
application-managed API registration opens no implicit network listener. A
standalone `createApi()` still starts its explicitly managed listener when its
`start()` method is called.

For direct HTTPS, provide `protocol:'https'` and external TLS files. `minVersion`
defaults to `TLSv1.2` and also accepts `TLSv1.3`. Set
`clientCertificate:'required'` with `caFile` to require trusted client certificates;
this verifies the TLS peer and does not assign an application tenant. Encrypted
keys use `privateKeyPassphraseEnv`, an explicit environment variable name. The
private key file and passphrase reference are redacted from configuration snapshots.
Certificate rotation takes effect through a controlled application restart.

Routes, schema validation, OpenAPI, readiness and drain remain Fastify-owned.
Bind failures use `EK_HTTP_LISTEN`. Ephemeral `port:0` is restricted to the test
environment. The current adapter supports HTTPS with HTTP/1.1; selecting
`http2:true` raises `EK_UNSUPPORTED_CAPABILITY` before binding. HTTP/2, WSS and the
complete transport observability/performance acceptance remain separate requirements.
