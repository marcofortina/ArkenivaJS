# Native HTTPS tenant routing verification

```sh
node tools/benchmark/routing.mjs --verify /absolute/private/new-directory
```

Build the workspace first. The evidence directory must be new and outside the
repository. The controller owns a synthetic signing authority and private HTTPS
certificate; every native and public-framework request verifies that certificate.
No database, container, external issuer or host trust change is required.

Four isolated profiles use the locked Fastify, JOSE and tenant-routing packages.
Each performs nineteen actual requests against three logical operations, four
preinstalled local implementations and six bindings for two tenants. The native
reference enforces the same JSON schemas, signed identity, scopes, binding lookup
and application-owned row policy. Client tenant/implementation hints cannot select
a different handler. Missing or rejected credentials, insufficient scopes,
explicit authorization refusal and malformed bodies execute no business handler.
A known foreign row stays absent; a valid unbound tenant has no fallback.

Discovery returns only authorized public operation fields, with private/no-store
cache policy and Authorization variance. The one-result limit accepts one visible
capability and rejects two explicitly with `EK_TCAP_LIMIT_EXCEEDED`, HTTP 503,
without a truncated list.
An unscoped or unbound tenant receives an empty list; query-string tenant selection
is refused. Both paths retain the same logical ID, immutable revision and activation
generation. Framework inspection uses the public administrative capability and
real authentication provenance; the native reference has no equivalent brand.

`STANDARD` and `DETAILED` enable actual SDK exports and private JSONL technical
usage. Five successful operation children must match their actual HTTP parents,
tenant and request IDs, without repeating HTTP byte counters. Reports and SDK
payloads exclude credentials, trust paths and private business input. Tenant and
registry identifiers remain permitted trace diagnostics, as specified by their
privacy policy. Fixture streams, temporary JSONL files, TLS files and listeners
are closed and removed after success or failure.

This is a functional corpus: `measured:false`, `releaseGate:false`. Native code
omits complete hostile registry/input validation, provenance brands, concurrency
admission, cancellation/deadlines and framework lifecycle policy. It therefore
establishes no policy-equivalent timing or overhead result. REST without routing,
approved upstreams, 100/10,000 bindings, large discovery, cold start, rolling
generations, complete resource accounting, variance analysis, five repeated
campaigns and the long soak remain separate acceptance work.
