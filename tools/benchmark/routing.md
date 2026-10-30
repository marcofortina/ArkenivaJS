# Native HTTPS tenant routing verification and short measurements

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
usage. Successful operation children must match their actual HTTP parents,
tenant and request IDs, without repeating HTTP byte counters. Reports and SDK
payloads exclude credentials, trust paths and private business input. Tenant and
registry identifiers remain permitted trace diagnostics, as specified by their
privacy policy. Fixture streams, temporary JSONL files, TLS files and listeners
are closed and removed after success or failure.

`--verify` is a functional corpus: `measured:false`, `releaseGate:false`. Native code
omits complete hostile registry/input validation, provenance brands, concurrency
admission, cancellation/deadlines and framework lifecycle policy. It therefore
establishes no policy-equivalent timing or overhead result. REST without routing,
approved upstreams, 100/10,000 bindings, large discovery, cold start, rolling
generations, complete resource accounting, variance analysis, five repeated
campaigns and the long soak remain separate acceptance work.

## Short disposable-runner measurements

Run measured traffic only on an owned disposable VM or CI runner:

```sh
ARKENIVA_ROUTING_BENCHMARK_DISPOSABLE=1 node tools/benchmark/routing.mjs --smoke /absolute/private/new-directory
```

The same nineteen-request verification runs before sampling in each of the four
isolated profiles. Tinybench then executes three sequential closed-loop scenarios:
local dispatch, one-result capability discovery and an authorized status operation.
Each scenario warms up for twenty callbacks and retains one hundred measured
callbacks. Every callback opens a new verified HTTPS connection and checks the
actual response; bearer verification, JSON validation, TLS handshakes, parsing
and assertions contribute to its observed latency. Client and server share the
worker process. Whole-worker CPU, sampled RSS/heap, event-loop and GC observations
include warmup, the native client, server, sampling and asynchronous SDK work.
Trace sampling is explicitly one in both instrumented profiles.

The controller reports `measured:true` and `releaseGate:false`. Each benchmark
record includes Tinybench's actual measured `rawLatency.values` with
`rawLatency.unit:'milliseconds'`; its length equals `sampleCount` and excludes
warmup. Samples are copied without a second timer or truncation, with a finite
10,000-value ceiling. The latency quantiles use the same Tinybench samples.

Actual successful callback counts must match the benchmark sample and warmup
counts and the independent native handler counters. JSONL child counts derive
from completed dispatch/status work, including warmup; every child must retain
its real parent. Discovery timing does not invent a JSONL operation or parent:
the current routing usage path covers dispatched operation routes. Meter and SDK
drop/export-failure checks must stay zero, exported rows must match acknowledged
events, and every retained operation identifier must be unique.

One short serial run provides no confidence interval, equivalent-policy overhead,
open-loop scheduling, concurrent tenant fairness, scaling, calibrated CI budget
or release approval. The controller refuses `--full`; five repeated complete
campaigns and the one-hour soak remain separate work.
