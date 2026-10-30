# Native HTTPS GraphQL verification and short smoke

```sh
pnpm --filter @arkenivajs/benchmark-foundation graphql --verify /absolute/private/new-directory
```

The directory must be fresh and outside the source tree. Run a current workspace
build first. The controller owns an actual synthetic signing authority and private
HTTPS certificate; all requests verify that certificate. No external issuer,
database, container or host trust change is required. Four independent processes
use the locked Fastify, Mercurius, GraphQL and JOSE versions.

The native reference and framework profiles perform twelve actual requests each:
anonymous, tampered and foreign-tenant credentials fail before mutations; an
alias/fragment/variable query returns its own row while denying the private getter;
a known foreign row remains absent. Read-only credentials cannot mutate. Retrying
one application idempotency key changes the counter once, and another verified
tenant has its own receipt and counter. Invalid syntax cannot change business
state. The controller independently observes four real JWKS fetches.

`FRAMEWORK` retains all GraphQL guards. `STANDARD` and `DETAILED` additionally
enable actual telemetry and JSONL technical metering. Each GraphQL usage child
must point to its actual HTTP parent and verified tenant, without HTTP byte
counters repeated on the child. SDK exports are checked for private fixture
inputs. Temporary JSONL files, TLS material, issuers and listeners are closed
and removed after every profile, including failures.

This is a functional verification corpus. Reports set `measured:false`,
`releaseGate:false` and provide no latency, CPU or throughput claims. The native
reference retains explicit signature/scope/field/row checks but does not implement
all framework provenance, complexity, admission, cancellation and output guards.
It therefore cannot establish a policy-equivalent overhead result. Business
counters and idempotency receipts remain bounded process memory. Shared storage,
SQL-loader and subscription comparisons, sustained concurrency, complete resource
accounting, repeated measurements and the long soak remain separate acceptance
work.

## Explicit disposable smoke

Run the optional short measurement only inside an owned disposable VM or CI runner:

```sh
ARKENIVA_GRAPHQL_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation graphql --smoke /absolute/private/new-smoke-directory
```

`--smoke` refuses an unmarked runner before starting its signing/TLS fixture or
creating evidence. `--full` is unsupported. Verification still runs first in
every profile, and all framework guards remain enabled. Each isolated worker then
executes three asynchronous Tinybench scenarios with twenty warmup callbacks and
one hundred measured callbacks each, sequentially with concurrency one:

- `simple-query` reads the authenticated tenant's existing counter.
- `own-row-query` uses a named variable query for its own customer's ID and label.
- `idempotent-mutation-retry` uses an explicitly named mutation and the already
  verified `same-owned-action` receipt. It measures retry lookup, not a fresh
  write or durable/shared storage. The receipt map remains capped at four entries;
  the two verification mutations are the only physical effects.

The normal smoke therefore has 1,200 measured calls, 240 warmup calls and 48
verification requests across four profiles. Completion checks use actual server
receipts and resolver callbacks to account for every request. For instrumented
profiles, actual 200 responses determine expected GraphQL children, and admitted
authenticated responses determine HTTP parents. Counts include verification,
warmup and measurement; they are not inferred from raw sample counts alone.
Every child must retain its real HTTP parent and verified tenant, without
duplicated byte counters. Final active meter sessions must be zero.

Each measured record retains its real latency samples as
`rawLatency: {unit: 'milliseconds', values: [...]}`, checked against the actual
callback and sample counts. Percentiles and throughput include complete HTTPS
response consumption, result assertions and callback bookkeeping. CPU, sampled
memory, event-loop and GC values describe the whole worker during sampling,
including asynchronous exports; final flush/readback is outside that interval.
Short samples can miss transient resource peaks.

The shared diagnostic helper intentionally uses trace sampling **1** for both
STANDARD and DETAILED. STANDARD here is not a normal production sampling/budget
claim. Smoke reports use `measured:true`, one repetition and `releaseGate:false`.
They provide no confidence interval or policy-equivalent overhead result: the
native reference still omits complete framework admission and security policy.
SQL loaders, subscriptions, fresh writes, sustained/open-loop concurrency,
complete resource accounting, five full campaigns and the hour-long soak remain
separate acceptance work.
