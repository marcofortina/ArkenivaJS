# Data validation comparison

This workload compares public validation methods with the pinned `validator`,
`ipaddr.js`, `uuid` and Ajv libraries plus Node URL parsing. The same fixed inert
corpus covers normalized email, an HTTPS URL with one approved hostname, IPv4,
IPv6, UUID version policy, JSON Schema success and expected rejections.

Build the workspace, then verify the workload without reporting timings:

```sh
pnpm --filter @arkenivajs/benchmark-foundation validation --verify /private/new-validation-verification
```

The absolute output directory must be new and outside the checkout, with an
existing parent. Four sequential isolated processes exercise the bare baseline,
framework, standard telemetry and detailed telemetry profiles. Verification
reports `measured:false`; fixture values never enter reports or labels.

The baseline applies the same fixed email/IP/host/version/schema decisions on
this corpus. It does not reproduce the framework's complete hostile-object,
descriptor, size, lifecycle or safe-error boundary. Those additional checks are
part of the framework work being compared. A native baseline is not a substitute
for the framework's security tests or a general-purpose validation service.

`--smoke` instead collects a short exploratory microcomparison: 1,000 warmup
iterations, at least 10,000 samples per operation, nanosecond latency quantiles,
operations per second and process-aggregate CPU/memory/event-loop/GC observations.
Expected invalid inputs are verified outcomes, not hidden workload failures.
The actual telemetry SDK is installed in diagnostic profiles without inventing
per-call spans for these pure helpers. Sampling and timer overhead apply.

Both modes set `releaseGate:false`. Neither establishes production overhead,
request CPU/RSS attribution, a confidence interval, repeated release campaigns or
soak acceptance. Retain complete comparative measurements separately when those
campaigns are authorized.
