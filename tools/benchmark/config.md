# Configuration service comparison

Build the workspace and select a fresh absolute output directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation config --verify /private/config-verification
```

Four sequential isolated Node profiles exercise flat native YAML/Ajv values,
the public configuration plugin and actual standard/detailed SDK modes. The
fixed corpus has no secrets. Defaults, YAML, explicit environment data and
runtime values verify their precedence without changing `process.env`.
Preflight also checks nullable/missing keys, immutable earlier snapshots,
validated reload and unchanged state after a rejected reload.

The sampled service operations are `get`, `require`, `has`, `snapshot` and
`reload`. Configuration construction, YAML parsing, schema compilation and
filesystem work occur before sampling. A uniform asynchronous wrapper is used
for every operation in every mode because reload is asynchronous. Diagnostic
callbacks discard metadata in this scenario; no audit-delivery claim is made.
No artificial per-read spans or counters are added.

`--verify` records functional evidence with `measured: false`, no timing samples
and null resource results. `--smoke` only tests the optional sampling path with
100 warmup iterations and at least 1,000 completed samples per operation/profile.
Every report retains `releaseGate: false`; no acceptance or repeated campaign
is inferred. The fixed data marker must not reach telemetry or reports.

The baseline uses YAML 2.9.1, Ajv 8.20.0 and flat frozen values for this corpus.
It does not implement production secret handling, environment grammar, protected
paths, preflight coordination, audit policy or general nested reload semantics.
Those framework guarantees remain additional work and retain their runtime tests.
No security-policy equivalence, loading benchmark, release budget, five-repeat
campaign or one-hour soak evidence is claimed.
