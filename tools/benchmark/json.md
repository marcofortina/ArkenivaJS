<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native JSON workflow verification

Build the workspace and choose a fresh absolute external report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation json --verify /private/json-verification
```

Four isolated profiles compare native Node JSON/Ajv with the public JSON service
and actual standard/detailed SDK instrumentation. The schema compiler uses the
same pinned Draft 2020-12 backend and reviewed equality patch. Checks cover parse,
deterministic compact/pretty serialization, valid/invalid schema results and one
deployment-approved mapping using grammar version 1.0.0.

The corpus preserves leading-zero identifiers, nested Unicode text, array order
and empty arrays. It verifies explicit boolean conversion, concatenation,
coalescing, an omitted missing field and an existing null field. An invalid
identifier must expose the stable `/id` schema path. Every workflow leaves its
input unchanged. Public results also retain immutable descendants and safe
prototypes; malformed input, dangerous keys and unknown catalogs are rejected.
Reports and actual SDK exports must exclude payload values.

The native baseline validates through Ajv and applies one ordinary fixed
application projection for this exact corpus. It does not implement the general
versioned mapping interpreter. It omits framework hostile-object capture,
interpreter/resource limits, worker isolation, deadlines and lifecycle policy;
this comparison cannot establish arbitrary-mapping equivalence.

`--verify` keeps the functional verification without measurements. `--smoke`
performs 20 warmup and 100 measured calls for each of parse, stringify, validate
and transform, in each of the four profiles. All profiles use the same finite
corpus. Exactly 480 results per profile are retained under that fixed bound and
checked after timing against independently constructed expected values. Completion
rejects altered or missing results, excess callbacks and input mutation. Actual
Tinybench millisecond samples are retained, excluding warmup samples. Fixed-size
result capture is included in each operation's latency in both implementations.

Measured profiles use the [Linux supervisor](./supervised-resources.md). Original
worker measurement-window CPU/RSS/heap, event-loop and GC observations remain
separate from whole-lifecycle Node resources. Lifecycle CPU includes Node worker
threads, bridge/worker startup, verification, warmup, measurements, result checking,
export and physical cleanup. The Python observer, parent and collector are excluded.
Sampled summed process RSS can repeat shared pages and miss brief peaks; it is not
unique physical memory. Inaccessible or truncated observations fail the comparison.
Both modes retain `releaseGate: false`; calibrated dedicated-runner budgets, five
paired repetitions and one-hour soak acceptance remain separate work. `--full`
remains unsupported.
