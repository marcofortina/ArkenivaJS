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

Only `--verify` is supported. Sampling is rejected before workload allocation
until complete worker resource accounting is available. Reports retain
`releaseGate: false`; dedicated-runner budgets, five paired repetitions and
one-hour soak acceptance remain separate work.
