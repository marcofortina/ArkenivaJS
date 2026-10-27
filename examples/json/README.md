<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# JSON Schema and deployment mapping example

This executable TypeScript application parses an inventory document, validates
it using actual Ajv Draft 2020-12, applies a deployment-approved mapping and
serializes the schema-validated result. It preserves `001` as a string and
Unicode text, with explicit boolean/numeric conversion and a null fallback.

```sh
pnpm install --frozen-lockfile
pnpm --filter '@arkenivajs/example-json...' build
pnpm --filter @arkenivajs/example-json start
pnpm --filter @arkenivajs/example-json test
pnpm test:packed:examples --example json
```

Use the exact tool versions declared in the root package. Expected CLI output
contains `valid: true`, `item: "001"`, `enabled: true` and positive `outputBytes`.
There are no external services or secret values; `.env.example` documents that
no environment configuration is required. Applications stop their native workers
in `finally`, including on validation failures.

`exampleSettings()` supplies two immutable schema IDs and a finite mapping
manifest. The provider is consulted only during construction; every request
selects from the captured approved catalog. Clients cannot supply expressions,
schemas or remote references. Unknown mapping IDs and invalid booleans fail
explicitly. An absent optional copy omits its property; null is preserved unless
coalesce explicitly selects a fallback.

Tests use real worker-backed parsing/mapping and real loopback OTLP collection.
Standard and detailed SDK checks require byte/duration/heap metrics, invalid
outcomes and mapping-version events while rejecting private payloads and unknown
caller IDs in all exported logs/metrics. Mapping IDs never become metric labels.
The packed verifier installs the actual private framework archives outside the
checkout, preserves their exact reviewed compatibility diffs and recompiles
this consumer strictly against public declarations before execution.

See the [adapter reference](../../packages/data-json/README.md) for limits,
schema support, worker retirement and synchronous-call behavior. Native parser,
schema and interpreter calls are bounded; this example makes no comparative
throughput or peak-memory claim.
