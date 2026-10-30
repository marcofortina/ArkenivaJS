<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# HTTP security header comparison

After building the workspace, select a fresh absolute directory outside it:

```sh
pnpm --filter @arkenivajs/benchmark-foundation http-security --verify /private/header-verification
```

Four fresh sequential processes compare native Fastify/Helmet, the public API and
security-http plugins without telemetry, and actual standard/detailed SDK profiles.
Each binds an owned loopback listener atomically on port zero. Actual HTTP 200,
404 and 500 replies must retain the same explicit CSP, HSTS, nosniff and referrer
policy. The success response must preserve its bounded private body. SDK exports
and reports must exclude that body value. Responses are fully consumed.

The native baseline uses Helmet in the same response middleware phase. Additional
framework work includes routing/response validation, request context, lifecycle
and logging. The comparison includes those costs and does not attribute the whole
difference to Helmet or security middleware alone.

`--verify` records functional evidence without latency or resource samples.
`--smoke` exercises 20 warmup iterations and at least 100 completed sequential
success requests per profile. Measurements include the local client and server
in the same child process. Sampled RSS/heap can miss short peaks. Both modes retain
`releaseGate: false`; neither establishes a dedicated-runner performance budget,
five repeated trials or a one-hour soak.

CSRF is explicitly disabled for this public response workload. Test-only storage
and authorization dependencies throw on every operation; an ephemeral random HMAC
key serves only the adapter initialization and is erased after framework shutdown.
These dependencies cannot prove durable CSRF behavior or production compatibility.
CSRF rejection/verification latency with real sessions and shared storage, TLS,
concurrency and distributed policy are separate scenarios.
