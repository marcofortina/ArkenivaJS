<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Multipart streaming protocol comparison

Build the workspace and select a fresh absolute directory outside it:

```sh
pnpm --filter @arkenivajs/benchmark-foundation upload --verify /private/upload-verification
```

Four fresh sequential processes exercise native Fastify/multipart, the public
upload/API plugins, and the actual standard/detailed SDK profiles. Each owns one
loopback listener bound atomically on port zero. Two fresh single-pass multipart
sources use chunked HTTP without Content-Length, bounded source chunks and actual
stream backpressure. The fragmented case splits UTF-8 metadata and boundaries.
Handlers digest consumed chunks rather than buffering a complete file. Exact
field/file order, field text, SHA256 digests, byte counts and an empty second file
must survive the network round trip. SDK exports and reports exclude private file
content and field values; instrumented profiles must export actual metrics.

Only synthetic nonsecret data enters this explicitly public test route. No
authentication, authorization, storage or durability is inferred from successful
parsing. The native baseline uses the same multipart parser and finite native
limits; framework wire-byte, metadata, admission and lifecycle policies add work.
Valid-corpus parity does not establish equivalence of all rejection policies.

`--verify` emits no latency or resource samples and retains `releaseGate: false`.
`--smoke` is rejected before creating reports: a streaming performance scenario
must first measure time to first byte, total duration, backpressure waits and peak
buffer bytes. This small functional transfer does not prove bounded heap for a
1 GiB upload, throughput budgets, dedicated-runner performance, five repeated
trials or a one-hour soak.
