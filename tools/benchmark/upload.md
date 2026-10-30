<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Multipart streaming protocol comparison

Build the workspace and select a fresh absolute directory outside it:

```sh
pnpm --filter @arkenivajs/benchmark-foundation upload --verify /private/upload-verification
ARKENIVA_UPLOAD_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation upload --smoke /private/upload-smoke
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
An explicitly disposable environment can opt into `--smoke`: each profile keeps
the two functional transfers, then performs 20 warmup and 100 measured transfers
sequentially through the same listener. Each request contains the same UTF-8 field,
one 94,208-byte file and an empty file. A fixed pattern block of at most 8,192 bytes
generates the file without constructing a complete sampled file buffer. Headers,
the field and multipart boundaries are fragmented. All existing request, file,
field and part limits remain unchanged; `--full` remains unsupported.

The application-owned sink independently hashes the consumed stream, counts actual
file/field/part bytes and finishes both file streams before responding. Its
4,096-byte high-water mark and asynchronous `setImmediate` write completion are
deliberate cooperative application work, not a storage performance model. Every
callback checks the exact receipt and waits for source retirement, response
completion, request closure and physical connection closure. Completion reconciles
120 requests, 240 files and 360 parts against the independent handler counters.
The framework's actual upload statistics must have zero active/rejected requests,
120 successful requests and observed HTTP body bytes equal to emitted body bytes.
The native baseline has no equivalent HTTP body observation; that value is `null`.
These are logical HTTP body bytes, excluding transport/chunk framing overhead.

Per-transfer observations retain elapsed milliseconds, time to the first file
chunk consumed by the handler, time to the first response chunk, actual client
`write(false)`/`drain` waits, and observed application source/client/sink queue
maxima. Per-transfer file/body bytes per second use that same complete lifetime,
not a separate timer or a network bandwidth claim. The client uses a 4,096-byte high-water mark, the source 16,384 bytes and
the sink 4,096 bytes. A Readable may coalesce bounded producer blocks before a
client write; those actual chunks and observed source queue sizes are checked
against 24,576 bytes. Client queue observations include HTTP framing. The
application bridge into the sink also has a 16,384-byte high-water mark. These
observed maxima do not describe opaque parser/kernel buffers, exact total peak
memory or causal downstream storage pressure; those unknown buffer sizes stay
`null`. SHA256 checks, cooperative sink scheduling and physical cleanup are part
of each timed Tinybench callback. Raw latency contains exactly 100 actual
Tinybench samples in milliseconds; the 20 warmups are excluded.

All four smoke profiles use the Linux process-tree supervisor. Its CPU scope is
the whole bridge/worker/descendant lifecycle, separate from the worker's measured
window. Sampled summed RSS is distinct from maximum single-process RSS, may count
shared pages repeatedly and may miss short-lived peaks. Python observer and any
external server resources are excluded. Inaccessible or truncated observations,
unwaited children, SDK drops/export failures and private input leakage fail the
run. STANDARD and DETAILED explicitly force diagnostic `samplingRatio: 1`; they
do not establish a normal production sampling budget.

This small closed-loop transfer keeps `releaseGate: false` and does not prove
bounded heap for a 1 GiB upload, equivalent rejection policies, calibrated
framework overhead, dedicated-runner throughput budgets, five repeated campaigns
or a one-hour soak.
