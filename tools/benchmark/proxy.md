<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native fixed HTTPS proxy verification

Build the workspace, including the proxy conformance fixtures, then run:

```sh
pnpm --filter @arkenivajs/benchmark-foundation proxy --verify /private/proxy-verification
ARKENIVA_PROXY_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation proxy --smoke /private/proxy-smoke
```

Four isolated profiles compare the actual pinned `@fastify/http-proxy@11.6.5`
backend with the public framework proxy and actual standard/detailed SDK exports.
Every profile sends two real requests through its loopback listener to an
independently owned HTTPS upstream. A fragmented 128 KiB binary POST is echoed;
a GET streams the same exact response bytes. Both preserve encoded query values,
duplicate query keys and the fixed rewritten path. A query value resembling a
destination never changes the actual fixed upstream.

The parent observes all eight upstream calls and independently checks request
digests, byte counts, method, query and absence of spoofed identity headers.
The native reference configures the same fixed route, verified private TLS trust,
pool bounds, no retry and a small request-header allowlist. No host trust store
is changed. Separate healthy controls precede native/public rejection of a live
wrong-hostname certificate, with zero upstream HTTP requests for that peer.
The bare backend returns its native 500 on that TLS failure; the framework
translates it to the specified sanitized 502. The test preserves this distinction.
Actual SDK exports exclude payload, credentials, identity headers and destinations.

The route is explicitly public and synthetic. This does not compare verified
user authentication, service credential delegation or authorization. The native
reference omits the framework's complete SSRF/connect-time DNS policy, hostile
path/header checks, body admission and shutdown policy; it is not a replacement
gateway. The independent test upstream buffers only a bounded fixture body for
digest verification, while both proxy paths forward streams through the native
backend. Full streaming saturation, cancellation, redirects and cross-process
resource accounting remain separate conformance/measurement work.

Optional smoke requires the explicit disposable marker before PKI allocation or
evidence creation. Each profile collects 100 actual Tinybench GET samples after
20 warmup callbacks, with concurrency one. Every callback consumes the complete
131,072-byte response, computes its SHA256 receipt, and retires its own native
HTTP client socket. The worker retains 120 compact status, byte-count, media-type
and digest receipts with an explicit cap of 128, rather than retaining a buffer
for every response. One bounded response buffer exists while consuming each
fixed synthetic request; this is not arbitrary-response buffering or large-file
pressure acceptance.

Parent observation is independently bounded at 512 receipts. It verifies exactly
488 upstream requests: four original POSTs and 484 GETs including the original
four verification GETs. Every completed response contains 131,072 payload bytes,
for 63,963,136 response bytes in total; the four POST bodies total 524,288 request
bytes. Method, query, request digest, response completion and stripped spoofed
headers remain mandatory. No observer handler remains pending at completion.
These are actual payload counters, not TLS wire-byte or monetary attribution.

Timing includes the native HTTP observer, complete response consumption, digest
and physical client retirement. Worker CPU/RSS includes both that observer and
the local proxy; parent HTTPS-origin resources remain explicitly unknown and
excluded. Existing verified upstream pooling remains unchanged, so these samples
do not claim fresh TLS handshakes. Original wrong-hostname rejection and native
500/public 502 distinctions remain verified. Reports retain `releaseGate: false`;
full SSRF/authorization-policy parity, resource parity, calibrated matched-load
budgets, five paired repetitions and the one-hour soak remain open.
