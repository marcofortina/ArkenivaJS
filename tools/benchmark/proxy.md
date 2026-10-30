<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native fixed HTTPS proxy verification

Build the workspace, including the proxy conformance fixtures, then run:

```sh
pnpm --filter @arkenivajs/benchmark-foundation proxy --verify /private/proxy-verification
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

Only `--verify` is supported. Reports retain `releaseGate: false`; matched-load
performance budgets, five paired repetitions and the one-hour soak remain open.
