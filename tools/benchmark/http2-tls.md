<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Secure HTTP/2 and HTTP/1.1 fallback JSON128B smoke

These two explicit R6 selections reuse the [direct HTTPS fixture and safety
policy](http-tls.md), existing Fastify/framework server worker, exact response,
four profiles and Go k6 load generator. They require the same disposable TLS
PostgreSQL fixture, OTel collector and pinned k6 executable:

```sh
ARKENIVA_HTTP_TLS_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation http /private/http2-smoke --smoke-http2
ARKENIVA_HTTP_TLS_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation http /private/http1-fallback-smoke --smoke-http1-fallback
```

Both selections create the same secure-listener configuration: native Fastify
HTTP/2 and framework `http2:true`, with **allowHTTP1 enabled**, minimum TLS 1.3
and one owned EC P-256 localhost certificate shared across the four profiles.
The fallback selection changes the load client's requested protocol, while the
server remains HTTP/2 capable. Each profile has one second of warmup and three
measured seconds of public JSON128B load at 50 offered requests/second. Existing
plain HTTP and HTTPS/H1 selections, defaults and report fields are preserved.

Every listener first receives independent native Node controls for **both**
protocols against that same listener instance and certificate. The HTTP/2
control requires actual ALPN `h2`, authorized nonresumed TLS 1.3, the exact
certificate/key metadata and one exact 128-byte response. The fallback control
requires actual `http/1.1` and the same bytes/trust policy. Both protocols reject
actual untrusted-CA and wrong-SAN connections. Node's existing HTTP/2 engine owns
framing, stream cancellation, GOAWAY and session retirement; no custom protocol
implementation or framework API is introduced. Public native ownership and
cancellation APIs are described in the
[pinned Node HTTP/2 documentation](https://github.com/nodejs/node/blob/v24.22.1/doc/api/http2.md).

The native HTTP/2 control caps its response accumulator at 128 bytes, disables
push and configures bounded header/session credits. Native session memory
credits are not an exact process-memory ceiling. An active native AbortSignal
cancels the stream; abort reasons and raw native diagnostics do not leave the
control. A result is returned only after the actual stream, session and TLS
socket close events. Native monotonic connection/handshake/payload observations
remain one control observation, separate from the Go workload's distributions.
Handshake metadata is captured at secureConnect inside the payload window;
public-key inspection occurs after the response-end timestamp.

Go's HTTP/2 selection clears inherited protocol-debug overrides and uses its
normal native HTTP/2 negotiation. The fallback process instead uses the pinned
k6 runner's `GODEBUG=http2client=0` support. Every response must report the
selected actual protocol (`HTTP/2.0` or `HTTP/1.1`), TLS 1.3, an actual supported
cipher and the exact body. Both selections retain the mandatory real Go trusted,
CA1310 and SAN1311 controls and the same process-local trust/proxy isolation.
Only expected-negative processes suppress native logs **before emission**;
their untouched raw metric streams, exact code/count checks and exit status
remain retained. Framework request/authentication audit logs remain enabled.

Reports retain actual native ALPN/handshake/resumption/error counters, actual
HTTP/2 versus HTTP/1 request counts, HTTP/2 session open/close/error counts and an
active-session gauge. Go response counters and cipher observations must agree
with their native counterparts using the appropriate request/handshake
denominators. Fallback may negotiate `http/1.1` or no ALPN; it must return actual
HTTP/1.1 and must not open an HTTP/2 session. HTTP/2 must negotiate `h2` and open
the corresponding native sessions. Warmup sessions retire before reset; measured
sessions retire before the server CPU/resource snapshot. The observer awaits
native closure rather than destroying application-owned sessions.

The server is warmed, while each load phase starts a new Go process and empty
connection pools. Server resources include the existing idle security/database
fixture machinery and measured load startup/shutdown/session retirement. Go,
database-server and collector CPU/RSS remain outside those process observations.
Go request duration excludes TCP/TLS setup; handshake trends include zero
observations from reused connections and are not handshake counts. One bounded
smoke does not establish calibrated overhead, production budgets, isolated cold
server performance, handshake capacity, five paired repetitions, a one-hour
soak or release acceptance. `releaseGate` remains `false`.

With the required fixture variables set, explicit permanent integration is:

```sh
ARKENIVA_HTTP_TLS_BENCHMARK_DISPOSABLE=1 node --test tools/benchmark/test/http2-tls.integration.test.mjs
```

Keep the existing plain `http.integration.test.mjs` and HTTPS/H1
`http-tls.integration.test.mjs` regressions in the same acceptance campaign.
Native host unit controls prove protocol/trust/body/cancellation and physical
retirement behavior; they make no host performance claim.
