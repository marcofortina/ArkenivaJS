<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Direct HTTPS HTTP/1.1 JSON128B smoke

This explicit, bounded R6 selection reuses the existing HTTP comparison worker,
Go k6 load generator, exact JSON response, four profiles, resource observations
and log audit. Build the workspace and provide the same disposable verified-TLS
PostgreSQL fixture and OTel collector as the plain HTTP comparison. Also set
`ARKENIVA_BENCHMARK_K6` to the pinned k6 executable and explicitly mark the HTTPS
measurement as disposable:

```sh
ARKENIVA_HTTP_TLS_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation http /private/https-smoke --smoke-https
```

Existing plain HTTP campaign, pilot, smoke and soak defaults and report fields
remain unchanged. This new selection supports only one smoke: each profile has
one second of warmup and three measured seconds, offering 50 JSON requests per
second with at most 25 virtual users. Actual completed counts are reconciled
rather than inferred from the offered rate. Authentication and database routes
receive no measured requests. Server process CPU/RSS include the existing idle
security/database fixture machinery; they are not attributed to a tenant or to
an empty HTTP-only process. Anonymous requests must not produce tenant meters.

Native Fastify HTTPS and framework direct HTTPS share one temporary EC P-256
certificate, its exact localhost identity and minimum TLS 1.3 policy. The private
key is owner-readable in a private directory outside Git, then removed after all
workers close. Native Node clients and Go load clients resolve only the owned
localhost listener. No machine trust store changes, skipped verification, proxy
trust or new TLS implementation are involved.

Before each profile's warmup, an independent native Node HTTPS control verifies
the exact certificate, HTTP/1.1 ALPN, authorized nonresumed TLS 1.3, actual cipher,
P-256 certificate key and exact 128-byte body. Separate wrong-SAN and untrusted-CA
controls must fail before application HTTP work. Node control timing starts
before native request construction, after reading the trust file. TCP connect,
secureConnect, first application byte and stream-end timestamps distinguish
connection, handshake and payload windows. Native handshake metadata is captured
at secureConnect, so that bounded observation work is inside the payload window;
certificate public-key inspection happens after the end timestamp. The positive result is returned only after the
physical client socket closes. One positive control is not a handshake latency
distribution or handshake capacity measurement.

Three independent one-iteration Go controls then require unknown-CA error 1310,
wrong-hostname error 1311, and a successful trusted exact response. These are the
[pinned k6 error classifications](https://github.com/grafana/k6/blob/v2.3.0/lib/netext/httpext/error_codes.go).
Go receives an owned empty options file, explicit verification, process-local
`SSL_CERT_FILE` and an empty `SSL_CERT_DIR`, with inherited k6/proxy overrides
removed. Those trust variables affect only the owned client process; see
[Go's trust pool documentation](https://pkg.go.dev/crypto/x509#SystemCertPool).
Only the two expected-negative Go processes select the pinned
[`--log-output=none` mode](https://github.com/grafana/k6/blob/v2.3.0/internal/cmd/root.go)
before startup, preventing native warning messages from emitting endpoints or
certificate diagnostics. Exact error-code checks, exit status, summaries and
untouched raw metric streams remain mandatory and retained. Framework
authentication/request audit logging remains enabled.
The pinned k6 runner explicitly supports
[`GODEBUG=http2client=0`](https://github.com/grafana/k6/blob/v2.3.0/internal/js/runner.go)
to select HTTP/1.1. Every actual load response must independently report
HTTP/1.1, TLS 1.3, a known TLS 1.3 cipher and the exact expected body.

Native server counters independently record completed/resumed TLS handshakes,
handshake failures, actual ALPN/version/cipher and HTTP versions. Measured
failure counters count emitted native tlsClientError events, which need not
correspond one-for-one with the client-side certificate rejections. Measured
request counts must agree with the Go response counters and the acknowledged
application log window. Controls and warmup are excluded from these counters.
Node and Go observations remain separate: their TLS engines may select different
ciphers. Reports retain only bounded protocol/cipher/key metadata, counts and
timings, without certificates, private keys or fixture paths.

The server remains warm between the two load phases, but each phase starts a
fresh Go process and empty connection pools. Request duration excludes TCP/TLS
setup; [k6 documents those timing windows separately](https://grafana.com/docs/k6/latest/javascript-api/k6-http/response/).
The handshake trend includes zero-valued observations for reused connections;
positive-duration observations are not a handshake count. Actual server
handshake counters remain separate. Resource observations cover the server
process, not Go load CPU/RSS, the collector or database server. No HTTP/2/fallback,
sustained HTTPS pilot, calibrated overhead, repeated release acceptance or
one-hour soak is claimed; `releaseGate` remains `false`.

With those fixture variables set, the permanent integration test is explicit:

```sh
ARKENIVA_HTTP_TLS_BENCHMARK_DISPOSABLE=1 node --test tools/benchmark/test/http-tls.integration.test.mjs
```

Run the existing `http.integration.test.mjs` alongside it to check plain identity,
tenant, logging and live SQL behavior. Unit tests exercise native CA/SAN checks,
body corruption/oversize rejection, subsequent healthy service, private material
retirement and inherited bypass/proxy isolation without external services.
