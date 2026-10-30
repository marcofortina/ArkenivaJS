<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native two-stage mTLS service identity verification

Build the workspace, including the private PKI conformance fixture, then run:

```sh
pnpm --filter @arkenivajs/benchmark-foundation mtls --verify /private/mtls-verification
ARKENIVA_MTLS_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation mtls --smoke /private/mtls-smoke
```

Four isolated profiles compare actual Node TLS/HTTP2 with the public mTLS plugin
and actual standard/detailed SDK exports. A separately owned HTTP/2 server uses
different signed client/server certificates and requires mutual authentication.
The native handshake proves certificate key possession and negotiates TLS 1.3
and HTTP/2. The client then passes the actual authenticated socket's peer DER to
an independently configured PKI authority. The server independently verifies its
actual client peer before processing the application request.

The existing conformance PKI fixture performs real OpenSSL chain, purpose and
CRL checks using its private root catalogue. A bounded, bearer-authenticated
loopback bridge exposes only client peer verification. No certificate URL can
select an issuer or network destination. Parent counters independently confirm
four authorized requests and four successful peer-policy checks for each role.
The native valid-profile reference checks hostname, exact approved URI identity
and the actual leaf fingerprint returned by that same PKI authority.

Negative controls first prove healthy native/public exchanges, then verify that
an invalid bridge credential, unavailable revocation authority and an actually
revoked server certificate permit no further application requests. Production
rejects the explicitly test-only providers. Credentials, certificate metadata,
fingerprints, identities and endpoints remain absent from actual SDK exports
and reports; no system trust store is changed.

The comparison exercises client material preparation/conversion and peer policy,
not the complete server conversion or certificate rotation API. The native
reference omits framework full material validation, generation provenance,
atomic reload, admission and cancellation ownership. This private test PKI is
not a production secret/trust provider or a mesh identity boundary.

Optional smoke requires the explicit disposable marker before PKI allocation or
evidence creation. Each profile retains 100 actual Tinybench samples after 20
warmup callbacks, with concurrency one. Every callback creates a new HTTP/2
connection, asserts actual TLS1.3 negotiation and non-resumption on the socket,
awaits the real asynchronous peer/CRL policy, consumes one exact authorized
response, and waits for physical session closure. No Agent, supplied TLS session
or connection pool can substitute an existing authenticated connection.

These samples include profile material preparation, handshake, peer-policy I/O,
HTTP/2 exchange and cleanup; they do not isolate native TLS handshake latency.
The parent independently requires 484 distinct non-resumed sessions and exactly
484 requests and successful peer checks per role, including four untimed
verification exchanges. Each session accepts exactly one application stream.
Completion requires no remaining parent sessions or provider work. Worker
results are private and bounded at120, with an explicit128 retention cap; all
responses must retain the original successful peer-policy and exchange evidence.

Worker CPU/RSS excludes the parent HTTP/2 server, PKI provider and its OpenSSL
descendants. Those parent resource observations remain explicitly unknown;
there is no complete process-tree resource parity claim. The existing30-second
profile controller limit remains unchanged. Reports retain `releaseGate: false`;
calibrated budgets, full matched-load campaigns, five repetitions and the
one-hour soak remain separate work.
