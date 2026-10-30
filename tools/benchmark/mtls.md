<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native two-stage mTLS service identity verification

Build the workspace, including the private PKI conformance fixture, then run:

```sh
pnpm --filter @arkenivajs/benchmark-foundation mtls --verify /private/mtls-verification
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

Only `--verify` is supported until complete provider/server process resource
accounting is available. Reports retain `releaseGate: false`; full matched-load
campaigns, five repetitions and the one-hour soak remain separate work.
