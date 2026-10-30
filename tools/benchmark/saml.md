<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native SAML signed request and response verification

Build the workspace, including the SAML signing conformance fixture, then run:

```sh
pnpm --filter @arkenivajs/benchmark-foundation saml --verify /private/saml-verification
```

Four isolated profiles compare pinned `@node-saml/node-saml@5.1.0` with the
public SAML plugin and actual standard/detailed SDK exports. Both produce signed
HTTP-Redirect authentication requests and validate signed HTTP-POST responses.
The parent uses the existing conformance signing fixture and separately owns
the IdP key and a verified HTTPS signing endpoint. Before issuing a response it
verifies each SP RSA-SHA256 signature and the actual request ID, ACS, issuer and
relay-state correlation. Native XML/signing libraries perform cryptography.

Every profile verifies signed SP metadata, consumes one correlated signed
identity and rejects replay. Two more signed requests exercise a subsequently
tampered response and a correctly signed response for the wrong audience.
Parent counters confirm twelve independently verified SP requests and twelve
signed responses. An IdP tenant attribute remains an untrusted attribute; it
does not become an authenticated tenant or MFA assurance.

This is a fixed generic federation corpus with ephemeral unit-only state:
the bare SDK correlation cache and the explicitly test-only framework state
fixture. It does not establish durable cross-pod replay protection. The HTTPS
IdP fixture bridge is bearer-authenticated test infrastructure, not a browser
cookie/ACS transaction or a production federation endpoint. POST request binding,
logout, federation membership and SPID/CIE accreditation remain separate work.
The native reference omits complete wrapper XML admission, additional assertion
policy, durable state, cancellation isolation and identity provenance.

Actual SDK exports and reports exclude keys, assertions, identities, session
indices and connection material. Only `--verify` is supported until complete
native worker, PKI and server resource accounting is available. Reports retain
`releaseGate: false`; full campaign acceptance, five repetitions and one-hour
soak are not claimed.
