<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native SAML signed request and response verification

Build the workspace, including the SAML signing conformance fixture, then run:

```sh
pnpm --filter @arkenivajs/benchmark-foundation saml --verify /private/saml-verification
ARKENIVA_SAML_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation saml --smoke /private/saml-smoke
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

`--verify` retains the original four-profile functional corpus without measured
samples. An explicitly disposable environment can opt into `--smoke`: every
profile additionally creates 20 warmup and 100 measured signed Redirect transfers,
sequentially. The same pinned SDK, signing certificate/key and trusted entity,
ACS and IdP endpoint corpus are used in the native and public adapters. No measured
transfer is sent to the IdP; the original twelve functional bridge requests and
responses remain unchanged. This measures creation and independent validation of
a browser transfer, not ACS verification or a complete browser transaction.

Every callback verifies the RSA-SHA256 signature with Node crypto over the exact
original encoded query bytes. Bounded DEFLATE/XML decoding verifies the request
ID, trusted destination, issuer, ACS and relay correlation. Generated IDs must be
unique across all 120 creations. The framework retains its actual per-operation
deadline, native worker-thread isolation and finite resource/admission bounds.
The native SDK owns its ordinary correlation cache; the public adapter retains
the existing explicitly test-only state provider. These stores are not a durable
cross-pod performance reference. Up to 120 short correlation identifiers are
retained privately with a 128-entry admission cap, then cleared; reports contain
only counts and byte totals, with no URL, protocol document or identifier.

Actual SDK exports and reports exclude keys, assertions, identities, session
indices, connection material and a fresh private nonce in the allowed return-path
correlation input. The collector additionally rejects raw protocol field/XML
markers and the observed leading-underscore SDK-created ID OTLP string-value form.
This is a format/marker check, not an exact-value comparison against every random
identifier. Negative controls send representative identifiers and protocol material
through actual SDK spans to the same HTTP collector guard; a positive SDK control
must be accepted. No protocol ID generator or cryptographic algorithm is replaced.

Raw latency retains exactly 100 actual Tinybench samples in milliseconds, excluding
the 20 warmups. Independent signature/XML verification and correlation bookkeeping
are included in each timed callback. All four smoke profiles use Linux process-tree
supervision. Whole-lifecycle CPU and RSS include the Node bridge, worker and native
worker threads through their owning process, including startup, functional checks,
export and cleanup. These observations stay separate from the worker's measured
window. Parent PKI generation, collector and HTTPS IdP resources are excluded.
Sampled summed RSS is not exact peak/PSS: shared pages may repeat and short-lived
peaks may be missed. Inaccessible/truncated observations, unwaited children, SDK
drops/export failures or privacy leaks fail the run. STANDARD and DETAILED force
diagnostic `samplingRatio: 1`, without a production sampling-budget claim.

Reports retain `releaseGate: false`. Equivalent native/wrapper security-policy
cost, durable replay, POST/logout timing, ACS verification latency, accreditation,
dedicated-runner budgets, five repetitions and one-hour soak remain separate work.
