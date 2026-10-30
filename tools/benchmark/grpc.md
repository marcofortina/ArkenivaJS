<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native mutual-TLS gRPC interoperability

Build the complete workspace, including compiled mTLS conformance fixtures, make
OpenSSL available and choose a fresh absolute external report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation grpc --verify /private/grpc-verification
```

Four isolated client profiles compare native grpc-js/proto-loader with the public
gRPC service and actual standard/detailed SDK instrumentation. A separate parent
process owns a real native gRPC server and the existing OpenSSL PKI/CRL fixture.
The approved test descriptor is copied into a private directory with mode 0600;
the source file's permissions and content remain untouched.

Every profile makes one unary call and one three-message server stream. Actual
protobuf results preserve signed int64 text, binary bytes and stream order.
The independent server must observe four unary calls, four streams and twelve
streamed messages. Client identity is checked against the actual native class.
Native TLS uses trust roots and client certificates. Framework channels also
complete actual OpenSSL chain/purpose/CRL checks through a bearer-authenticated,
bounded, private loopback test provider bridge. Invalid bearer requests cannot
invoke the trust provider. No application or tenant authority is granted.

Credentials originate from the ephemeral external test provider and cross only
owned private IPC. Providers are explicitly test-only; no production credential
provider is introduced. Reports and SDK exports must exclude key material,
certificate bodies, payloads, endpoints and provider tokens. Tests follow healthy
controls with foreign trust roots and unavailable revocation, proving that
rejected channels never reach the application handler.

The native baseline retains upstream protobuf and stream behavior but omits the
framework asynchronous CRL/identity stage, immutable descriptor capture, admission,
cancellation and lifecycle policy. This valid corpus does not establish bidi
streaming, distributed identity or full authorization equivalence. Client channels
close before worker acknowledgment; server/provider work settles before PKI files
and the descriptor snapshot are removed.

`--verify` remains nonmeasured, with null resource observations, no latency
samples and `releaseGate: false`.

## Short supervised unary comparison

Run measured protocol traffic only inside the owned disposable QEMU runner:

```sh
ARKENIVA_GRPC_BENCHMARK_DISPOSABLE=1 \
  pnpm --filter @arkenivajs/benchmark-foundation grpc --smoke /private/grpc-smoke
```

The explicit marker is required before PKI, provider, server or evidence
creation. Unsupported full campaigns are rejected. All four profiles opt into
`superviseProcessTree:true`, with no fallback to incomplete client resources.
Trust roots, the same leaf certificates/private keys and unchanged TLS profile
cross only owned private IPC. Both paths use explicit TLS material rather than
`trustAnchorFile`, ambient trust variables or insecure overrides. Framework
CRL/identity policy and the authenticated private provider bridge remain intact.

One sequential `mutual-tls-unary-bounce` scenario executes 20 warmup callbacks
and 100 actual retained Tinybench latency samples per profile. The existing
Echo.Bounce method, descriptor and protobuf fields are unchanged. Each callback
uses the established client/channel, preserves the exact maximum signed int64
string and four binary bytes, and waits for the actual unary echo. The existing
one-unary/one-three-message-stream verification corpus remains outside the
samples. Initial channel credentials/revocation admission occurs during that
verification, not as a fabricated per-RPC provider operation in the samples.
At most one callback is active, and native retries remain disabled.

A fresh private UUID suffix in the existing value string provides fixture
correlation only. It changes no schema, protocol or public API and grants no
authentication, tenant authority, idempotency or exactly-once property. The
independent server validates the full decoded input, the exact int64/binary
values and a native protobuf response serialize/deserialize roundtrip before
echoing it. Duplicate sample UUIDs fail. Workers check the exact actual echo and
retain only an aggregate SHA256 integrity digest over ordered private receipts
and fixed protobuf scalar/binary values. The parent compares that digest with
its independent receipt sequence, partitioned by actual profile counts. Raw
values, UUIDs, descriptor paths, endpoints, provider data and credentials never
enter reports or SDK exports; new fixture correlations are added to the parent's
dynamic privacy checks before export/report inspection. The digest is a private
benchmark proof, never a telemetry attribute or durable delivery receipt.

Worker receipt storage is capped at 128 entries and parent storage at 512;
protobuf messages remain bounded to 4096 bytes. The trust bridge admits at most
four concurrent jobs/connections and 8192 bytes per body. It keeps actual provider
work tracked through completion. Client callbacks must match actual retained
samples plus warmup, with zero active callbacks or retained receipt IDs at
completion. Client channels close before worker acknowledgment. The parent waits
for provider work and native server shutdown before removing the exact private
PKI/descriptor directories. A normal smoke verifies 484 unary echoes (400
measured, 80 warmup and four verification calls), four streams and twelve ordered
stream messages. No stream throughput is measured.

`resource` keeps the original measured-window worker CPU/RSS, heap, GC and
event-loop fields. Separate `processTreeResource` has
`scope: whole-supervised-lifecycle`: CPU includes the Node bridge, comparison
worker, descriptor worker threads and any waited descendants across startup,
verification, warmup, sampling, export, channel cleanup and exit. This lifecycle
CPU must not be treated as measured-window CPU/request cost. The independent
parent gRPC server, OpenSSL PKI/CRL verifier, trust provider, collector and Python
observer are excluded. Their awaited effects can influence wall-clock admission
or RPC latency, but their CPU/RAM is not attributed to the client process tree.

Every profile requires full accessible descendant/RSS observations, untruncated
discovery, positive bounded sampling rounds, all children waited and zero
remaining owned processes. Vanished short-lived reads and actual sampling gaps
remain explicit. Summed RSS is sampled/non-atomic, may miss brief peaks and
counts shared pages per process; it is not PSS or unique physical RAM. Largest
single-process RSS stays distinct. Existing client old-space, descriptor-worker,
message, admission and deadline limits remain in force. STANDARD and DETAILED
both explicitly use diagnostic trace sampling ratio 1, so STANDARD here does not
represent normal production sampling.

The native baseline still omits complete framework CRL/identity, descriptor,
admission, cancellation and lifecycle policies. This small valid corpus cannot
establish policy-equivalent overhead, full client/server cost, bidi or distributed
identity behavior, queue saturation, stable throughput, calibrated release
budgets or confidence intervals. Normative long warmup/steady trials, five
paired repetitions and one-hour soak remain separate and deferred. Dedicated
measured integration requires the explicit marker; normal CPU/unit checks make
no performance measurement.
