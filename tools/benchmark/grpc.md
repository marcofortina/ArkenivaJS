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

Only `--verify` is supported. Sampling is rejected before fixture allocation
until complete independent client/server resource accounting is available.
Reports retain `releaseGate: false`; dedicated-runner budgets, five paired
repetitions and one-hour soak acceptance remain separate work.
