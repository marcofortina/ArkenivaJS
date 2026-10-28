<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# gRPC communication example

Run `pnpm --filter @arkenivajs/example-grpc start` after building the workspace.
The disposable fixture creates local CA-signed server/client certificates, an
actual CRL verifier, a local JWKS issuer and signed audience-bound assertions.
OpenSSL must be available. Its test-only providers cannot be used in production.
No external broker, database, container engine or production secret is needed.

`echo()` uses only the public gRPC capability. It demonstrates unary and ordered
server-streaming calls, byte-preserving protobuf codecs and exact 64-bit integer
text. The native escape hatches return actual grpc-js client/server instances.
Channels remain owned by the application; stop the application to close them.

For production, supply approved static `.proto` assets, HTTPS-authenticated JWKS,
an application-owned authorization policy and the existing mTLS plugin backed by
secure credential/trust providers. Use explicit client `tlsProfile` selection
when configuring multiple TLS profiles. Never trust a tenant metadata header.
See the [adapter guide](../../docs/grpc.md) for limits and streaming ownership.
