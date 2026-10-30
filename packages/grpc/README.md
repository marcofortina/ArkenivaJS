<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Managed gRPC communication

Explicitly register `grpcPlugin(settings)` alongside the existing mTLS and,
for authenticated listeners, security plugins. Resolve `GRPC_CAPABILITY` as
`GrpcService` after startup. The adapter uses grpc-js 1.14.6 and proto-loader 0.8.1.
Trusted static descriptors are compiled offline by protobufjs 7.6.6 in an owned
worker before listeners activate. No alternate JSON codec is used.

Unary and server-streaming wrappers retain native TLS, cancellation, deadlines,
message limits and bounded admission. Native client/server escape hatches return
actual grpc-js instances, with owned credentials and common server authorization.
Client and bidirectional streaming use those native interfaces deliberately.

The configured authorization method is captured once with its original receiver.
Custom binding metadata cannot substitute another authority. Getter-based or
proxy authority metadata and proxy callbacks are rejected before resources open.

See the [guide](../../docs/grpc.md) and [executable example](../../examples/grpc/README.md).
