<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# gRPC services and clients

`@arkenivajs/grpc` provides an explicit `grpcPlugin(GrpcPluginSettings)` factory
and `GRPC_CAPABILITY`. It uses the approved grpc-js/proto-loader backends and the
existing mTLS capability. Authenticated server bindings also require the core
authentication capability. No global credentials, ambient HTTP proxy, DNS service
configuration, implicit retries or insecure channels are enabled.

Each service profile names an immutable absolute `.proto` asset, permitted method
names and a finite message limit. The profile name selects the matching protobuf
service; a descriptor with exactly one service also supports a short profile
alias. Client profiles specify `endpoint` as `hostname:port`; set `tlsProfile`
when more than one TLS profile is configured. Listener profiles use their explicit
`listener.tlsProfile`. Missing, ambiguous or unknown profile references fail closed.

Static handler catalogs bind `descriptor` to a configured service profile name.
`GrpcPolicy.methodAllowlist` must stay within that profile. Unary handlers return
the response object. Server-streaming handlers return an `AsyncIterable` as their
promised result. Handlers receive only a verified tenant context and a live
signal. Authentication verifies the signed bearer assertion against configured
issuer, audience, signature and expiry; the trusted authority then authorizes the
exact RPC and owner. Tenant metadata headers never grant tenant identity.

## Transport and lifecycle

Native TLS verifies the configured hostname and CA chain. Its owned secure
connector completes asynchronous mTLS trust/revocation checks before exposing the
connection to gRPC. Every server RPC checks the actual TLS client certificate and
current trust policy before forwarding metadata or messages to handlers. A valid
TLS connection alone does not authorize tenant operations.

Factory calls allocate no sockets. Descriptor compilation and registration run
during initialization; listeners bind only during activation, after all dependent
initializers have registered their handlers. Registration through either the
capability or native server fails with `EK_LIFECYCLE_STATE` after activation.
The framework owns channels and listeners. Shutdown stops admission, signals
active work, cancels client calls and drains the server within the configured
timeout before forcing transport closure. Application handlers and external
providers must honor cancellation; their unresolved work retains its physical
reservation rather than permitting extra work beyond the limit.

`GrpcClient.native()` and `GrpcService.nativeServer()` return `unknown`. Trusted
applications may narrow them using grpc-js's own `Client`/`Server` types. Native
client/bidirectional streams retain bounded deadlines, admission and configured
TLS. Register native server stream handlers during dependency initialization;
their methods must already have an approved service policy. Common native server
interceptors still authenticate and authorize every call. Applications explicitly
instrument unsupported native workflows and honor native stream backpressure.

## Bounds and protobuf values

- At most 16 service/TLS profiles and 128 methods per profile; runtime admission
  and each service's concurrency limit are positive integers, capped at 1024.
- Timeouts are integer milliseconds from 1 through 60000. Omission uses the
  configured finite timeout. A remote deadline can shorten that bound. Zero,
  nonfinite or fractional values fail before wrapper I/O.
- Input/output defaults are 1 MiB, with an 8 MiB hard maximum and stricter profile
  and binding limits. HTTP/2 advertises bounded concurrent streams, 16 KiB header
  lists and a 64 MiB native session memory bound. Handshakes and idle sessions have
  finite timeouts. Native object streams retain their finite readable buffer and
  use writable backpressure; wrappers never add an unbounded queue.
- Offline asset graphs contain at most 32 files, 1 MiB per file and 8 MiB total.
  Files must be owned, regular, valid UTF-8 and not writable by other users.
  Relative imports stay under the entry directory; remote imports, escapes,
  symlinks, cycles and missing weak imports fail. Approved protobufjs bundled
  common types do not require filesystem or network resolution.
- Parser workers have finite startup deadlines and memory/stack bounds, and are
  terminated and awaited after compilation. Schemas have bounded depth/entries.
- Binary values remain copied buffers; 64-bit integers remain exact canonical
  decimal strings. Unsafe numeric integers, overflow, unknown fields, implicit
  scalar conversions, conflicting oneofs, accessors, proxies, cycles and excessive
  nesting are rejected. No field is silently dropped to make a message fit.

Errors use safe `EK_GRPC_AUTH`, `EK_GRPC_STATUS`, `EK_GRPC_DEADLINE`, configuration,
lifecycle, cancellation and closed-resource codes. Native payloads, assertions,
certificate keys and provider diagnostics are not error/log fields.

## Observations and execution

Optional logging/telemetry plugins receive fixed operation/side/outcome labels,
RPC counters, duration histograms, protobuf payload byte histograms, active work
and process RSS. Payload bytes measure native protobuf messages, excluding HTTP/2,
gRPC framing and TLS overhead; they are not claimed to measure wire traffic.
Events use fresh correlation identifiers. JWTs, tenants, subjects, endpoints,
request bodies and raw provider/native errors are not diagnostic attributes.
The existing telemetry adapter injects only W3C trace context into native client
metadata. Server RPC spans extract that carrier into an instance-local scope;
trace headers never supply authentication or tenant identity. Unary client spans
and native server spans retain the same parent trace across the actual transport.

Run the [standalone example](../examples/grpc/README.md) after building. It uses
real CA-signed mTLS, OpenSSL CRL verification, signed JWT assertions and protobuf
requests. Tests also exercise native bidirectional streaming, forged metadata,
cross-tenant denial, cancellation, retained reservations and revoked certificates.
Comparative performance measurements and release acceptance remain separate gates.
