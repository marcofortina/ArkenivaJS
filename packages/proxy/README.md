<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Fixed-upstream HTTP reverse proxy

Optional `@arkenivajs/proxy` uses the official `@fastify/http-proxy` backend on
the existing Fastify HTTP/HTTPS listener. Routes are registered before listener
activation. `PROXY_CAPABILITY` resolves a monitoring-only `ProxyService` with
`stats()` and `health()`; it cannot add routes or choose runtime destinations.

```typescript
import { createApplication } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { proxyPlugin } from '@arkenivajs/proxy';
import type { ProxyPluginSettings } from '@arkenivajs/proxy';

export async function startGateway(settings: ProxyPluginSettings) {
  const app = await createApplication({
    service: { name: 'gateway', version: '1.0.0', environment: 'production' },
    http: { protocol: 'http', host: '127.0.0.1', port: 8080 },
    plugins: [loggingPlugin(), apiPlugin(), proxyPlugin(settings)],
  });
  await app.start();
  return app;
}
```

Protected routes also require the configured authentication plugin. Declare its
dependency, and telemetry when installed, in `apiPlugin({ dependencies: [...] })`.
The proxy discovers their capability owners through explicit support dependencies.
The [standalone HTTPS consumer](../../examples/proxy/README.md) demonstrates the
complete public API with explicitly reviewed synthetic public routes.

## Static destinations and connection policy

Each route requires `routeId`, `prefix`, `upstreamOrigin`, `methods`, `auth`,
`destinationPolicy`, `maxRequestBytes`, `maxResponseBytes` and `timeoutMs`.
`rewritePrefix` is optional. Origins are canonical scheme/hostname/port values
without path, credentials, query, fragment or ambiguous textual IP encoding.
Paths use literal bounded prefixes; parameters, wildcard configuration, traversal
and overlapping proxy namespaces are rejected. Facade routes cannot silently
shadow a proxy namespace during activation.

`public-only` rejects private, loopback, link-local, metadata, shared, multicast,
reserved and translated address spaces. Internal destinations require
`private-allowlisted` with nonempty exact `allowedHosts` and reviewed
`allowedCidrs`. Every new DNS connection checks all returned addresses before the
native transport chooses one. Static IP literals are classified directly and
cannot acquire a different destination through a request header. Mixed permitted
and forbidden DNS responses fail closed. Keep deployment egress restrictions in
place as an independent defense.

Request path and query cannot select protocol, hostname or port. The native
backend computes the fixed prefix rewrite; original query bytes are preserved.
Encoded separators, dot segments, double encoding and ambiguous paths are
rejected before forwarding. Redirects are never followed, and upstream Location,
Set-Cookie, caching and unsolicited identity headers are not relayed.

## Authentication, delegation and TLS

`auth: { required: true, scopes?: [...] }` performs actual runtime bearer
verification and every configured scope check before parsing or forwarding the
body. Verified tenant context comes from that authority. A public route requires
`auth: { required: false, reason: '...' }` with an explicit reviewed rationale.
Missing required authority fails startup. Request objects and proxy headers do
not manufacture trusted identity.

Only ordinary content/conditional/range headers cross the boundary. Incoming
Authorization, Cookie, Proxy-Authorization, Host, forwarded/tenant headers,
baggage and arbitrary extension headers are stripped. The native transport sets
the actual fixed upstream Host. Hop-by-hop headers and names nominated by
Connection are excluded using native parser/backend handling and the content
allowlist.

`identityDelegation: 'validated-service-credential'` requires HTTPS,
`serviceCredentialSecretRef` and `resolveSecret(reference, options?)`. The resolver
returns a complete HTTP Authorization token68 credential, such as an approved
Bearer service token including its scheme. No caller bearer is reused. The
upstream must independently authenticate this service credential. Missing,
invalid, cancelled or unavailable secret resolution fails closed. References and
values never enter diagnostics. `none` is the default and injects no identity.

Upstream HTTPS always validates the actual hostname and trusted CA with TLS 1.2
or later. `upstreamCaFile` may explicitly supply an internal CA; files must be
regular, bounded and readable without following a final symlink.
`upstreamTlsProfile?: TlsProfile` is the minimal optional completion for outbound
mTLS already required by the security contract. It requires the existing mTLS
capability, an approved configured profile and HTTPS. It cannot be combined with
a competing CA-file override. The existing credential provider loads client
material, and actual peer chain/revocation policy completes before any HTTP
metadata or body is sent. Every new connection resolves material again; reload
and established-connection policy remain application-owned. Profiles with an
explicit ALPN list must permit HTTP/1.1. Coordinate route and mTLS provider
deadlines. No new trust provider or production credential source is installed.

## Streaming and lifecycle

Request and response streams retain native backpressure with 16 KiB counting
transforms. Declared and observed body lengths are bounded; arbitrary responses
are never accumulated into a buffer. A request overflow returns 413. A response
overflow before headers rejects the body; after committed headers it terminates
the stream without appending a second JSON response.

Unavailable/untrusted upstreams return a fixed 502, absolute deadline failures
504 and policy failures 403. Authentication preserves 401/403. Errors exclude
endpoint URLs, addresses, certificate material and provider diagnostics. There
are no automatic retries, including 503 responses or non-idempotent requests.
HTTP smuggling/framing validation stays with Node, Fastify and the native backend.

Implementation ceilings are 32 nonoverlapping routes, 64 admitted physical
requests across the instance, 16 native connections per route, 1 GiB per
configured body ceiling, 8192-byte request targets and 1–30000 ms absolute route
deadlines. There is no unbounded application queue. Timed-out providers retain
their physical admission until they settle. Shutdown stops admission, drains
existing requests within the configured deadline and aborts remaining owned
streams/pools. Injected authentication, secret and mTLS providers retain their
existing application ownership.

## Observation and verification

One `proxy.request` span contains its nested `proxy.upstream` operation. Only
validated diagnostic trace context propagates; it never authorizes a caller and
baggage is not forwarded. `proxy.requests`, durations, observed request/response
body bytes and physical active gauges use configured route templates/upstream IDs,
fixed outcomes and numeric status codes. Configure telemetry `labelValues` for
`route` and `peer.service`, for example `/orders/*` and `orders`. SDK series limits
still apply. No account, tenant, query, URL, secret or arbitrary header labels are
introduced. These are observed HTTP body bytes, not TLS wire bytes or monetary
attribution; the upstream span is not a second business request.

Run `pnpm --filter @arkenivajs/proxy test:unit` after building, and the standalone
consumer against packed artifacts. Tests exercise real HTTP/HTTPS, actual signed
OIDC, native DNS connection policy, mTLS/CRL, framing, limits, partial response
termination, cancellation, restart, drain, parallel streams and actual SDK privacy.
Comparative native performance, remote CI and release acceptance remain separate
requirements. CONNECT, WebSocket upgrades, open/dynamic forwarding and HTTP
caching are outside this adapter's scope.
