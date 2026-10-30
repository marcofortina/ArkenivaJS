<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Authenticated WebSocket and SSE streams

`realtimePlugin(settings)` installs native `@fastify/websocket` 11.3.4 and
`@fastify/sse` 0.6.1 routes on the existing API listener. Resolve the service with
`app.resolve<RealtimeService>(REALTIME_CAPABILITY)`. The application needs explicit
API and authentication providers. Every stream authenticates before admission;
TypeScript tenant objects and tenant headers cannot grant identity.

Source, cursor, identity authority and iterator methods retain their original
receiver and callback. Capturing them does not evaluate callable `bind`, `name`
or `length` properties. Later provider method replacement cannot change the
captured callbacks; proxy providers, callbacks and prototype chains are rejected.

Declare routes during startup, with named handler, source and policy catalogs:

```typescript
import { realtimePlugin } from '@arkenivajs/realtime';

const realtime = realtimePlugin({
  routes: [{ kind: 'websocket', path: '/updates', handlerKey: 'echo', policyKey: 'bounded' }],
  websocketHandlers: {
    async echo(session) {
      for await (const message of session.receive()) await session.send(message);
    },
  },
  sseSources: {},
  policies: {
    bounded: {
      requireAuth: true,
      maxConnectionsPerTenant: 100,
      maxMessageBytes: 65536,
      maxBufferBytes: 262144,
      heartbeatMs: 15000,
      idleTimeoutMs: 120000,
    },
  },
  policy: { maxConcurrent: 256, timeoutMs: 5000 },
});
```

`RealtimeSession.send` and `receive` preserve `Uint8Array` bytes. Native WebSocket
frames contain strict UTF-8 JSON `{channel,payload,id?}`, with `payload` encoded
as canonical unpadded base64url. Unknown fields, invalid encodings and oversized
frames close the connection. Both the decoded payload and encoded frame must fit
the configured limits. Compression is disabled. Receiving a message does not
automatically publish it: application handlers own channel authorization.

The default authority verifies bearer signature, issuer, audience, tenant and
expiry through the application's actual authentication provider. Optional
`identityAuthority.authenticate` integrates a trusted session authority; its
result must still be the actual provider's current minted tenant context. It is
called at admission, before message delivery and on every heartbeat. Cookie
flows require an explicit exact `allowedOrigins` entry and a matching Origin.
Browser credential transport must be designed by the application; native browser
WebSocket and EventSource constructors cannot set arbitrary bearer headers.
Never place bearer credentials in URLs. Explicit `usage: 'test-only'` sources and
authorities are rejected outside the test environment.

SSE sources return native `{id,type,data}` events. IDs are opaque, URL-safe ASCII,
1–256 bytes; event data is exact UTF-8 text with LF/tab permitted and CR/control
injection rejected. Durable sources must implement `validateCursor` to check
ownership and retention before response headers. Throw `new SseCursorError('expired')`
for HTTP 410 or `'invalid'` for HTTP 409. Pubsub sources reject every resume cursor
with 409. No source fabricates history. Cancellation aborts the source signal and
calls iterator cleanup. A failed iterator cleanup remains visible as a sanitized
service shutdown failure after the peer has disconnected. The application owns persistent event storage and its
retention/order policy; see the [PostgreSQL source](../../examples/postgres/realtime.md).

`publish(channel, bytes, verifiedTenant, options?)` requires a configured shared
backend. For NATS, `pubsub: {provider:'nats',connectionName:'messaging'}` selects the
existing named messaging plugin owner. For Redis, select the actual configured
Redis database name; the existing adapter supplies a dedicated scoped subscriber.
The adapter never opens a second independently configured broker client or reads
new credentials. At most 32 active tenant subscriptions are admitted per owner.
Subjects use `realtime.v1.<sha256(JSON([issuer,tenantId]))>` within the provider's
existing prefix. Broker payloads contain the same channel/base64url representation;
they cannot select a tenant. Only the matching verified tenant's WebSocket
connections receive a broadcast. SSE sources integrate their own trusted
application event source and do not bypass replay policy through this method.

NATS Core and Redis Pub/Sub provide transient delivery, without retained replay,
durable acknowledgment or exactly-once guarantees. Redis transport failure closes
affected subscribers; applications reconnect explicitly. Broker ACLs must limit
publish/subscribe access to the approved prefix and application identities.
Backend encoded-envelope limits can be smaller than raw configured byte limits;
such publications fail explicitly. There is no in-process production fallback.

Policy limits are finite: at most 10,000 tenant connections, 1 MiB per message,
4 MiB per connection buffer, heartbeat 1–30,000 ms below idle timeout, and idle
timeout 1–3,600,000 ms. Global admission is 1–10,000 operations/connections;
operation timeout is 1–30,000 ms. Global input/output defaults are 1 MiB, maximum
4 MiB, and can restrict route limits further. Queues also cap item counts at
1,024. Slow peers disconnect. Physical provider work retains capacity until it
actually settles, including after cancellation; uncooperative providers cause a
bounded shutdown failure rather than an invented cleanup success.

Imperative `websocket`/`sse` registration is available only from dependency
initialization before listen. Late registration fails `EK_LIFECYCLE_STATE`.
`close()` rejects new work, cancels active streams and drains owned resources;
application shutdown invokes the same owner. The underlying API listener remains
application-owned. Use HTTPS/WSS directly or an explicitly trusted TLS terminator.

Aggregate metrics cover active connections, sent/received wire bytes, sampled
queue bytes and fixed disconnect reasons. Labels are limited to protocol/reason;
payloads, channels, credentials, cursors and identities are absent. Diagnostics
cannot replay delivery or relax authentication. The packaged compatibility diff
bounds native SSE heartbeat writes, handles close without drain and preserves
HTTP/2 headers; see [third-party notices](THIRD_PARTY_NOTICES.md).

Run the [owned HTTPS/WSS example](../../examples/realtime/README.md). Native tests
cover real paused receivers, cursor errors, authorization revocation, direct HTTP/2,
and separate Node processes connected through real TLS/ACL NATS and Redis fixtures.
These are local functionality checks; performance/soak and deployment acceptance
are separate requirements.
