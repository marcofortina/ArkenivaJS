<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native authenticated realtime protocol verification

Build the workspace, then run:

```sh
pnpm --filter @arkenivajs/benchmark-foundation realtime --verify /private/realtime-verification
```

Four isolated profiles compare the actual pinned Fastify WebSocket/SSE backends
and JOSE with the public realtime/security plugins and actual standard/detailed
SDK exports. A separate parent issuer signs actual JWTs and serves real JWKS;
the parent independently verifies four key fetches. Both native and public paths
verify signature, issuer, audience, expiry and the approved tenant before stream
admission. Anonymous, tampered-token and signed foreign-tenant requests fail for
both SSE and WebSocket upgrades.

Each profile exchanges a WebSocket message containing a byte-exact base64url
binary payload. Actual SSE bytes preserve Unicode, multiline and empty data,
event types and tenant-scoped IDs. A valid cursor resumes strictly after the
second event. Foreign/unknown cursors return 409 and an expired cursor returns
410. Sources are bounded synthetic catalogs with explicit test-only status;
this is not evidence of durable storage or distributed replay.

The native reference uses actual JOSE admission, fixed tenant projection and
ordinary native WebSocket/SSE routes. It omits framework provenance, session
reauthorization, connection quotas, hostile frame admission, backpressure,
cancellation ownership and cleanup quarantine. The small valid WebSocket frame
is echoed without implementing a second general message-validation layer.
Source fixture behavior is not a production event store.

The issuer and listeners use explicit test-only loopback HTTP. No production
TLS or cross-pod broker claim is made. Reports and actual SDK exports exclude
tokens, identity, event IDs and data. Only `--verify` is supported while complete
independent-client/server resource accounting remains open. Reports retain
`releaseGate: false`; five paired repetitions and one-hour soak remain separate.
