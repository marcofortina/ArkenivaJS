<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native authenticated realtime protocol verification

Build the workspace, then run:

```sh
pnpm --filter @arkenivajs/benchmark-foundation realtime --verify /private/realtime-verification
ARKENIVA_REALTIME_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation realtime --smoke /private/realtime-smoke
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
second event. Foreign/unknown cursors return 409 and an expired cursor returns 410. Sources are bounded synthetic catalogs with explicit test-only status;
this is not evidence of durable storage or distributed replay.

The native reference uses actual JOSE admission, fixed tenant projection and
ordinary native WebSocket/SSE routes. It omits framework provenance, session
reauthorization, connection quotas, hostile frame admission, backpressure,
cancellation ownership and cleanup quarantine. The small valid WebSocket frame
is echoed without implementing a second general message-validation layer.
Source fixture behavior is not a production event store.

The issuer and listeners use explicit test-only loopback HTTP. No production
TLS or cross-pod broker claim is made. Reports and actual SDK exports exclude
tokens, identity, event IDs and data.

Optional smoke requires an explicit disposable marker before issuer or listener
allocation. Each profile records 100 actual Tinybench finite SSE-response samples
after 20 warmup callbacks, with concurrency one. Existing WebSocket and SSE
negative/resume checks remain outside timing. A parent-owned native HTTP client
consumes each timed response using the actual signed JWT. Before opening that
connection, the parent independently authenticates through the real auth service
against the same issuer and validates its actual tenant context. No additional
signing or identity trust keys are introduced.

The parent compares all UTF8 bytes against the original three-event corpus,
including Unicode, multiline and empty data and exact tenant-scoped IDs, then
waits for its physical client socket to close before acknowledging the worker.
It independently requires 480 actual streams and 1,440 events, four registered
owned loopback listeners and no remaining observer socket or callback. The
additional independent auth service accounts for exactly one more JWKS request:
five in measured smoke, four in untimed verification. Public source callbacks
also check tenant provenance through their owning application's actual auth
service. Each worker verifies retirement of all source subscriptions, retaining
only 120 compact receipts under an explicit cap of 128 and no event-body corpus.

The existing two-connections-per-tenant limit and one-second server operation
policy remain unchanged, as does the 30-second profile controller. Timings include
the authenticated observer RPC, actual HTTP response and client retirement;
they do not isolate SSE encoding or server CPU. Worker resources cover the
server; parent client, auth and issuer CPU/RSS remain explicitly unknown and
excluded. Native signed-claim projection omits the public runtime's complete
provenance and lifecycle policy, so this is not policy or full resource parity.
The source is a finite test catalog: there is no persistent replay, broker,
cross-pod broadcast, exactly-once, WebSocket performance or production TLS claim.
Reports retain `releaseGate: false`; calibrated budgets, five paired repetitions
and one-hour soak remain separate.
