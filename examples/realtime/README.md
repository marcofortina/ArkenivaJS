<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Authenticated HTTPS SSE and WSS

Run `pnpm --filter @arkenivajs/example-realtime build` and
`pnpm --filter @arkenivajs/example-realtime start`. OpenSSL must be available.
The example creates private ephemeral certificates, an owned loopback OIDC issuer
and a framework HTTPS listener. Every resource is removed on completion. The
issuer and one-event source are explicitly test-only; they are not a production
authentication authority or durable event store.

The executable verifies certificate trust, anonymous rejection, exact SSE text,
explicit unsupported replay and lossless WebSocket bytes. The test also runs
against packed installed public framework packages. See the
[adapter guide](../../packages/realtime/README.md) for route configuration,
browser session integration and shared broker requirements, and the
[PostgreSQL example](../postgres/realtime.md) for persistent ordered replay.

Production applications supply their own identity authority, tenant/channel
authorization, TLS deployment and event retention. Native browser clients need a
trusted session flow or an appropriate authenticated client library; URL tokens
are not an acceptable shortcut.
