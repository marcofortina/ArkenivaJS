<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Changelog

## 0.1.0

- Capture source, cursor, authority and iterator callbacks without executable
  function metadata, preserving their original receiver and method identity.
- Add authenticated startup WebSocket/SSE routes with runtime identity provenance,
  reauthorization, bounded queues, cancellation and explicit durable cursor errors.
- Integrate tenant-isolated shared NATS and scoped Redis broadcast, including
  independent-process transport tests and aggregate private diagnostics.
- Preserve native SSE framing with a reviewed compatibility diff for heartbeat
  pressure, close acknowledgment and HTTP/2 response headers.
- Include a public HTTPS/WSS consumer and an ordered PostgreSQL replay source.
- Reuse one native WebSocket dispatcher on the application listener so optional GraphQL transport can coexist without duplicate upgrade handlers or weakened route limits.
