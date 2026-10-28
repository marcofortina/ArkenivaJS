<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Changelog

## 0.1.0

- Share the guarded fixed-upstream transport with framework adapters and bound CA reads before allocation.
- Add fixed-upstream HTTP/HTTPS streaming through the official Fastify proxy backend.
- Enforce connect-time address policy, trusted authentication, header isolation and optional approved mTLS.
- Add bounded byte limits, cancellation/drain, nested tracing and installed HTTPS consumer verification.
