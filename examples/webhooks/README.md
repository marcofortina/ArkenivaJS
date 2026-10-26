<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Verified webhook consumer

Run with the workspace's pinned Node.js/pnpm toolchain:

```sh
pnpm --filter '@arkenivajs/example-webhooks...' build
pnpm --filter @arkenivajs/example-webhooks start
pnpm --filter @arkenivajs/example-webhooks test
pnpm test:packed:examples --example webhooks
```

Expected output:

```json
{
  "accepted": true,
  "attempts": 1,
  "deliveries": 1,
  "unauthenticatedDenied": true,
  "replayDenied": true,
  "logsPrivate": true,
  "metricsObserved": true,
  "metricsPrivate": true
}
```

The executable starts only owned loopback fixtures. It issues real ephemeral signed ES256 OIDC credentials for separate sender and receiver roles, resolves their approved tenant through the real authentication service, and authorizes each operation at runtime. The receiver uses its own verified service principal independently of caller-provided headers. The sender signs exact JSON bytes and posts once to the configured receiver. A repeated signed request receives 409; an unauthenticated send is denied before delivery.

The example exercises actual Pino and OTel exports and checks that body contents, HMAC material, MAC, nonce, bearer credentials and tenant/subject metric labels remain private. No secret or payload is printed. All owned applications, authentication clients, listeners, agents and ephemeral HMAC buffers are closed/erased afterward. The packed check compiles/runs this consumer against installed archives outside the workspace.

The in-memory `disposableStore()` is explicitly test-only, bounded and single-process. It demonstrates the required storage shape and is rejected in production. It does **not** establish cross-pod replay guarantees or serve as a production backend. Real atomic replay, separate PostgreSQL connection pools, restart persistence, unavailable storage and signed-session revocation are verified in [the PostgreSQL guide](../postgres/webhooks.md).

Loopback HTTP and ephemeral credentials are limited to this test configuration. Production requires trusted HTTPS, externally managed immutable key versions, independently verified authentication/destination policy and durable shared storage. The package's native HTTPS tests independently prove rejection of an untrusted CA and acceptance of explicitly trusted fixture CA material without disabling verification. No system trust store, container engine or package is installed on the host.
