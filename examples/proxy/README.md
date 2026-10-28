<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Fixed HTTPS reverse proxy example

Run an actual HTTPS gateway and separately owned HTTPS upstream using public
ArkenivaJS imports. The example generates ephemeral OpenSSL credentials, verifies
both TLS peers through explicit CA trust and removes only its owned temporary
directory at teardown. No external database, container or persistent service is
needed. OpenSSL must be available on PATH.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-proxy start
pnpm --filter @arkenivajs/example-proxy test
pnpm test:packed:examples --example proxy
```

Expected output includes `untrustedCertificateRejected`, `rewritten`,
`identityHeadersStripped` and `unsafePathRejected` equal to `true`, `bytes` equal
to 65536, and statistics containing one forwarded and one rejected request.
The input is streamed through `/orders/42?state=ready` to the fixed upstream
`/api/orders/42?state=ready`. Spoofed credentials, cookies, tenant/forwarded headers
and baggage are absent upstream. A traversal request fails with 403. A client
that omits the private fixture CA fails TLS verification.

[run.ts](src/run.ts) contains the application setup and verification. Both
listeners use native TLS and an explicit loopback `/32` allowlist. This is a
test-only deployment policy. The public-route rationale permits only ephemeral
synthetic bytes; it grants no authenticated identity or protected data access.
For protected routes install the framework security plugin, configure a real
issuer/audience and require scopes before forwarding. The module's independent
signed-OIDC tests verify that boundary.

Read the [proxy contract guide](../../packages/proxy/README.md) for service-token
delegation, mTLS, egress policy, error semantics and observability. Production
must use reviewed host/CIDR rules, independent upstream authentication and secure
credential providers. Never infer proxy trust from Host, forwarded or tenant
headers. No inbound bearer is forwarded automatically.

The test and CLI run the same application code. Packed verification recompiles
this consumer against installed package archives and runs actual HTTPS traffic.
Output contains only safe booleans and observed byte/request counts. All owned
listeners, pools, keys and certificates are closed or removed on success and
failure. Comparative performance and release checks remain separate gates.
