<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Durable OAuth machine-grant comparison

Build the complete workspace and use the private environment runner for the
[owned PostgreSQL fixture](../../packages/database-postgres/test/fixtures/README.md).
Both `DATABASE_URL` and the explicit disposable flag are required. OpenSSL must
already be available; the harness installs no host package or trust anchor.

```sh
pnpm --filter @arkenivajs/benchmark-foundation oauth --verify /private/oauth-verification
```

The parent creates an owned HTTPS authorization server with a fresh temporary
certificate and a fresh SQL schema. Only the four isolated child processes trust
that certificate through their explicit `NODE_EXTRA_CA_CERTS`. The parent's
environment and the system trust store remain unchanged. An authenticated
loopback provider bridge supplies a synthetic authorized machine principal,
external test key material and the actual SQL technical-budget port. SQL
credentials never enter the child. Unrelated state-store operations fail closed.

Direct `openid-client`, the public OAuth/crypto plugins, and standard/detailed
SDK profiles each obtain two distinct authenticated client-credentials grants.
Each grant must retain the approved scope and audience, finite expiry and Bearer
type, without an unexpected refresh reference. Unapproved scopes are rejected.
Independent readback requires eight token requests received by the HTTPS issuer
and eight grants acknowledged in the SQL budget. No token, client credential,
principal, tenant, provider endpoint or key enters reports or SDK exports.

The native baseline shares the actual SQL budget and authority work; it does not
duplicate the framework's full input, discovery endpoint, admission, cancellation
or lifecycle policy. Crypto plugin startup checks real ephemeral encryption/MAC
test keys even though this machine-grant corpus creates no refresh state.
The loopback bridge is test infrastructure, not a production provider deployment.

Only `--verify` is supported, with no latency/resource samples and
`releaseGate: false`. Interactive OIDC/PKCE, refresh rotation, revocation,
provider failure performance, dedicated-runner budgets, five paired repetitions
and a one-hour soak remain separate scenarios. The integration suite also proves
untrusted TLS rejection, unauthorized provider rejection, namespace confinement
and deletion of the temporary certificate directory.
