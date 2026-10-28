<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Magic links with durable state and HTTPS confirmation

The optional [magic-link service](../../packages/security-magiclink/README.md)
uses the application-owned [transactional PostgreSQL store](security-state.md).
Mail delivery, session issuance and recovery effects stay outside the credential
service. All fixture keys and account authorities are explicitly test-only.

Build with pinned pnpm and a supported Node version:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/security-magiclink test:unit
pnpm --filter @arkenivajs/example-postgres test
pnpm test:packed:examples --example postgres
```

The public-artifact consumer uses a labeled single-process unit store. It proves
installation and public contracts; these integrations prove actual transactions
and network behavior. Prepare the
[owned PostgreSQL fixture](../../packages/database-postgres/test/fixtures/README.md),
which supplies private credentials, verified TLS trust and explicit disposable
authorization. Never put credentials in command arguments or logs.

```sh
node --test examples/postgres/dist-test/integration/magiclink.integration.test.js examples/postgres/dist-test/integration/magiclink-process.integration.test.js examples/postgres/dist-test/integration/magiclink-https.integration.test.js
```

Expected result: five passing integration tests without skips. They exercise
signed OIDC management, two shared-state instances, independent Node processes
with separate verified SQL pools and JWT validation, tenant isolation, disabled
accounts, key rotation, quotas and secret-provider failure. Every test creates
and drops only its owned random schema.

The [confirmation plugin](src/magiclink-confirmation.ts) registers native Fastify
routes before the framework HTTPS listener starts. Supply an explicit trusted
HTTPS origin and the resolved `MagicLinkService` to
`magicLinkConfirmationPlugin`. Its GET page and first-party script set
`no-referrer`, `no-store`, restrictive CSP and framing protections. The script
reads the fragment and clears it from the address bar immediately. It sends no
redemption until the user submits the confirmation form. POST requires actual
TLS, the exact configured Origin and a bounded JSON body.

The live HTTPS test generates ephemeral OpenSSL certificates and uses explicit
client CA trust with certificate verification enabled. It follows the issued URL
as a scanner GET, checks that the credential never reaches the request URL or
HTML page, rejects a foreign-origin POST, confirms once and returns a generic
failure for reuse. CSP allows only same-origin scripts and network requests.

The confirmation returns only `{ "confirmed": true }` on success or
`{ "confirmed": false }` on failure. Any resulting session or account mutation
needs a separately authorized application flow. Email possession never upgrades
MFA assurance.

Process fixture secrets travel through owned IPC rather than arguments or output.
Random keys are zeroed at teardown; child processes, applications, pools,
certificates and owned schemas are closed or removed. Production must supply
secure external key resolution and an independent current account/session
authority. Test providers require replacement/review before production use.
