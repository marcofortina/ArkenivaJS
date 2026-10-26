<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Durable webhook replay with PostgreSQL

Use the disposable verified-TLS PostgreSQL fixture described in [the PostgreSQL example](README.md). Provide `ARKENIVA_POSTGRES_DISPOSABLE=1` and `DATABASE_URL` through the private fixture environment; never place credentials or operational evidence in the checkout. Build the workspace first, then run:

```sh
node --test examples/postgres/dist-test/integration/webhooks.integration.test.js
pnpm test:packed:examples --integration postgres
```

The suite creates fresh owned schemas, uses the existing `createPostgresSecurityStateStore` application adapter, and removes only those schemas. Independent connection pools back two webhook applications. Real signed OIDC identities must pass scope, tenant and durable primary-session revocation policy. Manually constructed identity data cannot authorize verification.

One valid MAC and nonce are verified concurrently through the two applications: exactly one gets a verified result. The PostgreSQL claims table retains only an opaque owner-bound digest and expiry, with no body, MAC, raw nonce, key or bearer token. Stopping an application and creating another cannot restore the consumed nonce. Rotations preserve nonce identity because the replay key excludes the signing version.

Foreign tenant, unavailable key provider and durably revoked primary session fail before consuming the valid nonce. Dropping the test-owned claims table causes verification to fail with an explicitly unknown persistence outcome; no in-memory fallback produces success. All tests use the same canonical receiver owner across replicas, including verified issuer, subject and tenant.

Run these functional cases on PostgreSQL 17 and 18 and every supported Node line. The existing CI PostgreSQL matrix and packed-integration gate include them. No real production database or certificate-verification bypass is permitted. The reference adapter remains classified test-only until its separate production review; a successful fixture does not establish production KMS, deployment, outbox, performance or release readiness.
