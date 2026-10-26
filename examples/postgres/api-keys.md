# API keys with durable PostgreSQL

This executable guide exercises all five public operations through two
independent application instances sharing a disposable PostgreSQL schema.
Actual signed OIDC assertions authenticate administrators; the authentication
service verifies tenant provenance. Caller-built subjects authenticate nobody.

Use the [private TLS fixture](../../packages/database-postgres/test/fixtures/README.md)
and the workspace's pinned Node/pnpm versions:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/security-apikey test
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm --filter @arkenivajs/example-postgres test:integration
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm test:packed:examples --integration postgres
```

The private mapping supplies `DATABASE_URL` and
`ARKENIVA_POSTGRES_DISPOSABLE=1`. Credentials belong outside arguments and Git.
The [fixture](test/integration/api-key-fixture.ts) creates only its owned schema
and closes its OIDC listener, native HMAC keys, applications and SQL resources.
Its issuer's HTTP loopback exception is test-only. Production identity, storage
and secret providers require independent verification and transport policy.

The [complete tests](test/integration/api-key.integration.test.ts) demonstrate:

- Authenticated issuance, verification from another instance, rotation,
  fresh-read revocation and bounded metadata listing.
- Denial for anonymous management, foreign tenants, unapproved scopes and
  revoked signed administrator sessions.
- One winner for concurrent issuance at quota and concurrent rotation,
  without partial replacement or cached old-key acceptance.
- HMAC rotation with stable blind indexes, native source-network restrictions
  and fail-closed authority, secret and storage outages.

The test HMAC provider holds independent random blind-index and versioned
verifier keys in a fixture closure and uses native constant-time comparison.
Keys are neither persisted nor printed. This exercises the provider port
without claiming production secret-management certification.

`session().run(...)` enters application-owned `AsyncLocalStorage` after actual
OIDC verification. It is test infrastructure, not a public authentication API.
The authority checks that context, recent signed authentication, verified tenant
membership and bounded management rate. Credential verification checks current
account policy after HMAC proof without requiring a prior user session.

Deliver issued tokens once over authenticated TLS. Tests keep them in memory
and assert the database contains no raw secret suffix or administrator bearer.
Test output consists only of outcomes. See the
[package reference](../../packages/security-apikey/README.md) for complete
contracts, key-rotation constraints, budget scope and unknown-write handling,
and the [store guide](security-state.md) for multiprocess storage conformance.
