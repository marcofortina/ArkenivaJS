# PostgreSQL orders example

Run typed named queries, `RETURNING`, a committed transaction, duplicate-key
classification and an application-requested rollback against real PostgreSQL.
Bigint and NUMERIC remain exact strings in the result. The example creates and
drops its own random schema; it requires `CREATE` on a **disposable** database.
It does not alter existing application tables.

Use Node 22.23.4, 24.22.1 or 26.12.1 and the workspace's pinned pnpm. From the
workspace root:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-postgres test
```

Prepare an isolated server using the adapter's
[disposable TLS fixture](../../packages/database-postgres/test/fixtures/README.md).
Supply `DATABASE_URL` from that private fixture environment and
`ARKENIVA_POSTGRES_DISPOSABLE=1`; [.env.example](.env.example) documents the shape.
The program reads environment variables directly and does not automatically load
a dotenv file. Never paste a real URL into a tracked file, command transcript or log.

```sh
pnpm --filter @arkenivajs/example-postgres start
pnpm --filter @arkenivajs/example-postgres test:integration
```

Expected output:

```json
{
  "rows": [{ "id": "9007199254740993", "total": "5.25" }],
  "duplicateRejected": true,
  "rollbackVerified": true
}
```

Without the disposable marker, startup fails with `EK_CONFIG_INVALID`; without
the URL it fails with `EK_CONFIG_MISSING`. Invalid certificates, wrong endpoint
identities and invalid credentials fail startup. Safe error JSON excludes secrets.
Every successful run removes its schema and stops its application, including pools.

The fixed `demo` tenant is tutorial data. A multitenant HTTP handler must obtain
tenant identity from verified authentication and enforce its data-access policy.
The adapter integration suite additionally verifies JWT rejection before SQL and
database-enforced tenant isolation with PostgreSQL row-level security.

The same disposable fixture also exercises the
[shared MFA state adapters](mfa-shared-state.md), including exact owner/session
matching, one-time challenge/evidence consumption and bounded rate quotas across independent Node processes. This
application-owned reference does not implement a factor verifier or issue a session.

The [WebAuthn credential reference](webauthn-state.md) adds stable account handles,
database-owned revisions and cross-process counter/revocation concurrency using
the same named SQL provider. It remains explicitly test-only until application-owned
production storage policy and the separate factor acceptance gates are satisfied.
The [controlled browser suite](webauthn-browser.md) exercises the public factor service
with the pinned browser SDK, a virtual authenticator and this shared SQL state.

The [transactional security-state reference](security-state.md) adds complete
CAS/batch/index/owner-epoch behavior for credential-service adapters, with actual
cross-process PostgreSQL tests and no implicit database pool.

The [API key lifecycle guide](api-keys.md) uses signed OIDC administration and
the complete transactional store through two public credential-service instances.
