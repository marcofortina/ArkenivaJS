# Atomic password resets with PostgreSQL

The [executable suite](test/integration/password.integration.test.ts) uses the
public password and session services with signed OIDC primary authentication.
All tables live in an owned random schema on the explicit disposable TLS
fixture. Credentials and keys are never printed or written into Git.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/security-password test
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm --filter @arkenivajs/example-postgres test:integration
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm test:packed:examples --integration postgres
```

Use the [private database fixture](../../packages/database-postgres/test/fixtures/README.md)
to create the external environment mapping. The
[application committer](test/integration/password-fixture.ts) locks the exact
live reset version and current account, replaces its PHC, deletes that reset
and advances the same owner epoch read by the session service. Those writes
share one native SQL transaction; no success is acknowledged before commit.

Tests verify that both independent session-service instances reject an old
cookie credential after reset. A controlled failure after the password UPDATE
proves real rollback: the old password and existing session remain valid and
the reset is still usable. Two consumers reach the same commit barrier; only
one replacement password wins.

The account table, authority, signing issuer and external-key closure are
explicitly test-only. Production must supply independently reviewed account,
secret, breach and transaction providers. Test KDF settings intentionally keep
functional fixtures small and are not a production calibration recommendation.
The fixture supports the configured account-wide logout policy; it does not
claim arbitrary cross-database atomicity or automatically grant MFA.

See the [package reference](../../packages/security-password/README.md) for
the mandatory persistence port, deadline and resource limits, external key
version behavior and unknown-write outcomes. Applications still own account
registration, password-change transactions, recovery delivery, session policy
and browser/CSRF integration.
