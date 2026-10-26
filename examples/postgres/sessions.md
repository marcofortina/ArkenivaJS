# Durable sessions with signed primary authentication

The [executable integration suite](test/integration/sessions.integration.test.ts)
exercises all five public session methods through two independent application
instances sharing real PostgreSQL. The fixture verifies signed OIDC tokens,
tenant provenance and primary authentication before issuing an opaque session.
It persists original authentication events separately from credential records.

Use the [private TLS fixture](../../packages/database-postgres/test/fixtures/README.md)
and pinned Node/pnpm versions:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/security-sessions test
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm --filter @arkenivajs/example-postgres test:integration
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm test:packed:examples --integration postgres
```

The private environment supplies the disposable database marker and verified
TLS connection. Credentials stay outside Git and command arguments. The
[authority fixture](test/integration/session-fixture.ts) owns its test issuer,
account catalog and explicit request context; the transactional backend creates
and removes only a random owned schema. It is not a production identity provider.

The suite verifies:

- Rejection of unauthenticated caller-built identities, stale/future primary
  authentication and a primary-session revocation marker shared in PostgreSQL.
- Canonical privileges, no raw token or primary bearer in stored records,
  preservation of original authentication/MFA metadata and token rotation.
- A synchronized transaction barrier for simultaneous renewals, one replacement
  winner and no remaining active old credential.
- Cross-instance individual/global revocation and quota recovery after epoch
  changes, without a per-pod acceptance cache.
- Foreign-tenant denial and fail-closed secret, identity-provider and actual
  persistence failures.
- Signed logout issuer/subject/tenant/session binding, exact event shape,
  forbidden nonce rejection and durable replay protection across HMAC rotation.

The resolver reads current privileges from its trusted account catalog while
retaining the original authentication event. Upstream `auth_time`, `acr`, `amr`
and `sid` claims are omitted from returned claims so a later primary login
cannot accidentally replace the local session's original authentication facts.
Read explicit `authenticatedAt`, `assuredAt` and `assurance` for those facts.

The controlled logout example requires both subject and session identifiers
and applies an explicit account-wide revocation policy. It does not claim every
OIDC logout profile or production federation certification. The application
must separately implement its provider's approved logout and retention policy.

HTTP integration remains explicit: send the one-time value only in
`__Host-session` with Secure, HttpOnly, Path=/, no Domain and the authorized
SameSite policy. State-changing cookie routes require CSRF protection, and
session values must never enter URLs, logs or JavaScript storage. This suite
verifies the headless session and durable authority boundaries; it does not
claim browser-cookie or CSRF end-to-end acceptance.

See the [package reference](../../packages/security-sessions/README.md) for
the required authority completion, seven-method store port, key-domain policy,
deadline/admission bounds and ambiguous-write behavior. Performance measurements
and deployment review remain separate release requirements.
