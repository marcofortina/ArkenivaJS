# @arkenivajs/security-totp

`createTotpService(options)` implements optional server-side TOTP enrollment,
verification, PNG provisioning and recovery. It requires a real application
authentication authority and explicitly selected durable providers. This private
workspace has no published release; production readiness depends on the chosen
authority, storage, secret providers and the applicable release gates.

The private compatibility adapter delegates cryptographic verification to pinned
`otplib` 13.5.0 and provisioning to `@otplib/uri` 13.5.0. It uses 160-bit CSPRNG
seeds, SHA1, six digits, a 30-second period and drift limited to zero or one
adjacent interval. It returns the exact verified timestep; only a subsequent
durable generation-bound CAS may accept that step. Repeated primitive calls
have no replay defense by themselves and cannot issue MFA evidence.

Unit checks cover the six SHA1 RFC 6238 vectors reduced to six digits, including
leading zeros, strict proof syntax, both interval boundaries, adjacent drift,
larger drift rejection and sanitized failures. Provisioning URI tests check
encoded issuer/account labels and standard defaults. Seeds, codes and URIs are
never printed. [Upstream release](https://github.com/yeojz/otplib/releases/tag/v13.5.0),
[URI API](https://otplib.yeojz.dev/api/%40otplib/uri/) and
[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) describe the underlying format.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/security-totp test
```

The type contract requires encrypted pending enrollment bound to a primary
session, exact factor generation, atomic activation/step acceptance/revocation,
and atomic replacement/consumption of keyed recovery hashes. It extends the
shared challenge SPI and accepts common operation cancellation/deadlines.
There is no implicit database driver, browser client or production memory store.
See the [shared PostgreSQL reference](../../examples/postgres/mfa-shared-state.md)
for independently tested challenge, limiter and evidence adapters.

## Trusted runtime configuration

`TotpServiceOptions` requires `subjectAuthority`, `recoveryHmac` and the four
storage/protection providers. `environment` defaults to `production`. Providers
may declare `usage:'production'|'test-only'`; production rejects explicit test-only
adapters. The HMAC provider must declare `securityLevel:'production'` in production.
Declarations alone cannot establish durability or authorization: concrete adapters
require independent atomicity, failure, secret-management and provenance tests.

`subjectAuthority.resolveSubject(subject, options?)` must consult the application's
real primary authority to revalidate the session, issuer, authenticated tenant and
owner, returning its immutable context. The service rejects subject substitution.
A TypeScript brand, copied object or caller-supplied account ID establishes no trust.
`subjectAuthority.authorize({action,subject,authorization?}, options?)` must reject
denied actions; successful authorization resolves without a value. It runs before
factor/limiter access for **every** operation, including QR and enabled-state reads.
Actions are `begin-enrollment`, `read-enrollment-qr`, `confirm-enrollment`, `verify`,
`is-enabled`, `disable`, `generate-recovery-codes` and `verify-recovery-code`.

The authority independently enforces sufficiently strong recent authentication for
enrollment, replacement and management. It must recheck the current transition at
confirmation, since another activation may turn enrollment into replacement.
Disabling/regeneration additionally require an independently verified management
grant; its fields alone do not confer authority. Sensitive primary authentication
is bounded to five minutes and supplied management grants to one minute; an
application may require stricter freshness. Authority failures fail closed;
explicit denials use sanitized `EK_AUTH_FORBIDDEN`/`EK_MFA_ASSURANCE_REQUIRED`.

`recoveryHmac` uses exactly `algorithm:'HMAC-SHA256'`. `createVerifier(input)` returns
a version/key-ID-qualified opaque keyed verifier. `candidateVerifiers(input)` returns
one through eight distinct opaque verifiers for approved current/retained keys.
The input contains issuer, subject, optional tenant, the **server-retrieved active
factor ID**, and plaintext code. The backend must use unambiguous domain separation
and external secret-managed keys with at least 256 bits of entropy. It may use a
KMS MAC operation: the framework never requests raw HMAC keys. Retain old versions
while their unused codes remain valid; retiring a key invalidates those codes.
Missing keys, duplicate/oversized candidates and provider failures reject safely.
Only opaque verifiers reach the state store; provider errors and verifier values
are excluded from public errors and telemetry.

`clock?:TotpClock` supplies `nowEpochMs():number` only with `environment:'test'`.
Production and development reject injected clocks. Otherwise the service captures
the host wall clock; deployment operators must synchronize it. Every reading must
be a finite nonnegative integer epoch millisecond value. Request arguments cannot
select clock, environment or providers. Provider operations obey deadlines and
cancellation; late results cannot initiate subsequent work.

## Service operations and persistence

| Method                                                    | Behavior                                                                                                                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `beginEnrollment(subject, options?)`                      | Resolve the trusted owner, authorize enroll/replace, encrypt a fresh seed and persist expiring pending state before returning its opaque ID and secret-bearing URI. |
| `getQrCodeImage(subject, id, options?)`                   | Revalidate owner/session and management policy, then return a PNG data URL for the unexpired enrollment. QR code dependencies load only on this path.               |
| `confirmEnrollment(subject, id, code, options?)`          | Reauthorize the current transition, verify through otplib and atomically activate the exact pending generation with its accepted step.                              |
| `verify(subject, code, options?)`                         | Verify the six-digit proof and generation-bound durable step CAS, then persist one-use evidence before returning it.                                                |
| `isEnabled(subject, options?)`                            | Resolve the current verified owner and inspect its active factor.                                                                                                   |
| `disable(subject, authorization, options?)`               | Independently authorize recent management proof and atomically revoke an existing factor, pending state and recovery set.                                           |
| `generateRecoveryCodes(subject, authorization, options?)` | Authorize management, issue 10–20 independent 256-bit random codes and atomically replace the stored keyed-hash set before returning plaintext once.                |
| `verifyRecoveryCode(subject, code, options?)`             | Resolve the primary owner, obtain bounded versioned candidates, consume its exact factor/owner-bound verifier atomically and persist evidence.                      |

TOTP defaults stay SHA1/30 seconds/six digits with ±1 step; `driftSteps:0`
selects the exact interval. Enrollment TTL defaults to 300000 ms, bounded to
1–300000 ms. IDs are opaque CSPRNG references. Pending state binds the exact
primary session, and replacement keeps the old factor until activation commits.
Every accepted step must be greater than the persisted value for that factor
ID/generation. Two pods cannot both accept a step or a recovery code.

A shared limit permits five attempts per owner/operation in 60000 ms. The scope
includes issuer and tenant and is shared across primary sessions. Invalid
attempts count, and provider outage never skips the limit. Primary authentication
and authorization run before factor access. Caller deadlines/cancellation apply
to every provider, with no automatic write retry.

Recovery plaintext is canonical base64url encoding of 32 independent random bytes.
`recoveryCodeCount` defaults to 10 and accepts only integers 10 through 20.
Only a factor/owner-bound versioned HMAC verifier is stored. Rotation retains old external keys while
old unused codes remain valid. Regeneration and factor replacement/revocation
invalidate earlier sets. Missing keys or an uncertain write never produce a
success result. A consumed OTP/recovery proof stays spent if evidence persistence
fails; begin a fresh verification instead of retrying a non-idempotent write.

Returned evidence has `method`, `assurance:'mfa'`, subject, verification/expiry
and an opaque ID, with a one-minute lifetime. The application authority must
consume its separately persisted issuer/tenant/primary-session-bound record
before issuing its own session decision. Existing identities are never upgraded
in place; the framework signs no JWT and sets no cookie. TOTP and recovery are
not phishing-resistant and do not implement Microsoft Authenticator push.

## Executable integration

The [PostgreSQL guide](../../examples/postgres/mfa-shared-state.md) runs this
public factory with real signed OIDC identities, authenticated encryption,
external ephemeral test keys and shared SQL. Inject its protected disposable
TLS `DATABASE_URL` and run:

```sh
export ARKENIVA_POSTGRES_DISPOSABLE=1
pnpm --filter @arkenivajs/example-postgres test:integration
pnpm test:packed:examples --integration postgres
```

Tests fail explicitly if the fixture is missing; they do not silently skip.
They verify all operations, foreign/unowned objects, independent management
grants, interval/expiry boundaries, key rotation, rate limits, corrupted data,
unknown persistence outcomes and two complete independent factor processes.
Only owned schemas, pools, issuer sockets and ephemeral test keys are cleaned up.

Enrollment URI/QR and recovery lists are sensitive return values. Applications
must deliver them only over authenticated HTTPS with `Cache-Control: no-store`
and exclude them from logs, tracing, metering, analytics and error payloads.
The module emits no secret-bearing telemetry. The disposable adapters are
explicitly rejected in production; production providers must pass durable
conformance and key-readiness checks before the application exposes a listener.

ArkenivaJS is AGPL-3.0-or-later. Upstream components retain the licenses in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
