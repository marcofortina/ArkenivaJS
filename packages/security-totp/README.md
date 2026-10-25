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

`TotpServiceOptions` requires an explicit framework `environment`, a
`TotpTrustPolicy`, `recoveryCodeHmac` and the four storage/protection providers.
Every provider and trust policy declares `usage:'production'|'test-only'`;
production rejects every test-only declaration. This classification does not
prove durability or authorization: concrete adapters still require their own
atomicity, failure and runtime-provenance conformance tests.

`trustPolicy.resolveSubject(subject, operation, options?)` must ask the
application's real primary authority to revalidate session, authenticated
tenant and owner, returning its immutable context or `null`. The service checks
the exact issuer/account/session/tenant binding. A TypeScript brand, copied
object or caller-supplied account ID establishes no provenance.
`trustPolicy.authorize(subject, {action,authorization?}, options?)` independently
checks permission and sufficiently strong recent authentication for enrollment,
replacement, disabling and recovery-code management. Enrollment/replacement
require authority-owned proof even though the API has no caller grant argument.
Disabling/recovery additionally require the existing management authorization;
its fields alone cannot establish authority. Primary authentication for those
sensitive operations is bounded to five minutes and supplied management grants
to one minute; the application can enforce a stricter policy.

`recoveryCodeHmac` selects exactly `algorithm:'HMAC-SHA256'` and a versioned
external `keyProvider`. `currentKeyId(options?)` chooses a new set's version;
`resolveKey(keyId, options?)` obtains 32–64 secure key bytes. Version IDs use
1–64 ASCII letters, digits, underscores or hyphens. Retain old versions while
their unused codes remain valid. The framework computes a framed HMAC bound to
version, issuer, subject and tenant. Provider-owned keys are never changed;
owned copies are cleared after use. Database state contains keyed hashes only.

`clock?:()=>number` accepts trusted integer epoch milliseconds at construction
in test/development. Production forbids this override and captures the system
clock; the deployment must maintain trustworthy synchronized time. Request
arguments cannot choose the clock, environment or provider. Provider operations
obey cancellation/deadlines, and late results cannot initiate subsequent work.

## Service operations and persistence

| Method                                                    | Behavior                                                                                                                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `beginEnrollment(subject, options?)`                      | Resolve the trusted owner, authorize enroll/replace, encrypt a fresh seed and persist expiring pending state before returning its opaque ID and secret-bearing URI. |
| `getQrCodeImage(subject, id, options?)`                   | Revalidate owner/session and management policy, then return a PNG data URL for the unexpired enrollment. QR code dependencies load only on this path.               |
| `confirmEnrollment(subject, id, code, options?)`          | Reauthorize the current transition, verify through otplib and atomically activate the exact pending generation with its accepted step.                              |
| `verify(subject, code, options?)`                         | Verify the six-digit proof and generation-bound durable step CAS, then persist one-use evidence before returning it.                                                |
| `isEnabled(subject, options?)`                            | Resolve the current verified owner and inspect its active factor.                                                                                                   |
| `disable(subject, authorization, options?)`               | Independently authorize recent management proof and atomically revoke an existing factor, pending state and recovery set.                                           |
| `generateRecoveryCodes(subject, authorization, options?)` | Authorize management, issue ten independent 256-bit random codes and atomically replace the stored keyed-hash set before returning plaintext once.                  |
| `verifyRecoveryCode(subject, code, options?)`             | Resolve the primary owner, obtain the code's retained HMAC key version, consume its exact owner-bound hash atomically and persist evidence.                         |

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

Recovery plaintext uses `keyVersion.base64urlRandomBytes`; only a framed,
owner-bound versioned HMAC is stored. Rotation retains old external keys while
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
