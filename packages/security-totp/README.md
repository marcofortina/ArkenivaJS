# @arkenivajs/security-totp

This optional package is under development. Its entry point currently exports
the TOTP lifecycle/storage types and shared MFA types. It does not yet export
`createTotpService` or enable enrollment, verification, QR or recovery flows.
Do not deploy it as a factor service or treat its types as runtime authorization.

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

The public service factory remains unavailable while durable lifecycle wiring
is completed. These runtime contracts and guards do not by themselves activate
a factor or issue an authentication session.

Trusted subject/management policy, factor-specific durable state, protection and
key rotation, distributed limits, evidence persistence, QR delivery, recovery,
end-to-end guides and release checks remain necessary before activation. TOTP
is not phishing-resistant and does not implement Microsoft Authenticator push.

ArkenivaJS is AGPL-3.0-or-later. Upstream components retain the licenses in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
