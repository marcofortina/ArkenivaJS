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

Trusted subject/management policy, factor-specific durable state, protection and
key rotation, distributed limits, evidence persistence, QR delivery, recovery,
end-to-end guides and release checks remain necessary before activation. TOTP
is not phishing-resistant and does not implement Microsoft Authenticator push.

ArkenivaJS is AGPL-3.0-or-later. Upstream components retain the licenses in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
