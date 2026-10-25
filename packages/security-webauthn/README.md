# @arkenivajs/security-webauthn

This private workspace contains browser ceremony types and an internal compatibility
adapter for `@simplewebauthn/server` 14.0.3. The package root exports types only.
The adapter verifies cryptographic responses; successful primitive verification
requires subsequent trusted authorization and durable state transitions before it
can establish MFA evidence. No factor service is exposed by this version.

The internal adapter pins user presence and verification, exact challenge/RP/origin
checks and the upstream EdDSA, ES256 and RS256 algorithm set. It rejects cross-origin
ceremonies without an explicit embedding policy. Browser input is bounded and
snapshotted before asynchronous verification. Errors contain no response, challenge,
credential identifier, signature or upstream diagnostic text.

Registration tests use disposable synthetic authenticators and `none` attestation.
Authentication tests sign real assertions with ephemeral P-256 keys and verify
negative origin, RP, challenge, flags, credential and signature cases. These tests
exercise the upstream primitive; durable replay protection, account-handle policy,
credential state CAS, browser integration and a complete factor service have
separate acceptance requirements.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/security-webauthn test
```

The browser package is not a runtime dependency. This module does not load USB/HID
drivers or access browser APIs. See the [upstream server documentation](https://simplewebauthn.dev/docs/packages/server)
and [third-party notices](THIRD_PARTY_NOTICES.md).
