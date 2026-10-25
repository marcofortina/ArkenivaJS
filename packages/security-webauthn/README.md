# @arkenivajs/security-webauthn

Experimental server-side WebAuthn factor service using `@simplewebauthn/server`
14.0.3. `createWebAuthnService(options)` and the typed authority/storage contracts
are exported from the package root. Production acceptance requires real durable-store,
browser, performance and release checks; simulator tests alone do not establish it.

| Method                                                              | Result and required trust                                                                      |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `beginRegistration(subject, options?)`                              | Recent independently authenticated account; returns a bound, expiring browser ceremony.        |
| `finishRegistration(subject, ceremonyId, responseJSON, options?)`   | Consumes the ceremony, verifies attestation and inserts one unique owner-bound credential.     |
| `beginAuthentication(subject, options?)`                            | Independently authenticated account; browser allowlist contains its active credentials only.   |
| `finishAuthentication(subject, ceremonyId, responseJSON, options?)` | Verifies signature, RP/origin/UP/UV and durable state; returns persisted server-side evidence. |
| `beginPasswordless(options?)`                                       | Explicit opt-in and distributed anonymous attempt policy; no existing session is needed.       |
| `finishPasswordless(ceremonyId, responseJSON, options?)`            | Verifies the credential before resolving its canonical account and tenant.                     |
| `listCredentials(subject)`                                          | Authorized credential summaries without public keys or internal ownership metadata.            |
| `revokeCredential(subject, credentialId, authorization, options?)`  | Recent independently authorized management grant; versioned revocation.                        |

The module returns evidence to trusted server code. The application owns session
issuance and consumes evidence once before granting assurance. Never serialize
evidence to a browser as an authentication token. A normal assertion's evidence
uses the verified primary session binding. Passwordless evidence uses the consumed
ceremony ID as the pre-session authentication transaction: the application consumes
it using that ID in `MfaEvidenceStore.consume().primarySessionId`, together with the
verified issuer, subject and tenant, before issuing its own session.

## Configuration and trust

Required settings are stable `rpId`, `rpName`, exact `expectedOrigins`,
`stateStore`, `rateLimitStore`, `evidenceStore` and `subjectAuthority`.
Origins require HTTPS in production; localhost development has the browser's
explicit HTTP exception. No request header chooses an RP, origin, tenant or clock.
Subject objects and management grants are untrusted until the configured authority
checks live server-owned session, identity, tenant and authorization state.

Environment defaults to production. Only test instances may inject `clock`;
production rejects explicitly test-only providers. Provider declarations are not
independent security review. Methods are captured once with their original receiver.
Registration requires primary authentication within five minutes. Revocation also
requires a trusted grant verified within one minute. Sensitive finishes recheck
live identity and authentication freshness before mutation. Authorization runs once
per operation so the authority may consume a one-use grant.

User presence and verification are mandatory. Algorithms are the upstream EdDSA,
ES256 and RS256 set. Attestation defaults to `none`; `direct` delegates attestation
statement verification to the pinned SDK, including packed self-attestation.
Enterprise device provenance, hardware binding and certification require separately
approved trust-root/metadata policies. Cross-origin embedding is rejected.

## Durable provider requirements

Account handles are stable 32-byte random values, encoded as 43-character unpadded
base64url, scoped by RP/issuer/subject/tenant. `getOrCreateUserHandle()` atomically
allocates or reuses the account mapping. Handle ownership is immutable and independently
checked when the assertion supplies a handle and when it omits one.

`insertCredentialIfAbsent()` must atomically enforce credential/account uniqueness
and initialize a backend-owned `stateVersion`. The input contains a candidate marker;
the persisted initial revision must be independently allocated by the backend.
A read-after-insert that merely acknowledges the candidate marker is rejected.
Every successful authentication changes the backend version, including `0 → 0`.
Nonzero counters must strictly advance; backup eligibility is immutable while backup
state can change. Counter writes and revocations compare the same active row revision
and full ownership binding. Conflicts require a fresh ceremony and are never retried
automatically. Revocation invalidates affected outstanding account ceremonies.

Ceremonies persist only a SHA-256 digest bound to the RP, origin set, verification,
attestation and TTL policy. Claims also bind purpose, issuer, account, tenant and
primary session where applicable. Invalid proofs consume claimed ceremonies.
Passwordless has an independent anonymous namespace. Changing security configuration
invalidates unfinished ceremonies from the previous policy.

Evidence storage must retain write-once and consume-once guarantees across pods,
including after prior consumption. Storage outages, ambiguous acknowledgements and
invalid metadata fail closed. No in-process storage fallback or database driver is
installed by this package; the application supplies and owns its providers.

## Resource and privacy policy

- Challenge TTL defaults to 300,000 ms; accepted integer range is 1..300,000.
- Calls default to 30,000 ms; explicit timeouts are integer milliseconds 1..120,000.
- Thirty-two service operations and eight native verifications may be in flight per
  instance. Excess work is rejected immediately. Pending work retains its slot until
  it actually settles, including after caller timeout.
- Credential collections are bounded at 100 records per lookup; overflow is an error,
  never a truncated list. Providers must bound database reads accordingly.
- Attempt buckets separate RP/issuer/account/tenant/action: five attempts per minute
  for bound actions, twenty for each anonymous RP/action.
- Browser JSON is bounded at 1 MiB, 4,096 values and 16 levels. Accessors, serialization
  hooks, custom prototypes, cycles and unsafe keys are rejected.

No response, challenge, user handle, credential identifier, signature, public-key
material or provider diagnostic is included in errors, logs or telemetry. Authorized
credential summaries intentionally return credential IDs for account management.
Evidence lasts one minute and remains internal to the application trust boundary.

## Verification

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/security-webauthn test
```

Tests use ephemeral P-256 authenticators with real signatures, malformed proofs,
origin/RP/UP/UV failures, trusted-authority negatives, atomic simulators, counter and
revocation races, provider outages and bounded admission. Durable database and real
browser acceptance are separate gates. The executable
[PostgreSQL/browser guide](../../examples/postgres/webauthn-browser.md) covers actual
Chromium ceremonies and two full service processes contending on real SQL state.
The browser package is absent from runtime
dependencies; USB/HID drivers and browser APIs remain outside this Node.js module.
See [upstream documentation](https://simplewebauthn.dev/docs/packages/server) and
[third-party notices](THIRD_PARTY_NOTICES.md).
