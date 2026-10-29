# Local password helpers

Optional `@arkenivajs/security-password` uses the prescribed `argon2@0.45.1`
backend for Argon2id PHC hashing, verification, rehash checks and durable reset
tokens. It installs no route, account directory, mail transport or listener.
The native package bundles reviewed Node-API binaries; install hooks remain
disabled. The wrapper is MIT-licensed, and its bundled Argon2 reference source
offers CC0-1.0 or Apache-2.0. The dependency retains its upstream license files.
See the [pinned upstream source](https://github.com/ranisalt/node-argon2/tree/v0.45.1).

```typescript
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { passwordPlugin, PASSWORD_CAPABILITY } from '@arkenivajs/security-password';
import type { PasswordPluginSettings, PasswordService } from '@arkenivajs/security-password';

export async function startPasswords(settings: PasswordPluginSettings) {
  const app = await createApplication({
    service: { name: 'local-accounts', version: '1.0.0', environment: 'production' },
    plugins: [loggingPlugin(), passwordPlugin(settings)],
  });
  await app.start();
  return { app, passwords: app.resolve<PasswordService>(PASSWORD_CAPABILITY) };
}
```

## Required application ports

Settings require the complete seven-method `resetStore`, its production/test
classification and positive `operationTimeoutMs` from 1 to 120000. They also
require `secretProvider`, `resetHmacKeyRef`, `authority`, explicit `policy`,
`resetTtlMs` from 1 to 3600000 and `maxResetAttemptsPerHour` from 1 to 100000.
Providers explicitly marked test-only are rejected outside the test environment.
A production label does not prove a provider secure.

Configured methods retain their original receiver and implementation. Callable
`bind`, `name` and `length` properties are never evaluated. Proxy providers or
callbacks, accessors and prototype traversal beyond 32 levels fail configuration
validation; later method replacement does not change captured providers.

`resetCommitter.commitReset` is mandatory. This typed completion supplies the
atomic persistence already required by reset semantics: the exact live reset
version must be consumed, the account's password replaced and its prescribed
session invalidation applied in **one native backend transaction**. The input
carries the canonical subject, reset namespace/ID/version/owner and replacement
PHC. The committer must enforce ownership, current account policy and expiry
at that boundary. A false receipt means definite rejection without changes;
an uncertain commit must throw. A true receipt is returned only after commit.

The module never deletes a reset before calling an unrelated password callback.
It rechecks consumption after the native acknowledgement. This is not a
cross-database transaction protocol: all participating state must support the
same application-owned atomic boundary. The
[PostgreSQL guide](../../examples/postgres/passwords.md) verifies actual password
replacement and existing-session revocation, including rollback and contention.

`authority.require` independently checks server-owned authentication, account,
tenant and authorization state. Caller-built subject objects are only hints.
Issuance first authorizes the supplied actor with `password.reset_authorize`,
then the target with `password.create_reset`; the latter receives the canonical
actor in typed `context.authorization`. Consumption calls
`password.consume_reset` after keyed token proof. That recovery policy may
allow a legitimate bearer without an existing browser session, while checking
the live account and tenant. None of these methods grants login or MFA.

## Hashing and verification

| Method                                          | Effect                                                                       |
| ----------------------------------------------- | ---------------------------------------------------------------------------- |
| `hash(plain, policy?, options?)`                | Returns a newly salted Argon2id PHC string after applicable breach policy    |
| `verify(plain, stored, options?)`               | Returns `valid` and `rehashRecommended` for the supplied trusted stored hash |
| `needsRehash(stored)`                           | Synchronously compares a bounded PHC with the configured target parameters   |
| `createReset(subject, authorization, options?)` | Returns a new one-time reset value after durable issuance                    |
| `consumeReset(token, newPassword, options?)`    | Hashes the approved new password and calls the atomic committer              |

Defaults match the backend: Argon2id version 19, a random 16-byte salt, a
32-byte result, 65536 KiB memory, time cost 3 and parallelism 4. Default minimum
length is 12 Unicode code points. These are policy defaults, not performance
certification; calibrate approved parameters on target hardware before release.
Bounds are 262144 KiB, time cost 10, parallelism 16 and minimum-length setting
at most 128. Native memory must be at least eight times parallelism. Per-call
policy cannot lower configured costs/minimum length or disable required breach
checks. Applications remain responsible for approving a secure configured floor.

Plaintext is limited to 1024 UTF-8 bytes, preserves spaces and Unicode exactly,
and is never normalized. Malformed UTF-16 is rejected. Owned byte buffers are
cleared, and the native worker requests password/secret clearing in the reference
implementation. JavaScript strings and upstream copies cannot be guaranteed
securely erased. There is no hardcoded or implicit pepper.

Verification accepts bounded Argon2id PHCs, including supported older parameters,
and uses dummy native work for malformed or unsupported PHCs. It rejects
excessive memory/time/thread costs before invoking the native binding. This
reduces cheap malformed-hash differences without promising constant end-to-end
timing. Rehash recommendation does not write credentials or silently downgrade
their parameters: the application chooses the approved replacement policy.

Load `stored` from the trusted account backend, never from an HTTP client.
`verify` proves a match against that hash; it does not establish account
ownership, issue identity or bypass MFA. `hash` prepares a credential without
writing an account. Ordinary password changes must use the application's own
authorized transaction and session-invalidation policy.

## Breach checks and bounded resources

Blocking breached passwords defaults to true. A configured `breaches.lookup`
provider is then mandatory. The module computes a SHA1 digest solely for the
k-anonymity lookup and sends only its five-character uppercase prefix. Password
storage always uses Argon2id. The provider returns at most 20000 distinct
35-character uppercase suffixes with nonnegative integer counts; matching
remains local. Missing, malformed, oversized or unavailable results fail closed.
Use a trusted source and verified TLS, bounded responses and secure retention
policy. Never log prefixes, suffixes, passwords or complete digests. This check
applies to newly created/replacement passwords. Existing-password verification
checks the stored credential and resource policy; applications separately
enforce compromised-account actions.

Each application admits 32 operations, with two physical native KDF permits
and no queue. Timed-out workers keep permits until they settle. Hash/verify
share a durable 1000-attempt fixed-minute budget; reset issuance/consumption
share the configured fixed-hour budget across participating instances using
the same store. These are global technical budgets, not per-user/IP quotas.
Deploy trusted ingress/account policy to prevent starvation. Counter contention
gets up to eight bounded re-evaluations; credential transitions are not retried
after ambiguous writes. Clock overrides, zero deadlines and forged signals
are rejected. Injected resources remain application-owned after shutdown.

## Reset tokens and errors

Tokens use `pr1.<UUID>.<32-random-byte-secret>` and must reach only the intended
recipient through the application's approved recovery channel. The database
holds a domain-separated HMAC-SHA256 verifier, external key version, owner
binding and expiry, never the raw token. Secret material must come from the
configured provider with at least 32 bytes of adequate external entropy and
must never be persisted in application state or diagnostics.

Issuing a replacement reset atomically invalidates the previous live reset
under the owner guard. The current reset-key version is required for proof;
rotating that reference invalidates outstanding older-version tokens. Retain
an approved stable version through the desired recovery window when continuity
is required. This is not instant cancellation of already verified application
work. Expired physical rows require application/backend retention cleanup.

Failures use fixed English messages without provider causes:
`EK_PASSWORD_POLICY`, `EK_PASSWORD_INVALID`, `EK_PASSWORD_RESET` and
`EK_PASSWORD_KDF`, alongside core validation/cancellation/deadline/closed-resource
codes. Interrupted writes report `outcome: 'unknown'`; reconcile the account
state rather than asserting rollback. A reset returns no session or assurance.

Optional scoped telemetry exports fixed `password.<operation>` spans,
millisecond duration histograms, completion counters and accepted/denied
verification counters. Audit/export regression tests exclude plaintext, PHCs,
reset tokens, subjects and key verifiers. No monetary cost is calculated.

Run `pnpm --filter @arkenivajs/security-password test` and the executable SQL
guide. Performance, native architecture evidence, required remote CI and
production-provider review remain separate release requirements.
