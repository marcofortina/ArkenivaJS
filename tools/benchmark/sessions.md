<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native durable session-validation comparison

Build the complete workspace and load the owned disposable verified-TLS
PostgreSQL fixture environment:

```sh
pnpm --filter @arkenivajs/benchmark-foundation sessions --verify /private/sessions-verification
```

Four isolated profiles compare a benchmark-only positive-session reference with
the public session service and actual standard/detailed SDK instrumentation. The
parent reuses signed primary authentication, durable authentication events and
external HMAC providers to issue four real public sessions. Explicit test-only
authority decisions preserve the original fixture MFA assurance. Workers never
receive HMAC keys or independently grant account/tenant authority.

Both paths validate the same durable protocol through actual HMAC, current owner
epoch and account authority. They reserve verification attempts and update idle
activity using native hashing and real PostgreSQL CAS. Every profile validates
twice and rejects a modified bearer secret. Original authentication/MFA times,
assurance, creation time and absolute expiry cannot advance during activity.
Independent parent readback verifies all refreshed rows and their actual stored
HMACs. Outage tests leave session rows untouched until storage, HMAC and authority
return; incrementing the actual owner epoch revokes otherwise valid tokens.
Production configuration rejects the explicit test-only ports.

The native reference implements only the declared valid-session protocol. It is
not a production session implementation. It omits full hostile-record and
invalid-token admission handling, complete freshness policy, cancellation,
retry jitter/classification and lifecycle policy. This comparison makes no
creation, renewal, individual revocation, full cross-pod or production-provider
equivalence claim. A session token may be validated repeatedly while active;
ordinary activity is never a new authentication or MFA event.

The bounded bearer-authenticated bridge exposes only validation namespaces and
providers. Reports and actual SDK exports must exclude bearer secrets, identities,
keyed digests and provider credentials. Shutdown settles provider work and removes
the parent's exact owned SQL schema and issuer resources.

Only `--verify` is supported. Sampling is rejected before fixture allocation
until complete provider/server resource accounting is available. Reports retain
`releaseGate: false`; dedicated-runner budgets, five paired repetitions and
one-hour soak acceptance remain separate work.
