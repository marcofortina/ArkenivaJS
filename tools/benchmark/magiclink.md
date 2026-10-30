<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native durable magic-link consumption comparison

Build the complete workspace and load the owned disposable verified-TLS
PostgreSQL fixture environment:

```sh
pnpm --filter @arkenivajs/benchmark-foundation magiclink --verify /private/magiclink-verification
```

Four isolated profiles compare a benchmark-only native positive-corpus consumer
with the public service and actual standard/detailed SDK instrumentation. The
parent reuses the existing signed-authentication/account and external HMAC fixture
to issue four actual public magic links. HMAC key bytes remain in that external
provider; workers receive only scoped authenticated provider calls and one grant
per profile. No TypeScript object alone grants account or tenant authority.

Both paths verify through the same real HMAC provider, independently authorized
account lookup and PostgreSQL atomic batch. Two concurrent consume attempts must
produce exactly one winner and one loser. Subsequent replay, GET prefetch and
wrong-purpose attempts fail. Parent database readback independently requires four
consumed records, four successful atomic batches and a consume quota of exactly
four. Provider outage tests preserve SQL state until storage, HMAC and authority
are restored. Production configuration rejects the explicit test-only ports.

The native reference is limited to the declared valid issued-record protocol and
uses the native hash primitive with the existing provider implementations. It is
not a production magic-link implementation or a replacement security algorithm.
It omits full hostile-record validation, startup negative probes, admission,
cancellation, retry classification and lifecycle policy. The comparison makes no
issue/revoke equivalence, full cross-pod acceptance or MFA assurance claim.

The bearer-authenticated loopback bridge is bounded and restricted to the exact
consume namespaces. It never exposes HMAC keys. Reports and actual SDK exports
must exclude tokens, one-time URL fragments, keyed digests, identities and provider
credentials. Parent shutdown settles provider work and removes its owned SQL
schema and issuer resources.

Only `--verify` is supported. Sampling is rejected before fixture allocation
until complete provider/server resource accounting is available. Reports retain
`releaseGate: false`; dedicated-runner budgets, five paired repetitions and
one-hour soak acceptance remain separate work.
