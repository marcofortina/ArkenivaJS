<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native durable session-validation comparison

Build the complete workspace and load the owned disposable verified-TLS
PostgreSQL fixture environment:

```sh
pnpm --filter @arkenivajs/benchmark-foundation sessions --verify /private/sessions-verification
pnpm --filter @arkenivajs/benchmark-foundation sessions --smoke /private/sessions-smoke
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

`--verify` runs the positive and negative corpus without latency sampling.
`--smoke` adds 20 warmup validations and exactly 100 retained Tinybench latency
samples per profile. Each sample validates the same parent-issued active MFA
session and includes actual provider bridge round trips, HMAC, signed authority,
PostgreSQL reads, verification-attempt CAS and conditional activity CAS. The
existing trusted clock determines whether activity needs an update; the harness
does not force a new CAS, authentication or MFA event per sample. Measured
identities must preserve the original subject, issuer, tenant, authentication
time, MFA time and assurance.

Worker completion counts reconcile the real warmup and retained sample counts.
The parent independently checks all stored session HMACs and fixed absolute
expiry, then re-reads every verification-attempt row touched by the campaign.
Observed provider calls, successful attempt CAS and SQL count deltas must match
the actual successful validations plus the four rejected modified secrets.
Reports contain numeric protocol counts, never attempt-row keys or keyed MACs.

Child resource samples cover each worker measurement, including warmup and tool
import. `durable-observation.json` separately records actual process-wide parent
CPU, sampled RSS/heap, event-loop and GC observations across the whole campaign
after session issuance through independent readback. This includes child setup,
verification and teardown, the bridge, HMAC, authority, SQL client and collector.
It excludes fixture creation and final schema/issuer cleanup. Parent campaign
totals cannot be attributed to individual profiles or added to one profile's
resource costs. PostgreSQL server resources remain explicitly unknown (`null`).

This bounded single campaign is not complete resource parity or a release
measurement. Reports retain `releaseGate: false`; creation/renewal/revocation
measurements, dedicated-runner budgets, five paired repetitions and one-hour
soak acceptance remain separate work. Unsupported modes are rejected before
fixture allocation.
