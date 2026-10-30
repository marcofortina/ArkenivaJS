<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native Argon2id verification with durable admission

Build the workspace, start the owned verified-TLS PostgreSQL fixture and export
its documented `DATABASE_URL` and `ARKENIVA_POSTGRES_DISPOSABLE=1` environment.
Choose a fresh absolute output directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation password --verify /private/password-verification
pnpm --filter @arkenivajs/benchmark-foundation password --smoke /private/password-smoke
```

Four isolated profiles execute native argon2 0.45.1 and the public password
service. Each checks two independently salted hashes, a matching password,
a wrong password and verification/rehash of a legacy lower-cost hash. Inputs
are random disposable values. Native verification independently checks the
publicly produced PHC. No reset or login is performed.

The public service uses the existing PostgreSQL example's actual transactional
store through a bounded owned loopback bridge. The final report requires exactly
15 persisted admissions and 30 completed store calls across the three public
profiles; the bare Argon2 baseline has no durable admission. The private schema
and listener are removed. No in-memory persistence fallback is introduced.
The comparison's secret provider is explicitly test-only; authority and reset
committer ports deny all operations, and production startup rejects the fixture.

This fixed workload uses 8192 KiB, one time pass and one Argon2 lane to bound
functional-test resources. These are test parameters, not production advice or
hardware calibration. Native KDF memory is not an observed per-request RSS value.
The bare baseline omits durable rate control and other public policies.

Optional `--smoke` retains 100 actual Tinybench positive-verification samples
after 20 warmup callbacks per profile. The parent generates one current PHC
outside timing using the same pinned native backend and parameters. Each timed
callback awaits actual verification, including the public service's durable
budget calls, and all 120 private results must be valid with no rehash needed.
Private retained results are bounded at120 with an explicit128 cap and cleared
before worker completion. No hash generation, reset or login latency is claimed.

The three public profiles add360 durable admissions to the15 original untimed
verification admissions; the native baseline does not access SQL. Parent SQL
readback independently requires375 reservations,375 successful reads and375
committed compare-and-set writes,750 completed store calls in total. Every
stored quota retains the unchanged1000-per-minute bound; no budget is reset or
overridden. Parent native Argon2 independently checks the original current PHC
and rejects a wrong password after the measured workload.

Worker CPU includes native KDF threads. Parent provider/SQL-client and PostgreSQL
server CPU/RSS remain explicitly unknown and excluded. These observations do not
establish native/public admission-policy or complete resource parity. Actual
standard/detailed SDK exports must contain no plaintext, PHCs, database
credentials or bridge authorization. All reports retain `releaseGate: false`.
Production KDF calibration, controlled saturation, full process memory and
equivalent end-to-end performance measurement remain separate release work;
no repeated campaign or one-hour soak is claimed.
