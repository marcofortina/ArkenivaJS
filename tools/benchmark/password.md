# Native Argon2id functional comparison with durable admission

Build the workspace, start the owned verified-TLS PostgreSQL fixture and export
its documented `DATABASE_URL` and `ARKENIVA_POSTGRES_DISPOSABLE=1` environment.
Choose a fresh absolute output directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation password --verify /private/password-verification
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

Only `--verify` is accepted. Reports use `measured: false`, null resources,
no timing samples and `releaseGate: false`. Actual standard/detailed SDK exports
must contain no plaintext, PHCs, database credentials or bridge authorization.
Production KDF calibration, controlled saturation, full process memory and
equivalent end-to-end performance measurement remain separate release work;
no repeated campaign or one-hour soak is claimed.
