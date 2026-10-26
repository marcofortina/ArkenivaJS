# Durable MFA measurements

The `mfa` command exercises TOTP verification, WebAuthn assertion verification and
atomic challenge create/claim against the disposable PostgreSQL fixture. Actual
signed OIDC identities, external test AEAD material and the controlled Chromium
authenticator are used. Cryptography remains in pinned otplib/SimpleWebAuthn; the
benchmark adds no authentication algorithm or public framework option.

Follow the [browser/database setup](../../examples/postgres/webauthn-browser.md),
build the workspace, then run through the database fixture's private environment:

```sh
export ARKENIVA_POSTGRES_DISPOSABLE=1
export ARKENIVA_WEBAUTHN_BROWSER_DISPOSABLE=1
export ARKENIVA_WEBAUTHN_BROWSER_URL=http://127.0.0.1:19222
pnpm --filter @arkenivajs/benchmark-foundation mfa --smoke /private/mfa-smoke
```

`DATABASE_URL` comes from the protected fixture; never put its value in commands
or tracked files. The output directory must be new, absolute and outside the
repository. Its parent must already exist. It retains private reports, raw
latency samples, JSONL meter events and controlled OTLP payloads, with directory
mode 0700 and file mode 0600. The HTTP frontend and OTLP sink are short-lived
loopback test servers; PostgreSQL and Chromium can remain in the isolated VM.
The pinned browser dependency is frontend/test tooling only.

Four isolated Node workers run in a reproducible seeded order:

- `BASELINE`: direct upstream positive-path verifier orchestration, with actual
  authority, shared attempt limits, decryption/signatures, replay/version CAS and
  one-use evidence. Backing SQL providers are identical across modes. The reference
  in `mfa-native.mjs` is a benchmark fixture, separate from the public factor API.
- `FRAMEWORK`: the public factor service with diagnostic export disabled.
- `STANDARD`: public service plus actual trace sampling at 0.1 and tenant-scoped
  usage accounting with durable JSONL export.
- `DETAILED`: sampling at 1 and additional provider spans under the same workload.

Challenge create/claim uses the same application-owned state SPI in all modes;
its comparison measures instrumentation around that SPI. Bare PostgreSQL-driver
overhead remains the separate [SQL benchmark](README.md). Native MFA verification
uses the same persistence queries/providers as the service, rather than comparing
a cryptographic primitive alone to a complete factor lifecycle.

Smoke uses two warmup and twenty measured operations per scenario/mode, offered
at 20 operations/second with concurrency one. Input production/pacing is outside
verification latency; whole-worker CPU includes it and asynchronous exports.
The trusted **test clock** advances between proofs/batches, preserving OTP replay
and shared quota checks. These rates describe a controlled technical workload,
not a production per-account attempt allowance. Counterless WebAuthn uses the
same explicit owned-row bootstrap as the browser conformance fixture.

Each record includes p50/p95/p99/max and raw latency, achieved throughput,
errors, CPU, sampled RSS/heap, event-loop delay/utilization, observed GC,
queue/drop/export counts, synchronous `MeterSession.end()` latency and pool
observations. Export batch digests count actual attempts/retries without retaining
event identifiers in reports. Unsupported/disabled observations use `null` or
explicit coverage descriptions. GC and memory samples can miss short-lived peaks.
Provide nonsecret `PG_FIXTURE_IMAGE` and `ARKENIVA_BENCHMARK_RUNNER` metadata when
available; an image string is declared metadata, not independently observed image identity.

Metering and actual OTLP JSON output are checked for the synthetic factor,
challenge, signature and evidence material before success. The bounded HTTP sink
acknowledges actual SDK exports; production collector/backend persistence is a
separate integration gate. Successful reports require zero operation errors,
event drops, export failures and detected material leaks.

`--full /private/mfa-full` prepares one independent run with at least 60 seconds
of warmup and 180 measured seconds per scenario/mode. It still has
`releaseGate:false`. Five independent full campaigns, a dedicated controlled
runner, equivalent offered/achieved load and variance calibration are required
before a release comparison. The one-hour soak remains independent. Run long
campaigns only when scheduled/authorized; the smoke command performs neither.
Single-run changes have no confidence interval and cannot establish the proposed
five-percent budgets. Raw results belong outside product Git.
