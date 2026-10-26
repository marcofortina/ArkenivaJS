# API key verification smoke measurement

This exploratory harness compares one positive API key verification through four
isolated worker processes. It requires a built workspace and the
[owned verified-TLS PostgreSQL fixture](../../packages/database-postgres/test/fixtures/README.md).
It implements no full campaign or soak command.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/benchmark-foundation test
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm --filter @arkenivajs/benchmark-foundation apikey --smoke /private/fresh-apikey-smoke
```

The private mapping supplies `DATABASE_URL` and
`ARKENIVA_POSTGRES_DISPOSABLE=1`. The normalized report directory must be fresh,
absolute and outside the repository, including through symlinked parents.
Credentials never enter command arguments or worker environment variables.
Reports/directories use private permissions. No packages are published.

## Matched work and profile boundaries

The parent creates one ephemeral credential through the public API after actual
signed OIDC authentication. Every worker receives the same token, approved scope,
network policy and account binding over closed IPC. Native HMAC keys remain in
the parent fixture, together with the complete PostgreSQL state provider and
independent account authority. Each verification performs the same durable
attempt reservation, credential reads, HMAC proof, native CIDR check, fresh
authority decision, opaque owner-index derivation and final version check.

| Profile     | Behavior                                                                                              |
| ----------- | ----------------------------------------------------------------------------------------------------- |
| `BASELINE`  | Direct native-HMAC/subnet reference through the same shared provider workflow                         |
| `FRAMEWORK` | Public `ApiKeyService.verify`, finite admission/deadline/validation/audit path, telemetry uninstalled |
| `STANDARD`  | Public service with actual SDK metrics and 10% sampled operation spans                                |
| `DETAILED`  | Public service with actual SDK metrics, full operation tracing and closed-name provider spans         |

The baseline is a positive-corpus comparison reference, not an authentication
service for applications. It retains crypto, storage and authorization checks
without recreating the public adapter's complete hostile-input validation,
admission or audit machinery. The common store already uses the framework's
SQL abstraction over actual PostgreSQL. This isolates the additional credential
adapter cost, not the difference between bare HMAC and complete authentication,
or the SQL facade's own overhead. IPC/provider costs are common to all profiles.
Only the benchmark's fixed, approved corpus is measured.

Every profile warms up with five verifications, then offers 50 at a fixed rate
of 25/second with concurrency one. Missed/saturated offers are counted, with no
queue or catch-up burst. Runs fail on any operation error, drop or failed
conformance check. Provider calls and real PostgreSQL counter increments prove
that no profile skipped work:

| Provider boundary per profile | Acknowledged calls                                     |
| ----------------------------- | ------------------------------------------------------ |
| HMAC digest                   | 57: two bootstrap calls and 55 owner-index derivations |
| HMAC verification             | 55                                                     |
| Shared state read             | 165                                                    |
| Atomic attempt CAS            | 55                                                     |
| Independent authority         | 55                                                     |
| Total                         | 387, with exactly 55 durable attempt increments        |

The report records deterministic profile ordering, exact source-file hashes,
parent commit/dirty state, Node/OpenSSL/FIPS versions, PostgreSQL version and
hardware/affinity/governor information. Source files must not change while a
measurement runs. A report from uncommitted source keeps that fact; a later
commit does not retroactively change its recorded SHA.

## Measurements and privacy

Latency covers each verification promise; common result-conformance assertions
are outside the latency sample but inside resource windows. Reports retain all
50 latency samples plus p50/p95/p99/max, achieved throughput and input bytes.
These are method-input bytes, not HTTP wire traffic.

Child CPU/RSS/heap/GC/event-loop measurements include setup, warmup, paced waits,
SDK background work and flush. Memory uses 10 ms samples plus explicit
boundaries, not an exact allocation maximum. Parent CPU separately includes
native HMAC, SQL-provider/authority work, IPC validation and OTLP capture over
each worker's whole lifetime; parent RSS uses boundaries only. Do not add those
windows as precise per-request CPU or tenant allocation.

The bounded loopback OTLP receiver permits eight active requests, 1 MiB per body
and 32 MiB total. It inspects actual JSON exports for credentials, keyed
verifiers, account/tenant bindings and bootstrap material. The absence marker
`''` is not sensitive corpus content; all nonempty values and versioned verifier
components remain checked. Regression tests prove that empty metric descriptions
do not mask real whole-value or embedded secret leaks. Exporter drops/failures
must be zero. Repeated body counts are observed; an exact exporter retry counter
is unavailable and remains `null`.

No raw corpus, OTLP bodies or sensitive comparison fingerprints are persisted in
the report. Worker diagnostics are never forwarded. Shutdown aborts outstanding
provider work and closes owned listeners, applications and schemas. The parent
has a 60-second worker watchdog. Providers are test-only native fixtures, not
production key-management certification.

Results have one run iteration, `confidenceInterval95:null` and
`releaseGate:false`. They do not establish capacity, calibrated regression
budgets, negative-path timing equivalence, performance of other API key methods,
five independent campaigns or the deferred one-hour soak.
