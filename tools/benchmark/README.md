# Local foundation measurements

Performance comparisons run through the explicit
[manual performance workflow](../../.github/workflows/performance.yml) after
functional implementation and verification. Automatic CI keeps functional,
integration, security, privacy-regression and benchmark-analysis tests active.
Manual measurement results remain required evidence for their release gates;
deferring execution does not count a measurement as passed.

The [identifier comparison](identifiers.md) verifies native/public UUID parity in
four isolated profiles before any optional exploratory timing is requested.

The [validation comparison](validation.md) checks a fixed email/URL/IP/UUID/schema
corpus against the pinned native libraries through the same isolated profiles.

The [password verification](password.md) checks native/public Argon2id results
and actual PostgreSQL KDF admission counters in four isolated profiles.

The [SMTP verification](mail.md) checks actual STARTTLS authentication and received
MIME attachments through an owned temporary server in four isolated profiles.

The [CSV verification](csv.md) exchanges native/public CSV and TSV streams,
including one-shot fragmented UTF-8 sources and exact text fields.

The [logging comparison](logging.md) validates actual acknowledged JSON rows,
redaction, child bindings and level filtering before optional local sampling.

The [configuration comparison](config.md) checks source precedence, immutable
snapshots and atomic validated reload using a fixed nonsecret corpus.

The [compression verification](compression.md) consumes actual GZIP/ZIP streams
and exchanges native/public archives; streaming measurement remains separate.

The [barcode verification](codes.md) checks actual native/public image
interoperability in four profiles; resource sampling awaits child accounting.

The [time comparison](time.md) checks native Temporal/Intl parity, nanoseconds
and elapsed DST transitions without changing the process timezone.

The [diagnostics comparison](diagnostics.md) checks actual process CPU bounds,
memory, timestamps and interval event-loop semantics in four isolated profiles.

The [DNS comparison](dns.md) exercises an actual owned loopback authority, every
supported record family and completed asynchronous calls in four profiles.

The [health comparison](health.md) verifies actual successful and failed HTTP
dependency probes, independent liveness and private SDK observations in four profiles.

The [HTTP security header comparison](http-security.md) checks native Helmet and
public framework hardening on actual success and error responses in four profiles.

The [multipart verification](upload.md) checks actual chunked streaming, ordered
parts, consumed-file digests and SDK privacy in four isolated profiles.

The [Redis cache comparison](cache.md) verifies actual stored JSON, TTL, expiry,
corrupt-state rejection and acknowledged roundtrips against the real TLS backend.

The [webhook verification](webhooks.md) checks native signature interoperability,
unchanged body bytes and one-use nonce claims against actual PostgreSQL state.

The [LDAP verification](ldap.md) compares actual verified service/user binds and
directory lookups without claiming incomplete native child resource measurements.

The [OAuth machine-grant verification](oauth.md) checks actual HTTPS token requests,
persisted SQL grant budgets and private SDK exports in four isolated profiles.

The [XLSX verification](xlsx.md) exchanges native/public typed and styled workbooks,
one-shot sources and awaited targets without claiming incomplete child measurements.

The [PDF verification](pdf.md) exchanges actual searchable documents, metadata,
rotated text and ordered merged pages through the same four isolated profiles.

The [SFTP/SSH verification](sftp.md) checks pinned-host file exchange, actual hashes,
remote cleanup and literal allowed commands against the owned OpenSSH server.

The [Redis comparison](redis.md) checks portable operation results, actual server
state and ephemeral subscriber observations before optional bounded roundtrips.

The [SQL query comparison](sql-query.md) checks actual PostgreSQL bound rows,
bigint precision, pool release and four isolated instrumentation profiles.

The [socket verification](socket.md) checks five actual TCP/TLS/UDP/Unix scenarios
with independent native client processes and four isolated server profiles.

The [Core NATS verification](nats.md) checks actual mutual-TLS wire interoperability
with a separate native observer and no invented broker acknowledgment.

The [AMQPS verification](amqp.md) checks actual publisher confirms, mandatory
returns, binary/header interoperability and dedicated topology retirement.

The [MySQL query comparison](mysql-query.md) verifies actual prepared results,
native bigint text precision, released ownership and bounded four-profile samples.

The [MariaDB query comparison](mariadb-query.md) independently preserves native
bigint results and verifies actual pool counters across the four profiles.

The [XML interoperability verification](xml.md) checks ordered mixed content,
namespace prefixes, native writer roundtrips and actual SDK privacy.

The [JSON workflow verification](json.md) checks native schemas, actual declarative
mapping semantics, deterministic serialization and missing/null distinctions.

The [SOAP HTTPS verification](soap.md) checks actual native WSDL interoperability,
server-observed calls, explicit TLS trust and real SDK privacy.

The [gRPC mTLS verification](grpc.md) checks native unary/streaming protobuf fidelity,
independent server counts and actual framework chain/revocation checks.

The [magic-link comparison](magiclink.md) verifies actual one-use SQL consumption,
concurrent winner counts, external HMAC/authority and exact persisted quotas.

The [core lookup comparison](core.md) verifies actual public capability identity
and lifecycle boundaries in four profiles without adding per-lookup instruments.

The [API key verification smoke](apikey.md) compares the public credential
adapter with the same native HMAC, durable quota and trusted-authority work in
four isolated profiles, checking actual PostgreSQL increments and export privacy.

The [certificate utility smoke](x509.md) compares native parsing, expiry,
fingerprints and actual TLS/CRL verification in four isolated profiles.

The [native cryptography smoke](crypto.md) compares eight operations in four
isolated profiles with actual OTLP exports, fixed offers and privacy checks.

The [durable MFA harness](mfa.md) adds bounded four-mode TOTP/WebAuthn/challenge
smoke measurements with actual SQL, a controlled authenticator and export privacy checks.

This Tinybench workload measures errors, strict configuration reads/loads, an isolated application's start/stop, Pino logging and native process snapshots. It exercises the same public package entries used by applications. It requires a built workspace and Node.js 24; no server or database is needed.

Run from the workspace root:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --silent --filter @arkenivajs/benchmark-foundation start
```

Standard output is a measured JSON report. Redirect it to a protected location outside the checkout when retaining results. The script fails on task errors, missing samples, transport failure or dropped framework log lines. Raw measurements, profiles and reports do not belong in Git.

Each scenario warms up for 100 iterations, then measures 1,000 operations (100 for configuration loading and application lifecycle). Runs are sequential, with one independent repetition. Latencies use milliseconds and include the timer's overhead; p95 is interpolated from the retained sorted samples. CPU deltas include warmup and measurement, and RSS records only the interval's endpoints. Unsupported values use `null` or appear in the measurement coverage list. No environment-variable dump is collected.

The report records the commit, exact runtime, tool versions, CPU model, affinity, governor and container limits where available. Its `BASELINE` rows call underlying Node/Pino APIs directly; `FRAMEWORK` rows include the additional framework work. Error serialization and strict configuration validation perform extra work, and process snapshots also add timestamps and event-loop counters. These component measurements do not establish equivalent end-to-end overhead. Logging uses a synchronous in-memory sink with matching service context and credential redaction, excluding disk/network durability and realistic contention.

Every report has `measured:true` and `releaseGate:false`. Shared-host timing, brief warmup and one repetition cannot prove a regression budget. A release comparison requires equivalent HTTP, authentication and database workloads in baseline, framework, standard telemetry and detailed modes, a dedicated runner, at least 60 seconds of warmup, 180 seconds of steady load and five independent repetitions, with confidence analysis and retained raw evidence. Those workloads require their respective implemented modules. Do not infer request or tenant CPU/RAM from whole-process counters.

`pnpm --silent --filter @arkenivajs/benchmark-foundation metering` exercises trusted meter scopes with export disabled and with real private JSONL export. It uses the same 100 warmup/1,000 measured iteration policy and reports observed scope/enqueue latency, whole-process CPU/RSS, queue/drop/failure counts and actual file readback. File dispatch overlaps the measured asynchronous work; the final flush/readback verifies delivery without pretending enqueue latency is durable acknowledgment latency. The operation counter records one actual benchmark callback invocation; it does not represent a database query. Temporary files are removed. Keep the JSON report outside the checkout; this is a local component observation with `releaseGate:false`.

`pnpm --silent --filter @arkenivajs/benchmark-foundation sql` measures the named
binding compiler in four dialects with representative quoted tokens, comments and
repeated bigint parameters. Each dialect warms up for 1,000 operations and measures
10,000 operations. Assertions verify the exact number of compiler calls and consume
their output. Latency includes value capture and the statement fingerprint; no
database connection or query is involved. Whole-process CPU and event-loop deltas
include warmup and benchmark overhead. RSS is sampled at interval endpoints, while
event-loop delay and GC pauses remain null. Retain the JSON outside the checkout;
this short component workload has `releaseGate:false`.

`pnpm --silent --filter @arkenivajs/benchmark-foundation postgres` compares a real
PostgreSQL `SELECT` through direct `pg`/`pg-cursor` and through the SQL facade.
It requires the [disposable TLS fixture](../../packages/database-postgres/test/fixtures/README.md),
`ARKENIVA_POSTGRES_URL` and `ARKENIVA_POSTGRES_DISPOSABLE=1`. Use the fixture's
private environment runner rather than printing or pasting its credentials.
`ARKENIVA_POSTGRES_IMAGE` and `ARKENIVA_POSTGRES_CONTAINER_LIMITS` can supply
non-secret fixture metadata; omitted metadata remains null rather than guessed.

Both paths verify TLS identity, use a pool maximum of two, discard session state,
restore UTF-8/standard strings and fetch at most two rows. Both assert the same
integer result. The framework path additionally validates/captures named bindings,
computes a fingerprint and owns cancellation and observation boundaries.
Each path warms up for 100 operations and measures 1,000 sequential operations.
The report records the actual server version, p50/p95/p99/max client latency,
whole-client-process CPU/memory/loop observations and waiting counts sampled after
completion. Those samples do not establish the maximum queue length under load.
Server CPU, network bytes, GC pauses and exporter drops remain unobserved.
Tracing, metrics and metering are disabled. This short, single-repetition component
comparison has `releaseGate:false`; it does not replace the dedicated four-mode
HTTP/authentication/database measurements and soak runs required before release.

## Matched HTTP, authentication and PostgreSQL workloads

See the [server equivalence contract](http-worker.md),
[statistical method](analysis.md) and [private tool installation](runtime.md)
for independently testable components.

The `http` command compares the same three GET routes in four isolated server
processes. `/json` is public, `/authenticated` verifies an actual RS256 JWT and
scope, and `/database` additionally executes a parameterized PostgreSQL query.
Every successful response is exactly 128 bytes. The native baseline uses Fastify,
Ajv, JOSE, Pino and `pg`/`pg-cursor` directly, including certificate verification,
pool maximum two, session reset and bounded result fetching. The framework modes
use public package entries for the same work. Standard tracing samples at 0.1;
detailed tracing samples at 1 and records a V8 CPU profile at 10 ms intervals.
Both instrumented modes export verified tenant usage to private JSONL files and
send telemetry to the real disposable collector. Framework mode omits those two
plugins; baseline mode uses the underlying libraries directly.

First validate identity failures, actual database work, safe output and cleanup:

```sh
pnpm --filter @arkenivajs/benchmark-foundation test
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm --filter @arkenivajs/benchmark-foundation test:integration
```

The integration command also requires `ARKENIVAJS_OTLP_ENDPOINT` pointing at the
[disposable OTel collector](../../packages/telemetry/test/fixtures/compose.yaml).
It fails when infrastructure is absent; it never substitutes mocked queries.

### Install load tools inside a disposable Linux x64 VM

Use Python 3.12 or later. The installer creates a new private directory outside
Git, verifies pinned SHA-256 archives for Node 24.22.1 and k6 2.3.0, and installs
Corepack 0.36.0 within that directory. It changes no system packages. Archive
extraction has path, file-count and size bounds; existing targets are rejected.
Keep the source checkout inside the same VM for execution and build it with its
frozen lockfile before running the benchmark.

```sh
python3 tools/benchmark/prepare-runtime.py /private/benchmark-tools
export PATH="/private/benchmark-tools/node-v24.22.1-linux-x64/bin:/private/benchmark-tools/corepack/node_modules/.bin:$PATH"
export ARKENIVA_BENCHMARK_K6=/private/benchmark-tools/k6-v2.3.0-linux-amd64/k6
export ARKENIVAJS_OTLP_ENDPOINT=http://127.0.0.1:4318
pnpm install --frozen-lockfile
pnpm build
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json node tools/benchmark/http.mjs /private/http-smoke --smoke
```

k6 is an external AGPL-3.0 development executable, never a runtime dependency or
part of a package archive. Node retains its MIT and bundled dependency notices;
Corepack is MIT. Official artifacts and license texts remain in the private tool
directory. Load-tool usage reporting is disabled explicitly. Review current
upstream security information before updating tool pins.

### Long comparisons and soak

The default campaign uses five independent repetitions of all four modes in a
seeded randomized order: 60 seconds of warmup and 180 seconds of measured load
per run. Each route receives 50 requests/second with 25 preallocated and maximum
virtual users. Offered load stays fixed when responses slow down; errors,
dropped iterations, incorrect response bytes and observed exporter failures
fail the run. These checks do not establish maximum sustainable capacity.

Long runs require a clean committed checkout, `ARKENIVA_BENCHMARK_RUNNER=disposable-vm`,
at least 5 GiB of free artifact space, and `ARKENIVA_BENCHMARK_FIXTURE_METADATA`
pointing to a protected JSON description of actual fixture image digests and
resource limits. Supply measured infrastructure metadata without credentials.
`ARKENIVA_BENCHMARK_SERVER_CPU` and `ARKENIVA_BENCHMARK_LOAD_CPU` optionally pin
the owned processes through Linux `taskset`; the report records those choices.
Give each command a new output directory outside Git:

```sh
export ARKENIVA_BENCHMARK_RUNNER=disposable-vm
export ARKENIVA_BENCHMARK_FIXTURE_METADATA=/private/fixture-metadata.json
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json node tools/benchmark/http.mjs /private/http-campaign
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json node tools/benchmark/http.mjs /private/http-soak --soak
```

The separate soak warms up for 60 seconds, then measures STANDARD mode for one
hour. Campaign minimum load time is 80 minutes; soak minimum load time is 61
minutes, plus process preparation and final flush. `--smoke` runs only one
repetition with one second of warmup and three measured seconds and must not
be presented as long-run evidence.

### Evidence and interpretation

Each protected run retains compressed raw k6 JSON, summaries, application logs,
meter events, a server resource time series and, in detailed mode, a CPU profile.
`environment.json` records the exact commit, versions, OS, affinity, limits,
workload and explicit coverage gaps. Short-lived token configuration files are
removed after each load phase. `report.json` and `summary.csv` retain measured
results; partial failures leave an explicit failure record. No artifacts belong
in the product checkout or Git history.

Latency percentiles describe client HTTP send/wait/receive time; raw k6 output
also retains connection/blocking observations. RSS and heap are sampled once
per second; short peaks can be missed. Pool waiting and logger/meter queue maxima
are sampled, not exhaustive histories. CPU, GC, memory and event-loop values
belong to the server process across all three route classes; they cannot be
assigned exactly to a request or tenant. The CPU interval includes measured
load-process preparation and graceful completion. Export flush and CPU-profile
shutdown are outside that CPU interval. Client bytes are observed application
traffic rather than billed egress or complete packet measurements.

Comparisons resample whole paired repetitions 10,000 times with a fixed seed,
report 95% percentile confidence intervals, and expose baseline variation.
They do not treat thousands of requests as independent infrastructure trials.
Physical host contention and virtualization remain reported limitations. All
reports use `releaseGate:false`: preliminary relative budgets and near-zero
latency absolute budgets require calibration and explicit approval before they
can become release gates. A successful command proves its recorded checks and
measurements, without asserting production capacity or a regression budget.
