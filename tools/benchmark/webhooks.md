<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Durable webhook signature verification comparison

Build the workspace and use the private environment runner for the
[owned PostgreSQL fixture](../../packages/database-postgres/test/fixtures/README.md).
Both `DATABASE_URL` and the fixture's explicit disposable flag are required.

```sh
pnpm --filter @arkenivajs/benchmark-foundation webhooks --verify /private/webhook-verification
```

Four isolated profiles compare direct Node HMAC-SHA256 with the public webhook
plugin and actual standard/detailed SDK instrumentation. An authenticated owned
loopback bridge supplies a test principal, an ephemeral random external test key
and the actual PostgreSQL atomic nonce store. The child never receives database
credentials. The bridge checks its bearer credential, allowed operations and
nonce namespace at runtime. Other transactional-store operations fail closed.

Native/public signatures must agree on raw body bytes including whitespace and
the final LF. Verification must reject a compact reserialization, accept the
original bytes exactly once and reject replay. Independent SQL readback requires
four persisted nonce rows from eight claim attempts, rather than trusting child
receipts. Reports and SDK exports exclude payload, bearer, key, principal and
tenant values. The parent waits for actual provider work before dropping only
its fresh owned SQL schema and erasing its test key.

This valid-corpus verification does not duplicate the framework's full hostile
input, rotation, clock-window, admission or lifecycle policy in the baseline.
Provider bridge calls add local HTTP overhead shared by both paths. They do not
recommend a production authentication or secret-store deployment. No outbound
delivery, retries, receipt durability or TLS transport performance is measured.

`--verify` emits no latency or resource samples and keeps `releaseGate: false`.
Integration tests use actual SQL and also reject unauthorized bridge access and
unsupported namespaces.

## Short measured component comparison

Run measurements only inside the owned disposable QEMU runner, with the existing
verified-TLS PostgreSQL fixture and private environment runner. Set
`ARKENIVA_WEBHOOKS_BENCHMARK_DISPOSABLE=1` in addition to
`ARKENIVA_POSTGRES_DISPOSABLE=1`; database credentials stay in the private parent
fixture. No additional dependency or service is required.

```sh
ARKENIVA_WEBHOOKS_BENCHMARK_DISPOSABLE=1 \
  pnpm --filter @arkenivajs/benchmark-foundation webhooks --smoke /private/webhook-smoke
```

Each of the same four isolated profiles measures one sequential
`sign-and-durable-verify` scenario with Tinybench: 20 warmup callbacks followed by
100 retained measured latency samples. Each callback creates a fresh random
24-byte nonce, signs the same unchanged padded payload and awaits a successful
actual atomic SQL nonce claim. It is not a cached verification or repeated claim
of one already-consumed nonce. The last successful receipt remains private to
the worker until an untimed replay rejection, then is discarded. Generated
nonces, signatures, raw payloads and secret bytes never enter reports or SDK
exports.

The report includes actual raw sample values in milliseconds, quantiles,
throughput and worker resource observations. Completion cross-checks actual
successful callbacks against the retained sample count plus warmup count. The
parent independently reads the persisted SQL rows and verifies actual provider
claim, authorization and secret-read counters against totals derived from those
callbacks and the initial verification corpus. A normal smoke yields 400
measured samples plus 80 warmup callbacks across all profiles; the initial
verification and final replay checks remain outside the latency samples.
`durable-observation.json` records the independent totals without nonce keys or
receipts.

Timed latency includes the awaited local provider bridge and PostgreSQL work.
CPU, RSS, heap, event-loop and GC observations cover only the worker process;
they exclude the parent bridge and database server. They cannot establish whole
pipeline resource costs. Workers retain the existing 256 MiB old-space limit,
30-second per-profile deadline and bounded owned collector. Both STANDARD and
DETAILED use the shared helper's explicit diagnostic trace sampling ratio 1;
STANDARD here does not represent the normal production sampling policy.

This is a valid-corpus signing and durable verification **component** comparison.
The native adapter does not implement all framework hostile-input, rotation,
timestamp, admission or lifecycle policies, so the result cannot establish
policy-equivalent wrapper overhead. No outbound HTTP delivery, retry, handshake,
queue pressure, clock-window failure campaign, complete pipeline resource
accounting, calibrated budget, confidence interval or release acceptance is
claimed. The normative 60-second warmup, 180-second steady trials, five paired
repetitions and one-hour soak remain separate and deferred. The full campaign
flag is rejected, and unmarked smoke fails before fixture or report creation.

The dedicated measured integration case runs only when the explicit webhook
smoke marker is set. Ordinary unit checks use an untimed bounded in-memory
provider solely to test helper accounting; they provide no SQL durability or
performance evidence.
