<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native Core NATS interoperability verification

Build the workspace and use the private environment runner for the
[owned mutual-TLS fixture](../../packages/messaging/test/fixtures/README.md):

```sh
python3 packages/messaging/test/fixtures/run.py /private/nats-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation nats --verify /private/nats-verification
```

Four isolated profiles compare the pinned native `nats` client with the public
messaging service and actual standard/detailed SDK instrumentation. Each profile
uses its own random literal topic inside the credential-scoped namespace. A
separate native connection publishes one valid envelope and observes a service
publication. Both connections verify identifiers, exact payload, ordering and
correlation. Unauthenticated wire fields never create tenant authority.

The native baseline serializes only this declared valid JSON envelope. It does
not duplicate framework hostile-input validation, immutable capture, bounded
queue admission, cancellation or lifecycle policy. The broker requires a trusted
server certificate, an authenticated client certificate and scoped credentials.
A healthy positive control precedes wrong-hostname certificate rejection tests.
Subscriptions close and connections drain before worker completion is accepted.
SDK exports and reports must exclude subjects, payloads, correlation, connection
data and private credential paths.

Core NATS publish flush is not a persistence or broker-acknowledgment guarantee.
The tool verifies actual local observations separately and requires
`acknowledged: false`. It does not claim JetStream semantics, durable delivery,
retry safety or authenticated distributed business authority.

`--verify` retains its nonmeasured protocol checks and `releaseGate: false`.

## Short client component comparison

Measurements run only inside the owned disposable QEMU runner, using the same
private mutual-TLS fixture environment. Both the existing
`ARKENIVA_NATS_DISPOSABLE=1` and the explicit smoke marker are required. The
smoke guard runs before fixture validation or report creation.

```sh
ARKENIVA_NATS_BENCHMARK_DISPOSABLE=1 \
  python3 packages/messaging/test/fixtures/run.py /private/nats-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation nats --smoke /private/nats-smoke
```

One sequential `publish-flush-and-dual-observed-receipt` scenario runs in each of
the four profiles: 20 warmup callbacks followed by 100 actual retained Tinybench
latency samples. At most one publication is pending. The first warmup callback
creates one service subscription and one separately connected native subscriber
on the owned literal topic. Each callback publishes the same bounded JSON shape
with its sequence number and waits for both actual deliveries. It checks exact
message ID, marker, sequence, correlation and absence of untrusted tenant state
against the returned receipt. Actual observed encoded envelope bytes are checked
against the exact expected envelope. No hidden retries or retained message-ID
history is used; only the current private receipt is retained.

Completion compares actual callbacks with measured samples plus warmup, requires
exactly one native and one service-handler delivery per publication, closes both
subscriptions and drains the independent connection. It requires zero pending
receipts, callbacks, owned subscriptions or independent connections before
accepting the result. The initial two-way interoperability corpus is outside
the samples and retains its existing wrong-hostname certificate controls.
Reports contain only aggregate counts and observed byte totals, never subjects,
correlation identifiers, envelopes, connection credentials or private key paths.
The measured integration case is enabled only with the explicit smoke marker;
ordinary unit checks make no broker connection or performance measurement.

Latency covers publication flush plus both actual observed receipts. This is
neither request/reply latency nor a durable broker acknowledgment: every receipt
still has `acknowledged: false`. CPU/RSS, heap, GC and event-loop observations
cover the comparison client process, including its two client connections, and
exclude broker/server resources. The shared helper retains the existing
256 MiB old-space limit, 30-second per-profile deadline and bounded owned
collector. Both STANDARD and DETAILED explicitly use diagnostic trace sampling
ratio 1, so STANDARD does not represent normal production sampling.

The native baseline still omits complete framework hostile-input, admission,
cancellation and lifecycle policy. This small valid-corpus comparison cannot
establish policy-equivalent overhead, server CPU cost, durable delivery,
JetStream, exactly-once processing, queue/backpressure performance, confidence
intervals, calibrated budgets or release acceptance. Normative long warmup and
steady trials, five paired repetitions and one-hour soak remain deferred. The
unsupported full-campaign flag and unmarked smoke are rejected before evidence
creation.
