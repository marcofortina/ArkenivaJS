<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native AMQPS publisher confirmation comparison

Build the workspace and load the private metadata for the owned RabbitMQ fixture:

```sh
ARKENIVA_AMQP_FIXTURE=/private/amqp/runtime.json \
  pnpm --filter @arkenivajs/benchmark-foundation amqp --verify /private/amqp-verification

# Short measurements belong only on an explicitly disposable VM or CI runner.
ARKENIVA_AMQP_FIXTURE=/private/amqp/runtime.json \
ARKENIVA_AMQP_BENCHMARK_DISPOSABLE=1 \
  pnpm --filter @arkenivajs/benchmark-foundation amqp --smoke /private/amqp-smoke
```

Four isolated profiles compare the same pinned `amqplib` installation and reviewed
codec patch with the public AMQP service, including standard/detailed SDK modes.
The parent uses the fixture administrator only to bootstrap random dedicated
exchange/queue names. Every child uses restricted service credentials and checks
pre-existing topology; provisioning is disabled in child application settings.

A separate native connection publishes binary bytes and scalar headers to the
service consumer, which manually acknowledges receipt. It then independently
retrieves a service publication, verifies exact bytes, headers and message ID,
and submits its own acknowledgment. A confirmed mandatory publication without
a matching binding must return `unroutable`. A broker confirm proves neither
consumer commitment nor business completion; local acknowledgment submission
does not provide an acknowledgment receipt.

Both owned queues have limits of 128 messages and 131,072 body bytes, with overflow
rejecting publication. Each smoke profile can produce only 120 workload messages,
and the verification corpus drains its messages before sampling begins. These
fixture ceilings do not change application admission or broker policy. Both owned
queues must have zero messages and consumers after every profile and
in the independent parent check. Cleanup attempts every exact owned resource,
even after another deletion fails; it uses separate native channels so a missing
resource cannot prevent subsequent cleanup. The protocol observation is written
only after acknowledged resource deletion and connection closure. No unrelated
queue or exchange is removed. TLS positive controls precede wrong-hostname
rejection tests. SDK exports and reports exclude topology, credentials, identifiers,
headers and body data. Wire headers never establish tenant authority.

This is a bounded valid-input interoperability check. The native baseline omits
framework hostile-field validation, single-use acknowledgment guards, admission,
recovery and lifecycle policy. It does not exercise unknown delivery retries,
broker restart or concurrent pods.

`--smoke` first runs the same verification corpus, then executes one sequential
`publishConfirmed` scenario in each of the four profiles. Tinybench excludes the
20 warmup callbacks from its 100 retained measured latency samples. Each callback
publishes a distinct message ID, the same 1,024 binary bytes and typed scalar
headers, with `mandatory:true` and `persistent:false`, and awaits the actual broker
publisher-confirm receipt. A write boolean or enqueue acknowledgment cannot finish
the callback. Receipt assertions and request construction are inside that latency
boundary, alongside client validation, AMQPS and broker-confirm latency. No new
timer is used; raw samples use milliseconds and match `sampleCount` exactly.

After timing, an independent native connection retrieves all 120 messages from
the owned publication queue. It checks every message ID, exact binary bytes,
headers, exchange, routing key and nonpersistent delivery mode, rejects duplicates
or extras, and submits acknowledgments before queue/consumer checks. This readback
is outside measured callback latency and worker resource sampling. Each smoke
profile therefore performs 123 publications including the three original
verification publications; all four profiles produce 400 measured publications,
80 warmup publications and 12 verification publications. The separate readback
provides interoperability evidence, not a consumer or business commitment promise.

Worker CPU/RSS/heap, event-loop and GC observations cover the publisher process,
warmup, measurement machinery, retained samples and SDK activity. They exclude
RabbitMQ server resources and the parent/collector processes. Standard and detailed
profiles use diagnostic trace sampling at ratio 1, rather than a normal production
sampling budget. SDK privacy checks and zero reported drops/export failures remain
mandatory. The native reference omits framework policy, so these short observations
do not establish policy-equivalent overhead, capacity, representative backpressure,
durable delivery, calibrated production budgets or production readiness.
`--full` remains refused before fixture access. Reports retain `releaseGate:false`;
five paired repetitions and one-hour soak acceptance remain separate work.
