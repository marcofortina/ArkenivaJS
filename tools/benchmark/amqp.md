<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native AMQPS interoperability verification

Build the workspace and load the private metadata for the owned RabbitMQ fixture:

```sh
ARKENIVA_AMQP_FIXTURE=/private/amqp/runtime.json \
  pnpm --filter @arkenivajs/benchmark-foundation amqp --verify /private/amqp-verification
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

Both owned queues must have zero messages and consumers after every profile and
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
broker restart or concurrent pods. `--smoke` is rejected before fixture access
until complete broker/client resource and representative backpressure measurement
is available. Reports retain `releaseGate: false`; dedicated-runner budgets,
five paired repetitions and one-hour soak acceptance remain separate work.
