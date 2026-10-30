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

Only `--verify` is supported. Sampling is rejected before fixture allocation
until complete broker/client resource accounting and representative queue and
backpressure workloads are available. Reports retain `releaseGate: false`;
dedicated-runner budgets, five paired repetitions and one-hour soak acceptance
remain separate work.
