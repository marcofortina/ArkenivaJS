<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native Kafka producer and independent receipt verification

Build the workspace and explicitly compile the reviewed native SDK for the
current Node ABI. Load the owned disposable two-partition Kafka fixture with
verified TLS/SASL, its private secret directory and the prescribed topic/ACLs:

```sh
pnpm --filter @arkenivajs/benchmark-foundation kafka --verify /private/kafka-verification
```

Four isolated profiles compare the pinned native producer with the public Kafka
service, including actual standard/detailed SDK instrumentation. Every client
verifies the server certificate and authenticates using the owned fixture's SASL
identity. Both paths require all-replica acknowledgments and an idempotent
producer; neither can create topics.

Every profile publishes a binary value, an empty value and a tombstone using one
key. Repeated headers preserve binary, empty and null values, including inert
prototype-like names. An independent native consumer starts before publishing,
reads the actual records, verifies every byte and commits exact next offsets.
Its observed partition/offset pairs must match every producer acknowledgment.
A wire tenant hint remains untrusted metadata and cannot create a verified
application tenant context.

The native reference implements only this fixed producer corpus. It omits the
public wrapper's complete capture, admission, cancellation, lifecycle and
uncertain-outcome policy. Observer commits do not establish public consumer,
redelivery, transactional or end-to-end exactly-once parity. Existing module
integration suites cover broader consumer, failure, restart and security behavior.

The observer's bounded loopback receipt bridge requires a private bearer value.
Separate tests deny unauthenticated receipt claims and reject the explicitly
test-only secret resolver in production. Reports and actual SDK exports must
exclude credentials, private keys, payloads, tenant hints and connection details.
Shutdown closes all native producers, the observer consumer and the bridge.
The independently owned broker fixture retains responsibility for its topic
and consumer-group cleanup.

Only `--verify` is supported. Sampling is rejected before fixture allocation
until complete broker/client resource accounting is available. Reports retain
`releaseGate: false`; dedicated-runner budgets, five paired repetitions and
one-hour soak acceptance remain separate work.
