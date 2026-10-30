<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native Kafka producer and independent receipt verification

Build the workspace and select the existing reviewed native SDK cache for the
current Node ABI; this harness does not install or rebuild native dependencies.
Load the owned disposable two-partition Kafka fixture with verified TLS/SASL,
its private secret directory and the prescribed topic/ACLs. The compacted topic
must retain the full campaign: the owned fixture sets
`min.compaction.lag.ms=3600000`, which exceeds this bounded campaign. Do not run
against a topic whose compaction or deletion can remove records before independent
verification:

```sh
pnpm --filter @arkenivajs/benchmark-foundation kafka --verify /private/kafka-verification
pnpm --filter @arkenivajs/benchmark-foundation kafka --smoke /private/kafka-smoke
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

`--verify` retains the original three-record corpus without latency samples.
`--smoke` adds 20 warmup publications and exactly 100 retained Tinybench samples
per profile. Every sequential timed callback awaits and validates the actual
producer receipt. It cycles the same binary, empty and tombstone values under
the same profile key, with identical repeated nullable headers. There is no
application callback retry. Raw samples measure publish-to-receipt elapsed time,
including receipt checks and bounded metadata capture; they do not time a
consumer business action.

After sampling, outside the measured callback, the worker submits its exact
partition/decimal-offset pairs to the independently running native observer.
The observer checks every value and header, commits actual next offsets and
matches every receipt, including warmup. It retains at most 123 receipt rows
per profile (492 total) in smoke mode and three per profile in verify mode;
receipt requests remain byte bounded. Completion counters reconcile actual
Tinybench sample and warmup counts and separately report value bytes for both.
Protocol observation reports contain counts and byte totals, without private
profile keys, payloads or offsets.

Child resource observations cover each process during warmup and sampling.
Process CPU includes native librdkafka threads; RSS includes native process
allocations, while JavaScript heap does not measure native buffer allocation.
The parent observer and broker process resources remain separately unknown
(`null`), and observer commits occur outside the timed workload. These readings
cannot establish complete resource parity, broker replication performance under
fault, application commitment or exactly-once delivery. The owned fixture has
replication factor one; `acks:all` tests that configured policy without claiming
multi-replica fault tolerance.

Reports retain `releaseGate: false`; complete broker/client resource accounting,
dedicated-runner budgets, five paired repetitions and one-hour soak acceptance
remain separate work. Unsupported modes reject before fixture allocation.
