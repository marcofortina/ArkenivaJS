# @arkenivajs/messaging-kafka

Explicit native Kafka producers and consumer groups through the pinned Confluent JavaScript SDK and librdkafka. Install `kafkaPlugin(settings)` and resolve `KAFKA_CAPABILITY` as `KafkaService` after application startup. No clients, topics or groups are created merely by importing this optional package.

## Required native compatibility setup

The reviewed SDK correction in [compat](compat/confluent-exact-offsets-and-build.diff) is required. Apply that exact diff as a pnpm `patchedDependencies` entry for `@confluentinc/kafka-javascript@1.11.0`, permit that exact dependency's build, and explicitly install/build it. Independent applications must carry the reviewed diff from the package archive into their own dependency policy; installing an uncorrected upstream SDK is insufficient. The workspace and packed consumer checks configure this policy explicitly.

The correction preserves exact signed 64-bit offsets, nullable/empty binary headers and timestamp zero, bounds prefetching, and makes the asynchronous worker wait for librdkafka's confirmed offset commit. A compiled compatibility marker prevents an old or uncorrected native binary from passing startup. Marker validation runs before secret-provider, certificate or network access. The marker detects a missing compatibility build; dependency integrity and source review remain separate controls. Compatibility format 2 also preserves a missing group assignor as `null` while retaining the explicit broker error; an older compiled format is rejected before resource access.

Source compilation requires a C++20 compiler, Python and make. Build jobs are bounded. Linux/glibc x64 Node 22.23.4, 24.22.1 and 26.12.1 have executable native fixtures; Node 26 uses a source build. Node-independent, hash-reviewed bundled C/C++ libraries may be cached while each Node binding is compiled separately. Other operating systems and architectures require their own native compatibility evidence.

The reviewed build correction binds configuration output and compilation input to the same source file using relative paths, including inside pnpm's hash-qualified installation directories. Fresh parallel builds must succeed without a preexisting `config.h` or native build cache.

## Startup configuration

Each `KafkaClusterConfig` supplies a unique `name`, explicit `brokers`, `clientId`, exact `topics`, `maxBufferedMessages`, `maxMessageBytes`, `acks: 'all'` and `idempotentProducer: true`. Reliability cannot silently downgrade. Bootstrap reads metadata and rejects missing topics; framework methods never create topics, groups or ACLs administratively.

All environments use verified TLS with hostname checking. The only plaintext exception is an explicit `test` environment with literal loopback brokers and no credentials or CA override. TLS 1.2 uses ECDHE AEAD suites; TLS 1.3 retains native defaults. Older TLS protocols have no permitted cipher suites. A custom `tlsCaFile` must be an absolute path to a bounded regular file, read once without following symlinks.

When `credentialSecretRef` is supplied, `resolveSecret(reference, options)` must obtain a private JSON descriptor from a trusted external secret source:

```ts
{ mechanism: 'plain' | 'scram-sha-256' | 'scram-sha-512', username: string, password: string }
```

The descriptor is bounded to 16 KiB and rejects unknown fields. Credentials are never accepted from publication or consumption requests. SASL always uses TLS. A resolver marked `usage: 'test-only'` is rejected outside the test environment. Credential changes require a controlled restart; no secret-store implementation or automatic rotation is implied.

Static bounds are 16 clusters, 32 brokers and 64 exact topics per cluster, 10000 buffered messages, 16 MiB per value/key budget and 256 MiB aggregate configured buffer budget per cluster. Startup and assignments bound a cluster to 1024 partitions, with partition identifiers 0 through 1023. A service admits at most 16 subscriptions. Header snapshots permit 128 names, 256 entries and 16 KiB total names/values.

## Publication and consumption

`publish({ cluster, topic, value, key?, headers?, messageId? }, options?)` accepts bytes or a null tombstone. A tombstone requires a nonempty key. Empty byte arrays remain distinct from tombstones. Input bytes and header arrays are copied before the first asynchronous yield. Duplicate header order, null values, embedded zero bytes and prototype-sensitive names remain data. Unsupported or oversized input is rejected before publication.

A successful receipt contains `status: 'acknowledged'`, topic, partition and an exact nonnegative decimal offset string. The optional caller `messageId` is echoed only after the broker acknowledgement and is not added as a wire identity assertion. Cancellation, timeout or lost delivery acknowledgement after submission carries `details.outcome: 'unknown'`; it does not promise rollback. A late broker acknowledgement can be observed diagnostically without changing the caller's canceled result. Admission remains occupied until the actual native operation settles.

`consume({ cluster, topics, groupId, offsetReset, maxInFlightPerPartition?, failurePolicy? }, handler, options?)` requires an explicit group, known topics and `earliest` or `latest`. Previously committed offsets are authoritative. Auto-commit is disabled; concurrency is one and the failure policy is `stop`. Only after the handler resolves successfully does the adapter commit the next offset and wait for broker confirmation. Handler rejection or timeout stops the member without skipping the record. Actual commit failures use `EK_KAFKA_OFFSET`, including when a business side effect already exists.

A private assignment lease and current native assignment gate commits. Revocation invalidates the lease. Offset values never pass through unsafe JavaScript numbers. Headers and `tenant_id` do not establish publisher identity or a `VerifiedTenantContext`; the application must independently authenticate and authorize any tenant binding.

Delivery is at least once. Rebalance, process death and uncertain commits can repeat an already completed business action. Make handlers idempotent. Producer idempotence does not provide cross-database exactly-once behavior.

Operation deadlines default to 10 seconds and accept integer milliseconds from 1 through 30000. The consume deadline bounds setup and each handler interval; its signal also owns subscription lifetime. Ordinary close stops new admission, drains admitted handlers and confirmed commits, then leaves the group. A close deadline or cancellation stops later commits that were not already dispatched. Physical work remains owned until it settles. Calling subscription/service close from its own handler fails with `EK_LIFECYCLE_STATE` instead of deadlocking.

`health(cluster)` probes actual broker metadata. A stopped faulty consumer degrades its cluster's health until that service is replaced. `native(cluster)` returns the managed SDK producer and emits an instrumentation warning; direct SDK calls bypass framework validation, accounting and lifecycle guarantees. The SDK's declared `stop()` method is not implemented; managed subscriptions use `disconnect()`.

## Observation and executable consumers

See the [public Kafka example](../../examples/kafka/README.md) for a complete typed consumer using only package exports.

Optional existing logger, telemetry and usage-meter capabilities are discovered through the support SPI. Observations include actual value/key/header bytes, confirmed publications, delivery and handler latency, retained in-flight work, assignment/revocation, commit/authentication errors and sampled broker-derived lag. Lag probes are limited to four concurrent calls per cluster and one sample per partition every five seconds. An unsafe integer lag is unavailable rather than rounded.

For the framework telemetry SDK, explicitly approve static `kafka.cluster` and `kafka.topic` values through `TelemetryOptions.labelValues`. Partition labels are bounded integers; outcome labels are fixed. Existing series/instrument limits still apply. Rejected or failed diagnostics increment `kafka.diagnostics.failures` where reporting remains available. No payload, key, header value, group ID, client ID, tenant ID or credential becomes a metric label. Consumer spans run outside the original request scope. Without independently verified tenant provenance, the adapter does not manufacture a tenant usage session.

Run `pnpm --filter @arkenivajs/messaging-kafka build`, `test:unit` and `typecheck`. Live tests require an explicitly owned disposable broker environment with `ARKENIVA_KAFKA_DISPOSABLE=1`, `ARKENIVA_KAFKA_CONTROL=1`, loopback `ARKENIVA_KAFKA_BROKER`, and private `ARKENIVA_KAFKA_SECRETS`. The fixture controls stop/restart only the named test broker and alter temporary group ACLs; run these cases sequentially. New groups using `latest` skip existing records; an existing group's committed position takes precedence over its reset policy.

The live suite uses actual native bindings, KRaft brokers, TLS/SASL/ACLs, a linked C++ integer bridge, independent Java timestamp-zero production, competing consumers, a process crash after fsync, broker restart, typed offset failures and real Pino/OTLP privacy exports. Platform conformance, comparative performance and release acceptance require their corresponding evidence; passing a local fixture is not a production support claim.

See [third-party notices](THIRD_PARTY_NOTICES.md).
