# @arkenivajs/messaging-kafka

Kafka producer/consumer data contracts and bounded input snapshots. This foundation does not yet expose a plugin or runtime client. It cannot be used to publish or consume records. The selected backend is the pinned Confluent JavaScript client. Internal producer integration now validates physical admission, broker acknowledgements, secure connection setup and cancellation; the public plugin and consumer lifecycle are not yet exported. Native compatibility fixtures exercise it against a real broker; the framework service, lifecycle and security acceptance remain separate requirements.

Payloads are bytes or null tombstones. Tombstones require a nonempty compaction key. Empty byte arrays remain empty payloads. Header snapshots retain binary values, strings, nulls and duplicate ordering; wire tenant headers remain untrusted data. An eventual native adapter must explicitly reject any unsupported value before publication instead of coercing it. Independent snapshots prevent caller mutation from changing an admitted operation.

Offsets are nonnegative signed 64-bit decimal strings. Unsafe JavaScript numbers are rejected. A decimal string obtained after a native numeric precision loss cannot recover the original offset; runtime integration must validate the actual driver's conversion boundary.

Static validation bounds configurations to 16 clusters, 32 brokers and 64 exact topics per cluster. Buffers permit at most 10000 messages and 16 MiB payloads, with an aggregate payload/header budget of 256 MiB per cluster. Header snapshots allow 128 names, 256 total entries and 16 KiB of names/values. CA paths must be absolute; credentials require a trusted secret resolver. Validation performs no file, network or secret-provider access.

The startup-owned `KafkaClusterConfig.topics` catalog supplies the topic policy required by provisioning and bounded metric dimensions. It does not authorize automatic topic creation or administration. Consumer groups remain explicit, per-partition concurrency is one, and handler failure leaves the offset uncommitted. No verified tenant can be derived from wire metadata.

Run `pnpm --filter @arkenivajs/messaging-kafka build` and `pnpm --filter @arkenivajs/messaging-kafka test:unit`. Data tests exercise exact offsets, byte ownership, tombstone distinctions, duplicate headers, bounded input and hostile object rejection. They do not prove native compatibility or broker behavior.

## Native build and compatibility controls

The corrected asynchronous commit worker waits for librdkafka's confirmed commit result instead of reporting that a request was merely queued. Administrative offset reads preserve the same exact decimal metadata as the producer and consumer. Partition-only committed-offset queries retain their missing-offset sentinel. Timestamp zero remains `"0"`, including when produced by the independent Kafka Java client.

The actual compiled addon exports a compatibility version marker. This is a build capability check, not cryptographic attestation. Source compilation must include the complete reviewed correction; changing only the JavaScript wrapper cannot supply the compiled marker. Independent consumers must explicitly carry the packaged compatibility diff into their own pnpm dependency policy.

The reviewed SDK correction requires source compilation with a C++20 compiler, Python and make. It bounds native build jobs, accommodates pnpm archive paths, preserves exact offset strings through native serialization and promisified commit/seek arithmetic, and distinguishes empty bytes from null headers. The original native callback numeric offset fields remain for compatibility; exact decimal fields are authoritative when values exceed the safe JavaScript integer range. A configurable hard message cache limit complements the native byte queue bounds.

The integration fixtures run on Linux/glibc x64 with Node 22.23.4, 24.22.1 and 26.12.1. The Node 26 path also builds the bundled C/C++ libraries from source. Other ABI runs can reuse those independently compiled, hash-reviewed static libraries while compiling each Node binding separately. This is a build cache, not a substitute for running the actual broker tests on each Node version. Other operating systems and architectures are unverified for this optional package.

With the package built and an explicitly owned local broker, set `ARKENIVA_KAFKA_DISPOSABLE=1` and `ARKENIVA_KAFKA_BROKER=127.0.0.1:19092`, then run `node --test packages/messaging-kafka/dist-test/integration/*.test.js`. Create `orders.created` explicitly with two partitions and retain compaction records for the test duration. The tests do not create topics. The native integer fixture additionally compiles a temporary bridge linked to the actual installed SDK, exercising its C++ conversions across the full nonnegative signed 64-bit range. Broker tests cover tombstones, empty values, nullable/repeated binary headers, embedded zero bytes, prototype-sensitive names, manual commits and disconnection. The SDK's declared `stop()` method is not implemented; direct consumers must use its supported disconnect lifecycle.

See [third-party notices](THIRD_PARTY_NOTICES.md). These controls establish local native behavior, not a completed framework adapter, production conformance, full platform support or final CI acceptance.

The timestamp interoperability fixture additionally requires `ARKENIVA_KAFKA_CONTROL=1` and Docker access within the owned disposable environment. It invokes only the named `arkenivajs-kafka-test` broker's official Java producer; provision the fixture before running it.

Producer integration tests cover caller-owned byte snapshots and cancellation after a real broker acknowledgement, retaining capacity until the actual native work settles. The native compatibility guard rejects unsupported compiled addons before reading secrets or opening connections. Technical observations use bounded startup catalogs and safe fixed outcomes; message contents, keys, correlation values and consumer groups are excluded from metric labels.
