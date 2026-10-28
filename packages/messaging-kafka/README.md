# @arkenivajs/messaging-kafka

Kafka producer/consumer data contracts and bounded input snapshots. This foundation does not yet expose a plugin or runtime client. It cannot be used to publish or consume records. The selected backend remains the Confluent JavaScript client; its native installation and real broker matrix must pass before runtime support is claimed.

Payloads are bytes or null tombstones. Tombstones require a nonempty compaction key. Empty byte arrays remain empty payloads. Header snapshots retain binary values, strings, nulls and duplicate ordering; wire tenant headers remain untrusted data. An eventual native adapter must explicitly reject any unsupported value before publication instead of coercing it. Independent snapshots prevent caller mutation from changing an admitted operation.

Offsets are nonnegative signed 64-bit decimal strings. Unsafe JavaScript numbers are rejected. A decimal string obtained after a native numeric precision loss cannot recover the original offset; runtime integration must validate the actual driver's conversion boundary.

Static validation bounds configurations to 16 clusters, 32 brokers and 64 exact topics per cluster. Buffers permit at most 10000 messages and 16 MiB payloads, with an aggregate payload/header budget of 256 MiB per cluster. Header snapshots allow 128 names, 256 total entries and 16 KiB of names/values. CA paths must be absolute; credentials require a trusted secret resolver. Validation performs no file, network or secret-provider access.

The startup-owned `KafkaClusterConfig.topics` catalog supplies the topic policy required by provisioning and bounded metric dimensions. It does not authorize automatic topic creation or administration. Consumer groups remain explicit, per-partition concurrency is one, and handler failure leaves the offset uncommitted. No verified tenant can be derived from wire metadata.

Run `pnpm --filter @arkenivajs/messaging-kafka build` and `pnpm --filter @arkenivajs/messaging-kafka test:unit`. Data tests exercise exact offsets, byte ownership, tombstone distinctions, duplicate headers, bounded input and hostile object rejection. They do not prove native compatibility or broker behavior.
