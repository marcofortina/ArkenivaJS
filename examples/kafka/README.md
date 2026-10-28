# Kafka public consumer

This example imports only the public core and Kafka APIs. It sends binary bytes, an empty record and a tombstone with the same explicit key, then checks actual broker receipts and independent consumer snapshots. Raw tenant headers remain untrusted.

`runKafkaExample(settings, groupId, environment)` defaults to production and uses the startup-owned broker/topic catalog. Production settings require verified TLS; load any SASL descriptor through an application-owned secret provider. See the [adapter configuration](../../packages/messaging-kafka/README.md) for the required native compatibility diff, credential format and buffer limits.

For the owned test fixture, explicitly set `ARKENIVA_KAFKA_DISPOSABLE=1` and `ARKENIVA_KAFKA_BROKER=127.0.0.1:19092`. Provision `orders.created` with two partitions and compaction retention before running the example. The plaintext exception is confined to the example's explicit test startup configuration.

Run `pnpm --filter @arkenivajs/example-kafka build` and `pnpm --filter @arkenivajs/example-kafka test` for resource-free import validation. Run `pnpm --filter @arkenivajs/example-kafka test:integration` or `pnpm test:packed:examples --integration kafka` inside the owned disposable environment for real broker checks. The packed gate explicitly compiles the corrected native dependency; it does not substitute a fake client.

Broker acknowledgement is distinct from consumer processing. The adapter commits only after the handler returns and waits for confirmation. Graceful shutdown drains an admitted handler; cancellation or a crash can still lead to redelivery. Use idempotent application effects and do not infer end-to-end exactly once from producer idempotence.
