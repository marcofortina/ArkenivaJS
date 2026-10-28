// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import type { Environment } from '@arkenivajs/core';
import { kafkaPlugin, KAFKA_CAPABILITY } from '@arkenivajs/messaging-kafka';
import type {
  KafkaPluginSettings,
  KafkaRecord,
  KafkaService,
  KafkaPublicationReceipt,
} from '@arkenivajs/messaging-kafka';

/** The disposable plaintext fixture is selected by startup configuration, never request data. */
export function fixtureSettings(): KafkaPluginSettings {
  const broker = process.env.ARKENIVA_KAFKA_BROKER;
  if (
    process.env.ARKENIVA_KAFKA_DISPOSABLE !== '1' ||
    !broker ||
    !/^127\.0\.0\.1:[0-9]{1,5}$/.test(broker)
  )
    throw new Error('An explicitly owned local Kafka fixture is required');
  return {
    clusters: [
      {
        name: 'events',
        brokers: [broker],
        clientId: 'owned-public-example',
        topics: ['orders.created'],
        maxBufferedMessages: 8,
        maxMessageBytes: 262144,
        acks: 'all',
        idempotentProducer: true,
      },
    ],
  };
}

/** Broker acknowledgement and completed consumer processing remain separate observations. */
export async function runKafkaExample(
  settings: KafkaPluginSettings,
  groupId: string,
  environment: Environment = 'production',
) {
  const plugin = kafkaPlugin(settings),
    cluster = settings.clusters[0]!;
  const app = await createApplication({
    service: { name: 'kafka-example', version: '0.1.0', environment },
    plugins: [plugin],
  });
  const marker = randomUUID(),
    received: KafkaRecord[] = [];
  let complete!: () => void, failed!: (error: Error) => void;
  const delivered = new Promise<void>((done, reject) => {
    complete = done;
    failed = reject;
  });
  void delivered.catch(() => undefined);
  const timer = setTimeout(
    () => failed(new Error('The owned Kafka example delivery deadline expired')),
    15000,
  );
  try {
    await app.start();
    const service = app.resolve<KafkaService>(KAFKA_CAPABILITY);
    const subscription = await service.consume(
      { cluster: cluster.name, topics: [cluster.topics[0]!], groupId, offsetReset: 'earliest' },
      async (record) => {
        if (Buffer.from(record.key ?? []).toString() !== marker) return;
        received.push(record);
        if (received.length === 3) complete();
      },
    );
    const receipts: KafkaPublicationReceipt[] = [];
    for (const value of [Uint8Array.of(0, 128, 255), new Uint8Array(), null])
      receipts.push(
        await service.publish({
          cluster: cluster.name,
          topic: cluster.topics[0]!,
          key: Buffer.from(marker),
          value,
          headers: {
            repeated: [null, Uint8Array.of(0, 255), ''],
            tenant_id: 'untrusted-wire-claim',
          },
          messageId: randomUUID(),
        }),
      );
    await delivered;
    await subscription.close();
    return { receipts: Object.freeze(receipts), received: Object.freeze(received) };
  } finally {
    clearTimeout(timer);
    await app.stop();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = await runKafkaExample(fixtureSettings(), 'owned-example-' + randomUUID(), 'test');
  console.log(
    JSON.stringify({ acknowledged: result.receipts.length, delivered: result.received.length }),
  );
}
