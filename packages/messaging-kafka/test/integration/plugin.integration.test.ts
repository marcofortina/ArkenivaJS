// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { kafkaPlugin, KAFKA_CAPABILITY } from '../../dist/index.js';
import type { KafkaService } from '../../dist/index.js';

test(
  'The public Kafka plugin owns isolated application clients and closes retained capabilities',
  { timeout: 30000 },
  async () => {
    assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
    const broker = process.env.ARKENIVA_KAFKA_BROKER!;
    assert.match(broker, /^127\.0\.0\.1:[0-9]{1,5}$/);
    const plugin = kafkaPlugin({
      clusters: [
        {
          name: 'owned',
          brokers: [broker],
          clientId: 'owned-plugin-' + randomUUID(),
          topics: ['orders.created'],
          maxBufferedMessages: 8,
          maxMessageBytes: 262144,
          acks: 'all',
          idempotentProducer: true,
        },
      ],
    });
    const first = await createApplication({
      service: { name: 'kafka-first', version: '1.0.0', environment: 'test' },
      plugins: [plugin],
    });
    const second = await createApplication({
      service: { name: 'kafka-second', version: '1.0.0', environment: 'test' },
      plugins: [plugin],
    });
    try {
      assert.throws(() => first.resolve(KAFKA_CAPABILITY), { code: 'EK_LIFECYCLE_STATE' });
      await first.start();
      await second.start();
      const a = first.resolve<KafkaService>(KAFKA_CAPABILITY),
        b = second.resolve<KafkaService>(KAFKA_CAPABILITY);
      assert.notEqual(a, b);
      assert.equal((await a.health('owned')).available, true);
      await first.stop();
      await assert.rejects(
        a.publish({ cluster: 'owned', topic: 'orders.created', value: Buffer.from([1]) }),
        { code: 'EK_RESOURCE_CLOSED' },
      );
      assert.equal(
        (
          await b.publish({
            cluster: 'owned',
            topic: 'orders.created',
            key: Buffer.from(randomUUID()),
            value: Buffer.from([0, 255]),
          })
        ).status,
        'acknowledged',
      );
      assert.equal((await b.health('owned')).available, true);
    } finally {
      await first.stop();
      await second.stop();
    }
  },
);
