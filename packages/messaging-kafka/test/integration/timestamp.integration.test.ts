// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomInt, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { managedService } from '../../dist/service.js';
import { settings } from '../../dist/settings.js';

test(
  'An independent Kafka Java producer timestamp zero survives the actual native consumer conversion',
  { timeout: 30000 },
  async () => {
    assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
    assert.equal(process.env.ARKENIVA_KAFKA_CONTROL, '1');
    assert.equal(process.env.ARKENIVA_KAFKA_BROKER, '127.0.0.1:19092');
    const prefix = String(randomInt(1, 2000000000));
    const output = await promisify(execFile)(
      '/usr/bin/docker',
      [
        'exec',
        'arkenivajs-kafka-test',
        '/opt/kafka/bin/kafka-verifiable-producer.sh',
        '--bootstrap-server',
        '127.0.0.1:19092',
        '--topic',
        'orders.created',
        '--max-messages',
        '1',
        '--message-create-time',
        '0',
        '--repeating-keys',
        '1',
        '--value-prefix',
        prefix,
      ],
      { timeout: 15000, maxBuffer: 1048576 },
    );
    const events = output.stdout
      .split('\n')
      .filter((line) => line.startsWith('{'))
      .map((line) => JSON.parse(line) as { name: string; value?: string });
    assert.ok(
      events.some(
        (event) => event.name === 'producer_send_success' && event.value === prefix + '.0',
      ),
    );
    const owner = managedService(
      settings({
        clusters: [
          {
            name: 'owned',
            brokers: ['127.0.0.1:19092'],
            clientId: 'owned-epoch',
            topics: ['orders.created'],
            maxBufferedMessages: 8,
            maxMessageBytes: 262144,
            acks: 'all',
            idempotentProducer: true,
          },
        ],
      }),
      new AbortController().signal,
      () => true,
      'test',
    );
    let timestamp: string | undefined;
    try {
      await owner.init();
      const subscription = await owner.service.consume(
        {
          cluster: 'owned',
          topics: ['orders.created'],
          groupId: 'owned-epoch-' + randomUUID(),
          offsetReset: 'earliest',
        },
        async (record) => {
          if (record.value && Buffer.from(record.value).toString() === prefix + '.0')
            timestamp = record.timestamp;
        },
      );
      for (let i = 0; i < 200 && timestamp === undefined; i++) await delay(50);
      assert.equal(timestamp, '0');
      await subscription.close();
    } finally {
      await owner.close();
    }
  },
);
