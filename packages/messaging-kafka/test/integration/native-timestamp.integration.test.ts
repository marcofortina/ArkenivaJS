// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createRequire } from 'node:module';
import { randomInt, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

test(
  'The actual corrected SDK preserves epoch zero from an independent Kafka Java producer',
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
    const { KafkaJS } = createRequire(import.meta.url)(
      '@confluentinc/kafka-javascript',
    ) as typeof import('@confluentinc/kafka-javascript');
    const logger: import('@confluentinc/kafka-javascript').KafkaJS.Logger = {
      info() {},
      error() {},
      warn() {},
      debug() {},
      namespace() {
        return this;
      },
      setLogLevel() {},
    };
    const reader = new KafkaJS.Kafka({
      log_level: 0,
      kafkaJS: { brokers: ['127.0.0.1:19092'], logger, logLevel: 0 },
    }).consumer<Buffer, Buffer>({
      kafkaJS: {
        groupId: 'owned-native-epoch-' + randomUUID(),
        fromBeginning: true,
        autoCommit: false,
        allowAutoTopicCreation: false,
      },
    });
    let timestamp: string | undefined;
    try {
      await reader.connect();
      await reader.subscribe({ topics: ['orders.created'] });
      await reader.run({
        eachMessage: async ({ message }) => {
          if (message.value?.toString() === prefix + '.0') timestamp = message.timestamp;
        },
      });
      for (let i = 0; i < 200 && timestamp === undefined; i++) await delay(50);
      assert.equal(timestamp, '0');
    } finally {
      await reader.disconnect();
    }
  },
);
