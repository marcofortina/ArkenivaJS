// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';

test(
  'Actual pinned native Kafka client preserves tombstones, empty records and repeated nullable headers',
  { timeout: 45000 },
  async () => {
    const broker = process.env.ARKENIVA_KAFKA_BROKER;
    assert.equal(
      process.env.ARKENIVA_KAFKA_DISPOSABLE,
      '1',
      'An explicitly owned disposable Kafka broker is required',
    );
    assert.match(broker ?? '', /^127\.0\.0\.1:[0-9]{1,5}$/);
    const require = createRequire(import.meta.url);
    const { KafkaJS } =
      require('@confluentinc/kafka-javascript') as typeof import('@confluentinc/kafka-javascript');
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
    const client = new KafkaJS.Kafka({
      kafkaJS: { brokers: [broker!], clientId: 'owned-native-conformance', logger, logLevel: 0 },
      log_level: 0,
    });
    const producer = client.producer<Buffer, Buffer>({
      kafkaJS: { idempotent: true, acks: -1, allowAutoTopicCreation: false },
      'message.timeout.ms': 10000,
      'queue.buffering.max.messages': 10,
    });
    const consumer = client.consumer<Buffer, Buffer>({
      kafkaJS: {
        groupId: 'owned-conformance-' + randomUUID(),
        fromBeginning: true,
        autoCommit: false,
        allowAutoTopicCreation: false,
      },
      'js.consumer.max.cache.messages': 4,
      'max.poll.interval.ms': 30000,
    });
    const marker = randomUUID(),
      seen: (number[] | null)[] = [];
    let complete!: () => void, fail!: (error: unknown) => void;
    const finished = new Promise<void>((resolve, reject) => {
      complete = resolve;
      fail = reject;
    });
    void finished.catch(() => undefined);
    const deadline = setTimeout(
      () => fail(new Error('The owned native Kafka fixture exceeded its deadline')),
      30000,
    );
    try {
      await producer.connect();
      await consumer.connect();
      await consumer.subscribe({ topics: ['orders.created'] });
      await consumer.run({
        partitionsConsumedConcurrently: 1,
        eachMessage: async ({ topic, partition, message }) => {
          try {
            if (message.key?.toString() !== marker) return;
            assert.equal(typeof message.offset, 'string');
            assert.equal(Object.getPrototypeOf(message.headers), null);
            assert.deepEqual(message.headers?.duplicate, [
              Buffer.from('first'),
              Buffer.from([0, 255]),
              null,
              Buffer.alloc(0),
            ]);
            assert.deepEqual(message.headers?.textual, Buffer.from('a\0b'));
            assert.deepEqual(message.headers?.constructor, Buffer.from('inert'));
            assert.deepEqual(message.headers?.['__proto__'], Buffer.from('inert-prototype'));
            assert.deepEqual(message.headers?.tenant_id, Buffer.from('untrusted-wire-claim'));
            assert.ok(!Object.hasOwn(message, 'verifiedTenant'));
            seen.push(message.value === null ? null : [...message.value]);
            await consumer.commitOffsets([
              { topic, partition, offset: (BigInt(message.offset) + 1n).toString() },
            ]);
            if (seen.length === 3) complete();
          } catch (error) {
            fail(error);
            throw error;
          }
        },
      });
      for (const value of [Buffer.from([0, 128, 255]), Buffer.alloc(0), null]) {
        const receipt = await producer.send({
          topic: 'orders.created',
          messages: [
            {
              key: Buffer.from(marker),
              value,
              headers: Object.assign(
                Object.create(null),
                {
                  duplicate: ['first', Buffer.from([0, 255]), null, Buffer.alloc(0)],
                  textual: 'a\0b',
                  constructor: Buffer.from('inert'),
                  tenant_id: 'untrusted-wire-claim',
                },
                JSON.parse('{"__proto__":"inert-prototype"}'),
              ),
            },
          ],
        });
        assert.equal(receipt.length, 1);
        assert.equal(receipt[0]!.errorCode, 0);
        assert.equal(typeof receipt[0]!.baseOffset, 'string');
      }
      await finished;
      assert.deepEqual(seen, [[0, 128, 255], [], null]);
    } finally {
      clearTimeout(deadline);
      await consumer.disconnect();
      await producer.disconnect();
    }
  },
);
