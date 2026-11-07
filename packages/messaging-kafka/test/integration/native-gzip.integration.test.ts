// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';

test(
  'Actual private-zlib gzip publication preserves binary, empty, repeated records and nullable headers through confirmed consumer commits',
  { timeout: 45000 },
  async () => {
    assert.equal(
      process.env.ARKENIVA_KAFKA_DISPOSABLE,
      '1',
      'An explicitly owned disposable Kafka broker is required',
    );
    const broker = process.env.ARKENIVA_KAFKA_BROKER;
    assert.match(broker ?? '', /^127\.0\.0\.1:[0-9]{1,5}$/);
    const require = createRequire(import.meta.url),
      local = createRequire(require.resolve('@confluentinc/kafka-javascript/package.json')),
      binding = local('./librdkafka.js') as Record<string, unknown>;
    for (const [name, expected] of [
      ['arkenivajsNativeCompatibilityVersion', 3],
      ['arkenivajsNativeZlibVersion', '1.4'],
    ] as const) {
      const descriptor = Object.getOwnPropertyDescriptor(binding, name);
      assert.ok(descriptor && Object.hasOwn(descriptor, 'value'));
      assert.equal(descriptor.value, expected);
    }
    const { KafkaJS } =
      require('@confluentinc/kafka-javascript') as typeof import('@confluentinc/kafka-javascript');
    const logger: import('@confluentinc/kafka-javascript').KafkaJS.Logger = {
      info() {},
      error() {},
      warn() {},
      debug() {},
      setLogLevel() {},
      namespace() {
        return this;
      },
    };
    const marker = randomUUID(),
      group = 'owned-gzip-' + randomUUID(),
      client = new KafkaJS.Kafka({
        log_level: 0,
        kafkaJS: { brokers: [broker!], clientId: 'owned-private-gzip', logger, logLevel: 0 },
      });
    const producer = client.producer<Buffer, Buffer>({
        kafkaJS: {
          compression: KafkaJS.CompressionTypes.GZIP,
          idempotent: true,
          acks: -1,
          allowAutoTopicCreation: false,
        },
        'message.timeout.ms': 10000,
        'queue.buffering.max.messages': 8,
        'queue.buffering.max.ms': 100,
      }),
      consumer = client.consumer<Buffer, Buffer>({
        kafkaJS: {
          groupId: group,
          fromBeginning: true,
          autoCommit: false,
          allowAutoTopicCreation: false,
        },
        'js.consumer.max.cache.messages': 8,
        'max.poll.interval.ms': 30000,
      }),
      admin = client.admin();
    const binary = Buffer.concat([
        Buffer.from([0, 128, 255]),
        Buffer.alloc(8192, 65),
        Buffer.from([255, 0, 1]),
      ]),
      repeated = Buffer.alloc(32768, 'owned-compressible-record'),
      expected = [binary, Buffer.alloc(0), binary, repeated, repeated],
      values: Buffer[] = [],
      offsets: string[] = [],
      partitions: number[] = [];
    let complete!: () => void, fail!: (cause: unknown) => void;
    const received = new Promise<void>((resolve, reject) => {
      complete = resolve;
      fail = reject;
    });
    void received.catch(() => undefined);
    const timer = setTimeout(
      () => fail(new Error('The owned gzip Kafka fixture exceeded its deadline')),
      30000,
    );
    try {
      await producer.connect();
      await consumer.connect();
      await admin.connect();
      await consumer.subscribe({ topics: ['orders.created'] });
      await consumer.run({
        partitionsConsumedConcurrently: 1,
        eachMessage: async ({ topic, partition, message }) => {
          if (message.key?.toString() !== marker) return;
          try {
            assert.ok(
              values.length < expected.length,
              'The owned gzip corpus must not duplicate a committed record',
            );
            assert.ok(Buffer.isBuffer(message.value));
            assert.deepEqual(message.value, expected[values.length]);
            assert.deepEqual(message.headers?.repeated, [
              Buffer.from([0, 255]),
              Buffer.alloc(0),
              null,
              Buffer.from([0, 255]),
            ]);
            assert.equal(Object.getPrototypeOf(message.headers), null);
            assert.match(message.offset, /^(?:0|[1-9][0-9]*)$/);
            await consumer.commitOffsets([
              { topic, partition, offset: (BigInt(message.offset) + 1n).toString() },
            ]);
            values.push(Buffer.from(message.value));
            offsets.push(message.offset);
            partitions.push(partition);
            if (values.length === expected.length) complete();
          } catch (cause) {
            fail(cause);
            throw cause;
          }
        },
      });
      const receipts = await producer.send({
        topic: 'orders.created',
        messages: expected.map((value) => ({
          key: Buffer.from(marker),
          value,
          headers: {
            repeated: [Buffer.from([0, 255]), Buffer.alloc(0), null, Buffer.from([0, 255])],
          },
        })),
      });
      assert.equal(receipts.length, 1);
      assert.equal(receipts[0]!.errorCode, 0);
      assert.match(receipts[0]!.baseOffset!, /^(?:0|[1-9][0-9]*)$/);
      await received;
      assert.deepEqual(values, expected);
      assert.ok(partitions.every((value) => value === receipts[0]!.partition));
      assert.equal(offsets[0], receipts[0]!.baseOffset);
      assert.ok(offsets.slice(1).every((value, index) => BigInt(value) > BigInt(offsets[index]!)));
      const committed = await admin.fetchOffsets({
        groupId: group,
        topics: ['orders.created'],
        timeout: 5000,
      });
      assert.equal(
        committed[0]?.partitions.find((value) => value.partition === receipts[0]!.partition)
          ?.offset,
        (BigInt(offsets.at(-1)!) + 1n).toString(),
      );
    } finally {
      clearTimeout(timer);
      try {
        await consumer.disconnect();
      } finally {
        try {
          await admin.disconnect();
        } finally {
          await producer.disconnect();
        }
      }
    }
  },
);
