// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { setImmediate } from 'node:timers/promises';
import { managedProducer } from '../../dist/producer.js';
import { settings } from '../../dist/settings.js';

const require = createRequire(import.meta.url);
function fixture(maximum = 8) {
  const broker = process.env.ARKENIVA_KAFKA_BROKER;
  assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
  assert.match(broker ?? '', /^127\.0\.0\.1:[0-9]{1,5}$/);
  const application = new AbortController();
  let ready = false;
  const owner = managedProducer(
    settings({
      clusters: [
        {
          name: 'owned',
          brokers: [broker],
          clientId: 'owned-producer-' + randomUUID(),
          topics: ['orders.created'],
          maxBufferedMessages: maximum,
          maxMessageBytes: 262144,
          acks: 'all',
          idempotentProducer: true,
        },
      ],
    }),
    application.signal,
    () => ready,
    'test',
  );
  return {
    ...owner,
    broker: broker!,
    setReady() {
      ready = true;
    },
  };
}
const body = (key: string, value: Uint8Array | null = Buffer.from([0, 128, 255])) => ({
  cluster: 'owned',
  topic: 'orders.created',
  key: Buffer.from(key),
  value,
});

test(
  'Managed Kafka producer uses actual broker acknowledgements, exact offsets and independent byte snapshots',
  { timeout: 30000 },
  async () => {
    const f = fixture();
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
      kafkaJS: { brokers: [f.broker], logger, logLevel: 0 },
      log_level: 0,
    });
    const reader = client.consumer<Buffer, Buffer>({
      kafkaJS: {
        groupId: 'owned-managed-' + randomUUID(),
        fromBeginning: true,
        autoCommit: false,
        allowAutoTopicCreation: false,
      },
    });
    const marker = randomUUID(),
      seen: (number[] | null)[] = [];
    let complete!: () => void, reject!: (error: unknown) => void;
    const received = new Promise<void>((resolve, fail) => {
      complete = resolve;
      reject = fail;
    });
    void received.catch(() => undefined);
    const timer = setTimeout(
      () => reject(new Error('The actual managed publication was not observed')),
      20000,
    );
    try {
      await f.init();
      await assert.rejects(f.service.publish(body(marker)), { code: 'EK_LIFECYCLE_STATE' });
      f.setReady();
      assert.equal((await f.service.health('owned')).available, true);
      await reader.connect();
      await reader.subscribe({ topics: ['orders.created'] });
      await reader.run({
        eachMessage: async ({ message }) => {
          if (message.key?.toString() !== marker) return;
          seen.push(message.value === null ? null : [...message.value]);
          if (seen.length === 3) complete();
        },
      });
      const source = Buffer.from([0, 128, 255]);
      const pending = f.service.publish({
        ...body(marker, source),
        messageId: 'caller-correlation',
      });
      source.fill(9);
      const first = await pending;
      assert.equal(first.status, 'acknowledged');
      assert.equal(first.messageId, 'caller-correlation');
      assert.match(first.offset, /^(?:0|[1-9][0-9]*)$/);
      assert.ok(Number.isInteger(first.partition));
      const empty = await f.service.publish(body(marker, Buffer.alloc(0)));
      const tombstone = await f.service.publish(body(marker, null));
      assert.equal(first.partition, empty.partition);
      assert.equal(first.partition, tombstone.partition);
      assert.ok(
        BigInt(first.offset) < BigInt(empty.offset) &&
          BigInt(empty.offset) < BigInt(tombstone.offset),
      );
      await received;
      assert.deepEqual(seen, [[0, 128, 255], [], null]);
    } finally {
      clearTimeout(timer);
      await reader.disconnect();
      await f.close();
    }
    await assert.rejects(f.service.publish(body(marker)), { code: 'EK_RESOURCE_CLOSED' });
  },
);

test(
  'Managed Kafka cancellation retains admission until actual driver work settles and never claims rollback',
  { timeout: 30000 },
  async () => {
    const f = fixture(1);
    let release!: () => void, acknowledged!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const reached = new Promise<void>((resolve) => {
      acknowledged = resolve;
    });
    try {
      await f.init();
      f.setReady();
      const writer = f.service.native(
        'owned',
      ) as import('@confluentinc/kafka-javascript').KafkaJS.Producer<Buffer, Buffer>;
      const send = writer.send.bind(writer);
      let actual = 0;
      writer.send = async (request) => {
        actual++;
        const result = await send(request);
        acknowledged();
        await held;
        return result;
      };
      const controller = new AbortController();
      const pending = f.service.publish(body(randomUUID()), { signal: controller.signal });
      await reached;
      controller.abort('private-cancellation-reason');
      await assert.rejects(pending, (error: unknown) => {
        const value = error as { code?: string; details?: { outcome?: string } };
        assert.equal(value.code, 'EK_ABORTED');
        assert.equal(value.details?.outcome, 'unknown');
        assert.ok(!JSON.stringify(error).includes('private-cancellation-reason'));
        return true;
      });
      await assert.rejects(f.service.publish(body(randomUUID())), { code: 'EK_KAFKA_PUBLISH' });
      assert.equal(actual, 1);
      release();
      await setImmediate();
      assert.equal((await f.service.publish(body(randomUUID()))).status, 'acknowledged');
      assert.equal(actual, 2);
      for (const timeoutMs of [0, -1, 0.5, NaN, Infinity, 30001])
        await assert.rejects(f.service.publish(body(randomUUID()), { timeoutMs }), {
          code: 'EK_CONFIG_INVALID',
        });
      await assert.rejects(f.service.publish({ ...body(randomUUID()), topic: 'unapproved' }), {
        code: 'EK_KAFKA_CONFIG',
      });
      await assert.rejects(
        f.service.publish({ ...body(randomUUID()), value: new Uint8Array(262145) }),
        { code: 'EK_KAFKA_CONFIG' },
      );
      assert.equal(actual, 2);
    } finally {
      release();
      await f.close();
    }
  },
);
