// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { operation, Task } from '../../dist/operation.js';
import { settings } from '../../dist/settings.js';
import { managedProducer } from '../../dist/producer.js';

test('Kafka operation options reject invalid deadlines and fabricated signals before resource work', () => {
  assert.throws(() => operation({ timeoutMs: null as never }), { code: 'EK_CONFIG_INVALID' });
  for (const timeoutMs of [0, -1, 0.5, NaN, Infinity, 30001])
    assert.throws(() => operation({ timeoutMs }), { code: 'EK_CONFIG_INVALID' });
  for (const signal of [{ aborted: false }, new Proxy(new AbortController().signal, {})])
    assert.throws(() => operation({ signal: signal as AbortSignal }), {
      code: 'EK_CONFIG_INVALID',
    });
  let executed = 0;
  assert.throws(
    () =>
      operation(
        Object.defineProperty({}, 'timeoutMs', {
          get() {
            executed++;
            return 100;
          },
        }),
      ),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.equal(executed, 0);
  assert.equal(operation(undefined).timeoutMs, 10000);
});

test('Kafka provider errors cannot export arbitrary codes or execute hostile diagnostic accessors', async () => {
  let executed = 0;
  for (const error of [
    { code: 'untrusted-provider-detail' },
    Object.defineProperty({}, 'code', {
      get() {
        executed++;
        return 'EK_TIMEOUT';
      },
    }),
    new Proxy(
      {},
      {
        getOwnPropertyDescriptor() {
          executed++;
          throw new Error('The diagnostic trap must not execute');
        },
      },
    ),
  ]) {
    const task = new Task<void>(
      undefined,
      new AbortController().signal,
      () => undefined,
      async () => {
        throw error;
      },
      'EK_KAFKA_CONNECT',
    );
    await assert.rejects(task.result, (failure: unknown) => {
      assert.equal((failure as { code?: string }).code, 'EK_KAFKA_CONNECT');
      assert.ok(!JSON.stringify(failure).includes('untrusted-provider-detail'));
      return true;
    });
  }
  assert.equal(executed, 0);
});

test('Kafka logical cancellation cannot release pending work or lose an uncertain mutation outcome', async () => {
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  let entered!: () => void;
  const dispatched = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const controller = new AbortController();
  const task = new Task<void>(
    { signal: controller.signal },
    new AbortController().signal,
    () => {
      throw new Error('The cleanup fixture could not interrupt native work');
    },
    async (task) => {
      task.check();
      task.submitted = true;
      entered();
      await task.wait(pending);
    },
    'EK_KAFKA_PUBLISH',
  );
  await dispatched;
  let settled = false;
  void task.done.then(() => {
    settled = true;
  });
  controller.abort('private-reason');
  await assert.rejects(task.result, (error: unknown) => {
    assert.equal((error as { code?: string }).code, 'EK_ABORTED');
    assert.equal((error as { details?: { outcome?: string } }).details?.outcome, 'unknown');
    assert.ok(!JSON.stringify(error).includes('private-reason'));
    return true;
  });
  assert.equal(settled, false);
  release();
  await task.done;
  assert.equal(settled, true);
});

test('Kafka production rejects marked test secret resolvers, including inherited metadata and executable markers', () => {
  let invoked = 0;
  const resolver = async () => {
    invoked++;
    return '{}';
  };
  const config = {
    clusters: [
      {
        name: 'owned',
        brokers: ['127.0.0.1:19092'],
        clientId: 'owned',
        topics: ['orders.created'],
        maxBufferedMessages: 1,
        maxMessageBytes: 1024,
        acks: 'all',
        idempotentProducer: true,
      },
    ],
    resolveSecret: resolver,
  };
  Object.setPrototypeOf(resolver, { usage: 'test-only' });
  const captured = settings(config);
  assert.equal(captured.resolverUsage, 'test-only');
  for (const environment of ['production', 'development', 'staging'])
    assert.throws(
      () => managedProducer(captured, new AbortController().signal, () => true, environment),
      { code: 'EK_KAFKA_CONFIG' },
    );
  Object.setPrototypeOf(
    resolver,
    Object.defineProperty({}, 'usage', {
      get() {
        invoked++;
        return 'production';
      },
    }),
  );
  assert.throws(() => settings(config), { code: 'EK_KAFKA_CONFIG' });
  assert.equal(invoked, 0);
});
