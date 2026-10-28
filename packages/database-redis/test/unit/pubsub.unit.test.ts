// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { setImmediate, setTimeout as delay } from 'node:timers/promises';
import type { RedisClientType } from 'redis';
import { RedisSubscriber, subscriptionOptions } from '../../dist/pubsub.js';

function native() {
  let receive!: (message: string) => void;
  const client = Object.assign(new EventEmitter(), {
    isOpen: false,
    channel: '',
    async connect() {
      this.isOpen = true;
    },
    async subscribe(channel: string, handler: (message: string) => void) {
      this.channel = channel;
      receive = handler;
    },
    destroy() {
      this.isOpen = false;
    },
  });
  return {
    client,
    sdk: client as unknown as RedisClientType,
    send: (message: string) => receive(message),
  };
}
test('Redis subscriber serializes callbacks and retains physical work until cancellation actually settles', async () => {
  const sdk = native(),
    abort = new AbortController(),
    failures: unknown[] = [],
    messages: string[] = [];
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const subscriber = new RedisSubscriber(
    sdk.sdk,
    async (message, options) => {
      messages.push(message);
      assert.ok(options.signal);
      await gate;
    },
    subscriptionOptions({
      signal: abort.signal,
      timeoutMs: 1000,
      onFailure: (error) => {
        failures.push(error);
      },
    }),
  );
  await subscriber.start('scope:topic');
  sdk.send('first');
  sdk.send('second');
  await setImmediate();
  assert.deepEqual(messages, ['first']);
  abort.abort();
  let settled = false;
  const closing = subscriber.close().then(() => {
    settled = true;
  });
  await delay(10);
  assert.equal(settled, false);
  release();
  await closing;
  assert.equal(sdk.client.isOpen, false);
  assert.deepEqual(messages, ['first']);
  assert.deepEqual(failures, []);
});
test('Redis subscriber terminates oversized frames and native transport failures with safe bounded diagnostics', async () => {
  for (const scenario of ['overflow', 'transport', 'handler'] as const) {
    const sdk = native(),
      failures: Error[] = [];
    const subscriber = new RedisSubscriber(
      sdk.sdk,
      async () => {
        if (scenario === 'handler') throw new Error('private-payload');
      },
      subscriptionOptions({
        onFailure: (error) => {
          failures.push(error);
        },
      }),
    );
    await subscriber.start('scope:topic');
    if (scenario === 'transport') sdk.client.emit('error', new Error('private-credential'));
    else sdk.send(scenario === 'overflow' ? 'x'.repeat(1048577) : 'private-payload');
    await setImmediate();
    await setImmediate();
    await subscriber.close();
    assert.equal(failures.length, 1);
    assert.equal(failures[0]!.message.includes('private'), false);
    assert.equal(sdk.client.isOpen, false);
  }
});
test('Redis subscription options reject accessors, forged signals and invalid deadlines without evaluating caller code', () => {
  let reads = 0;
  const accessor = {
    get timeoutMs() {
      reads++;
      return 10;
    },
    onFailure() {},
  };
  for (const value of [
    null,
    [],
    accessor,
    { onFailure() {}, timeoutMs: 0 },
    { onFailure() {}, timeoutMs: 15001 },
    { onFailure() {}, signal: {} },
    { onFailure() {}, extra: true },
  ])
    assert.throws(() => subscriptionOptions(value as never), { code: 'EK_CONFIG_INVALID' });
  assert.equal(reads, 0);
  assert.throws(() => subscriptionOptions({ signal: AbortSignal.abort(), onFailure() {} }), {
    code: 'EK_ABORTED',
  });
});
