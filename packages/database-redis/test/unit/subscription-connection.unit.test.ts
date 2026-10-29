// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { setImmediate } from 'node:timers/promises';
import type { RedisClientType } from 'redis';
import { sdkDouble } from '../fixtures/native-double.js';

function child(fail = false) {
  let receive!: (message: string) => void;
  const client = Object.assign(new EventEmitter(), {
    isOpen: false,
    channel: '',
    destroys: 0,
    async connect() {
      this.isOpen = true;
      if (fail) throw new Error('Private native connection diagnostic');
    },
    async subscribe(channel: string, handler: (message: string) => void) {
      this.channel = channel;
      receive = handler;
    },
    destroy() {
      this.isOpen = false;
      this.destroys++;
    },
  });
  return {
    client,
    sdk: client as unknown as RedisClientType,
    send: (value: string) => receive(value),
  };
}

test('Redis connection owns prefixed dedicated subscribers and releases capacity only after physical callback completion', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection(),
    children: ReturnType<typeof child>[] = [];
  Object.assign(sdk.client, {
    duplicate() {
      const selected = child();
      children.push(selected);
      return selected.sdk;
    },
  });
  await connection.start();
  const received: string[] = [];
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const subscription = await connection.subscribe(
    'events',
    async (message, options) => {
      received.push(message);
      assert.ok(options.signal);
      await gate;
    },
    {
      onFailure() {
        assert.fail('A normal close must not report transport failure');
      },
    },
  );
  assert.equal(children[0]!.client.channel, 'scope:events');
  children[0]!.send('first');
  children[0]!.send('second');
  await setImmediate();
  let closed = false;
  const closing = subscription.close().then(() => {
    closed = true;
  });
  await setImmediate();
  assert.equal(closed, false);
  assert.equal(children[0]!.client.isOpen, false);
  release();
  await closing;
  assert.deepEqual(received, ['first']);
  const next = await connection.subscribe('next', async () => {}, { onFailure() {} });
  await connection.close();
  assert.equal(children[1]!.client.destroys, 1);
  await next.close();
  await assert.rejects(
    connection.subscribe('later', async () => {}, { onFailure() {} }),
    { code: 'EK_RESOURCE_CLOSED' },
  );
  assert.equal(children.length, 2);
});

test('Redis subscription admission bounds concurrent native acquisitions and recovers after a failed connection', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection(),
    children: ReturnType<typeof child>[] = [];
  let fail = true;
  Object.assign(sdk.client, {
    duplicate() {
      const selected = child(fail);
      children.push(selected);
      return selected.sdk;
    },
  });
  await connection.start();
  await assert.rejects(
    connection.subscribe('failed', async () => {}, { onFailure() {} }),
    { code: 'EK_BACKEND_UNAVAILABLE' },
  );
  assert.equal(children[0]!.client.destroys, 1);
  fail = false;
  const attempts = await Promise.allSettled(
    Array.from({ length: 33 }, () =>
      connection.subscribe('topic', async () => {}, { onFailure() {} }),
    ),
  );
  assert.equal(attempts.filter((result) => result.status === 'fulfilled').length, 32);
  const rejected = attempts.filter((result) => result.status === 'rejected');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0]!.reason.code, 'EK_BACKEND_UNAVAILABLE');
  assert.equal(children.length, 33);
  await assert.rejects(
    connection.subscribe('topic', async () => {}, { onFailure() {} }),
    { code: 'EK_BACKEND_UNAVAILABLE' },
  );
  await connection.close();
  assert.ok(children.every(({ client }) => !client.isOpen && client.destroys === 1));
});

test('Redis rejects invalid and proxied subscription handlers before duplicating the native connection', async (context) => {
  const sdk = sdkDouble(context),
    connection = sdk.connection();
  let duplicates = 0,
    calls = 0;
  Object.assign(sdk.client, {
    duplicate() {
      duplicates++;
      return child().sdk;
    },
  });
  await connection.start();
  const proxied = new Proxy(async () => {}, {
    apply() {
      calls++;
    },
  });
  for (const handler of [null, {}, proxied])
    await assert.rejects(connection.subscribe('topic', handler as never, { onFailure() {} }), {
      code: 'EK_CONFIG_INVALID',
    });
  assert.equal(duplicates, 0);
  assert.equal(calls, 0);
  await connection.close();
});
