// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError, createApplication } from '@arkenivajs/core';
import { amqpPlugin, AMQP_CAPABILITY } from '../../dist/index.js';
import type { AmqpPluginSettings } from '../../dist/index.js';
import { managedService } from '../../dist/service.js';
import { capture } from '../../dist/settings.js';
import { Task, operation } from '../../dist/operation.js';

const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
function settings(): AmqpPluginSettings {
  return {
    connections: [
      {
        name: 'events',
        connectionUriSecretRef: 'fixture-uri',
        maxInFlightPublishes: 2,
        maxMessageBytes: 1024,
        topology: {
          exchanges: [{ name: 'fixture.events', type: 'topic', routingKeys: ['event.created'] }],
          queues: [],
          bindings: [],
        },
      },
    ],
    resolveSecret: async () => {
      throw new Error('No resolver I/O is allowed');
    },
  };
}
test('AMQP factories expose an opt-in capability without provider I/O and lifecycle checks fail closed', async () => {
  let calls = 0;
  const config = {
      ...settings(),
      resolveSecret: async () => {
        calls++;
        throw new Error('Must not execute');
      },
    },
    plugin = amqpPlugin(config),
    manager = managedService(capture(config), new AbortController().signal, () => false);
  assert.ok(plugin.capabilities.has('messaging-amqp'));
  assert.equal(typeof AMQP_CAPABILITY, 'symbol');
  assert.equal(calls, 0);
  await assert.rejects(manager.service.health('events'), code('EK_LIFECYCLE_STATE'));
  await manager.close();
  assert.throws(() => manager.service.native('events'), code('EK_RESOURCE_CLOSED'));
  assert.equal(calls, 0);
});
test('AMQP refuses inherited test-only resolvers in production before connecting or resolving secrets', async () => {
  let calls = 0;
  const resolver = async () => {
    calls++;
    throw new Error('Must not execute');
  };
  Object.setPrototypeOf(resolver, { usage: 'test-only' });
  const app = await createApplication({
    service: { name: 'amqp-production', version: '1.0.0', environment: 'production' },
    plugins: [amqpPlugin({ ...settings(), resolveSecret: resolver })],
  });
  try {
    await assert.rejects(
      app.start(),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_PLUGIN_FAILED' &&
        error.cause instanceof KitError &&
        error.cause.code === 'EK_AMQP_CONFIG',
    );
    assert.equal(calls, 0);
  } finally {
    await app.stop();
  }
});
test('AMQP validates timeout and signal brands before operation work begins', () => {
  assert.throws(() => operation(null as unknown as undefined), code('EK_CONFIG_INVALID'));
  for (const timeoutMs of [0, -1, 0.5, Infinity, NaN, 30001])
    assert.throws(() => operation({ timeoutMs }), code('EK_CONFIG_INVALID'));
  assert.throws(
    () => operation({ signal: { aborted: false } as AbortSignal }),
    code('EK_CONFIG_INVALID'),
  );
  let calls = 0;
  const signal = new AbortController().signal;
  Object.defineProperty(signal, 'aborted', {
    get() {
      calls++;
      return false;
    },
  });
  assert.throws(() => operation({ signal }), code('EK_CONFIG_INVALID'));
  assert.equal(calls, 0);
});
test('AMQP task cancellation retains owned cleanup after caller hook replacement', async () => {
  for (const cancelled of [false, true]) {
    const controller = new AbortController();
    let effects = 0,
      release!: () => void;
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    const task = new Task(
      { signal: controller.signal },
      new AbortController().signal,
      () => undefined,
      async () => {
        await hold;
        return true;
      },
    );
    Object.defineProperty(controller.signal, 'removeEventListener', {
      value() {
        effects++;
      },
    });
    try {
      if (cancelled) {
        controller.abort();
        await assert.rejects(task.result, code('EK_ABORTED'));
      }
      release();
      if (!cancelled) assert.equal(await task.result, true);
      await task.done;
      assert.equal(effects, 0);
    } finally {
      release();
      await task.done;
    }
  }
});
test('AMQP rejects proxy operation controls and excessive signal prototype traversal without evaluating traps', () => {
  let effects = 0;
  const trap = () => {
    effects++;
    throw new Error('Operation control traps must not execute');
  };
  assert.throws(
    () => operation(new Proxy({}, { getPrototypeOf: trap, ownKeys: trap }) as never),
    code('EK_CONFIG_INVALID'),
  );
  assert.equal(effects, 0);
  const signal = new AbortController().signal;
  let prototype: object = AbortSignal.prototype;
  for (let depth = 0; depth < 65; depth++) prototype = Object.create(prototype) as object;
  Object.setPrototypeOf(signal, prototype);
  assert.throws(() => operation({ signal }), code('EK_CONFIG_INVALID'));
});
test('An aborted submitted publication reports unknown and retains started work until actual settlement', async () => {
  let release!: () => void, entered!: () => void;
  const hold = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    controller = new AbortController();
  const task = new Task(
    { signal: controller.signal },
    new AbortController().signal,
    () => undefined,
    async (task) => {
      task.submitted = true;
      entered();
      await task.wait(hold);
      return 'confirmed';
    },
    () => 'unknown',
  );
  await started;
  controller.abort();
  assert.equal(await task.result, 'unknown');
  let ended = false;
  void task.done.then(() => {
    ended = true;
  });
  await delay(10);
  assert.equal(ended, false);
  release();
  await task.done;
  assert.equal(ended, true);
});
test('Uncooperative secret resolution retains startup and shutdown ownership after cancellation', async () => {
  let release!: () => void, entered!: () => void;
  const hold = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    controller = new AbortController();
  const manager = managedService(
    capture({
      ...settings(),
      resolveSecret: async () => {
        entered();
        await hold;
        return 'must-not-be-used';
      },
    }),
    controller.signal,
    () => true,
  );
  const opening = manager.init();
  await started;
  controller.abort();
  await assert.rejects(opening, code('EK_ABORTED'));
  let ended = false;
  const closed = manager.close().then(() => {
    ended = true;
  });
  await delay(10);
  assert.equal(ended, false);
  release();
  await closed;
  assert.equal(ended, true);
});
