// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { Application, Plugin, PluginContext } from '@arkenivajs/core';
import { ACTIVATE_PLUGIN, DRAIN_PLUGIN, PREPARE_PLUGIN } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';

const service = { name: 'capability-test', version: '1.0.0', environment: 'test' } as const;
const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
const plugin = (id: string, changes: Partial<ComposablePlugin> = {}): ComposablePlugin => ({
  id,
  version: '1.0.0',
  capabilities: new Set(),
  init() {},
  close() {},
  ...changes,
});
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

test('EK-CORE-002 symbol resolution is explicit, instance-local and guarded by startup/closed state', async () => {
  const key = Symbol('test.service'),
    absent = Symbol('absent'),
    undefinedKey = Symbol('undefined');
  const first = await createApplication({
    service,
    plugins: [
      plugin('provider', {
        init(context) {
          context.provide(key, 1);
          context.provide(undefinedKey, undefined);
        },
      }),
    ],
  });
  const second = await createApplication({
    service,
    plugins: [
      plugin('provider', {
        init(context) {
          context.provide(key, 2);
        },
      }),
    ],
  });
  try {
    assert.throws(() => first.resolve(key), hasCode('EK_LIFECYCLE_STATE'));
    assert.throws(() => first.tryResolve(absent), hasCode('EK_LIFECYCLE_STATE'));
    await Promise.all([first.start(), second.start()]);
    assert.equal(first.resolve<number>(key), 1);
    assert.equal(second.resolve<number>(key), 2);
    assert.equal(first.tryResolve<number>(key), 1);
    assert.equal(first.resolve<undefined>(undefinedKey), undefined);
    assert.equal(first.tryResolve(absent), undefined);
    assert.equal(first.tryResolve(Symbol('test.service')), undefined);
    assert.throws(() => first.resolve(absent), hasCode('EK_UNSUPPORTED_CAPABILITY'));
    const borrowed = first.resolve;
    assert.equal(borrowed.call(second, key), 1);
    await first.stop();
    assert.throws(() => first.resolve(key), hasCode('EK_LIFECYCLE_STATE'));
    assert.throws(() => first.tryResolve(absent), hasCode('EK_LIFECYCLE_STATE'));
    assert.equal(second.resolve(key), 2);
  } finally {
    await Promise.all([first.stop(), second.stop()]);
  }
});

test('EK-CORE-002 initialization retains declared dependency checks across awaits and admits optional absence', async () => {
  const key = Symbol(),
    missing = Symbol();
  const provider = plugin('provider', {
    init(context) {
      context.provide(key, 42);
      assert.equal(app.resolve(key), 42);
    },
  });
  const undeclared = plugin('undeclared', {
    init() {
      assert.throws(() => app.resolve(key), hasCode('EK_PLUGIN_DEPENDENCY'));
      assert.throws(() => app.tryResolve(key), hasCode('EK_PLUGIN_DEPENDENCY'));
    },
  });
  const consumer = plugin('consumer', {
    dependencies: ['provider'],
    async init() {
      await Promise.resolve();
      assert.equal(app.resolve<number>(key), 42);
      assert.equal(app.tryResolve(missing), undefined);
      assert.throws(() => app.resolve(missing), hasCode('EK_UNSUPPORTED_CAPABILITY'));
    },
  });
  const app = await createApplication({ service, plugins: [provider, undeclared, consumer] });
  try {
    await app.start();
  } finally {
    await app.stop();
  }
});

test('EK-CORE-002 external callers and expired asynchronous initialization scopes cannot borrow another plugin admission', async () => {
  const key = Symbol(),
    consumerStarted = gate(),
    finishConsumer = gate(),
    releaseOrphan = gate(),
    orphanDone = gate();
  const app = await createApplication({
    service,
    plugins: [
      plugin('provider', {
        init(context) {
          context.provide(key, 7);
          void releaseOrphan.promise.then(() => {
            try {
              assert.throws(() => app.resolve(key), hasCode('EK_LIFECYCLE_STATE'));
            } finally {
              orphanDone.release();
            }
          });
        },
      }),
      plugin('consumer', {
        dependencies: ['provider'],
        async init() {
          assert.equal(app.resolve(key), 7);
          consumerStarted.release();
          await finishConsumer.promise;
          assert.equal(app.resolve(key), 7);
        },
      }),
    ],
  });
  const starting = app.start();
  try {
    await consumerStarted.promise;
    assert.throws(() => app.resolve(key), hasCode('EK_LIFECYCLE_STATE'));
    releaseOrphan.release();
    await orphanDone.promise;
    finishConsumer.release();
    await starting;
    assert.equal(app.resolve(key), 7);
  } finally {
    releaseOrphan.release();
    finishConsumer.release();
    await starting.catch(() => undefined);
    await app.stop();
  }
});

test('EK-CORE-002 concurrent applications never share their active initialization scope', async () => {
  const key = Symbol(),
    firstEntered = gate(),
    secondEntered = gate(),
    release = gate();
  const plugins = (
    value: number,
    entered: ReturnType<typeof gate>,
    own: () => Application,
    other: () => Application,
  ): Plugin[] => [
    plugin('provider', {
      init(context) {
        context.provide(key, value);
      },
    }),
    plugin('consumer', {
      dependencies: ['provider'],
      async init() {
        entered.release();
        await release.promise;
        assert.equal(own().resolve(key), value);
        assert.throws(() => other().resolve(key), hasCode('EK_LIFECYCLE_STATE'));
      },
    }),
  ];
  const first = await createApplication({
    service,
    plugins: plugins(
      1,
      firstEntered,
      () => first,
      () => second,
    ),
  });
  const second = await createApplication({
    service,
    plugins: plugins(
      2,
      secondEntered,
      () => second,
      () => first,
    ),
  });
  const starting = [first.start(), second.start()];
  try {
    await Promise.all([firstEntered.promise, secondEntered.promise]);
    release.release();
    await Promise.all(starting);
  } finally {
    release.release();
    await Promise.allSettled(starting);
    await Promise.all([first.stop(), second.stop()]);
  }
});

test('EK-CORE-002 activation uses the same declared dependency scope without reopening registration', async () => {
  const key = Symbol();
  const app = await createApplication({
    service,
    plugins: [
      plugin('provider', {
        init(context) {
          context.provide(key, 5);
        },
      }),
      plugin('consumer', {
        dependencies: ['provider'],
        async [ACTIVATE_PLUGIN](context) {
          await Promise.resolve();
          assert.equal(app.resolve(key), 5);
          assert.throws(() => context.provide(Symbol(), 6), hasCode('EK_LIFECYCLE_STATE'));
        },
      }),
    ],
  });
  try {
    await app.start();
  } finally {
    await app.stop();
  }
});

test('EK-CORE-002 admitted drain work keeps initialized dependencies until their owner closes', async () => {
  const key = Symbol(),
    draining = gate(),
    release = gate();
  const instance = Object.freeze({ value: 1 });
  const app = await createApplication({
    service,
    plugins: [
      plugin('provider', {
        init(context) {
          context.provide(key, instance);
        },
        async [DRAIN_PLUGIN]() {
          draining.release();
          await release.promise;
        },
      }),
    ],
  });
  await app.start();
  const stopping = app.stop();
  try {
    await draining.promise;
    assert.equal(app.state, 'DRAINING');
    assert.equal(app.resolve(key), instance);
  } finally {
    release.release();
    await stopping;
  }
  assert.throws(() => app.tryResolve(key), hasCode('EK_LIFECYCLE_STATE'));
});

test('EK-CORE-002 stopping before startup cannot expose prepared but uninitialized services', async () => {
  const prepared = {};
  const app = await createApplication({
    service,
    plugins: [
      plugin('endpoint', {
        capabilities: new Set(['api']),
        [PREPARE_PLUGIN]: () => new Map([[COMPONENTS.api, prepared]]),
      }),
    ],
  });
  assert.equal(app.api, prepared);
  const stopping = app.stop();
  assert.throws(() => app.tryResolve(COMPONENTS.api), hasCode('EK_LIFECYCLE_STATE'));
  await stopping;
});

test('EK-CORE-002 duplicate registration preserves the bootstrap error and never overwrites the first owner', async () => {
  const key = Symbol();
  let closed = 0;
  const app = await createApplication({
    service,
    plugins: [
      plugin('first', {
        init(context) {
          context.provide(key, 1);
        },
        close(context) {
          assert.equal(context.require(key), 1);
          closed++;
        },
      }),
      plugin('second', {
        init(context) {
          context.provide(key, 2);
        },
      }),
    ],
  });
  await assert.rejects(app.start(), (error) => {
    assert.ok(error instanceof KitError);
    assert.equal(error.code, 'EK_PLUGIN_DUPLICATE');
    assert.ok(error.cause instanceof KitError);
    assert.equal(error.cause.code, 'EK_PLUGIN_DUPLICATE');
    return true;
  });
  assert.equal(closed, 1);
  assert.equal(app.state, 'CLOSED');
  assert.throws(() => app.resolve(key), hasCode('EK_LIFECYCLE_STATE'));
  await app.stop();
});

test('EK-CORE-002 non-symbol keys fail without coercion in registry and public resolution', async () => {
  let context!: PluginContext,
    invoked = 0;
  const invalid = Object.defineProperty({}, Symbol.toPrimitive, {
    get() {
      invoked++;
      return () => 'unexpected';
    },
  });
  const app = await createApplication({
    service,
    plugins: [
      plugin('provider', {
        init(value) {
          context = value;
          for (const key of ['string', 1, null, invalid]) {
            assert.throws(() => value.provide(key as symbol, 1), hasCode('EK_CONFIG_INVALID'));
            assert.throws(() => value.require(key as symbol), hasCode('EK_CONFIG_INVALID'));
          }
        },
      }),
    ],
  });
  try {
    await app.start();
    for (const key of ['string', 1, null, invalid]) {
      assert.throws(() => app.resolve(key as symbol), hasCode('EK_CONFIG_INVALID'));
      assert.throws(() => app.tryResolve(key as symbol), hasCode('EK_CONFIG_INVALID'));
    }
    assert.equal(invoked, 0);
    assert.ok(context);
  } finally {
    await app.stop();
  }
});

test(
  'EK-CORE-002 startup cancellation immediately closes active resolution admission',
  { timeout: 3000 },
  async () => {
    const key = Symbol(),
      closed = gate();
    let stopping!: Promise<void>,
      closes = 0;
    const app = await createApplication({
      service,
      plugins: [
        plugin('provider', {
          init(context) {
            context.provide(key, 1);
            assert.equal(app.resolve(key), 1);
            stopping = app.stop({ timeoutMs: 1000 });
            assert.equal(context.require<AbortSignal>(APPLICATION_SIGNAL).aborted, true);
            assert.throws(() => app.resolve(key), hasCode('EK_LIFECYCLE_STATE'));
          },
          close() {
            closes++;
            closed.release();
          },
        }),
      ],
    });
    await assert.rejects(app.start(), hasCode('EK_ABORTED'));
    await stopping;
    await closed.promise;
    assert.equal(closes, 1);
    assert.equal(app.state, 'CLOSED');
  },
);
