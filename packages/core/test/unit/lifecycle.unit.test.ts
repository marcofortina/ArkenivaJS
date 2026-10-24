import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication, KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { ApplicationOptions, Plugin, PluginContext } from '@arkenivajs/core';

const service = { name: 'test-service', version: '1.0.0', environment: 'test' } as const;
const code =
  (expected: string) =>
  (error: unknown): boolean =>
    error instanceof KitError && error.code === expected;
const plugin = (id: string, changes: Partial<Plugin> = {}): Plugin => ({
  id,
  version: '1.0.0',
  capabilities: new Set(),
  init() {},
  close() {},
  ...changes,
});

test('EK-CORE-001 concurrent startup and reverse shutdown run hooks exactly once', async () => {
  const order: string[] = [];
  const key = Symbol();
  let saved: PluginContext | undefined;
  const a = plugin('a', {
    init(ctx) {
      saved = ctx;
      ctx.provide(key, 42);
      order.push('a+');
    },
    close() {
      order.push('a-');
    },
  });
  const b = plugin('b', {
    dependencies: ['a'],
    init(ctx) {
      assert.equal(ctx.require(key), 42);
      order.push('b+');
    },
    close() {
      order.push('b-');
    },
  });
  const app = await createApplication({ service, plugins: [b, a] });
  assert.equal(app.state, 'CREATED');
  assert.equal(app.config.require('service'), app.config.get('service'));
  const first = app.start();
  assert.equal(app.state, 'INITIALIZING');
  assert.equal(first, app.start());
  await first;
  await app.start();
  assert.equal(app.state, 'READY');
  assert.throws(() => saved?.provide(Symbol(), 1), code('EK_LIFECYCLE_STATE'));
  assert.throws(() => app.logger, code('EK_UNSUPPORTED_CAPABILITY'));
  for (const field of [
    'api',
    'http',
    'sql',
    'telemetry',
    'meter',
    'diagnostics',
    'health',
  ] as const)
    assert.throws(() => app[field], code('EK_UNSUPPORTED_CAPABILITY'));
  for (const field of ['auth', 'redis', 'etcd', 'mongo', 'cache', 'messaging'] as const)
    assert.equal(app[field], undefined);
  const stop = app.stop();
  assert.equal(stop, app.stop());
  await stop;
  await app.stop();
  assert.equal(app.state, 'CLOSED');
  assert.deepEqual(order, ['a+', 'b+', 'b-', 'a-']);
  await assert.rejects(app.start(), code('EK_LIFECYCLE_STATE'));
});

test('EK-CORE-001 startup failure preserves primary cause and rolls back all started hooks', async () => {
  const order: string[] = [];
  const cause = new Error('fake-secret');
  const app = await createApplication({
    service,
    plugins: [
      plugin('a', {
        close() {
          order.push('a');
          throw new Error('cleanup');
        },
      }),
      plugin('b', {
        dependencies: ['a'],
        close() {
          order.push('b');
        },
      }),
      plugin('c', {
        init() {
          throw cause;
        },
      }),
    ],
  });
  await assert.rejects(app.start(), (error: unknown) => {
    assert.ok(error instanceof KitError);
    assert.equal(error.code, 'EK_PLUGIN_FAILED');
    assert.equal(error.cause, cause);
    assert.equal(error.details.cleanupFailureCount, 1);
    return true;
  });
  assert.equal(app.state, 'CLOSED');
  assert.deepEqual(order, ['b', 'a']);
  await app.stop();
});

test('EK-CORE-001 shutdown continues after hook errors and bounds hung hooks', async () => {
  for (const timeout of [false, true]) {
    let closed = 0;
    const app = await createApplication({
      service,
      plugins: [
        plugin('a', {
          close() {
            closed++;
          },
        }),
        plugin('b', {
          close() {
            if (timeout) return new Promise<void>(() => {});
            throw new Error('close');
          },
        }),
      ],
    });
    await app.start();
    await assert.rejects(
      app.stop({ timeoutMs: 15 }),
      code(timeout ? 'EK_TIMEOUT' : 'EK_PLUGIN_FAILED'),
    );
    assert.equal(closed, 1);
    assert.equal(app.state, 'CLOSED');
  }
});

test('EK-CORE-001 stop cancels initializing hooks through kernel signal', async () => {
  let entered!: () => void;
  const ready = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const app = await createApplication({
    service,
    plugins: [
      plugin('waiting', {
        async init(ctx) {
          const signal = ctx.require<AbortSignal>(APPLICATION_SIGNAL);
          entered();
          await delay(1000, undefined, { signal });
        },
      }),
    ],
  });
  const start = app.start();
  const rejected = assert.rejects(start, code('EK_ABORTED'));
  await ready;
  await app.stop({ timeoutMs: 100 });
  await rejected;
  assert.equal(app.state, 'CLOSED');
});

test('EK-CORE-001 stop before start closes without initializing; invalid deadlines reject', async () => {
  const app = await createApplication({ service });
  for (const timeoutMs of [0, -1, 0.1, Infinity, NaN])
    await assert.rejects(app.stop({ timeoutMs }), code('EK_CONFIG_INVALID'));
  await app.stop();
  assert.equal(app.state, 'CLOSED');
});

test('EK-CORE-002 duplicate, missing and cyclic plugin dependencies reject before hooks', async () => {
  for (const [plugins, expected] of [
    [[plugin('a'), plugin('a')], 'EK_PLUGIN_DUPLICATE'],
    [[plugin('a', { dependencies: ['absent'] })], 'EK_PLUGIN_DEPENDENCY'],
    [
      [plugin('a', { dependencies: ['b'] }), plugin('b', { dependencies: ['a'] })],
      'EK_PLUGIN_DEPENDENCY',
    ],
    [[plugin('INVALID')], 'EK_CONFIG_INVALID'],
  ] as const)
    await assert.rejects(createApplication({ service, plugins }), code(expected));
});

test('EK-CORE-002 providers cannot overwrite or consume undeclared dependencies', async () => {
  const key = Symbol();
  for (const duplicate of [true, false]) {
    const app = await createApplication({
      service,
      plugins: [
        plugin('a', {
          init(ctx) {
            ctx.provide(key, 1);
            assert.equal(ctx.require(key), 1);
          },
        }),
        plugin('b', {
          init(ctx) {
            if (duplicate) ctx.provide(key, 2);
            else ctx.require(key);
          },
        }),
      ],
    });
    await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
  }
});

test('EK-CONF-001 rejects invalid root data and unsupported feature configuration', async () => {
  for (const invalid of [
    null,
    [],
    {},
    { service: { ...service, name: 'BAD' } },
    { service: { ...service, version: 'bad' } },
    { service, typo: true },
    { service, plugins: {} },
    {
      get service() {
        throw new Error('getter');
      },
    },
  ]) {
    await assert.rejects(
      createApplication(invalid as ApplicationOptions),
      code('EK_CONFIG_INVALID'),
    );
  }
  for (const data of [
    { http: { host: '127.0.0.1', port: 8000 } },
    { security: { issuer: 'https://example.invalid', audience: 'test' } },
    { telemetry: { mode: 'off' } },
    { metering: { enabled: false } },
    { databases: { main: { driver: 'postgresql', connectionStringEnv: 'PG_URL' } } },
  ]) {
    await assert.rejects(
      createApplication({ service, ...data } as ApplicationOptions),
      code('EK_PLUGIN_DEPENDENCY'),
    );
  }
});

test('EK-CONF-001 validates database definitions without loading drivers', async () => {
  const db = plugin('db', { capabilities: new Set(['database.redis', 'database.postgresql']) });
  for (const databases of [
    { a: { driver: 'redis' }, b: { driver: 'redis' } },
    { a: { driver: 'redis', poolMin: 0 } },
    { a: { driver: 'postgresql', poolMin: 5, poolMax: 2 } },
    { a: { driver: 'postgresql', connectionStringEnv: 'bad-env' } },
  ])
    await assert.rejects(
      createApplication({ service, plugins: [db], databases } as ApplicationOptions),
      code('EK_CONFIG_INVALID'),
    );
  const app = await createApplication({
    service,
    plugins: [db],
    databases: {
      a: { driver: 'postgresql' },
      b: { driver: 'postgresql', poolMax: 2 },
      cache: { driver: 'redis' },
    },
  });
  await app.start();
  await app.stop();
});

test('EK-CORE-002 capability components remain isolated between applications', async () => {
  const instance = { marker: 42 };
  const app = await createApplication({
    service,
    plugins: [
      plugin('provider', {
        init(ctx) {
          ctx.provide(COMPONENTS.http, instance);
          ctx.provide(COMPONENTS.config, { snapshot: () => ({}) });
        },
      }),
    ],
  });
  await app.start();
  assert.equal(app.http, instance);
  assert.deepEqual(app.config.snapshot(), {});
  const other = await createApplication({ service });
  assert.throws(() => other.http, code('EK_UNSUPPORTED_CAPABILITY'));
  await app.stop();
  await other.stop();
});

test('EK-CORE-001 a successful hook finishing after cancellation closes exactly once', async () => {
  let resolveInit!: () => void;
  let entered!: () => void;
  const ready = new Promise<void>((resolve) => {
    entered = resolve;
  });
  let closed = 0;
  const app = await createApplication({
    service,
    plugins: [
      plugin('late', {
        init() {
          entered();
          return new Promise<void>((resolve) => {
            resolveInit = resolve;
          });
        },
        close() {
          closed++;
        },
      }),
    ],
  });
  const start = app.start();
  const rejected = assert.rejects(start, code('EK_ABORTED'));
  await ready;
  await app.stop({ timeoutMs: 100 });
  await rejected;
  resolveInit();
  await delay(5);
  assert.equal(closed, 1);
  await app.stop();
  assert.equal(closed, 1);
});

test('EK-CORE-001 cancellation reports rollback errors and keeps repeated closed stops harmless', async () => {
  let entered!: () => void;
  const ready = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const app = await createApplication({
    service,
    plugins: [
      plugin('owned', {
        close() {
          throw new Error('cleanup');
        },
      }),
      plugin('waiting', {
        dependencies: ['owned'],
        async init(ctx) {
          entered();
          await delay(1000, undefined, { signal: ctx.require<AbortSignal>(APPLICATION_SIGNAL) });
        },
      }),
    ],
  });
  const start = app.start();
  const rejected = assert.rejects(start, code('EK_ABORTED'));
  await ready;
  await assert.rejects(app.stop({ timeoutMs: 100 }), code('EK_PLUGIN_FAILED'));
  await rejected;
  await app.stop();
});

test('EK-CORE-002 class plugins retain their receiver and expose immutable capabilities', async () => {
  class CounterPlugin implements Plugin {
    readonly id = 'class-plugin';
    readonly version = '1.0.0';
    readonly capabilities = new Set(['class']);
    count = 0;
    init(ctx: PluginContext) {
      this.count++;
      const selected = ctx.options.plugins?.[0]?.capabilities;
      assert.equal(selected?.has('class'), true);
      assert.deepEqual([...(selected ?? [])], ['class']);
      assert.equal(selected?.size, 1);
      assert.deepEqual([...(selected?.keys() ?? [])], ['class']);
      assert.deepEqual([...(selected?.values() ?? [])], ['class']);
      assert.deepEqual([...(selected?.entries() ?? [])], [['class', 'class']]);
      selected?.forEach((value, key, set) => {
        assert.equal(value, key);
        assert.equal(set, selected);
      });
      assert.equal((selected as unknown as { add?: unknown }).add, undefined);
    }
    close() {
      this.count--;
    }
  }
  const counter = new CounterPlugin();
  const app = await createApplication({ service, plugins: [counter] });
  await app.start();
  assert.equal(counter.count, 1);
  await app.stop();
  assert.equal(counter.count, 0);
});
