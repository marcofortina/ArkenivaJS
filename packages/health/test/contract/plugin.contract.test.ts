import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import { healthPlugin } from '@arkenivajs/health';
import { setTimeout as delay } from 'node:timers/promises';
import { DRAIN_PLUGIN } from '@arkenivajs/core/support';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import { apiPlugin } from '@arkenivajs/api';
import type { ManagedApiServer } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { Writable } from 'node:stream';
import { createServer } from 'node:net';

const service = { name: 'health-contract', version: '1.0.0', environment: 'test' as const };
const logging = () =>
  loggingPlugin({
    destination: new Writable({
      write(_chunk, _encoding, done) {
        done();
      },
    }),
  });

test('Health plugin automatically probes optional owner hooks and prevents an unhealthy HTTP listener from activating', async () => {
  const reserve = createServer();
  await new Promise<void>((resolve) => reserve.listen(0, '127.0.0.1', resolve));
  const address = reserve.address();
  assert.ok(address && typeof address === 'object');
  const port = address.port;
  await new Promise<void>((resolve, reject) =>
    reserve.close((error) => (error ? reject(error) : resolve())),
  );
  let available = true,
    calls = 0;
  const dependency: ComposablePlugin = {
    id: 'dependency',
    version: '0.1.0',
    capabilities: new Set(),
    init() {},
    close() {},
    health() {
      calls++;
      return available;
    },
  };
  const app = await createApplication({
    service,
    http: { host: '127.0.0.1', port },
    plugins: [apiPlugin(), healthPlugin(), dependency, logging()],
  });
  await app.start();
  try {
    assert.equal(calls, 1);
    const api = app.api as ManagedApiServer;
    assert.equal((await fetch(api.address() + '/readyz')).status, 200);
    available = false;
    const response = await fetch(api.address() + '/readyz');
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { status: 'not_ready' });
    assert.deepEqual(await app.health.ready(), {
      status: 'not_ready',
      failing: ['plugin.dependency'],
    });
    assert.equal((await fetch(api.address() + '/livez')).status, 200);
  } finally {
    await app.stop();
  }
  const failed = await createApplication({
    service,
    http: { host: '127.0.0.1', port },
    plugins: [apiPlugin(), healthPlugin(), dependency, logging()],
  });
  const api = failed.api as ManagedApiServer;
  await assert.rejects(failed.start());
  assert.equal(api.address(), undefined);
  assert.equal(failed.state, 'CLOSED');
  await failed.stop();
});

test('Health facade rechecks the root lifecycle after a custom probe completes during inbound drain', async () => {
  let calls = 0,
    release!: () => void,
    drain!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const draining = new Promise<void>((resolve) => {
    drain = resolve;
  });
  const inbound: ComposablePlugin = {
    id: 'inbound',
    version: '0.1.0',
    capabilities: new Set(),
    init() {},
    close() {},
    async [DRAIN_PLUGIN]() {
      drain();
      await gate;
    },
  };
  const app = await createApplication({
    service,
    plugins: [
      healthPlugin({
        checks: [
          {
            name: 'custom',
            async check() {
              if (++calls > 1) await gate;
              return true;
            },
          },
        ],
      }),
      inbound,
    ],
  });
  const health = app.health;
  await app.start();
  const waiting = health.ready();
  await delay(0);
  const stopping = app.stop();
  await draining;
  assert.equal(app.state, 'DRAINING');
  release();
  assert.deepEqual(await waiting, { status: 'not_ready', failing: ['application'] });
  await stopping;
});
test('Health plugin prepares a frozen process-local facade and probes only its declared dependency', async () => {
  const key = Symbol('health.dependency');
  let available = true,
    reads = 0;
  const plugin = healthPlugin({
    dependencies: ['dependency'],
    checks: [
      {
        name: 'primary',
        check(context) {
          reads++;
          return context.require<() => boolean>(key)();
        },
      },
    ],
  });
  const app = await createApplication({
    service,
    plugins: [
      plugin,
      {
        id: 'dependency',
        version: '0.1.0',
        capabilities: new Set(['dependency']),
        init(context) {
          context.provide(key, () => available);
        },
        close() {},
      },
    ],
  });
  const health = app.health;
  assert.equal(Object.isFrozen(health), true);
  assert.deepEqual(health.live(), { status: 'live' });
  assert.deepEqual(await health.ready(), { status: 'not_ready', failing: ['application'] });
  assert.equal(reads, 0);
  await app.start();
  try {
    assert.deepEqual(await health.ready(), { status: 'ready', failing: [] });
    available = false;
    assert.deepEqual(await health.ready(), { status: 'not_ready', failing: ['primary'] });
  } finally {
    await app.stop();
  }
  assert.deepEqual(await health.ready(), { status: 'not_ready', failing: ['application'] });
  assert.deepEqual(health.live(), { status: 'live' });
});

test('Health startup fails closed for an unavailable dependency and rejects malformed plugin policy before initialization', async () => {
  for (const options of [
    null,
    [],
    { unexpected: true },
    { dependencies: false },
    { dependencies: [42] },
    { checks: false },
    { timeoutMs: 0 },
    { checks: [{ name: 'invalid' }] },
  ])
    assert.throws(() => healthPlugin(options as never), { code: 'EK_CONFIG_INVALID' });
  const app = await createApplication({
    service,
    plugins: [healthPlugin({ checks: [{ name: 'offline', check: () => false }] })],
  });
  const health = app.health;
  await assert.rejects(app.start());
  assert.equal(app.state, 'CLOSED');
  assert.deepEqual(await health.ready(), { status: 'not_ready', failing: ['application'] });
  await app.stop();
});

test('Health rejects duplicate automatic names and combined capacity before initializing any owner', async () => {
  let initialized = 0;
  const owner: ComposablePlugin = {
    id: 'owner',
    version: '0.1.0',
    capabilities: new Set(),
    init() {
      initialized++;
    },
    close() {},
    health() {
      return true;
    },
  };
  for (const checks of [
    [{ name: 'plugin.owner', check: () => true }],
    Array.from({ length: 32 }, (_, index) => ({ name: 'check' + index, check: () => true })),
  ])
    await assert.rejects(
      createApplication({ service, plugins: [owner, healthPlugin({ checks })] }),
      { code: 'EK_CONFIG_INVALID' },
    );
  assert.equal(initialized, 0);
});

test(
  'Health reports a bounded failed-start cleanup when a dependency ignores cancellation',
  { timeout: 10000 },
  async () => {
    let release!: () => void;
    const gate = new Promise<boolean>((resolve) => {
      release = () => resolve(true);
    });
    const app = await createApplication({
      service,
      plugins: [
        healthPlugin({ timeoutMs: 5, checks: [{ name: 'uncooperative', check: () => gate }] }),
      ],
    });
    const health = app.health;
    const began = performance.now();
    try {
      await assert.rejects(
        app.start(),
        (error: unknown) =>
          error instanceof KitError &&
          error.cause instanceof KitError &&
          error.cause.details.cleanupFailed === true &&
          error.cause.cause instanceof AggregateError &&
          error.cause.cause.errors.length === 2,
      );
      assert.ok(performance.now() - began < 8000, 'Startup cleanup exceeded its bounded deadline');
      assert.equal(app.state, 'CLOSED');
      assert.deepEqual(await health.ready(), { status: 'not_ready', failing: ['application'] });
    } finally {
      release();
      await app.stop();
    }
  },
);
