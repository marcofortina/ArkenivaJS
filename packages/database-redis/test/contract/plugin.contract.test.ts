// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError, COMPONENTS } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { redisPlugin } from '@arkenivajs/database-redis';
import { sdkDouble } from '../fixtures/native-double.js';
import { RedisConnection } from '../../dist/connection.js';

const service = { name: 'redis-contract', version: '1.0.0', environment: 'test' as const };
const variable = 'ARKENIVA_REDIS_PLUGIN_TEST';
const databases = { cache: { driver: 'redis' as const, connectionStringEnv: variable } };
const factory: () => Plugin = redisPlugin;
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('EK-CORE-002 Redis factory prepares a frozen non-SQL facade without opening a connection', async (context) => {
  const sdk = sdkDouble(context),
    plugin = factory();
  assert.ok(plugin.capabilities.has('redis'));
  assert.ok(plugin.capabilities.has('database.redis'));
  const app = await createApplication({ service, plugins: [plugin], databases });
  assert.equal(app.state, 'CREATED');
  assert.equal(sdk.configurations.length, 0);
  assert.ok(app.redis && Object.isFrozen(app.redis));
  const stale = app.redis;
  assert.throws(() => app.redis!.native(), code('EK_LIFECYCLE_STATE'));
  await assert.rejects(app.redis!.get('key'), code('EK_LIFECYCLE_STATE'));
  await app.stop();
  assert.equal(sdk.configurations.length, 0);
  assert.throws(() => stale.native(), code('EK_RESOURCE_CLOSED'));
});

test('EK-CONF-001 Redis rejects missing, multiple and invalid definitions before native allocation', async (context) => {
  const sdk = sdkDouble(context);
  try {
    for (const definitions of [undefined, databases]) {
      delete process.env[variable];
      const app = await createApplication({
        service,
        plugins: [factory()],
        ...(definitions ? { databases: definitions } : {}),
      });
      await assert.rejects(
        app.start(),
        (error) =>
          error instanceof KitError &&
          error.cause instanceof KitError &&
          error.cause.code === 'EK_CONFIG_MISSING',
      );
      await app.stop();
      assert.equal(app.state, 'CLOSED');
    }
    process.env[variable] = 'redis://user:password@untrusted.example';
    const app = await createApplication({ service, plugins: [factory()], databases });
    await assert.rejects(
      app.start(),
      (error) =>
        error instanceof KitError &&
        error.cause instanceof KitError &&
        error.cause.code === 'EK_CONFIG_INVALID',
    );
    await app.stop();
    assert.equal(sdk.configurations.length, 0);
    await assert.rejects(
      createApplication({
        service,
        plugins: [factory()],
        databases: { ...databases, second: databases.cache },
      }),
      code('EK_CONFIG_INVALID'),
    );
    await assert.rejects(
      createApplication({
        service,
        plugins: [factory()],
        databases: { other: { driver: 'postgresql', connectionStringEnv: variable } },
      }),
      code('EK_PLUGIN_DEPENDENCY'),
    );
  } finally {
    delete process.env[variable];
  }
});

test('EK-CORE-001 Redis reusable factories keep application facade lifetime and closure isolated', async (context) => {
  const sdk = sdkDouble(context),
    plugin = factory();
  process.env[variable] = 'redis://user:password@localhost?prefix=contract:';
  const first = await createApplication({ service, plugins: [plugin], databases });
  const second = await createApplication({ service, plugins: [plugin], databases });
  try {
    assert.notEqual(first.redis, second.redis);
    await first.start();
    assert.equal(await first.redis!.set('key', 'value'), true);
    assert.equal(first.redis!.native(), sdk.client);
    await assert.rejects(second.redis!.get('key'), code('EK_LIFECYCLE_STATE'));
    const stale = first.redis!;
    await first.stop();
    await assert.rejects(stale.get('key'), code('EK_RESOURCE_CLOSED'));
    await second.start();
    assert.equal(await second.redis!.get('key'), 'value');
    assert.equal(await second.redis!.increment('counter'), 1);
    assert.equal(await second.redis!.del(['key']), 1);
    assert.equal(await second.redis!.publish('topic', 'message'), 0);
    await assert.rejects(stale.publish('topic', 'message'), code('EK_RESOURCE_CLOSED'));
    await second.stop();
    assert.equal(sdk.counts.connects, 2);
    assert.equal(sdk.counts.destroys, 2);
  } finally {
    await Promise.allSettled([first.stop(), second.stop()]);
    delete process.env[variable];
  }
});

test('EK-CORE-001 Redis startup failure closes owned native resources and prevents facade activation', async (context) => {
  const sdk = sdkDouble(context);
  sdk.failConnect(new Error('Native connection failed'));
  process.env[variable] = 'redis://user:password@localhost';
  const app = await createApplication({ service, plugins: [factory()], databases });
  const stale = app.redis!;
  try {
    await assert.rejects(app.start());
    await assert.rejects(stale.get('key'), code('EK_RESOURCE_CLOSED'));
    await app.stop();
    assert.equal(sdk.counts.connects, 1);
    assert.equal(sdk.counts.destroys, 1);
  } finally {
    await app.stop();
    delete process.env[variable];
  }
});

test('EK-DB-004 Redis resolves optional observation owners before opening its socket and closes before them', async (context) => {
  const sdk = sdkDouble(context),
    events: string[] = [];
  const observation: Plugin = {
    id: 'redis-contract-observation',
    version: '1.0.0',
    capabilities: new Set(['telemetry', 'meter', 'logger']),
    init(context) {
      events.push('observation-ready');
      context.provide(COMPONENTS.logger, { debug() {}, warn() {} });
      context.provide(COMPONENTS.telemetry, {
        async withSpan(_name: string, work: () => Promise<unknown>) {
          events.push('span');
          return work();
        },
        recordHistogram() {
          events.push('histogram');
        },
      });
      context.provide(COMPONENTS.meter, {
        current() {
          return {
            recordOperation() {
              events.push('operation');
            },
            recordUsage() {},
          };
        },
        markMissing() {},
      });
    },
    close() {
      assert.equal(sdk.client.isOpen, false);
      events.push('observation-closed');
    },
  };
  process.env[variable] = 'redis://user:password@localhost';
  const app = await createApplication({ service, plugins: [factory(), observation], databases });
  try {
    await app.start();
    await app.redis!.get('key');
    await app.stop();
    assert.deepEqual(events, [
      'observation-ready',
      'span',
      'operation',
      'histogram',
      'observation-closed',
    ]);
  } finally {
    await app.stop();
    delete process.env[variable];
  }
});

test('EK-CORE-001 Redis initialization retains both acquisition and cleanup failures', async (context) => {
  const sdk = sdkDouble(context);
  sdk.failConnect(new Error('Acquisition failed'));
  const close = RedisConnection.prototype.close;
  let calls = 0;
  context.mock.method(RedisConnection.prototype, 'close', function (this: RedisConnection) {
    if (++calls === 1) return Promise.reject(new Error('Cleanup failed'));
    return close.call(this);
  });
  process.env[variable] = 'redis://user:password@localhost';
  const app = await createApplication({ service, plugins: [factory()], databases });
  try {
    await assert.rejects(
      app.start(),
      (error) =>
        error instanceof KitError &&
        error.cause instanceof KitError &&
        error.cause.cause instanceof AggregateError &&
        error.cause.cause.errors.length === 2,
    );
    assert.equal(sdk.client.isOpen, false);
  } finally {
    await app.stop();
    delete process.env[variable];
  }
});
