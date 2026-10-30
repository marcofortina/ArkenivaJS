// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import type { Telemetry, Logger } from '@arkenivajs/core';
import { createHealthRegistry } from '@arkenivajs/health';

test('Health liveness stays local while lifecycle readiness requires successful explicit startup', async () => {
  let lifecycle = true,
    calls = 0;
  const registry = createHealthRegistry({
    isReady: () => lifecycle,
    checks: [
      {
        name: 'storage',
        check: () => {
          calls++;
          return true;
        },
      },
    ],
  });
  assert.deepEqual(registry.live(), { status: 'live' });
  assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['application'] });
  assert.equal(calls, 0);
  const starting = registry.start();
  assert.equal(starting, registry.start());
  await starting;
  assert.deepEqual(await registry.ready(), { status: 'ready', failing: [] });
  lifecycle = false;
  assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['application'] });
  assert.equal(calls, 2);
  const closing = registry.close();
  assert.equal(closing, registry.close());
  await closing;
  await assert.rejects(registry.start(), { code: 'EK_RESOURCE_CLOSED' });
  assert.deepEqual(registry.live(), { status: 'live' });
});

test('Health captures callback metadata and exposes deterministic bounded dependency names without raw error text', async () => {
  let available = true;
  const failure = new Error('private-backend-credential');
  const check = {
      name: 'primary',
      check() {
        if (!available) throw failure;
        return true;
      },
    },
    checks = [check],
    registry = createHealthRegistry({ checks });
  check.name = 'changed';
  check.check = () => false;
  checks.push({ name: 'later', check: () => false });
  try {
    await registry.start();
    available = false;
    const result = await registry.ready();
    assert.deepEqual(result, { status: 'not_ready', failing: ['primary'] });
    assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.isFrozen(result.failing), true);
    assert.equal(JSON.stringify(result).includes('private-backend'), false);
    available = true;
    assert.deepEqual(await registry.ready(), { status: 'ready', failing: [] });
  } finally {
    await registry.close();
  }
});

test('Health concurrent readiness requests share a single bounded native probe batch', async () => {
  let calls = 0,
    release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const registry = createHealthRegistry({
    checks: [
      {
        name: 'shared',
        async check() {
          if (++calls > 1) await gate;
          return true;
        },
      },
    ],
  });
  await registry.start();
  try {
    const waiting = Array.from({ length: 100 }, () => registry.ready());
    await delay(0);
    assert.equal(calls, 2);
    assert.equal(registry.stats().pendingChecks, 1);
    release();
    assert.ok((await Promise.all(waiting)).every((value) => value.status === 'ready'));
    assert.equal(registry.stats().pendingChecks, 0);
  } finally {
    release();
    await registry.close();
  }
});

test('Health timeouts retain ownership of uncooperative callbacks and prevent overlapping retries until settlement', async () => {
  let calls = 0,
    stuck = false,
    release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const registry = createHealthRegistry({
    timeoutMs: 5,
    checks: [
      {
        name: 'bounded',
        async check(options) {
          calls++;
          assert.equal(options.timeoutMs, 5);
          assert.ok(options.signal instanceof AbortSignal);
          if (stuck) await gate;
          return true;
        },
      },
    ],
  });
  await registry.start();
  try {
    stuck = true;
    assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['bounded'] });
    assert.equal(registry.stats().pendingChecks, 1);
    assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['bounded'] });
    assert.equal(calls, 2);
    release();
    await delay(0);
    stuck = false;
    assert.deepEqual(await registry.ready(), { status: 'ready', failing: [] });
    assert.equal(calls, 3);
  } finally {
    release();
    await registry.close();
  }
});

test('Health drain cancels cooperative dependency work and cannot return stale ready after closure', async () => {
  let calls = 0;
  const registry = createHealthRegistry({
    checks: [
      {
        name: 'cooperative',
        async check(options) {
          if (++calls === 1) return true;
          return new Promise<boolean>((resolve) =>
            options.signal!.addEventListener('abort', () => resolve(false), { once: true }),
          );
        },
      },
    ],
  });
  await registry.start();
  const waiting = registry.ready();
  await delay(0);
  await registry.close();
  assert.deepEqual(await waiting, { status: 'not_ready', failing: ['application'] });
  assert.equal(registry.stats().pendingChecks, 0);
  assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['application'] });
});

test('Health startup preserves native failure causes and rejects invalid evidence without repeated initialization', async () => {
  const failure = new Error('private-native-failure');
  for (const check of [
    () => false,
    () => {
      throw failure;
    },
    () => 'ready' as never,
  ]) {
    const registry = createHealthRegistry({ checks: [{ name: 'unavailable', check }] });
    try {
      const starting = registry.start();
      assert.equal(starting, registry.start());
      await assert.rejects(
        starting,
        (cause: unknown) =>
          cause instanceof KitError &&
          cause.code === 'EK_HEALTH_NOT_READY' &&
          cause.cause instanceof AggregateError &&
          cause.cause.errors.length === 1,
      );
      assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['application'] });
    } finally {
      await registry.close();
    }
  }
});

test('Health diagnostic failures and invalid lifecycle callbacks fail closed without changing dependency evidence', async () => {
  const telemetry = {
      recordHistogram() {
        throw new Error('Metric sink failed');
      },
    } as unknown as Telemetry,
    logger = {
      warn() {
        throw new Error('Log sink failed');
      },
    } as unknown as Logger;
  let state = 'ready';
  const registry = createHealthRegistry({
    telemetry,
    logger,
    isReady() {
      if (state === 'broken') throw new Error('Lifecycle callback failed');
      return true;
    },
    checks: [{ name: 'dependency', check: () => state !== 'failed' }],
  });
  await registry.start();
  try {
    state = 'failed';
    assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['dependency'] });
    state = 'broken';
    assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['application'] });
    assert.ok(registry.stats().observerFailures >= 3);
  } finally {
    await registry.close();
  }
});

test('Health rejects invalid capacities, callbacks and duplicate names before invoking a dependency', () => {
  for (const options of [
    null,
    [],
    { checks: {} },
    { checks: new Array(2) },
    { isReady: true },
    { timeoutMs: 0 },
    { timeoutMs: 1.5 },
    { timeoutMs: 5001 },
    { timeoutMs: NaN },
    { checks: [{ name: 'application', check: () => true }] },
    { checks: [{ name: 'bad\n', check: () => true }] },
    { checks: [{ name: 'missing', check: false }] },
    { checks: [null] },
    {
      checks: [
        { name: 'same', check: () => true },
        { name: 'same', check: () => true },
      ],
    },
    {
      checks: Array.from({ length: 33 }, (_, index) => ({
        name: 'check' + index,
        check: () => true,
      })),
    },
  ])
    assert.throws(() => createHealthRegistry(options as never), { code: 'EK_CONFIG_INVALID' });
});

test('Health startup cancelled before a probe runs cannot establish readiness or leave pending work', async () => {
  let calls = 0;
  const registry = createHealthRegistry({
    checks: [
      {
        name: 'resource',
        check() {
          calls++;
          return true;
        },
      },
    ],
  });
  const starting = assert.rejects(registry.start(), { code: 'EK_RESOURCE_CLOSED' });
  await registry.close();
  await starting;
  assert.equal(calls, 0);
  assert.equal(registry.stats().pendingChecks, 0);
});

test('Health probes ignore custom bind metadata and preserve the original receiver', async () => {
  let calls = 0,
    binds = 0;
  const probe = {
    name: 'unavailable',
    available: false,
    check() {
      calls++;
      assert.equal(this, probe);
      return this.available;
    },
  };
  Object.defineProperty(probe.check, 'bind', {
    value: () => {
      binds++;
      return () => true;
    },
  });
  const registry = createHealthRegistry({ checks: [probe] });
  try {
    await assert.rejects(registry.start(), { code: 'EK_HEALTH_NOT_READY' });
    assert.equal(calls, 1);
    assert.equal(binds, 0);
    assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['application'] });
  } finally {
    await registry.close();
  }
});

test('Health captures inherited methods once and never evaluates probe accessors or proxy traps', async () => {
  let effects = 0;
  class Probe {
    name = 'native-owner';
    available = true;
    check() {
      assert.ok(this instanceof Probe);
      return this.available;
    }
  }
  const probe = new Probe(),
    registry = createHealthRegistry({ checks: [probe] });
  probe.check = () => true;
  await registry.start();
  try {
    probe.available = false;
    assert.deepEqual(await registry.ready(), { status: 'not_ready', failing: ['native-owner'] });
  } finally {
    await registry.close();
  }
  const trap = () => {
    effects++;
    throw new Error('Application metadata must not execute');
  };
  const valid = { name: 'invalid', check: () => true };
  const accessor = Object.defineProperty({ name: 'invalid' }, 'check', { get: trap });
  const arrayAccessor = Object.defineProperty([valid], '0', { get: trap });
  const proxiedCallback = { name: 'invalid', check: new Proxy(() => true, { apply: trap }) };
  const proxy = new Proxy(valid, {
    get: trap,
    getOwnPropertyDescriptor: trap,
    getPrototypeOf: trap,
  });
  const prototypeProxy = Object.create(proxy) as typeof valid;
  const deep = Array.from({ length: 33 }).reduce<object>(
    (previous) => Object.create(previous) as object,
    valid,
  );
  for (const checks of [
    [accessor],
    arrayAccessor,
    [proxiedCallback],
    [proxy],
    [prototypeProxy],
    [deep],
    new Proxy([valid], { get: trap }),
  ]) {
    assert.throws(() => createHealthRegistry({ checks: checks as never }), {
      code: 'EK_CONFIG_INVALID',
    });
  }
  for (const options of [
    new Proxy({}, { get: trap }),
    Object.defineProperty({}, 'checks', { get: trap }),
    Object.defineProperty({}, 'isReady', { get: trap }),
  ]) {
    assert.throws(() => createHealthRegistry(options), { code: 'EK_CONFIG_INVALID' });
  }
  assert.equal(effects, 0);
});
